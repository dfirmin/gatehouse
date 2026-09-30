"""Claude Code Stop hook for one gatehouse pipeline.

Reads the hook payload from stdin. While the resolved pipeline still has unmet
gates or incomplete dispatch waves it prints Claude Code's top-level
`{"decision": "block", ...}` response; otherwise it allows the stop. It never
executes a CHECK. A progress guard releases the block after MAX_BLOCKS
consecutive blocks without any change in resolved gate state, so it cannot
wedge a session.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, NoReturn, Optional

from . import gates as G
from .dispatch import dispatch_status

MAX_BLOCKS = 6
MAX_GATE_LEDGER_BYTES = 8 * 1024 * 1024
MAX_HOOK_STATE_BYTES = 1024 * 1024
_UNSAFE = re.compile("[\u0000-\u001f\u007f-\u009f؜‎‏ -‮⁦-⁩]")
_HEX24 = re.compile(r"^[a-f0-9]{24}\Z")


def _safe_host_text(value: Any, limit: int = 500) -> str:
    return re.sub(r"\s+", " ", _UNSAFE.sub(" ", str(value))).strip()[:limit]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        datetime.fromisoformat(text)
        return True
    except ValueError:
        return False


def _normalize_state(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != 1 or not isinstance(value.get("sessions"), dict):
        return {"schema": 1, "sessions": {}}
    sessions: Dict[str, Any] = {}
    for key, current in value["sessions"].items():
        if (
            not _HEX24.match(str(key)) or not isinstance(current, dict)
            or not _HEX24.match(str(current.get("hash") or ""))
            or not isinstance(current.get("blocks"), int) or isinstance(current.get("blocks"), bool)
            or current["blocks"] < 0 or not _valid_timestamp(current.get("updatedAt"))
        ):
            continue
        sessions[key] = current
    return {"schema": 1, "sessions": sessions}


def _read_hook_state(path: str, root: str) -> Dict[str, Any]:
    try:
        text = G.read_stable_regular_file(path, root=root, max_bytes=MAX_HOOK_STATE_BYTES, label="hook state")
    except FileNotFoundError:
        return {"missing": True, "state": {"schema": 1, "sessions": {}}}
    try:
        return {"missing": False, "state": _normalize_state(json.loads(text))}
    except ValueError:
        return {"missing": False, "state": {"schema": 1, "sessions": {}}}


def _emit(payload: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def _allow(message: Optional[str]) -> NoReturn:
    if message:
        _emit({"systemMessage": message})
    raise SystemExit(0)


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    scope_arg: Optional[str] = None
    scope_given = "--scope" in args
    if scope_given:
        position = args.index("--scope")
        scope_arg = args[position + 1] if position + 1 < len(args) else None
    if scope_given and (not scope_arg or G.validate_scope_id(scope_arg)):
        _allow("gatehouse: installed hook has an invalid --scope value; not blocking.")

    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        _allow(None)
    if not isinstance(payload, dict):
        payload = {}

    cwd = payload.get("cwd")
    root = os.path.abspath(cwd if isinstance(cwd, str) and cwd else os.getcwd())
    session_id = payload.get("session_id") or payload.get("sessionId") or "anonymous"
    target = G.resolve_target(root, scope_arg, None, session_id)

    if target.ambiguous:
        _allow(f"gatehouse: {len(target.ambiguous)} pipelines under {G.STATE_DIR}/ "
               f"({', '.join(target.ambiguous)}) and none bound to this session; not blocking.")
    if target.error and not target.ambiguous:
        _allow(f"gatehouse: {_safe_host_text(target.error)}; not blocking.")

    discovery_errors = target.discovery_errors or []
    # An invalid named scope cannot safely hold its own hook-state file. Keep its
    # bounded loop-guard state at the real repository root and include the target
    # identity in the session key so it cannot collide with another scope.
    state_path = G.hook_state_path(root, None if discovery_errors else target.scope)
    session_key = G.sha256(f"{session_id}\0{target.scope or 'unscoped'}")[:24]

    def clear_session_state() -> None:
        try:
            if _read_hook_state(state_path, root)["missing"]:
                return
        except (OSError, G.GateFileError):
            return
        try:
            with G.file_lock(root, state_path, timeout_ms=10000):
                loaded = _read_hook_state(state_path, root)
                if loaded["missing"]:
                    return
                state = loaded["state"]
                state["sessions"].pop(session_key, None)
                if not state["sessions"]:
                    try:
                        os.unlink(state_path)
                    except OSError:
                        pass
                else:
                    G.write_atomic(state_path, json.dumps(state, indent=2) + "\n", root=root)
        except Exception:  # noqa: BLE001 - cleanup must never trap a finished session
            pass

    # Do not even open dispatch state through a scope path already proven unsafe.
    dispatch = ({"blocking": [], "abandoned": [], "resolved": []} if discovery_errors
                else dispatch_status(root, target.scope))

    if not target.files and not discovery_errors and not dispatch["blocking"] and not dispatch["abandoned"]:
        clear_session_state()
        _allow(None)

    unmet: List[str] = list(dispatch["blocking"])
    invalid: List[str] = ["discovery:PARSE " + _safe_host_text(e) for e in discovery_errors]
    handoffs: List[str] = list(dispatch["abandoned"])

    def handoff_message() -> str:
        if not handoffs:
            return ""
        shown = ", ".join(handoffs[:5]) + (f", +{len(handoffs) - 5} more" if len(handoffs) > 5 else "")
        return f" HANDOFF REQUIRED: {len(handoffs)} abandoned item(s): {_safe_host_text(shown)}."

    # The loop guard compares resolved gate state between stops, not raw bytes.
    # Byte comparison counted any edit as progress: a comment, a reflowed line, or
    # the checker rewriting an evidence line with a fresh PATH hash. That rearmed
    # the guard indefinitely, so the release could only ever fire for an agent
    # doing literally nothing, which is the one case least in need of it.
    resolved: List[str] = list(dispatch["resolved"])
    if discovery_errors:
        resolved.append("discovery:PARSE=invalid")
    for file in sorted(target.files):
        try:
            text = G.read_stable_regular_file(file, root=root, max_bytes=MAX_GATE_LEDGER_BYTES,
                                              label="gate ledger")
        except (OSError, G.GateFileError) as error:
            invalid.append(f"{G.qualify(file, 'PARSE')} unreadable: {_safe_host_text(error)}")
            resolved.append(f"{G.qualify(file, 'PARSE')}=unreadable")
            continue
        doc = G.parse_gates(text)
        if doc.errors:
            invalid.append(f"{G.qualify(file, 'PARSE')} " + "; ".join(_safe_host_text(e) for e in doc.errors[:2]))
            # Record only that the ledger is invalid. Diagnostic text carries line
            # numbers, which shift on an unrelated edit and would restore byte coupling.
            resolved.append(f"{G.qualify(file, 'PARSE')}=invalid")
            continue
        for gate in doc.gates:
            state = G.gate_state(gate, doc.abandoned)
            resolved.append(f"{G.qualify(file, gate.id)}={state}")
            if state == "abandoned":
                handoffs.append(G.qualify(file, gate.id))
            elif state != "met":
                unmet.append(G.qualify(file, gate.id))

    where = f" [scope {target.scope}]" if target.scope else ""
    if not unmet and not invalid:
        clear_session_state()
        if not handoffs:
            _allow(None)
        _allow(f"gatehouse{where}:{handoff_message()}")

    progress_hash = G.sha256("\0".join(sorted(resolved)))[:24]
    try:
        with G.file_lock(root, state_path, timeout_ms=10000):
            state = _read_hook_state(state_path, root)["state"]
            current = state["sessions"].get(session_key)
            if not current or current["hash"] != progress_hash:
                current = {"hash": progress_hash, "blocks": 0}
            current["blocks"] += 1
            current["updatedAt"] = _now()
            state["sessions"][session_key] = current
            # Bound abandoned session debris without mixing counters between sessions.
            newest = sorted(state["sessions"].items(), key=lambda kv: str(kv[1]["updatedAt"]), reverse=True)
            state["sessions"] = dict(newest[:64])
            G.write_atomic(state_path, json.dumps(state, indent=2) + "\n", root=root)
            session_state = current
    except Exception as error:  # noqa: BLE001 - never trap the session on hook infrastructure
        if discovery_errors:
            _emit({"decision": "block",
                   "reason": "gatehouse: invalid named scope input must be repaired before Stop: "
                             + _safe_host_text(discovery_errors[0])})
            return 0
        _allow("gatehouse: could not update the serialized hook state ("
               + _safe_host_text(error) + "); not blocking to avoid a trap.")

    outstanding = [_safe_host_text(item) for item in invalid + unmet]
    if session_state["blocks"] > MAX_BLOCKS:
        _allow(f"gatehouse: releasing after {MAX_BLOCKS} blocks without gate progress{where}; "
               f"{len(outstanding)} item(s) remain ({', '.join(outstanding[:4])})." + handoff_message())

    listing = ", ".join(outstanding[:5]) + (f", +{len(outstanding) - 5} more" if len(outstanding) > 5 else "")
    _emit({
        "decision": "block",
        "reason": (
            f"gatehouse{where}: {len(outstanding)} gate/ledger/dispatch item(s) need work: {listing}. "
            "Run `gatehouse check --status` to inspect without execution. To run inherited CHECK lines, "
            "inspect them and use --approve. Use ABANDON: <id> <non-blank reason> only when a gate is "
            "genuinely impossible." + handoff_message()
        ),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
