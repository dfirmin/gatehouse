"""Read-only view of native dispatch-wave state (`.gatehouse/<scope>/dispatch.json`).

The checker and the Stop hook use this to refuse completion while a launch wave
is open or sealed. The recorder that *writes* wave state is not ported yet, but
files written by the upstream recorder are validated and honored.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .gates import GateFileError, read_stable_regular_file, scope_root, validate_scope_id

SCHEMA = 1
MAX_STATE_BYTES = 8 * 1024 * 1024
STATES = {"open", "sealed", "complete", "abandoned"}
_CONTROL = re.compile("[\u0000-\u001f\u007f-\u009f؜‎‏ -‮⁦-⁩]")


class DispatchError(Exception):
    pass


def _safe_diagnostic(value: Any) -> str:
    return re.sub(r"\s+", " ", _CONTROL.sub(" ", str(value))).strip()[:500]


def _valid_id(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise DispatchError(f"{label} must be a string")
    error = validate_scope_id(value, label)
    if error:
        raise DispatchError(error)
    return value


def _valid_handle(value: Any) -> str:
    if not isinstance(value, str):
        raise DispatchError("handle must be a string")
    handle = value.strip()
    if not handle or len(handle) > 256 or _CONTROL.search(handle):
        raise DispatchError("handle must be printable, nonblank, and at most 256 characters")
    return handle


def _valid_reason(value: Any) -> str:
    if not isinstance(value, str):
        raise DispatchError("reason must be a string")
    reason = value.strip()
    if not reason or len(reason) > 500 or _CONTROL.search(reason):
        raise DispatchError("reason must be printable, nonblank, and at most 500 characters")
    return reason


def _valid_time(value: Any, label: str) -> float:
    if not isinstance(value, str) or not value:
        raise DispatchError(f"{label} must be an ISO timestamp")
    text = value.strip()
    if text[-1:] in ("Z", "z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        raise DispatchError(f"{label} must be an ISO timestamp") from None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp() * 1000.0


def _is_object(value: Any) -> bool:
    return isinstance(value, dict)


def _validate_state(state: Any) -> Dict[str, Any]:
    if not _is_object(state) or state.get("schema") != SCHEMA or not _is_object(state.get("waves")):
        raise DispatchError("expected schema 1 with a waves object")

    for wave_id, wave in state["waves"].items():
        _valid_id(wave_id, "wave")
        if (
            not _is_object(wave) or wave.get("state") not in STATES
            or not isinstance(wave.get("leaves"), list) or not wave["leaves"]
            or not _is_object(wave.get("started")) or not _is_object(wave.get("returned"))
        ):
            raise DispatchError(f"wave {wave_id} has an invalid shape")
        opened_at = _valid_time(wave.get("openedAt"), f"wave {wave_id} openedAt")
        abandoned_at: Optional[float] = None
        if wave["state"] == "abandoned":
            abandoned_at = _valid_time(wave.get("abandonedAt"), f"wave {wave_id} abandonedAt")
            wave["reason"] = _valid_reason(wave.get("reason"))
        elif "abandonedAt" in wave or "reason" in wave:
            raise DispatchError(f"{wave['state']} wave {wave_id} contains abandonment metadata")

        leaves = set()
        for leaf in wave["leaves"]:
            leaf_id = _valid_id(leaf, "leaf")
            if leaf_id in leaves:
                raise DispatchError(f"wave {wave_id} has duplicate leaf {leaf_id}")
            leaves.add(leaf_id)

        handles = set()
        start_times: Dict[str, float] = {}
        latest_start = opened_at
        for leaf, start in wave["started"].items():
            if leaf not in leaves:
                raise DispatchError(f"wave {wave_id} started unknown leaf {leaf}")
            if not _is_object(start):
                raise DispatchError(f"wave {wave_id} has invalid start for {leaf}")
            handle = _valid_handle(start.get("handle"))
            if handle in handles:
                raise DispatchError(f"wave {wave_id} reuses handle {handle}")
            handles.add(handle)
            at = _valid_time(start.get("at"), f"wave {wave_id} start time for {leaf}")
            if at < opened_at:
                raise DispatchError(f"wave {wave_id} starts {leaf} before it opened")
            start_times[leaf] = at
            latest_start = max(latest_start, at)

        return_times: List[float] = []
        for leaf, returned in wave["returned"].items():
            if leaf not in leaves or leaf not in wave["started"]:
                raise DispatchError(f"wave {wave_id} returned unstarted leaf {leaf}")
            if not _is_object(returned):
                raise DispatchError(f"wave {wave_id} has invalid return for {leaf}")
            at = _valid_time(returned.get("at"), f"wave {wave_id} return time for {leaf}")
            if at < start_times[leaf]:
                raise DispatchError(f"wave {wave_id} returns {leaf} before it started")
            return_times.append(at)

        all_started = len(wave["started"]) == len(wave["leaves"])
        all_returned = len(wave["returned"]) == len(wave["leaves"])
        status = wave["state"]
        if status == "open" and wave["returned"]:
            raise DispatchError(f"open wave {wave_id} contains returns")
        if status not in ("open", "abandoned") and not all_started:
            raise DispatchError(f"{status} wave {wave_id} is missing starts")
        if status == "complete" and not all_returned:
            raise DispatchError(f"complete wave {wave_id} is missing returns")
        if status == "sealed" and all_returned:
            raise DispatchError(f"sealed wave {wave_id} should be complete")

        needs_seal = status in ("sealed", "complete") or (status == "abandoned" and "sealedAt" in wave)
        sealed_at: Optional[float] = None
        if needs_seal:
            sealed_at = _valid_time(wave.get("sealedAt"), f"wave {wave_id} sealedAt")
            if not all_started:
                raise DispatchError(f"{status} wave {wave_id} is missing starts after sealing")
            if sealed_at < latest_start:
                raise DispatchError(f"wave {wave_id} was sealed before its final start")
        elif "sealedAt" in wave:
            raise DispatchError(f"{status} wave {wave_id} contains seal metadata")

        if return_times:
            if sealed_at is None:
                raise DispatchError(f"{status} wave {wave_id} contains returns without being sealed")
            if any(at < sealed_at for at in return_times):
                raise DispatchError(f"wave {wave_id} contains a return before sealing")

        if status == "complete":
            completed_at = _valid_time(wave.get("completedAt"), f"wave {wave_id} completedAt")
            if completed_at < max([sealed_at or 0.0] + return_times):
                raise DispatchError(f"wave {wave_id} completed before its final return")
        elif "completedAt" in wave:
            raise DispatchError(f"{status} wave {wave_id} contains completion metadata")

        if status == "abandoned":
            if all_returned:
                raise DispatchError(f"abandoned wave {wave_id} already has every return and must be complete")
            latest = max([opened_at, latest_start, sealed_at if sealed_at is not None else opened_at] + return_times)
            if abandoned_at is not None and abandoned_at < latest:
                raise DispatchError(f"wave {wave_id} was abandoned before its latest transition")
    return state


def dispatch_state_path(root: str, scope: str) -> str:
    return os.path.join(scope_root(os.path.abspath(root), _valid_id(scope, "scope")), "dispatch.json")


def _read_state(root: str, path: str) -> Dict[str, Any]:
    try:
        text = read_stable_regular_file(
            path, root=os.path.abspath(root), max_bytes=MAX_STATE_BYTES, label="dispatch state")
        return _validate_state(json.loads(text))
    except FileNotFoundError:
        return {"schema": SCHEMA, "waves": {}}
    except (DispatchError, GateFileError, OSError, ValueError) as error:
        raise DispatchError("invalid dispatch state: " + str(error)) from None


def dispatch_status(root: str, scope: Optional[str]) -> Dict[str, List[str]]:
    """Summarize wave state: blocking (open/sealed), abandoned, resolved, and errors."""
    result: Dict[str, List[str]] = {"blocking": [], "abandoned": [], "resolved": [], "errors": []}
    if not scope:
        return result
    try:
        state = _read_state(root, dispatch_state_path(root, scope))
    except DispatchError as error:
        return {
            "blocking": ["dispatch:PARSE invalid dispatch state"],
            "abandoned": [],
            "resolved": ["dispatch:PARSE=invalid"],
            "errors": [f"invalid dispatch state for scope {scope}: {_safe_diagnostic(error)}"],
        }
    for wave_id in sorted(state["waves"]):
        wave = state["waves"][wave_id]
        started = len(wave["started"])
        returned = len(wave["returned"])
        total = len(wave["leaves"])
        result["resolved"].append(
            f"dispatch:{wave_id}={wave['state']};started={started}/{total};returned={returned}/{total}")
        if wave["state"] == "complete":
            continue
        if wave["state"] == "abandoned":
            result["abandoned"].append(f"dispatch:{wave_id}")
        elif wave["state"] == "open":
            result["blocking"].append(f"dispatch:{wave_id} open ({started}/{total} started)")
        else:
            result["blocking"].append(f"dispatch:{wave_id} sealed ({returned}/{total} returned)")
    return result
