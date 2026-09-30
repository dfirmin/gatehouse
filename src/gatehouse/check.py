"""gatehouse check: execute gate oracles, record evidence, coordinate scopes and leases.

Standard library only. POSIX-first. Exit codes: 0 all met / action succeeded,
1 unmet, 2 usage / parse / infrastructure error, 3 lease conflict.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import select
import signal
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from . import gates as G
from .dispatch import dispatch_status

HELP = """usage: gatehouse check [options] [file ...]

run modes:
  (default)             run unmet runnable gates and update their ledgers
  --status              report only; never execute, approve, or write
  --reverify            re-run every runnable gate and demote stale failures
  --approve             approve each exact pending oracle, then run it
  --jobs N              rolling concurrency, integer 1..64 (default 1)
  --timeout S           per-check timeout, integer seconds 1..86400 (default 120)
  --shell PATH          command shell (GATEHOUSE_SHELL, then /bin/sh)
  --cwd DIR             default CHECK directory (explicit: file dir; discovered: --root)

pipeline actions:
  --claim --scope ID [--leaf NAME]   atomically claim the leaf's OWNS paths
  --release --scope ID [--leaf NAME] release serialized ownership leases
  --log TEXT --scope ID              append one status line
  --bind SESSION --scope ID          bind a session to one pipeline
  --list-scopes                      list .gatehouse pipelines

targeting:
  --scope ID             use .gatehouse/ID (or GATEHOUSE_SCOPE)
  --root DIR             repository/pipeline root (default current directory)
  file ...               explicit regular ledger files; all are honored

CHECK execution requires prior approval keyed to the exact CHECK, EXPECT,
resolved CWD, resolved shell, timeout, output/regex limits, platform, and PATH.
Approvals live outside the repository under ~/.gatehouse/approved by default.

exit codes: 0 all met/action succeeded; 1 unmet; 2 usage/parse/infrastructure;
            3 lease conflict."""

FLAG_OPTIONS = {"--status", "--reverify", "--approve", "--claim", "--release", "--list-scopes", "--help", "-h"}
VALUE_OPTIONS = {"--scope", "--leaf", "--timeout", "--jobs", "--cwd", "--root", "--log", "--bind", "--shell"}
MAX_OUTPUT_BYTES = G.MAX_CHECK_OUTPUT_BYTES
MAX_APPROVAL_BYTES = 256 * 1024
MAX_GATE_LEDGER_BYTES = 8 * 1024 * 1024
REGEX_TIMEOUT_S = 0.25
REGEX_STARTUP_TIMEOUT_S = 5.0
MAX_REGEX_WORKERS = 4
DEFAULT_TIMEOUT_SECONDS = 120

_REGEX_SLOTS = threading.BoundedSemaphore(MAX_REGEX_WORKERS)

# The worker imports nothing from gatehouse: it receives an already-translated
# Python pattern, so it can run under `python -I` from any directory.
_REGEX_WORKER_SOURCE = r"""
import json, re, sys, warnings
warnings.simplefilter("ignore")
sys.stdout.write("ready\n")
sys.stdout.flush()
data = json.loads(sys.stdin.read())
try:
    hit = re.compile(data["pattern"], data["flags"]).search(data["output"]) is not None
    sys.stdout.write(json.dumps({"matched": hit}))
except Exception as error:
    sys.stdout.write(json.dumps({"error": str(error)}))
"""


class UsageError(Exception):
    pass


class ApprovalError(Exception):
    pass


def _out(*values: Any) -> None:
    sys.stdout.write(" ".join(G.terminal_safe(v) for v in values) + "\n")


def _err(*values: Any) -> None:
    sys.stderr.write(" ".join(G.terminal_safe(v) for v in values) + "\n")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_args(argv: List[str]) -> Tuple[Dict[str, Any], List[str]]:
    options: Dict[str, Any] = {}
    files: List[str] = []
    positional = False
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--":
            positional = True
            index += 1
            continue
        if not positional and arg in FLAG_OPTIONS:
            key = arg.lstrip("-")
            if key in options:
                raise UsageError(f"duplicate option {arg}")
            options[key] = True
        elif not positional and arg.startswith("--"):
            name, eq, inline = arg.partition("=")
            if name not in VALUE_OPTIONS:
                raise UsageError(f"unknown option {name}")
            key = name[2:]
            if key in options:
                raise UsageError(f"duplicate option {name}")
            if eq:
                value: Optional[str] = inline
            else:
                index += 1
                value = argv[index] if index < len(argv) else None
            if value is None or value == "":
                raise UsageError(f"{name} needs a value")
            options[key] = value
        elif not positional and arg.startswith("-"):
            raise UsageError(f"unknown option {arg}")
        else:
            files.append(arg)
        index += 1
    return options, files


def _bounded_int(value: Optional[str], default: int, low: int, high: int, name: str) -> int:
    if value is None:
        return default
    try:
        number = float(value)
        ok = number == number and number not in (float("inf"), float("-inf")) and number.is_integer()
    except ValueError:
        ok = False
    if not ok or not (low <= int(number) <= high):
        raise UsageError(f"{name} needs an integer from {low} through {high}, got {json.dumps(value)}")
    return int(number)


def _as_directory(path: str, label: str) -> None:
    try:
        if not stat.S_ISDIR(os.stat(path).st_mode):
            raise UsageError(f"{label} is not a directory: {path}")
    except FileNotFoundError:
        raise UsageError(f"{label} does not exist: {path}") from None
    except OSError as error:
        raise UsageError(f"cannot inspect {label} {path}: {error}") from None


# ---------------------------------------------------------------------------
# Shell resolution
# ---------------------------------------------------------------------------


def _resolve_shell(raw: Optional[str]) -> str:
    requested = raw or os.environ.get("GATEHOUSE_SHELL") or "/bin/sh"
    candidates: List[str] = []
    if os.sep in requested or os.path.isabs(requested):
        candidates.append(os.path.abspath(os.path.join(os.getcwd(), requested)))
    else:
        for directory in [d for d in os.environ.get("PATH", "").split(os.pathsep) if d]:
            candidates.append(os.path.join(directory, requested))
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise UsageError(f"cannot resolve command shell {json.dumps(requested)} from PATH")


# ---------------------------------------------------------------------------
# Regex matching in a disposable process (bounded time, bounded parallelism)
# ---------------------------------------------------------------------------


def safe_regex_match(expectation: Dict[str, Any], output: str) -> Dict[str, Any]:
    if expectation["kind"] == "text":
        return {"matched": expectation["value"] in output}
    with _REGEX_SLOTS:
        try:
            proc = subprocess.Popen(
                [sys.executable, "-I", "-X", "utf8", "-c", _REGEX_WORKER_SOURCE],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
        except OSError as error:
            return {"matched": False, "error": f"EXPECT worker could not start: {error}"}
        try:
            ready, _, _ = select.select([proc.stdout], [], [], REGEX_STARTUP_TIMEOUT_S)
            if not ready or proc.stdout.readline().strip() != b"ready":
                return {"matched": False,
                        "error": f"EXPECT worker startup exceeded {int(REGEX_STARTUP_TIMEOUT_S * 1000)}ms"}
            payload = json.dumps({
                "pattern": expectation["pattern"], "flags": expectation["reflags"], "output": output,
            }).encode("ascii")
            try:
                stdout, _ = proc.communicate(payload, timeout=REGEX_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                return {"matched": False, "error": f"EXPECT regex exceeded {int(REGEX_TIMEOUT_S * 1000)}ms"}
            try:
                message = json.loads(stdout.decode("utf-8", "replace") or "{}")
            except ValueError:
                return {"matched": False, "error": "EXPECT worker exited without a result"}
            if "matched" in message:
                return {"matched": bool(message["matched"])}
            return {"matched": False, "error": message.get("error", "EXPECT worker exited without a result")}
        finally:
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass


# ---------------------------------------------------------------------------
# Running one CHECK
# ---------------------------------------------------------------------------


@dataclass
class Task:
    file: str
    gate: G.Gate
    cwd: str
    starting_state: str
    was_met: bool
    definition_digest: Optional[str]
    approval_signature: str


@dataclass
class Result:
    task: Task
    output: str = ""
    sha256: str = ""
    bytes: int = 0
    exit_code: Optional[int] = None
    signal: Optional[str] = None
    matched: bool = False
    error: Optional[str] = None
    ok: bool = False


class _Child:
    """Process-group leader that stays unreaped until cleanup is decided.

    Because the leader is only observed (waitid WNOWAIT) and not reaped, its PID
    remains reserved as the process-group id, so a later group kill cannot hit a
    recycled PID. Without waitid the child is polled and never signalled after
    it has been reaped.
    """

    def __init__(self, proc: "subprocess.Popen[bytes]") -> None:
        self.proc = proc
        self.nowait = all(hasattr(os, name) for name in ("waitid", "WNOWAIT", "P_PID", "WEXITED", "WNOHANG"))

    def exited(self) -> bool:
        if self.proc.returncode is not None:
            return True
        if self.nowait:
            try:
                info = os.waitid(os.P_PID, self.proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError:
                return True
            return info is not None
        return self.proc.poll() is not None

    def kill_group(self) -> Optional[str]:
        if self.proc.returncode is not None:
            return "process supervisor already exited"
        if not self.nowait and self.proc.poll() is not None:
            return "process supervisor already exited"
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
            return None
        except ProcessLookupError:
            return None
        except OSError as error:
            try:
                self.proc.kill()
                return f"process-group kill failed ({error.strerror or error}); child fallback requested"
            except OSError as fallback:
                return (f"process-group kill failed ({error.strerror or error}); "
                        f"child fallback failed ({fallback.strerror or fallback})")


def _output_fingerprint(output: str) -> Tuple[str, int]:
    data = output.encode("utf-8", "replace")
    return G.sha256(output), len(data)


def run_check(task: Task, shell: str, timeout_seconds: int) -> Result:
    result = Result(task)
    chunks: Dict[str, List[bytes]] = {"stdout": [], "stderr": []}
    lock = threading.Lock()
    counter = {"bytes": 0}
    overflow = threading.Event()
    stop_readers = threading.Event()

    try:
        proc = subprocess.Popen(
            [shell, "-c", task.gate.check or ""],
            cwd=task.cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, env=os.environ.copy(), bufsize=0,
        )
    except (OSError, ValueError) as error:
        result.error = str(error)
        result.sha256, result.bytes = _output_fingerprint("")
        return result

    child = _Child(proc)

    def reader(name: str, stream: Any) -> None:
        fd = stream.fileno()
        while not stop_readers.is_set():
            try:
                ready, _, _ = select.select([fd], [], [], 0.05)
            except (OSError, ValueError):
                return
            if not ready:
                continue
            try:
                data = os.read(fd, 65536)
            except OSError:
                return
            if not data:
                return
            with lock:
                remaining = MAX_OUTPUT_BYTES - counter["bytes"]
                if remaining > 0:
                    chunks[name].append(data[:remaining])
                counter["bytes"] += len(data)
                if counter["bytes"] > MAX_OUTPUT_BYTES:
                    overflow.set()

    readers = [
        threading.Thread(target=reader, args=("stdout", proc.stdout), daemon=True),
        threading.Thread(target=reader, args=("stderr", proc.stderr), daemon=True),
    ]
    for thread in readers:
        thread.start()

    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    cleanup_diagnostic: Optional[str] = None
    while True:
        if child.exited() and not any(t.is_alive() for t in readers):
            break
        if overflow.is_set() or time.monotonic() >= deadline:
            timed_out = not overflow.is_set()
            cleanup_diagnostic = child.kill_group()
            # Give stdio a short grace period to drain, then settle regardless of
            # any escaped descendant that still holds an inherited pipe.
            grace = time.monotonic() + 1.0
            while any(t.is_alive() for t in readers) and time.monotonic() < grace:
                time.sleep(0.01)
            break
        time.sleep(0.005)
    stop_readers.set()
    for thread in readers:
        thread.join(timeout=0.5)
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    for stream in (proc.stdout, proc.stderr):
        try:
            stream.close()
        except OSError:
            pass

    stdout = b"".join(chunks["stdout"]).decode("utf-8", "replace")
    stderr = b"".join(chunks["stderr"]).decode("utf-8", "replace")
    output = stdout + ("\n" if stdout and stderr else "") + stderr
    # EXPECT and persisted fingerprints both use this exact combined string, so
    # its UTF-8 size must stay within the same ceiling as raw capture.
    result.output = output
    result.sha256, result.bytes = _output_fingerprint(output)
    normalized_overflow = result.bytes > MAX_OUTPUT_BYTES
    raw_overflow = overflow.is_set()

    code = proc.returncode
    if code is not None and code < 0:
        try:
            result.signal = signal.Signals(-code).name
        except ValueError:
            result.signal = f"signal {-code}"
        result.exit_code = None
    else:
        result.exit_code = code

    suffix = f"; cleanup: {cleanup_diagnostic}" if cleanup_diagnostic else ""
    if timed_out:
        result.error = f"timed out after {timeout_seconds}s{suffix}"
    elif raw_overflow or normalized_overflow:
        result.error = (f"output exceeded {MAX_OUTPUT_BYTES} bytes"
                        + ("" if raw_overflow else " after stdout/stderr UTF-8 combination") + suffix)
    else:
        match = safe_regex_match(task.gate.expectation or {"kind": "text", "value": ""}, output)
        result.matched = bool(match.get("matched"))
        result.error = match.get("error")
    result.ok = not result.error and result.exit_code == 0 and result.matched
    return result


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------


class GateCheck:
    def __init__(self, opt: Dict[str, Any], file_args: List[str]) -> None:
        self.opt = opt
        self.file_args = file_args
        self.status = bool(opt.get("status"))
        self.reverify = bool(opt.get("reverify"))
        self.approve = bool(opt.get("approve"))
        self.root = ""
        self.target: G.Target = G.Target("none")
        self.timeout_seconds = DEFAULT_TIMEOUT_SECONDS
        self.jobs = 1
        self.default_cwd = ""
        self.shell: Optional[str] = None
        self.path_value = ""
        self.path_evidence = ""
        self.path_transcript = ""
        self.approval_dir = ""
        self.canonical_root = ""

    # -- targets and ledgers ------------------------------------------------

    def read_ledger_file(self, file: str) -> str:
        return G.read_stable_regular_file(
            file,
            root=None if self.target.mode == "explicit" else self.root,
            max_bytes=MAX_GATE_LEDGER_BYTES,
            label="gate ledger",
        )

    def load_ledger(self, file: str) -> Tuple[str, G.Ledger]:
        try:
            text = self.read_ledger_file(file)
        except (OSError, G.GateFileError) as error:
            raise UsageError(f"cannot read {file}: {error}") from None
        doc = G.parse_gates(text)
        for warning in doc.warnings:
            _err(f"gatehouse check: {file}: warning: {warning}")
        if doc.errors:
            for error in doc.errors:
                _err(f"gatehouse check: {file}: {error}")
            raise _Exit(2)
        return file, doc

    # -- oracle and approval ------------------------------------------------

    def resolved_gate_cwd(self, gate: G.Gate, file: str) -> str:
        if self.opt.get("cwd"):
            base = self.default_cwd
        elif self.target.mode == "explicit":
            base = os.path.dirname(os.path.abspath(file))
        else:
            base = self.root
        return os.path.abspath(os.path.join(base, gate.cwd)) if gate.cwd else base

    def oracle(self, file: str, gate: G.Gate) -> Dict[str, Any]:
        return {
            "schema": 1,
            "check": gate.check,
            "expect": gate.expect,
            "cwd": self.resolved_gate_cwd(gate, file),
            "shell": self.shell,
            "timeoutMs": self.timeout_seconds * 1000,
            "maxOutputBytes": MAX_OUTPUT_BYTES,
            "regexTimeoutMs": int(REGEX_TIMEOUT_S * 1000),
            "regexStartupTimeoutMs": int(REGEX_STARTUP_TIMEOUT_S * 1000),
            "maxRegexWorkers": MAX_REGEX_WORKERS,
            "platform": sys.platform,
            "path": self.path_value,
        }

    def approval_signature(self, file: str, gate: G.Gate) -> str:
        return G.sha256(json.dumps(self.oracle(file, gate), sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False))

    def approval_path(self, file: str, gate: G.Gate, directory: str) -> str:
        identity = os.path.abspath(file) + "\0" + gate.id + "\0" + self.approval_signature(file, gate)
        return os.path.join(directory, G.sha256(identity) + ".json")

    @staticmethod
    def _assert_private_entry(path: str, info: os.stat_result, kind: str) -> None:
        wanted = stat.S_ISDIR(info.st_mode) if kind == "directory" else stat.S_ISREG(info.st_mode)
        if stat.S_ISLNK(info.st_mode) or not wanted:
            raise ApprovalError(f"{path} must be a real {kind}")
        if info.st_uid != os.geteuid():
            raise ApprovalError(f"{path} must be owned by the current user")
        if info.st_mode & 0o077:
            raise ApprovalError(f"{path} must not grant group or other permissions")

    def _validated_approval_dir(self, create: bool = False) -> Optional[Dict[str, Any]]:
        if create:
            os.makedirs(self.approval_dir, mode=0o700, exist_ok=True)
        elif not os.path.exists(self.approval_dir):
            return None
        info = os.lstat(self.approval_dir)
        self._assert_private_entry(self.approval_dir, info, "directory")
        canonical = os.path.realpath(self.approval_dir)
        if G.path_is_inside(self.canonical_root, canonical):
            raise ApprovalError(f"approval directory resolves inside the repository root: {canonical}")
        canonical_info = os.lstat(canonical)
        self._assert_private_entry(canonical, canonical_info, "directory")
        return {"path": canonical, "dev": canonical_info.st_dev, "ino": canonical_info.st_ino}

    def _assert_approval_dir_unchanged(self, store: Dict[str, Any]) -> None:
        current = os.lstat(store["path"])
        self._assert_private_entry(store["path"], current, "directory")
        if current.st_dev != store["dev"] or current.st_ino != store["ino"]:
            raise ApprovalError(f"approval directory changed during use: {store['path']}")

    def _read_approval_file(self, path: str) -> str:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError as error:
            if isinstance(error, FileNotFoundError):
                raise
            raise ApprovalError(f"refusing linked or replaced approval record {path}") from None
        try:
            opened = os.fstat(fd)
            named = os.lstat(path)
            self._assert_private_entry(path, opened, "file")
            if opened.st_size > MAX_APPROVAL_BYTES:
                raise ApprovalError(f"approval record exceeds {MAX_APPROVAL_BYTES} bytes: {path}")
            self._assert_private_entry(path, named, "file")
            if opened.st_nlink != 1 or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
                raise ApprovalError(f"refusing linked or replaced approval record {path}")
            data = b""
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                data += chunk
                if len(data) > MAX_APPROVAL_BYTES:
                    raise ApprovalError(f"approval record exceeds {MAX_APPROVAL_BYTES} bytes: {path}")
            after = os.lstat(path)
            self._assert_private_entry(path, after, "file")
            if (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino):
                raise ApprovalError(f"approval record changed while it was read: {path}")
            return data.decode("utf-8", "replace")
        finally:
            os.close(fd)

    def approval_exists(self, file: str, gate: G.Gate) -> bool:
        store = self._validated_approval_dir()
        if not store:
            return False
        path = self.approval_path(file, gate, store["path"])
        try:
            text = self._read_approval_file(path)
        except FileNotFoundError:
            return False
        try:
            value = json.loads(text)
        except ValueError:
            return False
        self._assert_approval_dir_unchanged(store)
        return (
            isinstance(value, dict)
            and value.get("file") == os.path.abspath(file)
            and value.get("gate") == gate.id
            and value.get("signature") == self.approval_signature(file, gate)
        )

    def record_approval(self, file: str, gate: G.Gate) -> None:
        store = self._validated_approval_dir(create=True)
        assert store is not None
        token = self.approval_path(file, gate, store["path"])
        lock = token + ".lock"
        deadline = time.monotonic() + 10
        owner = os.urandom(16).hex()
        while True:
            try:
                fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                break
            except FileExistsError:
                # Fail closed instead of stealing by path: an owner can release
                # and a successor can acquire between stat and unlink.
                try:
                    os.stat(lock)
                except FileNotFoundError:
                    continue
                if time.monotonic() >= deadline:
                    raise ApprovalError("timed out waiting for approval lock") from None
                time.sleep(0.02)
        try:
            os.write(fd, json.dumps({"owner": owner, "pid": os.getpid(), "at": int(time.time() * 1000)}).encode())
            value = {
                "schema": 1, "file": os.path.abspath(file), "gate": gate.id,
                "signature": self.approval_signature(file, gate),
                "oracle": self.oracle(file, gate),
                "approvedAt": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            }
            G.write_atomic(token, json.dumps(value, indent=2) + "\n")
            self._assert_approval_dir_unchanged(store)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                with open(lock, "r", encoding="utf-8") as handle:
                    if json.load(handle).get("owner") == owner:
                        os.unlink(lock)
            except (OSError, ValueError):
                pass  # manual cleanup or a successor owns the lock

    def print_oracle(self, file: str, gate: G.Gate, prefix: str) -> None:
        value = self.oracle(file, gate)
        _out(f"{prefix} {G.qualify(file, gate.id)}")
        _out(f"    CHECK: {value['check']}")
        _out(f"    EXPECT: {value['expect']}")
        _out(f"    CWD: {value['cwd']}")
        _out(f"    SHELL: {value['shell']}")
        _out(f"    PATH: {self.path_transcript}")

    # -- evidence -----------------------------------------------------------

    def evidence_for(self, result: Result) -> str:
        def clean(value: Any) -> str:
            return re.sub(r"[\r\n\t]+", " ", G.terminal_safe(value))

        assert result.task.definition_digest is not None
        # Keep the definition binding and successful-output fingerprint ahead of
        # machine-specific fields so the evidence cap can truncate only transcript
        # detail, never the structural currentness or deciding output identity.
        text = (
            G.automatic_evidence_prefix(result.task.definition_digest)
            + f" exit=0; EXPECT=matched; output-sha256={result.sha256}; output-bytes={result.bytes}"
            + f"; shell={clean(self.shell)}; cwd={clean(result.task.cwd)}; path={self.path_evidence}"
        )
        return text[:G.MAX_AUTOMATIC_EVIDENCE_CHARS]

    @staticmethod
    def insert_or_update_evidence(doc: G.Ledger, gate: G.Gate, value: str) -> None:
        if gate.evidence_line != -1:
            match = re.match(r"^\s*", doc.lines[gate.evidence_line])
            indent = match.group(0) if match else "  "
            doc.lines[gate.evidence_line] = indent + "EVIDENCE: " + value
            return
        line = gate.line + 1
        while line < len(doc.lines) and re.match(r"^\s+(CHECK|EXPECT|EVIDENCE|CWD):", doc.lines[line]):
            line += 1
        doc.lines.insert(line, "  EVIDENCE: " + value)

    # -- pipeline actions ---------------------------------------------------

    def action_claim_release(self, action: str, scope: str) -> int:
        stems = [re.sub(r"\.md$", "", os.path.basename(f), flags=re.IGNORECASE) for f in self.target.files]
        leaf_opt = self.opt.get("leaf")
        if leaf_opt:
            error = G.validate_scope_id(leaf_opt, "leaf")
            if error:
                raise UsageError(error)
            if stems and leaf_opt not in stems:
                raise UsageError(f"unknown --leaf {leaf_opt} (have: {', '.join(stems)})")
        if action == "--release":
            try:
                count = G.release_leases(self.root, scope, leaf_opt or None)
            except (OSError, G.GateFileError, G.LockTimeout) as error:
                _err(f"gatehouse check: cannot release leases: {error}")
                return 2
            _out(f"released {count} lease(s) for {scope}" + (f"/{leaf_opt}" if leaf_opt else ""))
            return 0

        leaf = leaf_opt or (stems[0] if len(stems) == 1 else None)
        if not leaf:
            raise UsageError("--claim needs --leaf NAME when a scope has several gate files")
        selected = next((f for f in self.target.files
                         if re.sub(r"\.md$", "", os.path.basename(f), flags=re.IGNORECASE) == leaf), None)
        if selected is None:
            raise UsageError(f"unknown --leaf {leaf}")
        file, doc = self.load_ledger(selected)
        if not doc.owns:
            raise UsageError(f"{os.path.basename(file)} declares no OWNS paths")
        try:
            result = G.claim_leases(self.root, scope, leaf, doc.owns)
        except (OSError, G.GateFileError, G.LockTimeout) as error:
            _err(f"gatehouse check: cannot claim leases: {error}")
            return 2
        if not result["ok"]:
            if result.get("error"):
                raise UsageError(result["error"])
            for conflict in result["conflicts"]:
                if conflict.get("identity"):
                    _out(f"CONFLICT {conflict['with']} already holds a live lease; release it before claiming again")
                else:
                    _out(f"CONFLICT {conflict['glob']} overlaps {conflict['theirGlob']} held by {conflict['with']}")
            _out(f"CLAIM REFUSED ({len(result['conflicts'])} conflict(s))")
            return 3
        _out(f"CLAIMED {len(result['globs'])} path(s) for {scope}/{leaf}: {', '.join(result['globs'])}")
        return 0

    # -- main run -----------------------------------------------------------

    def run(self) -> int:
        opt = self.opt
        action_names: List[str] = []
        for key in ("claim", "release", "list-scopes"):
            if opt.get(key):
                action_names.append("--" + key)
        for key in ("log", "bind"):
            if opt.get(key) is not None:
                action_names.append("--" + key)
        if len(action_names) > 1:
            raise UsageError("pipeline actions are mutually exclusive: " + ", ".join(action_names))
        action = action_names[0] if action_names else None

        if self.status and self.reverify:
            raise UsageError("--status and --reverify are mutually exclusive")
        if self.status and self.approve:
            raise UsageError("--status never approves commands; remove --approve")
        if action and (self.status or self.reverify or self.approve):
            raise UsageError(f"{action} cannot be combined with a run mode")
        if action and self.file_args:
            raise UsageError(f"{action} cannot be combined with explicit files")
        if self.file_args and opt.get("scope"):
            raise UsageError("explicit files and --scope are mutually exclusive")
        if opt.get("leaf") and not opt.get("claim") and not opt.get("release"):
            raise UsageError("--leaf is only valid with --claim or --release")
        if any(opt.get(k) for k in ("timeout", "jobs", "shell", "cwd")) and (action or self.status):
            raise UsageError("--timeout, --jobs, --shell, and --cwd are execution options only")

        self.root = os.path.abspath(opt.get("root") or os.getcwd())
        _as_directory(self.root, "--root")
        self.timeout_seconds = _bounded_int(opt.get("timeout"), DEFAULT_TIMEOUT_SECONDS, 1, 86400, "--timeout")
        self.jobs = _bounded_int(opt.get("jobs"), 1, 1, 64, "--jobs")
        self.default_cwd = os.path.abspath(os.path.join(self.root, opt.get("cwd") or "."))
        if not action and not self.status:
            _as_directory(self.default_cwd, "--cwd")

        if action == "--list-scopes":
            scopes = G.list_scopes(self.root)
            if scopes:
                for name in scopes:
                    _out(name)
            else:
                _out(f"(no pipelines under {G.STATE_DIR}/)")
            return 0

        if opt.get("scope"):
            error = G.validate_scope_id(opt["scope"])
            if error:
                raise UsageError(error)

        self.target = G.resolve_target(self.root, opt.get("scope"), self.file_args)
        # A deleted/crashed pipeline can leave coordination leases behind after its
        # ledger directory is gone. An explicit, validated release target must
        # remain usable for that recovery path; claims still require a live ledger.
        if self.target.error and action == "--release" and opt.get("scope"):
            self.target = G.Target("scope", opt["scope"], [])
        elif self.target.error:
            raise UsageError(self.target.error)
        scope = self.target.scope

        if action == "--log":
            if not scope:
                raise UsageError("--log needs --scope ID or exactly one discoverable pipeline")
            if not G.js_trim(opt["log"]):
                raise UsageError("--log needs non-blank text")
            try:
                path = G.append_status(self.root, scope, opt["log"])
            except (OSError, G.GateFileError) as error:
                _err(f"gatehouse check: cannot append status: {error}")
                return 2
            _out(f"appended to {path}")
            return 0

        if action == "--bind":
            if not scope:
                raise UsageError("--bind needs --scope ID or exactly one discoverable pipeline")
            session = G.js_trim(opt["bind"])
            if not session:
                raise UsageError("--bind needs a non-blank session id")
            try:
                G.write_atomic(os.path.join(G.scope_root(self.root, scope), "session"), session + "\n",
                               root=self.root)
            except (OSError, G.GateFileError) as error:
                _err(f"gatehouse check: cannot bind session: {error}")
                return 2
            _out(f"bound session {opt['bind']} to scope {scope}")
            return 0

        if self.target.discovery_errors and action != "--release":
            raise UsageError("; ".join(self.target.discovery_errors))
        if not self.target.files and action != "--release":
            raise UsageError(
                f"no gate files found (looked for {G.STATE_DIR}/<scope>/, then GATES.md and gates/*.md "
                f"under {self.root})")

        for file in self.target.files:
            try:
                self.read_ledger_file(file)
            except FileNotFoundError:
                raise UsageError(f"no such gate file: {file}") from None
            except (OSError, G.GateFileError) as error:
                raise UsageError(f"cannot inspect gate file {file}: {error}") from None

        if action in ("--claim", "--release"):
            if not scope:
                raise UsageError(f"{action} needs --scope ID or exactly one discoverable pipeline")
            return self.action_claim_release(action, scope)

        return self.run_gates(scope)

    def run_gates(self, scope: Optional[str]) -> int:
        opt = self.opt
        ledgers = [self.load_ledger(f) for f in self.target.files]

        # Status currentness is a pure function of parsed ledger text. Do not
        # resolve a shell, read PATH, or initialize approval storage for it.
        if not self.status:
            self.shell = _resolve_shell(opt.get("shell"))
            self.path_value = os.environ.get("PATH", "")
            count = len(self.path_value.split(os.pathsep)) if self.path_value else 0
            self.path_evidence = f"{G.sha256(self.path_value)[:12]}/{count} entries"
            flat = re.sub(r"[\r\n]", " ", self.path_value)
            self.path_transcript = flat[:800] + ("..." if len(self.path_value) > 800 else "")
            self.approval_dir = os.path.abspath(
                os.environ.get("GATEHOUSE_APPROVAL_DIR")
                or os.path.join(os.path.expanduser("~"), ".gatehouse", "approved"))
            self.canonical_root = os.path.realpath(self.root)
            if G.path_is_inside(self.root, self.approval_dir):
                raise UsageError("GATEHOUSE_APPROVAL_DIR must be outside the repository root")

        pending: List[Task] = []
        for file, doc in ledgers:
            for gate in doc.gates:
                if gate.id in doc.abandoned or not gate.check:
                    continue
                state = G.gate_state(gate, doc.abandoned)
                if self.status or (not self.reverify and state == "met"):
                    continue
                cwd = self.resolved_gate_cwd(gate, file)
                try:
                    if not stat.S_ISDIR(os.stat(cwd).st_mode):
                        raise UsageError(f"gate {G.qualify(file, gate.id)} CWD is not a directory: {cwd}")
                except FileNotFoundError:
                    raise UsageError(f"gate {G.qualify(file, gate.id)} CWD does not exist: {cwd}") from None
                except OSError as error:
                    raise UsageError(f"cannot inspect gate CWD {cwd}: {error}") from None
                pending.append(Task(
                    file, gate, cwd, state, state == "met",
                    G.gate_definition_digest(gate), self.approval_signature(file, gate)))

        runnable: List[Task] = []
        not_run: List[Task] = []
        approval_failures = 0
        for task in pending:
            try:
                approved = self.approval_exists(task.file, task.gate)
            except (ApprovalError, OSError) as error:
                _err(f"gatehouse check: could not validate approval for "
                     f"{G.qualify(task.file, task.gate.id)}: {error}")
                approval_failures += 1
                not_run.append(task)
                continue
            if not approved:
                self.print_oracle(task.file, task.gate, "APPROVAL REQUIRED")
                if not self.approve:
                    _out("    NOT RUN: inspect this oracle, then re-run with --approve")
                    not_run.append(task)
                    continue
                try:
                    self.record_approval(task.file, task.gate)
                    store = self._validated_approval_dir()
                    assert store is not None
                    _out("    APPROVED: " + self.approval_path(task.file, task.gate, store["path"]))
                except (ApprovalError, OSError, G.GateFileError) as error:
                    _err(f"gatehouse check: could not record approval for "
                         f"{G.qualify(task.file, task.gate.id)}: {error}")
                    approval_failures += 1
                    not_run.append(task)
                    continue
            runnable.append(task)

        for task in runnable:
            _out(f"  RUN  {G.qualify(task.file, task.gate.id)} shell={self.shell} cwd={task.cwd} "
                 f"PATH={self.path_transcript}")
        results: List[Result] = []
        if not self.status and runnable:
            shell = self.shell or "/bin/sh"
            if self.jobs == 1 or len(runnable) == 1:
                results = [run_check(t, shell, self.timeout_seconds) for t in runnable]
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.jobs, len(runnable))) as pool:
                    results = list(pool.map(lambda t: run_check(t, shell, self.timeout_seconds), runnable))

        for result in results:
            gate = result.task.gate
            summary = (f"sha256={result.sha256}; bytes={result.bytes}" if result.ok
                       else self.failure_output(result.output))
            outcome = (f"exit={'none' if result.exit_code is None else result.exit_code}"
                       + (f" signal={result.signal}" if result.signal else "")
                       + f"; EXPECT={'matched' if result.matched else 'not matched'}; output={summary}")
            label = G.qualify(result.task.file, gate.id)
            if result.ok:
                _out(f"  PASS {label}: {gate.title}")
                _out(f"       {outcome}")
            else:
                _out(f"  FAIL {label}: {gate.title}")
                _out("       " + (f"{result.error}; " if result.error else "") + outcome)

        stale_results: Dict[str, str] = {}
        exit_code_2 = False
        for result in results:
            file = result.task.file
            gate_id = result.task.gate.id
            try:
                with G.file_lock(self.root, file):
                    doc = G.parse_gates(self.read_ledger_file(file))
                    if doc.errors:
                        raise G.GateFileError("fresh ledger became invalid: " + "; ".join(doc.errors))
                    fresh = next((g for g in doc.gates if g.id == gate_id), None)
                    if (fresh is None
                            or G.gate_definition_digest(fresh) != result.task.definition_digest
                            or self.approval_signature(file, fresh) != result.task.approval_signature):
                        stale_results[self._key(file, gate_id)] = G.qualify(file, gate_id)
                        _out(f"  STALE {G.qualify(file, gate_id)}: definition or runtime approval oracle "
                             "changed; result not written")
                        continue
                    fresh_state = G.gate_state(fresh, doc.abandoned)
                    if fresh_state == "abandoned":
                        continue
                    must_write_failure = (result.task.starting_state == "stale-unmet"
                                          or (self.reverify and result.task.was_met) or fresh.checked)
                    if not result.ok and not must_write_failure:
                        continue
                    if result.ok:
                        doc.lines[fresh.line] = re.sub(r"^- \[( |x|X)\]", "- [x]", doc.lines[fresh.line], count=1)
                        self.insert_or_update_evidence(doc, fresh, self.evidence_for(result))
                    else:
                        doc.lines[fresh.line] = re.sub(r"^- \[(x|X)\]", "- [ ]", doc.lines[fresh.line], count=1)
                        self.insert_or_update_evidence(doc, fresh, "pending")
                    G.write_atomic(file, G.format_document(doc))
            except (OSError, G.GateFileError, G.LockTimeout) as error:
                _err(f"gatehouse check: cannot update {file}: {error}")
                exit_code_2 = True
        if exit_code_2:
            return 2

        ledgers = [self.load_ledger(f) for f in self.target.files]
        total_met = total_unmet = total_abandoned = reverified = 0
        unmet_ids: List[str] = []
        abandoned_ids: List[str] = []
        final_states: Dict[str, str] = {}
        for result in results:
            if self.reverify and result.task.was_met and \
                    self._key(result.task.file, result.task.gate.id) not in stale_results:
                reverified += 1

        for file, doc in ledgers:
            for gate in doc.gates:
                state = G.gate_state(gate, doc.abandoned)
                final_states[self._key(file, gate.id)] = state
                if state == "abandoned":
                    total_abandoned += 1
                    abandoned_ids.append(G.qualify(file, gate.id))
                elif state == "met":
                    total_met += 1
                else:
                    total_unmet += 1
                    unmet_ids.append(G.qualify(file, gate.id))
                    if self.status:
                        reason = ("unchecked" if state == "unmet"
                                  else "checked but EVIDENCE pending" if state == "unmet-no-evidence"
                                  else "checked but automatic evidence is stale or unbound")
                        _out(f"  UNMET {G.qualify(file, gate.id)} ({reason}): {gate.title}")
            _out(f"{os.path.basename(file)}: {len(doc.gates)} gates")

        # A scoped pipeline is complete only when both its ledgers and its native
        # dispatch waves are resolved.
        aggregate = dispatch_status(self.root, scope)
        if aggregate["errors"]:
            for error in aggregate["errors"]:
                _err(f"gatehouse check: {error}")
            return 2
        total_abandoned += len(aggregate["abandoned"])
        abandoned_ids.extend(aggregate["abandoned"])
        if self.status:
            for blocker in aggregate["blocking"]:
                _out(f"  UNMET {blocker}")

        where = f" [scope {scope}]" if scope else ""
        verify_note = (f", reran: {len(results)}, previously met reverified: {reverified}"
                       if self.reverify else "")
        unverified_met = [t for t in not_run if t.was_met] if self.reverify else []
        extra_unmet: Dict[str, str] = {}
        for task in unverified_met:
            key = self._key(task.file, task.gate.id)
            if final_states.get(key, "met") == "met":
                extra_unmet[key] = G.qualify(task.file, task.gate.id) + " (reverify not run)"
        for key, label in stale_results.items():
            if final_states.get(key, "met") == "met":
                extra_unmet[key] = label + " (stale result discarded)"
        effective_unmet = total_unmet + len(extra_unmet) + len(aggregate["blocking"])
        unmet_ids.extend(extra_unmet.values())
        unmet_ids.extend(aggregate["blocking"])
        if approval_failures:
            _err(f"gatehouse check: infrastructure failure prevented {approval_failures} approval(s)")
            return 2
        met_shown = max(0, total_met - len(extra_unmet))
        if effective_unmet == 0 and total_abandoned == 0:
            _out(f"ALL MET ({total_met} met{verify_note}){where}")
            return 0
        if total_abandoned:
            _out(f"HANDOFF REQUIRED: {total_abandoned} abandoned (met: {met_shown}"
                 + (f", unmet: {effective_unmet}" if effective_unmet else "") + f"{verify_note}){where}")
            _out("  " + ", ".join(abandoned_ids[:12])
                 + (f", +{len(abandoned_ids) - 12} more" if len(abandoned_ids) > 12 else ""))
        if effective_unmet:
            _out(f"UNMET: {effective_unmet} (met: {met_shown}"
                 + (f", abandoned: {total_abandoned}" if total_abandoned else "") + f"{verify_note}){where}")
            _out("  " + ", ".join(unmet_ids[:12]) + (f", +{len(unmet_ids) - 12} more" if len(unmet_ids) > 12 else ""))
        return 1

    @staticmethod
    def _key(file: str, gate_id: str) -> str:
        return os.path.abspath(file) + "\0" + gate_id

    @staticmethod
    def failure_output(output: str, limit: int = 480) -> str:
        lines = [ln.strip() for ln in re.split(r"\r?\n", str(output))]
        lines = [ln for ln in lines if ln]
        if len(lines) <= 8:
            return (" | ".join(lines) or "(no output)")[:limit]
        return " | ".join(lines[:6] + ["..."] + lines[-2:])[:limit]


class _Exit(Exception):
    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        options, files = parse_args(args)
        if options.get("help") or options.get("h"):
            sys.stdout.write(HELP + "\n")
            return 0
        return GateCheck(options, files).run()
    except UsageError as error:
        _err(f"gatehouse check: {error}")
        _err("run gatehouse check --help for usage")
        return 2
    except _Exit as done:
        return done.code
    finally:
        try:
            sys.stdout.flush()
        except (OSError, ValueError):
            pass


if __name__ == "__main__":
    sys.exit(main())
