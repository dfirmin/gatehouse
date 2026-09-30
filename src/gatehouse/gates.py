"""Shared ledger parsing, scope resolution, durable writes, locks, and leases.

Standard library only. POSIX-first (Linux and macOS); Windows is not supported.

This module is a Python port of the gate-ledger core from Leonxlnx/unlazy
(MIT). The file-safety checks (no-follow opens, single-link regular files,
stable snapshots) are kept; the Windows-specific hardening is intentionally
not ported.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import random
import re
import secrets
import stat
import time
import warnings
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

STATE_DIR = ".gatehouse"
LOCK_DIR = os.path.join(STATE_DIR, "locks")
MAX_CHECK_OUTPUT_BYTES = 1024 * 1024
MAX_AUTOMATIC_EVIDENCE_CHARS = 900
DEFAULT_STABLE_FILE_MAX_BYTES = 8 * 1024 * 1024
LEASE_MAX_BYTES = 64 * 1024
MAX_REGEX_SOURCE_CHARS = 1000

DEFINITION_TAG = "gatehouse.gate-definition"


class GateFileError(Exception):
    """A ledger, state, or coordination file failed a safety check."""


class LockTimeout(Exception):
    """Timed out waiting for an advisory file lock."""


def sha256(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()


# ---------------------------------------------------------------------------
# Text helpers (kept close to JavaScript semantics so ledgers parse the same)
# ---------------------------------------------------------------------------

_WS_CLASS = " \\t\\n\\x0b\\x0c\\r\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"
WS_CHARS = (
    " \t\n\x0b\x0c\r  "
    + "".join(chr(c) for c in range(0x2000, 0x200B))
    + "    　﻿"
)
_W = "[" + _WS_CLASS + "]"
_NW = "[^" + _WS_CLASS + "]"
_DOT = "[^\\r\\n\\u2028\\u2029]"


def js_trim(value: str) -> str:
    return value.strip(WS_CHARS)


UNSAFE_TERMINAL_RE = re.compile("[\u0000-\u001f\u007f-\u009f؜‎‏ -‮⁦-⁩]")


def terminal_safe(value: Any) -> str:
    """Replace terminal control and bidi characters so repo text cannot rewrite the screen."""
    return UNSAFE_TERMINAL_RE.sub(" ", str(value))


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def path_is_inside(parent: str, child: str) -> bool:
    p = os.path.abspath(parent)
    c = os.path.abspath(child)
    try:
        rel = os.path.relpath(c, p)
    except ValueError:
        return False
    return rel == "." or (not rel.startswith(".." + os.sep) and rel != ".." and not os.path.isabs(rel))


def real_directory_inside(root: str, directory: str) -> bool:
    try:
        named = os.lstat(directory)
        if stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode):
            return False
        return path_is_inside(os.path.realpath(root), os.path.realpath(directory))
    except OSError:
        return False


def named_entry(path: str) -> bool:
    try:
        os.lstat(path)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return True


def _same_identity(a: os.stat_result, b: os.stat_result) -> bool:
    return a.st_dev == b.st_dev and a.st_ino == b.st_ino


def _same_snapshot(a: os.stat_result, b: os.stat_result) -> bool:
    return (
        _same_identity(a, b)
        and a.st_size == b.st_size
        and a.st_mtime_ns == b.st_mtime_ns
        and a.st_ctime_ns == b.st_ctime_ns
    )


def _assert_regular_single_link(info: os.stat_result, target: str, label: str, max_bytes: float) -> None:
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise GateFileError(f"{label} must be one unchanged regular single-link file: {target}")
    if info.st_size > max_bytes:
        raise GateFileError(f"{label} exceeds {int(max_bytes)} bytes: {target}")


def read_stable_regular_file(
    path: str,
    root: Optional[str] = None,
    max_bytes: Optional[int] = None,
    label: str = "file",
) -> str:
    """Read a bounded UTF-8 file without following links or accepting special files.

    The descriptor and the named entry must identify the same unchanged regular
    single-link file before and after the read. A missing file raises
    FileNotFoundError so callers can tell absence from a later race.
    """
    target = os.path.abspath(path)
    limit = DEFAULT_STABLE_FILE_MAX_BYTES if max_bytes is None else int(max_bytes)
    if limit < 1:
        raise GateFileError(f"{label} maxBytes must be a positive integer")

    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise GateFileError(f"{label} must be one unchanged regular single-link file: {target}") from None
        if isinstance(error, FileNotFoundError):
            try:
                named = os.lstat(target)
            except FileNotFoundError:
                raise error from None
            _assert_regular_single_link(named, target, label, limit)
            raise GateFileError(f"{label} appeared after its open reported it missing: {target}") from None
        raise

    try:
        opened = os.fstat(fd)
        named = os.lstat(target)
        _assert_regular_single_link(named, target, label, limit)
        _assert_regular_single_link(opened, target, label, limit)
        if not _same_identity(opened, named):
            raise GateFileError(f"{label} changed before it was read: {target}")
        canonical_root = os.path.realpath(root) if root is not None else None
        canonical_before = os.path.realpath(target)
        if canonical_root and not path_is_inside(canonical_root, canonical_before):
            raise GateFileError(f"{label} resolves outside the allowed root: {target}")

        chunks: List[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise GateFileError(f"{label} exceeds {limit} bytes: {target}")

        after_opened = os.fstat(fd)
        after_named = os.lstat(target)
        _assert_regular_single_link(after_opened, target, label, limit)
        if not _same_snapshot(opened, after_opened) or not _same_snapshot(after_opened, after_named):
            raise GateFileError(f"{label} changed while it was read: {target}")
        canonical_after = os.path.realpath(target)
        if canonical_after != canonical_before or (
            canonical_root and not path_is_inside(canonical_root, canonical_after)
        ):
            raise GateFileError(f"{label} changed canonical location while it was read: {target}")
        return b"".join(chunks).decode("utf-8", "replace")
    except FileNotFoundError:
        raise GateFileError(f"{label} changed while it was read: {target}") from None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Ledger parsing
# ---------------------------------------------------------------------------

GATE_RE = re.compile(r"^- \[( |x|X)\] (" + _DOT + r"*)\Z")
ATTR_RE = re.compile(r"^(" + _W + r"+)(CHECK|EXPECT|EVIDENCE|CWD):" + _W + r"?(" + _DOT + r"*)\Z")
UNINDENTED_ATTR_RE = re.compile(r"^(CHECK|EXPECT|EVIDENCE|CWD):" + _W + r"?(" + _DOT + r"*)\Z")
ABANDON_RE = re.compile(r"^ABANDON:" + _W + r"*(" + _NW + r"*)" + _W + r"*(" + _DOT + r"*)\Z")
INDENTED_ABANDON_RE = re.compile(r"^" + _W + r"+ABANDON:")
OWNS_RE = re.compile(r"^OWNS:" + _W + r"*(" + _DOT + r"*)\Z")
FENCE_OPEN_RE = re.compile(r"^( {0,3})(`{3,}|~{3,})(" + _DOT + r"*)\Z")
FENCE_CLOSE_RE = re.compile(r"^( {0,3})(`+|~+)[ \t]*\Z")
TITLE_ID_RE = re.compile(r"^(" + _NW + r"+?):(?:" + _W + r"+|\Z)")
GATE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\Z")
REGEX_RE = re.compile(r"^/(.*)/([a-z]*)\Z", re.DOTALL)
# A pattern author escapes an inner slash or has none. A literal path always
# carries one, so an unescaped inner slash marks the ambiguous reading.
UNESCAPED_SLASH_RE = re.compile(r"(^|[^\\])/")
SCOPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
SCOPE_RE_TEXT = "/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/"

_VALID_JS_FLAGS = set("dgimsuvy")
_NAMED_GROUP_RE = re.compile(r"\(\?<(?![=!])([A-Za-z_][A-Za-z0-9_]*)>")
_NAMED_BACKREF_RE = re.compile(r"\\k<([A-Za-z_][A-Za-z0-9_]*)>")


@dataclass
class Gate:
    line: int
    checked: bool
    id: str
    title: str
    check: Optional[str] = None
    expect: Optional[str] = None
    evidence: Optional[str] = None
    evidence_line: int = -1
    cwd: Optional[str] = None
    expectation: Optional[Dict[str, Any]] = None
    _attrs: Set[str] = field(default_factory=set, repr=False)


@dataclass
class Ledger:
    lines: List[str]
    eol: str
    final_newline: bool
    gates: List[Gate]
    abandoned: Dict[str, str]
    owns: List[str]
    errors: List[str]
    warnings: List[str]


def translate_regex(source: str, flags: str) -> Tuple[str, int]:
    """Map a JavaScript-style /source/flags to a Python pattern and re flags.

    Raises ValueError for unknown or repeated flags. Python `re` syntax is used
    for the pattern itself; only named groups and named back-references are
    translated. See docs/ledger-format.md for the remaining dialect notes.
    """
    seen: Set[str] = set()
    for flag in flags:
        if flag not in _VALID_JS_FLAGS or flag in seen:
            raise ValueError(f"Invalid flags supplied to regular expression: '{flags}'")
        seen.add(flag)
    if "u" in seen and "v" in seen:
        raise ValueError(f"Invalid flags supplied to regular expression: '{flags}'")
    pattern = _NAMED_GROUP_RE.sub(r"(?P<\1>", source)
    pattern = _NAMED_BACKREF_RE.sub(r"(?P=\1)", pattern)
    pattern = _apply_js_semantics(pattern, multiline="m" in seen, dotall="s" in seen)
    reflags = re.ASCII
    if "i" in seen:
        reflags |= re.IGNORECASE
    if "m" in seen:
        reflags |= re.MULTILINE
    if "s" in seen:
        reflags |= re.DOTALL
    return pattern, reflags


def _apply_js_semantics(pattern: str, multiline: bool, dotall: bool) -> str:
    """Rewrite the few constructs whose meaning differs between JS and Python `re`.

    - `$` without the m flag matches only at the very end of the input (Python's
      also matches before a trailing newline, which would let an anchored EXPECT
      pass on output the original implementation rejects). With the m flag, `^`
      and `$` also treat \\r, \\u2028 and \\u2029 as line terminators.
    - `.` without the s flag excludes \\n, \\r, \\u2028 and \\u2029 (Python excludes
      only \\n).
    - `\\s` / `\\S` use the JavaScript whitespace set rather than ASCII-only.
    Escapes and character classes are skipped so only real operators are touched.
    """
    out: List[str] = []
    in_class = False
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            nxt = pattern[i + 1] if i + 1 < len(pattern) else ""
            if nxt == "s":
                out.append(_WS_CLASS if in_class else "[" + _WS_CLASS + "]")
            elif nxt == "S" and not in_class:
                out.append("[^" + _WS_CLASS + "]")
            else:
                out.append(ch + nxt)
            i += 2
            continue
        if in_class:
            if ch == "]":
                in_class = False
            out.append(ch)
        elif ch == "[":
            in_class = True
            out.append(ch)
        elif ch == "$":
            out.append("(?:$|(?=[\\r\\u2028\\u2029]))" if multiline else "\\Z")
        elif ch == "^" and multiline:
            out.append("(?:^|(?<=[\\r\\u2028\\u2029]))")
        elif ch == "." and not dotall:
            out.append("[^\\n\\r\\u2028\\u2029]")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def parse_expectation(expect: str) -> Dict[str, Any]:
    match = REGEX_RE.match(str(expect))
    if not match:
        return {"kind": "text", "value": str(expect)}
    source, flags = match.group(1), match.group(2)
    if len(source) > MAX_REGEX_SOURCE_CHARS:
        return {"error": f"EXPECT regex is longer than {MAX_REGEX_SOURCE_CHARS} characters"}
    try:
        pattern, reflags = translate_regex(source, flags)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # e.g. FutureWarning for "[[:alpha:]]"
            re.compile(pattern, reflags)
    except (ValueError, re.error, RecursionError, OverflowError) as error:
        return {"error": f"invalid EXPECT regex: {error}"}
    return {
        "kind": "regex",
        "source": source,
        "flags": flags,
        "pattern": pattern,
        "reflags": int(reflags),
        "pathLike": bool(UNESCAPED_SLASH_RE.search(source)),
    }


def normalize_owns_glob(value: Any) -> Dict[str, str]:
    raw = str(value or "").strip().replace("\\", "/")
    if raw.startswith("./"):
        raw = raw[2:]
    if not raw:
        return {"error": "OWNS path is blank"}
    if raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw) or raw.startswith("//"):
        return {"error": f"OWNS path must be relative: {value}"}
    parts = raw.split("/")
    if "\0" in raw or any(part == ".." for part in parts):
        return {"error": f"OWNS path cannot contain traversal: {value}"}
    normalized = "/".join(part for part in parts if part not in ("", "."))
    if not normalized or normalized == ".":
        return {"error": "OWNS path cannot claim an implicit root"}
    return {"value": normalized}


def parse_gates(text: str, require_gates: bool = True) -> Ledger:
    """Parse a gate ledger. All diagnostics are collected in `errors`/`warnings`."""
    source = str(text)
    eol = "\r\n" if "\r\n" in source else "\n"
    final_newline = source.endswith("\n")
    lines = re.split(r"\r?\n", source)
    gates: List[Gate] = []
    abandoned: Dict[str, str] = {}
    owns: List[str] = []
    errors: List[str] = []
    warnings: List[str] = []
    ids: Dict[str, int] = {}
    current: Optional[Gate] = None
    seen_gate = False
    fence: Optional[Tuple[str, int]] = None

    for index, line in enumerate(lines):
        n = index + 1
        if fence:
            close = FENCE_CLOSE_RE.match(line)
            if close and close.group(2)[0] == fence[0] and len(close.group(2)) >= fence[1]:
                fence = None
            continue
        fence_match = FENCE_OPEN_RE.match(line)
        if fence_match and not (fence_match.group(2)[0] == "`" and "`" in fence_match.group(3)):
            fence = (fence_match.group(2)[0], len(fence_match.group(2)))
            continue

        gate_match = GATE_RE.match(line)
        if gate_match:
            seen_gate = True
            raw_title = js_trim(gate_match.group(2))
            id_match = TITLE_ID_RE.match(raw_title)
            gate_id = id_match.group(1) if id_match else f"L{n}"
            title = js_trim(raw_title[id_match.end():]) if id_match else raw_title
            current = Gate(index, gate_match.group(1).lower() == "x", gate_id, title)
            gates.append(current)
            if not id_match:
                errors.append(f"line {n}: gate needs an explicit ID followed by a colon")
            elif not GATE_ID_RE.match(gate_id):
                errors.append(f"line {n}: invalid gate id {gate_id}")
            if not title:
                errors.append(f"line {n}: gate outcome is blank")
            if gate_id in ids:
                errors.append(f"line {n}: duplicate gate id {gate_id} (first declared on line {ids[gate_id]})")
            else:
                ids[gate_id] = n
            continue

        # Attributes must be indented and ABANDON must not be, so the two rules
        # point opposite ways. Diagnose the indented abandonment rather than
        # ignoring it, or the author's honest exit fails with no explanation.
        if INDENTED_ABANDON_RE.match(line):
            errors.append(f"line {n}: indented ABANDON is not applied; start ABANDON at column 1")
            current = None
            continue

        unindented = UNINDENTED_ATTR_RE.match(line)
        if unindented:
            errors.append(
                f"line {n}: unindented {unindented.group(1)} is not attached to a gate; "
                "indent attribute lines with spaces"
            )
            current = None
            continue

        any_attr = ATTR_RE.match(line)
        if any_attr and current is None:
            errors.append(f"line {n}: orphan {any_attr.group(2)} is not attached to a gate")
            continue
        if current is not None and any_attr:
            key = any_attr.group(2).lower()
            value = js_trim(any_attr.group(3))
            if key in current._attrs:
                errors.append(f"line {n}: duplicate {any_attr.group(2)} for gate {current.id}")
            current._attrs.add(key)
            if key == "evidence":
                current.evidence = value
                current.evidence_line = index
            else:
                setattr(current, key, value)
            continue

        abandon_match = ABANDON_RE.match(line)
        if abandon_match:
            abandon_id = re.sub(r":$", "", abandon_match.group(1))
            reason = js_trim(abandon_match.group(2))
            if not abandon_id:
                errors.append(f"line {n}: ABANDON needs a gate id and reason")
            elif not reason:
                errors.append(f"line {n}: ABANDON {abandon_id} needs a non-blank reason")
            elif abandon_id in abandoned:
                errors.append(f"line {n}: duplicate ABANDON for {abandon_id}")
            else:
                abandoned[abandon_id] = reason
            current = None
            continue

        owns_match = OWNS_RE.match(line)
        if owns_match:
            if seen_gate:
                errors.append(f"line {n}: OWNS must appear before the first gate")
                current = None
                continue
            declared = [js_trim(item) for item in owns_match.group(1).split(",")]
            declared = [item for item in declared if item]
            if not declared:
                errors.append(f"line {n}: OWNS declares no paths")
            for item in declared:
                normalized = normalize_owns_glob(item)
                if "error" in normalized:
                    errors.append(f"line {n}: {normalized['error']}")
                else:
                    owns.append(normalized["value"])
            continue
        if re.match(r"^#|^- ", line):
            current = None

    if fence:
        errors.append("unclosed fenced block")

    for gate in gates:
        has_check = gate.check is not None and gate.check != ""
        has_expect = gate.expect is not None and gate.expect != ""
        if has_check != has_expect:
            errors.append(f"gate {gate.id}: runnable gates require both non-blank CHECK and EXPECT")
        if gate.check == "" or gate.expect == "":
            errors.append(f"gate {gate.id}: CHECK and EXPECT cannot be blank")
        if has_expect:
            parsed = parse_expectation(gate.expect or "")
            if "error" in parsed:
                errors.append(f"gate {gate.id}: {parsed['error']}")
            elif parsed.get("pathLike"):
                # Warn rather than reject: the pattern reading may be intended, and a
                # literal path cannot be expressed once the wrapping slashes sniff.
                warnings.append(
                    f"gate {gate.id}: EXPECT {json.dumps(gate.expect, ensure_ascii=False)} is read as a "
                    "regular expression, so its dots and other metacharacters are wildcards. Escape the "
                    "inner slashes to keep the pattern, or drop the wrapping slashes to match a literal "
                    "substring."
                )
            gate.expectation = parsed
        else:
            gate.expectation = None

    for abandoned_id in abandoned:
        if abandoned_id not in ids:
            errors.append(f"ABANDON references unknown gate {abandoned_id}")
    if require_gates and not gates:
        errors.append("ledger contains zero live gates")

    return Ledger(lines, eol, final_newline, gates, abandoned, owns, errors, warnings)


def format_document(doc: Ledger) -> str:
    output = doc.eol.join(doc.lines)
    if doc.final_newline and not output.endswith(doc.eol):
        output += doc.eol
    return output


def qualify(file_or_label: Any, gate_id: str) -> str:
    base = os.path.basename(str(file_or_label))
    return re.sub(r"\.md$", "", base, flags=re.IGNORECASE) + ":" + gate_id


# ---------------------------------------------------------------------------
# Gate definition digest, evidence, and state
# ---------------------------------------------------------------------------


def gate_definition_digest(gate: Optional[Gate]) -> Optional[str]:
    if gate is None or not isinstance(gate.check, str) or gate.check == "" or \
            not isinstance(gate.expect, str) or gate.expect == "":
        return None
    payload = [DEFINITION_TAG, 1, gate.check, gate.expect, None if gate.cwd is None else str(gate.cwd)]
    return sha256(json.dumps(payload, separators=(",", ":"), ensure_ascii=False))


def automatic_evidence_prefix(definition_digest: str) -> str:
    if not re.match(r"^[a-f0-9]{64}\Z", str(definition_digest or "")):
        raise ValueError("automatic evidence needs a full lowercase SHA-256 definition digest")
    return "automatic-evidence=v1; definition-sha256=" + definition_digest + ";"


_SUCCESS_FIELDS_RE = re.compile(
    r"^ exit=0; EXPECT=matched; output-sha256=[a-f0-9]{64}; output-bytes=(0|[1-9][0-9]{0,6}); shell=."
)


def classify_gate_evidence(gate: Optional[Gate]) -> str:
    evidence = "" if gate is None or gate.evidence is None else str(gate.evidence)
    if evidence == "" or evidence.lower() == "pending":
        return "pending"
    digest = gate_definition_digest(gate)
    if digest is not None:
        prefix = automatic_evidence_prefix(digest)
        deciding = evidence[len(prefix):]
        success = _SUCCESS_FIELDS_RE.match(deciding)
        if (
            len(evidence) <= MAX_AUTOMATIC_EVIDENCE_CHARS
            and evidence.startswith(prefix)
            and success
            and int(success.group(1)) <= MAX_CHECK_OUTPUT_BYTES
        ):
            return "automatic-current"
    if evidence.startswith("automatic-evidence=") or evidence.startswith("exit=0; shell="):
        return "automatic-stale"
    return "human"


def gate_state(gate: Gate, abandoned: Dict[str, str]) -> str:
    if gate.id in abandoned:
        return "abandoned"
    if not gate.checked:
        return "unmet"
    evidence = classify_gate_evidence(gate)
    runnable = gate_definition_digest(gate) is not None
    if runnable:
        return "met" if evidence == "automatic-current" else "stale-unmet"
    if evidence == "pending":
        return "unmet-no-evidence"
    if evidence in ("automatic-current", "automatic-stale"):
        return "stale-unmet"
    return "met"


def validate_scope_id(value: Any, label: str = "scope") -> Optional[str]:
    text = str(value or "")
    if not SCOPE_RE.match(text) or text in (".", ".."):
        return f"{label} must match {SCOPE_RE_TEXT} and cannot be . or .."
    return None


# ---------------------------------------------------------------------------
# OWNS globs
# ---------------------------------------------------------------------------

_GLOB_CHARS = re.compile(r"[*?\[{]")


def globs_overlap(left: str, right: str) -> bool:
    """Prove disjointness only when literal path segments disagree."""
    a = normalize_owns_glob(left)
    b = normalize_owns_glob(right)
    if "error" in a or "error" in b:
        return True
    a_parts = a["value"].split("/")
    b_parts = b["value"].split("/")
    for av, bv in zip(a_parts, b_parts):
        if _GLOB_CHARS.search(av) or _GLOB_CHARS.search(bv):
            return True
        if av != bv:
            return False
    return True


# ---------------------------------------------------------------------------
# Scopes and target resolution
# ---------------------------------------------------------------------------


def scope_root(root: str, scope: str) -> str:
    return os.path.join(root, STATE_DIR, scope)


def list_scopes(root: str) -> List[str]:
    directory = os.path.join(root, STATE_DIR)
    if not os.path.exists(directory):
        return []
    try:
        if not real_directory_inside(root, directory):
            return []
        names = []
        for entry in sorted(os.listdir(directory)):
            full = os.path.join(directory, entry)
            if entry == "locks" or validate_scope_id(entry):
                continue
            if os.path.islink(full) or not os.path.isdir(full):
                continue
            if real_directory_inside(root, full):
                names.append(entry)
        return names
    except OSError:
        return []


def _markdown_discovery(root: str, directory: str) -> Tuple[List[str], List[str]]:
    if not named_entry(directory):
        return [], []
    try:
        if not real_directory_inside(root, directory):
            return [], [f"gate directory must be a real directory inside the repository: {directory}"]
        # Include every named Markdown entry. Consumers perform the stable-file
        # check, so a FIFO, link, or directory cannot disappear as "no gates".
        files = sorted(os.path.join(directory, name) for name in os.listdir(directory) if name.endswith(".md"))
        return files, []
    except OSError as error:
        return [], [f"cannot inspect gate directory {directory}: {error}"]


def _scope_discovery(root: str, scope: str) -> Tuple[List[str], List[str]]:
    base = scope_root(root, scope)
    if not real_directory_inside(root, base):
        return [], [f"scope directory must be a real directory inside the repository: {base}"]
    files: List[str] = []
    top = os.path.join(base, "GATES.md")
    if named_entry(top):
        files.append(top)
    nested, errors = _markdown_discovery(root, os.path.join(base, "gates"))
    files.extend(nested)
    return files, errors


def _legacy_discovery(root: str) -> Tuple[List[str], List[str]]:
    files: List[str] = []
    top = os.path.join(root, "GATES.md")
    if named_entry(top):
        files.append(top)
    nested, errors = _markdown_discovery(root, os.path.join(root, "gates"))
    files.extend(nested)
    return files, errors


@dataclass
class Target:
    mode: str
    scope: Optional[str] = None
    files: List[str] = field(default_factory=list)
    discovery_errors: List[str] = field(default_factory=list)
    error: Optional[str] = None
    ambiguous: Optional[List[str]] = None


def _scope_target(root: str, scope: str) -> Target:
    files, errors = _scope_discovery(root, scope)
    return Target("scope", scope, files, errors)


def resolve_target(
    root: Optional[str] = None,
    scope: Optional[str] = None,
    files: Optional[List[str]] = None,
    session_id: Optional[str] = None,
) -> Target:
    root = os.path.abspath(root or os.getcwd())
    files = files or []
    if files:
        return Target("explicit", None, [os.path.abspath(os.path.join(root, f)) for f in files])

    scopes = list_scopes(root)
    wanted = scope or os.environ.get("GATEHOUSE_SCOPE") or None
    if wanted:
        invalid = validate_scope_id(wanted)
        if invalid:
            return Target("none", wanted, [], error=invalid)
        if wanted not in scopes:
            scope_path = scope_root(root, wanted)
            state_path = os.path.join(root, STATE_DIR)
            # A named scope that is physically absent is safe to treat as stale
            # configuration. A named entry that exists but was excluded from
            # list_scopes (link, file, FIFO, outside-root directory, or unreadable
            # state container) must remain visible as an invalid input.
            if named_entry(scope_path) or (named_entry(state_path) and not real_directory_inside(root, state_path)):
                return _scope_target(root, wanted)
            return Target(
                "none", wanted, [],
                error=f'no such scope "{wanted}" under {STATE_DIR}/ (have: {", ".join(scopes) or "none"})',
            )
        return _scope_target(root, wanted)

    if len(scopes) == 1:
        return _scope_target(root, scopes[0])
    if len(scopes) > 1:
        if session_id:
            owned = []
            for candidate in scopes:
                try:
                    bound = read_stable_regular_file(
                        os.path.join(scope_root(root, candidate), "session"),
                        root=root, max_bytes=4096, label="session binding",
                    )
                    if js_trim(bound) == js_trim(str(session_id)):
                        owned.append(candidate)
                except (OSError, GateFileError):
                    pass
            if len(owned) == 1:
                return _scope_target(root, owned[0])
        return Target(
            "none", None, [], ambiguous=scopes,
            error=f"{len(scopes)} pipelines present ({', '.join(scopes)}); "
                  "pass --scope <id> or set GATEHOUSE_SCOPE. Refusing to guess.",
        )

    legacy_files, legacy_errors = _legacy_discovery(root)
    if legacy_files or legacy_errors:
        return Target("legacy", None, legacy_files, legacy_errors)
    return Target("none", None, [])


def status_log_path(root: str, scope: Optional[str]) -> str:
    return os.path.join(scope_root(root, scope), "status.log") if scope else os.path.join(root, "gatehouse-status.log")


def hook_state_path(root: str, scope: Optional[str]) -> str:
    return (
        os.path.join(scope_root(root, scope), "hook-state.json")
        if scope else os.path.join(root, ".gatehouse-hook-state.json")
    )


# ---------------------------------------------------------------------------
# Durable writes, locks, status log
# ---------------------------------------------------------------------------


def _assert_safe_state_path(root: str, target: str) -> None:
    state_root = os.path.join(os.path.abspath(root), STATE_DIR)
    if os.path.exists(state_root):
        info = os.lstat(state_root)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise GateFileError(f"{state_root} must be a real directory, not a link or file")
    parent = os.path.dirname(target)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    info = os.lstat(parent)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise GateFileError(f"{parent} must be a real directory")


def write_atomic(file: str, text: str, root: Optional[str] = None) -> None:
    """Write via a private temp file and rename; refuse symlink parents and targets."""
    target = os.path.abspath(file)
    if root:
        _assert_safe_state_path(root, target)
    else:
        parent = os.path.dirname(target)
        os.makedirs(parent, exist_ok=True)
        info = os.lstat(parent)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise GateFileError(f"{parent} must be a real directory")
    try:
        existing = os.lstat(target)
        if stat.S_ISLNK(existing.st_mode):
            raise GateFileError(f"refusing to replace symlink {target}")
    except FileNotFoundError:
        pass

    temp = ""
    fd: Optional[int] = None
    for _ in range(8):
        temp = f"{target}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            break
        except FileExistsError:
            continue
    if fd is None:
        raise GateFileError(f"could not create a unique temporary file for {target}")
    try:
        data = str(text).encode("utf-8")
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(temp, target)
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if temp:
            try:
                os.unlink(temp)
            except OSError:
                pass  # renamed or absent


def _lock_directory(root: str) -> str:
    # Use the physical root so lexical aliases of one repository share one lock
    # namespace. The root itself must exist for any gatehouse operation.
    canonical_root = os.path.realpath(os.path.abspath(root))
    directory = os.path.join(canonical_root, LOCK_DIR)
    _assert_safe_state_path(canonical_root, directory)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    info = os.lstat(directory)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise GateFileError(f"{directory} must be a real directory")
    return directory


def _canonical_lock_target(target: str) -> str:
    # Lock targets are often not files yet. Canonicalize the nearest existing
    # ancestor and rebuild the missing suffix so real-root and symlink-root
    # spellings hash alike. Never follow the final named component.
    absolute = os.path.abspath(target)
    current = os.path.dirname(absolute)
    suffix = [os.path.basename(absolute)]
    while True:
        try:
            if os.path.exists(current):
                canonical = os.path.realpath(current)
                return os.path.join(canonical, *suffix)
        except OSError:
            pass
        parent = os.path.dirname(current)
        if parent == current:
            return os.path.join(current, *suffix)
        suffix.insert(0, os.path.basename(current))
        current = parent


@contextmanager
def file_lock(root: str, target: str, timeout_ms: int = 30000) -> Iterator[None]:
    """Advisory O_EXCL lock. A crashed owner's lock fails closed at timeout.

    A lock observed by path is never unlinked by a waiter: between stat and
    unlink its owner can release and a successor can acquire the same name.
    """
    directory = _lock_directory(root)
    lock_target = _canonical_lock_target(target)
    lock = os.path.join(directory, sha256(lock_target)[:24] + ".filelock")
    deadline = time.monotonic() + timeout_ms / 1000.0
    token = secrets.token_hex(16)
    fd: Optional[int] = None
    while True:
        try:
            fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            break
        except FileExistsError:
            missing = False
            try:
                os.stat(lock)
            except FileNotFoundError:
                missing = True
            if time.monotonic() >= deadline:
                raise LockTimeout(f"timed out waiting for lock on {target}") from None
            if missing:
                continue
            time.sleep(0.015 + random.random() * 0.025)
    identified = False
    try:
        os.write(fd, json.dumps(
            {"token": token, "pid": os.getpid(), "target": lock_target, "at": int(time.time() * 1000)}
        ).encode("utf-8"))
        identified = True
    except OSError:
        pass  # leave for manual cleanup rather than risk deleting a successor
    try:
        yield
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        if identified:
            try:
                with open(lock, "r", encoding="utf-8") as handle:
                    current = json.load(handle)
                if current.get("token") == token:
                    os.unlink(lock)
            except (OSError, ValueError):
                pass


def append_status(root: str, scope: str, line: str) -> str:
    path = status_log_path(root, scope)
    _assert_safe_state_path(root, path)
    fd: Optional[int] = None
    try:
        try:
            before = os.lstat(path)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise GateFileError(f"refusing non-file or linked status log {path}")
        except FileNotFoundError:
            pass
        flags = (
            os.O_WRONLY | os.O_APPEND | os.O_CREAT
            | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        fd = os.open(path, flags, 0o600)
        opened = os.fstat(fd)
        named = os.lstat(path)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or not _same_identity(opened, named):
            raise GateFileError(f"refusing non-file or replaced status log {path}")
        os.write(fd, (re.sub(r"[\r\n]+", " ", str(line)) + "\n").encode("utf-8"))
        os.fsync(fd)
        return path
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Ownership leases (coordination, not isolation)
# ---------------------------------------------------------------------------


def _invalid_lease(file: str, leaf: str = "locks") -> Dict[str, Any]:
    return {"scope": "(invalid)", "leaf": leaf, "globs": ["**"], "file": file, "invalid": True}


def _read_leases_unlocked(root: str) -> List[Dict[str, Any]]:
    directory = os.path.join(os.path.abspath(root), LOCK_DIR)
    try:
        os.lstat(directory)
    except FileNotFoundError:
        return []
    except OSError:
        return [_invalid_lease(directory)]
    if not real_directory_inside(root, directory):
        return [_invalid_lease(directory)]
    leases: List[Dict[str, Any]] = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".lease"):
            continue
        file = os.path.join(directory, name)
        try:
            value = json.loads(read_stable_regular_file(
                file, root=root, max_bytes=LEASE_MAX_BYTES, label="lease record"))
            if (
                not isinstance(value, dict)
                or not isinstance(value.get("scope"), str) or validate_scope_id(value["scope"])
                or not isinstance(value.get("leaf"), str) or validate_scope_id(value["leaf"], "leaf")
                or not isinstance(value.get("globs"), list) or not value["globs"]
                or name != sha256(value["scope"] + "::" + value["leaf"])[:24] + ".lease"
            ):
                raise ValueError("invalid lease record shape or identity")
            normalized = [normalize_owns_glob(g) for g in value["globs"]]
            if any("error" in item for item in normalized) or any(
                item.get("value") != original for item, original in zip(normalized, value["globs"])
            ):
                raise ValueError("invalid lease record OWNS paths")
            lease = dict(value)
            lease["globs"] = [item["value"] for item in normalized]
            lease["file"] = file
            leases.append(lease)
        except (OSError, GateFileError, ValueError):
            leases.append(_invalid_lease(file, name))
    return leases


def read_leases(root: str) -> List[Dict[str, Any]]:
    return _read_leases_unlocked(root)


def _lease_registry(root: str) -> str:
    return os.path.join(os.path.abspath(root), LOCK_DIR, "lease-registry")


def claim_leases(root: str, scope: str, leaf: str, globs: List[str]) -> Dict[str, Any]:
    with file_lock(root, _lease_registry(root)):
        scope_error = validate_scope_id(scope)
        leaf_error = validate_scope_id(leaf, "leaf")
        if scope_error or leaf_error:
            return {"ok": False, "conflicts": [], "error": scope_error or leaf_error}
        normalized: List[str] = []
        for glob in globs or []:
            result = normalize_owns_glob(glob)
            if "error" in result:
                return {"ok": False, "conflicts": [], "error": result["error"]}
            normalized.append(result["value"])
        if not normalized:
            return {"ok": False, "conflicts": [], "error": "no OWNS paths to claim"}

        held_leases = _read_leases_unlocked(root)
        same_owner = next((h for h in held_leases if h["scope"] == scope and h["leaf"] == leaf), None)
        if same_owner:
            return {
                "ok": False,
                "conflicts": [{"identity": True, "with": f"{scope}/{leaf}", "heldGlobs": same_owner["globs"]}],
            }

        conflicts: List[Dict[str, Any]] = []
        for glob in normalized:
            for held in held_leases:
                theirs = next((other for other in held["globs"] if globs_overlap(glob, other)), None)
                if theirs:
                    conflicts.append({"glob": glob, "with": f'{held["scope"]}/{held["leaf"]}', "theirGlob": theirs})
        if conflicts:
            return {"ok": False, "conflicts": conflicts}
        file = os.path.join(_lock_directory(root), sha256(scope + "::" + leaf)[:24] + ".lease")
        write_atomic(
            file,
            json.dumps({"scope": scope, "leaf": leaf, "globs": normalized, "pid": os.getpid()}, indent=2) + "\n",
            root=root,
        )
        return {"ok": True, "file": file, "conflicts": [], "globs": normalized}


def release_leases(root: str, scope: str, leaf: Optional[str] = None) -> int:
    with file_lock(root, _lease_registry(root)):
        count = 0
        for lease in _read_leases_unlocked(root):
            if lease["scope"] != scope:
                continue
            if leaf and lease["leaf"] != leaf:
                continue
            try:
                os.unlink(lease["file"])
                count += 1
            except OSError:
                pass  # raced or absent
        return count
