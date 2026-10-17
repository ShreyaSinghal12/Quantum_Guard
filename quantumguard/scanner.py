"""Current-code scanner.

The same `scan_text` function is used for the working tree, for every
historical blob in the Git auditor, and for changed files in the CI gate,
so all three features share one detection behaviour.

Repository content is treated as untrusted: files are only read, never
executed, symlinks are not followed, and binary / oversized files are skipped.
"""
from __future__ import annotations

import fnmatch
import hashlib
import os
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator

from .config import QGError, load_json

HASH_COMMENT_EXT = {"py", "pyi", "rb", "sh", "yaml", "yml", "toml", "conf", "cfg", "ini", "cmake", "txt"}
C_COMMENT_EXT = {"js", "mjs", "cjs", "jsx", "ts", "tsx", "java", "kt", "kts", "scala", "go",
                 "c", "h", "cc", "cpp", "hpp", "cs", "rs", "swift", "php"}
PY_DOCSTRING_START = re.compile(r'^[rRbBuUfF]{0,2}("""|\'\'\')')


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    algorithm: str
    operation: str
    algorithm_risk: str
    quantum_threat: str
    extensions: frozenset
    regex: re.Pattern
    remediation: str

    def applies_to(self, ext: str) -> bool:
        return "*" in self.extensions or ext in self.extensions


@dataclass
class ScanSettings:
    include_extensions: set
    exclude_dirs: set
    exclude_paths: list
    exclude_globs: list
    test_dirs: set
    test_file_globs: list
    max_file_bytes: int
    max_files: int
    suppression_marker: str

    @classmethod
    def from_dict(cls, data: dict) -> "ScanSettings":
        return cls(
            include_extensions={e.lower() for e in data.get("include_extensions", [])},
            exclude_dirs=set(data.get("exclude_dirs", [])),
            exclude_paths=list(data.get("exclude_paths", [])),
            exclude_globs=list(data.get("exclude_globs", [])),
            test_dirs={d.lower() for d in data.get("test_dirs", [])},
            test_file_globs=list(data.get("test_file_globs", [])),
            max_file_bytes=int(data.get("max_file_bytes", 1_000_000)),
            max_files=int(data.get("max_files", 20_000)),
            suppression_marker=str(data.get("suppression_marker", "quantumguard: ignore")).lower(),
        )


class RuleSet:
    REQUIRED = ("id", "title", "algorithm", "operation", "algorithm_risk", "pattern", "extensions")

    def __init__(self, data: dict):
        self.version = data.get("version", "unknown")
        self.settings = ScanSettings.from_dict(data.get("settings", {}))
        self.rules: list[Rule] = []
        seen = set()
        for raw in data.get("rules", []):
            missing = [k for k in self.REQUIRED if k not in raw]
            if missing:
                raise QGError(f"Rule {raw.get('id', '?')} is missing fields: {missing}")
            if raw["id"] in seen:
                raise QGError(f"Duplicate rule id: {raw['id']}")
            seen.add(raw["id"])
            try:
                regex = re.compile(raw["pattern"], re.IGNORECASE if raw.get("ignore_case") else 0)
            except re.error as exc:
                raise QGError(f"Rule {raw['id']} has an invalid regex: {exc}") from exc
            self.rules.append(Rule(
                id=raw["id"], title=raw["title"], algorithm=raw["algorithm"],
                operation=raw["operation"], algorithm_risk=raw["algorithm_risk"],
                quantum_threat=raw.get("quantum_threat", ""),
                extensions=frozenset(e.lower() for e in raw["extensions"]),
                regex=regex, remediation=raw.get("remediation", ""),
            ))

    @classmethod
    def load(cls, config_dir=None) -> "RuleSet":
        return cls(load_json("crypto_rules.json", config_dir))

    def by_id(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)


@dataclass
class Finding:
    rule_id: str
    title: str
    algorithm: str
    operation: str
    algorithm_risk: str
    file: str
    line: int
    snippet: str
    context: str            # "production" or "test"
    fingerprint: str        # rule + file + normalised code (stable across line moves)
    signature: str          # rule + normalised code (matches the same code in another file)
    remediation: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanStats:
    files_scanned: int = 0
    skipped: Counter = field(default_factory=Counter)
    errors: list = field(default_factory=list)
    truncated: bool = False

    def to_dict(self) -> dict:
        return {"files_scanned": self.files_scanned, "skipped": dict(self.skipped),
                "errors": self.errors[:50], "truncated": self.truncated}


@dataclass
class ScanResult:
    root: str
    findings: list
    stats: ScanStats


# ---------------------------------------------------------------- helpers

def file_extension(path: str) -> str:
    name = PurePosixPath(path).name
    if name == "CMakeLists.txt":
        return "cmake"
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def is_eligible_path(rel_path: str, settings: ScanSettings) -> tuple[bool, str]:
    rel_path = rel_path.replace("\\", "/")
    parts = PurePosixPath(rel_path).parts
    if any(p in settings.exclude_dirs for p in parts[:-1]):
        return False, "excluded_dir"
    if any(rel_path.startswith(p) for p in settings.exclude_paths):
        return False, "excluded_path"
    name = parts[-1] if parts else rel_path
    if any(fnmatch.fnmatch(name, g) for g in settings.exclude_globs):
        return False, "generated_or_lockfile"
    ext = file_extension(rel_path)
    if ext not in settings.include_extensions and name != "CMakeLists.txt":
        return False, "unsupported_extension"
    return True, ""


def is_test_path(rel_path: str, settings: ScanSettings) -> bool:
    parts = PurePosixPath(rel_path.replace("\\", "/")).parts
    if any(p.lower() in settings.test_dirs for p in parts[:-1]):
        return True
    return any(fnmatch.fnmatch(parts[-1], g) for g in settings.test_file_globs)


def normalize(code: str) -> str:
    return " ".join(code.split())


def _hash(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _strip_c_style(lines: list[str]) -> list[str]:
    """Remove // and /* */ comments while keeping string literals."""
    out, in_block, in_backtick = [], False, False
    for line in lines:
        buf, i, n, quote = [], 0, len(line), None
        while i < n:
            ch = line[i]
            nxt = line[i + 1] if i + 1 < n else ""
            if in_block:
                if ch == "*" and nxt == "/":
                    in_block = False
                    i += 2
                else:
                    i += 1
                continue
            if in_backtick:
                buf.append(ch)
                if ch == "`":
                    in_backtick = False
                i += 1
                continue
            if quote:
                buf.append(ch)
                if ch == "\\" and nxt:
                    buf.append(nxt)
                    i += 2
                    continue
                if ch == quote:
                    quote = None
                i += 1
                continue
            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                in_block = True
                i += 2
                continue
            if ch in "\"'":
                quote = ch
            elif ch == "`":
                in_backtick = True
            buf.append(ch)
            i += 1
        out.append("".join(buf))
    return out


def _strip_hash_style(lines: list[str], python: bool) -> list[str]:
    """Remove # comments (outside quotes) and, for Python, docstring blocks."""
    out, doc_quote = [], None
    for line in lines:
        stripped = line.lstrip()
        if python:
            if doc_quote:
                if doc_quote in line:
                    doc_quote = None
                out.append("")
                continue
            m = PY_DOCSTRING_START.match(stripped)
            if m:
                if m.group(1) not in stripped[m.end():]:
                    doc_quote = m.group(1)
                out.append("")
                continue
        buf, quote, i = [], None, 0
        while i < len(line):
            ch = line[i]
            if quote:
                buf.append(ch)
                if ch == "\\" and i + 1 < len(line):
                    buf.append(line[i + 1])
                    i += 2
                    continue
                if ch == quote:
                    quote = None
            elif ch == "#":
                break
            else:
                if ch in "\"'":
                    quote = ch
                buf.append(ch)
            i += 1
        out.append("".join(buf))
    return out


def code_view(lines: list[str], ext: str) -> list[str]:
    """Return each line with comments removed (same length as input)."""
    if ext in C_COMMENT_EXT:
        return _strip_c_style(lines)
    if ext in HASH_COMMENT_EXT:
        return _strip_hash_style(lines, python=ext in ("py", "pyi"))
    return list(lines)


def decode_bytes(data: bytes, settings: ScanSettings) -> tuple[str | None, str]:
    if len(data) > settings.max_file_bytes:
        return None, "too_large"
    if b"\x00" in data[:8192]:
        return None, "binary"
    return data.decode("utf-8", errors="replace"), ""


# ---------------------------------------------------------------- scanning

def scan_text(rel_path: str, text: str, ruleset: RuleSet) -> list[Finding]:
    rel_path = rel_path.replace("\\", "/")
    ext = file_extension(rel_path)
    rules = [r for r in ruleset.rules if r.applies_to(ext)]
    if not rules:
        return []
    lines = text.splitlines()
    code_lines = code_view(lines, ext)
    context = "test" if is_test_path(rel_path, ruleset.settings) else "production"
    marker = ruleset.settings.suppression_marker
    findings = []
    for number, (original, code) in enumerate(zip(lines, code_lines), start=1):
        if not code.strip() or (marker and marker in original.lower()):
            continue
        for rule in rules:
            if rule.regex.search(code):
                norm = normalize(code)
                findings.append(Finding(
                    rule_id=rule.id, title=rule.title, algorithm=rule.algorithm,
                    operation=rule.operation, algorithm_risk=rule.algorithm_risk,
                    file=rel_path, line=number, snippet=original.strip()[:200],
                    context=context, fingerprint=_hash(rule.id, rel_path, norm),
                    signature=_hash(rule.id, norm), remediation=rule.remediation,
                ))
    return findings


def validate_repo_path(path: str | os.PathLike | None) -> Path:
    if path is None or not str(path).strip():
        raise QGError("No repository path provided.")
    if "\x00" in str(path):
        raise QGError("Repository path contains an invalid character.")
    candidate = Path(str(path).strip()).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, RuntimeError) as exc:
        raise QGError(f"Path does not exist: {candidate}") from exc
    if not resolved.is_dir():
        raise QGError(f"Path is not a directory: {resolved}")
    if not os.access(resolved, os.R_OK | os.X_OK):
        raise QGError(f"Directory is not readable: {resolved}")
    return resolved


def iter_worktree_files(root: Path, settings: ScanSettings, stats: ScanStats) -> Iterator[tuple[str, str]]:
    """Yield (relative_posix_path, text) for eligible files. Never follows symlinks."""
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in settings.exclude_dirs
                             and not os.path.islink(os.path.join(dirpath, d)))
        rel_dir = os.path.relpath(dirpath, root)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = name if rel_dir == "." else f"{rel_dir}/{name}".replace(os.sep, "/")
            ok, reason = is_eligible_path(rel, settings)
            if not ok:
                stats.skipped[reason] += 1
                continue
            if os.path.islink(full):
                stats.skipped["symlink"] += 1
                continue
            if count >= settings.max_files:
                stats.truncated = True
                return
            try:
                if os.path.getsize(full) > settings.max_file_bytes:
                    stats.skipped["too_large"] += 1
                    continue
                with open(full, "rb") as handle:
                    data = handle.read(settings.max_file_bytes + 1)
            except OSError as exc:
                stats.errors.append(f"{rel}: {exc.strerror or exc}")
                continue
            text, reason = decode_bytes(data, settings)
            if text is None:
                stats.skipped[reason] += 1
                continue
            count += 1
            stats.files_scanned += 1
            yield rel, text


def scan_files(files: Iterable[tuple[str, str]], ruleset: RuleSet) -> list[Finding]:
    findings = []
    for rel, text in files:
        findings.extend(scan_text(rel, text, ruleset))
    return findings


def scan_repository(path, ruleset: RuleSet | None = None, config_dir=None) -> ScanResult:
    root = validate_repo_path(path)
    ruleset = ruleset or RuleSet.load(config_dir)
    stats = ScanStats()
    findings = scan_files(iter_worktree_files(root, ruleset.settings, stats), ruleset)
    return ScanResult(root=str(root), findings=findings, stats=stats)
