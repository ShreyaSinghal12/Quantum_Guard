"""Historical cryptography auditor.

Walks the first-parent history of a ref, rescans every changed file at each
commit with the shared scanner, and records when each finding (identified by
its fingerprint) was introduced, removed, and reintroduced.

Safety:
* git is called with an argument list (never a shell), a timeout, prompts
  disabled, fsmonitor disabled and optional locks off; only read commands run.
* refs are validated and resolved to a commit SHA before use, so user input
  can never be interpreted as a git option.
* git's own "safe.directory" ownership check is left enabled.
"""
from __future__ import annotations

import os
import re
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .config import QGError
from .scanner import RuleSet, decode_bytes, is_eligible_path, scan_text

REF_RE = re.compile(r"^[A-Za-z0-9._/@{}~^+-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
GIT_PREFIX = ["git", "-c", "core.fsmonitor=false", "-c", "core.quotepath=off"]


class GitError(QGError):
    pass


def run_git(repo: str | Path, args: list[str], timeout: int = 60, input_bytes: bytes | None = None) -> bytes:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", LC_ALL="C")
    try:
        proc = subprocess.run([*GIT_PREFIX, "-C", str(repo), *args], capture_output=True,
                              timeout=timeout, env=env, input=input_bytes, check=False)
    except FileNotFoundError as exc:
        raise GitError("git executable not found on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {args[0]} timed out after {timeout}s (repository too large? "
                       "lower max commits or raise the timeout).") from exc
    if proc.returncode != 0:
        message = proc.stderr.decode("utf-8", errors="replace").strip().splitlines()
        detail = message[0] if message else f"exit code {proc.returncode}"
        if "dubious ownership" in proc.stderr.decode("utf-8", errors="replace"):
            detail += " (git safe.directory check: the repository is owned by another user)"
        raise GitError(f"git {args[0]} failed: {detail}")
    return proc.stdout


def validate_ref(ref: str) -> str:
    ref = (ref or "").strip()
    if not ref or ref.startswith("-") or ".." in ref or not REF_RE.match(ref):
        raise GitError(f"Invalid Git ref: {ref!r}")
    return ref


def git_toplevel(path: str | Path) -> Path:
    try:
        out = run_git(path, ["rev-parse", "--show-toplevel"], timeout=15)
    except GitError as exc:
        raise GitError(f"Not a Git repository (or git refused access): {path}. {exc}") from exc
    return Path(out.decode().strip()).resolve()


def resolve_commit(repo: str | Path, ref: str) -> str:
    ref = validate_ref(ref)
    try:
        sha = run_git(repo, ["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], timeout=15).decode().strip()
    except GitError as exc:
        raise GitError(f"Unknown Git ref: {ref}") from exc
    if not SHA_RE.match(sha):
        raise GitError(f"Unknown Git ref: {ref}")
    return sha


def read_blobs(repo, specs: list[str], max_bytes: int, timeout: int = 120) -> dict[str, bytes | None]:
    """Read `<commit>:<path>` blobs with git cat-file. Oversized blobs return None."""
    specs = [s for s in specs if "\n" not in s]
    if not specs:
        return {}
    result: dict[str, bytes | None] = {}
    check = run_git(repo, ["cat-file", "--batch-check"], timeout=timeout,
                    input_bytes="".join(s + "\n" for s in specs).encode()).decode(errors="replace").splitlines()
    wanted = []
    for spec, header in zip(specs, check):
        parts = header.split()
        if len(parts) == 3 and parts[1] == "blob" and int(parts[2]) <= max_bytes:
            wanted.append(spec)
        else:
            result[spec] = None
    if not wanted:
        return result
    out = run_git(repo, ["cat-file", "--batch"], timeout=timeout,
                  input_bytes="".join(s + "\n" for s in wanted).encode())
    pos = 0
    for spec in wanted:
        newline = out.index(b"\n", pos)
        parts = out[pos:newline].decode(errors="replace").split()
        pos = newline + 1
        if len(parts) != 3:
            result[spec] = None
            continue
        size = int(parts[2])
        result[spec] = out[pos:pos + size]
        pos += size + 1
    return result


def list_tree(repo, sha: str) -> list[str]:
    out = run_git(repo, ["ls-tree", "-r", "-z", "--name-only", sha])
    return [p for p in out.decode("utf-8", errors="replace").split("\x00") if p]


def iter_ref_files(repo, sha: str, ruleset: RuleSet, paths: list[str] | None = None) -> Iterator[tuple[str, str]]:
    """Yield (path, text) for eligible files at a commit, without touching the working tree."""
    settings = ruleset.settings
    candidates = [p for p in (paths if paths is not None else list_tree(repo, sha))
                  if is_eligible_path(p, settings)[0]][: settings.max_files]
    for start in range(0, len(candidates), 400):
        chunk = candidates[start:start + 400]
        blobs = read_blobs(repo, [f"{sha}:{p}" for p in chunk], settings.max_file_bytes)
        for path in chunk:
            data = blobs.get(f"{sha}:{path}")
            if data is None:
                continue
            text, _ = decode_bytes(data, settings)
            if text is not None:
                yield path, text


# ------------------------------------------------------------- data model

def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


@dataclass
class HistoryEvent:
    type: str          # introduced | removed | reintroduced | present_at_window_start
    commit: str
    timestamp: int
    author: str
    subject: str
    line: int | None = None

    @property
    def short(self) -> str:
        return self.commit[:8]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["date"] = _iso(self.timestamp)
        d["short"] = self.short
        return d


@dataclass
class HistoryRecord:
    fingerprint: str
    signature: str
    rule_id: str
    title: str
    algorithm: str
    operation: str
    algorithm_risk: str
    file: str
    snippet: str
    context: str
    remediation: str
    events: list = field(default_factory=list)
    intervals: list = field(default_factory=list)   # [start_ts, end_ts or None]
    present_at_head: bool = False

    @property
    def first_seen(self) -> HistoryEvent | None:
        return self.events[0] if self.events else None

    @property
    def removals(self) -> list:
        return [e for e in self.events if e.type == "removed"]

    @property
    def reintroductions(self) -> list:
        return [e for e in self.events if e.type == "reintroduced"]

    def exposure_days(self, head_ts: int) -> float:
        total = 0
        for start, end in self.intervals:
            total += max(0, (end if end is not None else head_ts) - start)
        return round(total / 86400, 1)

    def to_dict(self, head_ts: int) -> dict:
        return {
            "fingerprint": self.fingerprint, "signature": self.signature, "rule_id": self.rule_id,
            "title": self.title, "algorithm": self.algorithm, "operation": self.operation,
            "file": self.file, "snippet": self.snippet, "context": self.context,
            "present_at_head": self.present_at_head,
            "exposure_days": self.exposure_days(head_ts),
            "reintroduced": bool(self.reintroductions),
            "events": [e.to_dict() for e in self.events],
        }


@dataclass
class HistoryResult:
    repo: str
    ref: str
    head_commit: str
    head_timestamp: int
    commits_scanned: int
    truncated: bool
    records: dict
    commits: list
    warnings: list = field(default_factory=list)

    def removed_signatures(self) -> dict:
        """signature -> record, for patterns that were removed at least once."""
        return {r.signature: r for r in self.records.values() if r.removals}

    def to_dict(self) -> dict:
        return {
            "repo": self.repo, "ref": self.ref, "head_commit": self.head_commit,
            "head_date": _iso(self.head_timestamp), "commits_scanned": self.commits_scanned,
            "truncated": self.truncated, "warnings": self.warnings, "commits": self.commits,
            "records": [r.to_dict(self.head_timestamp) for r in self.records.values()],
        }


# ------------------------------------------------------------- auditor

def _parse_log(raw: bytes) -> list[dict]:
    commits = []
    for chunk in raw.decode("utf-8", errors="replace").split("\x1e"):
        lines = [ln for ln in chunk.split("\n") if ln.strip()]
        if not lines:
            continue
        sha, ts, author, subject = (lines[0].split("\x1f") + ["", "", "", ""])[:4]
        changes = []
        for ln in lines[1:]:
            if "\t" in ln:
                status, path = ln.split("\t", 1)
                changes.append((status[:1], path))
        commits.append({"sha": sha, "timestamp": int(ts or 0), "author": author,
                        "subject": subject, "changes": changes})
    return commits


def audit_history(repo, ruleset: RuleSet | None = None, ref: str = "HEAD",
                  max_commits: int = 1000, timeout: int = 120) -> HistoryResult:
    ruleset = ruleset or RuleSet.load()
    top = git_toplevel(repo)
    head = resolve_commit(top, ref)
    fmt = "%x1e%H%x1f%at%x1f%an%x1f%s"
    raw = run_git(top, ["log", "--first-parent", "--diff-merges=first-parent", "--no-renames",
                        "--name-status", f"--max-count={max_commits + 1}", f"--format={fmt}", head],
                  timeout=timeout)
    commits = _parse_log(raw)
    truncated = len(commits) > max_commits
    commits = list(reversed(commits[:max_commits]))
    settings = ruleset.settings

    records: dict[str, HistoryRecord] = {}
    state: dict[str, Counter] = {}
    warnings: list[str] = []
    timeline: list[dict] = []

    def apply(path: str, new_findings: list, commit: dict, event_type_new: str | None = None):
        new_count, first_line, sample = Counter(), {}, {}
        for f in new_findings:
            new_count[f.fingerprint] += 1
            first_line.setdefault(f.fingerprint, f.line)
            sample.setdefault(f.fingerprint, f)
        old = state.get(path, Counter())
        events = 0
        for fp in set(old) | set(new_count):
            before, after = old[fp], new_count[fp]
            if before == 0 and after > 0:
                f = sample[fp]
                rec = records.get(fp)
                if rec is None:
                    rec = records[fp] = HistoryRecord(
                        fingerprint=fp, signature=f.signature, rule_id=f.rule_id, title=f.title,
                        algorithm=f.algorithm, operation=f.operation, algorithm_risk=f.algorithm_risk,
                        file=f.file, snippet=f.snippet, context=f.context, remediation=f.remediation)
                kind = event_type_new or ("reintroduced" if rec.removals else "introduced")
                rec.events.append(HistoryEvent(kind, commit["sha"], commit["timestamp"],
                                               commit["author"], commit["subject"], first_line[fp]))
                rec.intervals.append([commit["timestamp"], None])
                events += 1
            elif before > 0 and after == 0:
                rec = records[fp]
                rec.events.append(HistoryEvent("removed", commit["sha"], commit["timestamp"],
                                               commit["author"], commit["subject"]))
                if rec.intervals and rec.intervals[-1][1] is None:
                    rec.intervals[-1][1] = commit["timestamp"]
                events += 1
        if new_count:
            state[path] = new_count
        else:
            state.pop(path, None)
        return events

    # If the window is truncated, seed the state from the tree just before it.
    if truncated and commits:
        try:
            parent = resolve_commit(top, commits[0]["sha"] + "^")
            info = run_git(top, ["log", "-1", f"--format=%H%x1f%at%x1f%an%x1f%s", parent]).decode().strip()
            sha, ts, author, subject = info.split("\x1f", 3)
            seed = {"sha": sha, "timestamp": int(ts), "author": author, "subject": subject}
            per_file: dict[str, list] = {}
            for path, text in iter_ref_files(top, parent, ruleset):
                per_file.setdefault(path, []).extend(scan_text(path, text, ruleset))
            for path, found in per_file.items():
                apply(path, found, seed, event_type_new="present_at_window_start")
            warnings.append(f"History truncated to the latest {max_commits} commits; findings already "
                            f"present at {sha[:8]} are marked 'present_at_window_start'.")
        except GitError as exc:
            warnings.append(f"Could not seed truncated history window: {exc}")

    for commit in commits:
        changed = [(st, p) for st, p in commit["changes"] if is_eligible_path(p, settings)[0]]
        live = [p for st, p in changed if st != "D"]
        blobs = read_blobs(top, [f"{commit['sha']}:{p}" for p in live], settings.max_file_bytes, timeout)
        n_events = 0
        for status, path in changed:
            found = []
            if status != "D":
                data = blobs.get(f"{commit['sha']}:{path}")
                text = decode_bytes(data, settings)[0] if data is not None else None
                if text is not None:
                    found = scan_text(path, text, ruleset)
            n_events += apply(path, found, commit)
        timeline.append({"commit": commit["sha"], "short": commit["sha"][:8],
                         "date": _iso(commit["timestamp"]), "timestamp": commit["timestamp"],
                         "author": commit["author"], "subject": commit["subject"],
                         "files_changed": len(commit["changes"]), "crypto_events": n_events})

    present = set()
    for counter in state.values():
        present.update(fp for fp, n in counter.items() if n > 0)
    for fp, rec in records.items():
        rec.present_at_head = fp in present
    head_ts = commits[-1]["timestamp"] if commits else 0
    return HistoryResult(repo=str(top), ref=ref, head_commit=head, head_timestamp=head_ts,
                         commits_scanned=len(commits), truncated=truncated, records=records,
                         commits=timeline, warnings=warnings)
