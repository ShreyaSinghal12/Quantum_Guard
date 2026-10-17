"""Quantum-safe CI/CD gate.

Scans only the lines a change adds, using the shared scanner, then applies
the configurable warn/block policy in config/ci_policy.json.

Exit codes: 0 = pass (warnings allowed), 1 = blocked, 2 = tool/usage error.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .config import QGError, deep_merge, load_json
from .git_history import GitError, audit_history, git_toplevel, iter_ref_files, read_blobs, resolve_commit, run_git
from .pqc_validator import PQCValidator
from .scanner import RuleSet, ScanStats, decode_bytes, is_eligible_path, iter_worktree_files, scan_text

ORDER = {"pass": 0, "warn": 1, "block": 2}
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def load_ci_policy(config_dir=None, overrides: dict | None = None) -> dict:
    return deep_merge(load_json("ci_policy.json", config_dir), overrides)


@dataclass
class GateDecision:
    kind: str                 # crypto | pqc
    decision: str             # pass | warn | block
    file: str
    line: int | None
    rule_id: str
    title: str
    snippet: str
    reasons: list
    recommendation: str
    reintroduced_from: dict | None = None

    def to_dict(self):
        return self.__dict__.copy()


@dataclass
class CIResult:
    base: str
    head: str
    merge_base: str
    mode: str
    changed_files: list
    decisions: list
    exit_code: int
    fail_on_warn: bool
    warnings: list = field(default_factory=list)

    @property
    def blocked(self):
        return [d for d in self.decisions if d.decision == "block"]

    @property
    def warned(self):
        return [d for d in self.decisions if d.decision == "warn"]

    @property
    def outcome(self) -> str:
        if self.exit_code == 1:
            return "BLOCKED"
        return "PASSED WITH WARNINGS" if self.warned else "PASSED"

    def to_dict(self):
        return {"base": self.base, "head": self.head, "merge_base": self.merge_base, "mode": self.mode,
                "outcome": self.outcome, "exit_code": self.exit_code, "changed_files": self.changed_files,
                "blocked": len(self.blocked), "warned": len(self.warned), "warnings": self.warnings,
                "decisions": [d.to_dict() for d in self.decisions]}


# ---------------------------------------------------------------- diff helpers

def _parse_added_lines(diff_text: str) -> dict[str, set[int]]:
    added: dict[str, set[int]] = {}
    current = None
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            current = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
            if current is not None:
                added.setdefault(current, set())
        elif current is not None:
            m = HUNK_RE.match(line)
            if m:
                start, count = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
                added[current].update(range(start, start + count))
    return added


def _diff_args(*revs):
    return ["diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames", *revs]


def collect_changes(repo, merge_base: str, head_sha: str | None):
    """Return {path: added line numbers} for added/modified files."""
    revs = [merge_base] + ([head_sha] if head_sha else [])
    status = run_git(repo, _diff_args(*revs) + ["--name-status"]).decode("utf-8", errors="replace")
    changed = [ln.split("\t", 1)[1] for ln in status.splitlines()
               if "\t" in ln and ln[0] in "AMT"]
    added = _parse_added_lines(run_git(repo, _diff_args(*revs) + ["--unified=0"]).decode("utf-8", errors="replace"))
    result = {p: added.get(p, set()) for p in changed}
    if head_sha is None:
        untracked = run_git(repo, ["ls-files", "--others", "--exclude-standard", "-z"]).decode(errors="replace")
        for p in filter(None, untracked.split("\x00")):
            result[p] = None          # None = every line is new
    return result


# ---------------------------------------------------------------- decisions

def _crypto_decision(f, policy: dict, reintro) -> tuple[str, list]:
    if f.rule_id in policy.get("allow_rules", []):
        return "pass", ["Rule is allow-listed in ci_policy.json."]
    reasons = []
    decision = None
    if reintro is not None and policy.get("block_reintroduced", True):
        decision = "block"
        reasons.append(f"Reintroduces a pattern removed in {reintro['short']} ({reintro['date']}).")
    if f.rule_id in policy["block"].get("rules", []) or f.operation in policy["block"].get("operations", []):
        decision = "block"
        reasons.append(f"Policy blocks {f.operation} / {f.rule_id}.")
    elif decision == "block":
        pass
    elif f.rule_id in policy["warn"].get("rules", []) or f.operation in policy["warn"].get("operations", []):
        decision = "warn"
        reasons.append(f"Policy warns on {f.operation} / {f.rule_id}.")
    else:
        decision = "warn"
        reasons.append("Not covered by a block rule; reported as a warning.")
    if f.context == "test":
        mode = policy.get("test_paths", "warn")
        if mode == "ignore":
            return "pass", reasons + ["Test path ignored by policy (test_paths=ignore)."]
        if mode == "warn" and decision == "block":
            decision = "warn"
            reasons.append("Test path: downgraded to warning (test_paths=warn).")
    return decision, reasons


def _apply_mode(decision: str, reasons: list, mode: str) -> str:
    if mode == "warn" and decision == "block":
        reasons.append("Would block in enforce mode (policy mode is 'warn').")
        return "warn"
    return decision


def run_ci_gate(repo, base: str, head: str | None = "HEAD", config_dir=None,
                policy_overrides: dict | None = None, check_history: bool = True,
                timeout: int = 120) -> CIResult:
    policy = load_ci_policy(config_dir, policy_overrides)
    if policy.get("mode") not in ("enforce", "warn"):
        raise QGError("ci_policy.json: mode must be 'enforce' or 'warn'.")
    ruleset = RuleSet.load(config_dir)
    top = git_toplevel(repo)
    base_sha = resolve_commit(top, base)
    head_sha = resolve_commit(top, head) if head else None
    try:
        mb = run_git(top, ["merge-base", base_sha, head_sha or "HEAD"]).decode().strip()
    except GitError as exc:
        raise GitError(f"No common ancestor between {base} and {head or 'working tree'}.") from exc

    changes = collect_changes(top, mb, head_sha)
    eligible = {p: lines for p, lines in changes.items() if is_eligible_path(p, ruleset.settings)[0]}

    # Read the new version of each changed file (from the commit, or from disk).
    contents: dict[str, str] = {}
    if head_sha:
        blobs = read_blobs(top, [f"{head_sha}:{p}" for p in eligible], ruleset.settings.max_file_bytes, timeout)
        for p in eligible:
            data = blobs.get(f"{head_sha}:{p}")
            text = decode_bytes(data, ruleset.settings)[0] if data is not None else None
            if text is not None:
                contents[p] = text
    else:
        for p in eligible:
            full = Path(top, p)
            if full.is_symlink() or not full.is_file():
                continue
            text = decode_bytes(full.read_bytes(), ruleset.settings)[0]
            if text is not None:
                contents[p] = text

    removed_fp, removed_sig, warnings = {}, {}, []
    if check_history:
        try:
            hist = audit_history(top, ruleset, ref=base_sha, max_commits=int(policy.get("history_max_commits", 2000)),
                                 timeout=timeout)
            for rec in hist.records.values():
                if rec.removals and not rec.present_at_head:
                    brief = {"short": rec.removals[-1].short, "date": rec.removals[-1].to_dict()["date"],
                             "commit": rec.removals[-1].commit, "file": rec.file}
                    removed_fp[rec.fingerprint] = brief
                    removed_sig.setdefault(rec.signature, brief)
            warnings.extend(hist.warnings)
        except GitError as exc:
            warnings.append(f"Reintroduction check skipped: {exc}")

    decisions: list[GateDecision] = []
    mode = policy["mode"]
    for path, text in contents.items():
        lines = eligible[path]
        for f in scan_text(path, text, ruleset):
            if lines is not None and f.line not in lines:
                continue
            reintro = removed_fp.get(f.fingerprint) or removed_sig.get(f.signature)
            decision, reasons = _crypto_decision(f, policy, reintro)
            decision = _apply_mode(decision, reasons, mode)
            decisions.append(GateDecision("crypto", decision, f.file, f.line, f.rule_id, f.title, f.snippet,
                                          reasons, f.remediation, reintro))

    # PQC validation needs the whole tree (manifests + code), then keeps findings touched by the change.
    validator = PQCValidator.load(config_dir, ruleset)
    if head_sha:
        files = list(iter_ref_files(top, head_sha, ruleset))
    else:
        files = list(iter_worktree_files(top, ruleset.settings, ScanStats()))
    pqc = validator.validate(files)
    for pf in pqc.findings:
        manifest_file = pf.manifest.rsplit(":", 1)[0] if pf.manifest else ""
        touched = manifest_file in eligible or any(
            loc["file"] in eligible and (eligible[loc["file"]] is None or loc["line"] in eligible[loc["file"]])
            for loc in pf.code_locations)
        if not touched:
            continue
        decision = policy.get("pqc", {}).get(pf.status, "warn")
        reasons = [f"PQC validator: {pf.status_label} (confidence: {pf.confidence})."] + [e for e in pf.evidence if e][:2]
        if pf.context == "test" and policy.get("test_paths") == "ignore":
            decision = "pass"
        decision = _apply_mode(decision, reasons, mode)
        loc = pf.code_locations[0] if pf.code_locations else {"file": manifest_file,
                                                             "line": int(pf.manifest.rsplit(":", 1)[1]) if pf.manifest else None,
                                                             "snippet": pf.declared_version}
        decisions.append(GateDecision("pqc", decision, loc["file"], loc["line"], pf.id,
                                      f"{pf.algorithm} via {pf.library_name}", loc.get("snippet", ""),
                                      reasons, pf.recommendation))

    decisions.sort(key=lambda d: (-ORDER[d.decision], d.file, d.line or 0))
    fail_on_warn = bool(policy.get("fail_on_warn"))
    blocked = any(d.decision == "block" for d in decisions)
    warned = any(d.decision == "warn" for d in decisions)
    exit_code = 1 if blocked or (fail_on_warn and warned) else 0
    return CIResult(base=base, head=head or "WORKTREE", merge_base=mb, mode=mode,
                    changed_files=sorted(changes), decisions=decisions, exit_code=exit_code,
                    fail_on_warn=fail_on_warn, warnings=warnings)


# ---------------------------------------------------------------- output

def format_text(result: CIResult) -> str:
    out = [f"QuantumGuard CI gate (mode: {result.mode})",
           f"Base: {result.base}  Head: {result.head}  Merge-base: {result.merge_base[:8]}",
           f"Changed files: {len(result.changed_files)}", ""]
    for d in result.decisions:
        if d.decision == "pass" and d.kind != "pqc":
            continue
        out.append(f"[{d.decision.upper()}] {d.file}:{d.line}  {d.rule_id}  {d.title}")
        if d.snippet:
            out.append(f"    > {d.snippet}")
        for r in d.reasons:
            out.append(f"    reason: {r}")
        out.append(f"    fix: {d.recommendation}")
        out.append("")
    for w in result.warnings:
        out.append(f"note: {w}")
    out.append(f"Result: {result.outcome} - {len(result.blocked)} blocking, {len(result.warned)} warning(s) "
               f"(exit {result.exit_code})")
    return "\n".join(out)


def _esc_data(s: str) -> str:
    return str(s).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _esc_prop(s: str) -> str:
    return _esc_data(s).replace(":", "%3A").replace(",", "%2C")


def github_annotations(result: CIResult) -> str:
    lines = []
    for d in result.decisions:
        if d.decision == "pass":
            continue
        level = "error" if d.decision == "block" else "warning"
        msg = " ".join(d.reasons) + " Fix: " + d.recommendation
        lines.append(f"::{level} file={_esc_prop(d.file)},line={d.line or 1},"
                     f"title={_esc_prop('QuantumGuard ' + d.rule_id)}::{_esc_data(d.title + ' - ' + msg)}")
    return "\n".join(lines)


def format_markdown(result: CIResult) -> str:
    icon = {"block": "BLOCK", "warn": "WARN"}
    out = [f"## QuantumGuard CI gate: {result.outcome}", "",
           f"Mode `{result.mode}` | base `{result.base}` | head `{result.head}` | "
           f"{len(result.blocked)} blocking, {len(result.warned)} warnings", ""]
    rows = [d for d in result.decisions if d.decision != "pass"]
    if rows:
        out += ["| Decision | Location | Rule | Reason |", "|---|---|---|---|"]
        for d in rows:
            reason = " ".join(d.reasons).replace("|", "\\|")
            out.append(f"| {icon[d.decision]} | `{d.file}:{d.line}` | {d.rule_id} {d.title} | {reason} |")
    else:
        out.append("No quantum-vulnerable cryptography added by this change.")
    return "\n".join(out) + "\n"


def emit_github(result: CIResult) -> None:
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(github_annotations(result))
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as handle:
                handle.write(format_markdown(result))
