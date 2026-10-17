"""End-to-end audit: current scan + Git history + PQC validation + risk scoring."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import QGError
from .git_history import GitError, HistoryResult, audit_history, git_toplevel
from .pqc_validator import PQCResult, PQCValidator
from .risk_engine import apply_scores, load_policy
from .scanner import RuleSet, ScanStats, iter_worktree_files, scan_files, validate_repo_path

STATUS_LABELS = {
    "current_production": "Current (production code)",
    "current_test": "Current (test code only)",
    "uncommitted": "Current (uncommitted)",
    "present_at_head_not_in_worktree": "At audited commit, not in working tree",
    "historical_only": "Historical only",
}
SENSITIVITY_LEVELS = {"high", "medium", "low"}


@dataclass
class AuditResult:
    repo: str
    generated_at: str
    ref: str
    scan_stats: ScanStats
    current_findings: list
    history: HistoryResult | None
    history_error: str | None
    pqc: PQCResult
    items: list
    policy: dict
    repo_declared: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)

    def counts(self) -> dict:
        sev = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
        for item in self.items:
            sev[item["severity"]] += 1
        crypto = [i for i in self.items if i["kind"] == "crypto"]
        return {
            "total": len(self.items), "by_severity": sev,
            "current": sum(1 for i in crypto if i["status"] != "historical_only"),
            "historical_only": sum(1 for i in crypto if i["status"] == "historical_only"),
            "reintroduced": sum(1 for i in crypto if i.get("reintroduced")),
            "pqc": sum(1 for i in self.items if i["kind"] == "pqc"),
            "pqc_outdated": sum(1 for i in self.items if i["kind"] == "pqc" and i["status"] == "potentially_outdated_draft"),
            "pqc_manual": sum(1 for i in self.items if i["kind"] == "pqc" and i["status"] == "needs_manual_verification"),
        }

    def to_dict(self) -> dict:
        return {
            "tool": {"name": "QuantumGuard", "version": __version__},
            "generated_at": self.generated_at, "repository": self.repo, "ref": self.ref,
            "disclaimer": self.policy.get("disclaimer", ""),
            "summary": self.counts(),
            "scan": self.scan_stats.to_dict(),
            "history": self.history.to_dict() if self.history else None,
            "history_error": self.history_error,
            "pqc": self.pqc.to_dict(),
            "repo_declared_sensitivity": self.repo_declared,
            "risk_policy": self.policy,
            "warnings": self.warnings,
            "findings": self.items,
        }


def read_repo_declared(root: Path, warnings: list) -> dict:
    path = root / ".quantumguard.json"
    if not path.is_file() or path.is_symlink():
        return {}
    try:
        if path.stat().st_size > 64_000:
            raise ValueError("file too large")
        data = json.loads(path.read_text(encoding="utf-8"))
        raw = data.get("sensitivity", {})
        clean = {str(k): str(v).lower() for k, v in raw.items() if str(v).lower() in SENSITIVITY_LEVELS}
        if len(clean) != len(raw):
            warnings.append(".quantumguard.json: ignored sensitivity entries with unknown levels.")
        return clean
    except (ValueError, OSError, AttributeError) as exc:
        warnings.append(f"Ignored .quantumguard.json: {exc}")
        return {}


def _event_brief(e) -> dict:
    return {"commit": e.commit, "short": e.short, "date": e.to_dict()["date"], "author": e.author,
            "subject": e.subject}


def _crypto_recommendation(item: dict) -> str:
    if item["status"] == "historical_only":
        first = item["first_seen"]["date"] if item.get("first_seen") else "an unknown date"
        removed = item["removed_in"][-1]["date"] if item.get("removed_in") else "its removal"
        return (f"Not in current code. Check whether keys, ciphertexts or signed artifacts produced between "
                f"{first} and {removed} still exist (backups, logs, releases, captured traffic) and rotate or "
                f"re-encrypt if the data is sensitive. This is potential exposure, not confirmed compromise.")
    text = item["remediation"]
    if item.get("reintroduced") and item.get("removed_in") and item.get("reintroduced_in"):
        text = (f"Removed in {item['removed_in'][-1]['short']} and reintroduced in "
                f"{item['reintroduced_in'][-1]['short']}: confirm this was intentional and keep a CI block rule. "
                + text)
    if item["status"] == "current_test":
        text = "Test-only usage: low priority unless fixtures share keys with production. " + text
    return text


def build_crypto_items(findings: list, history: HistoryResult | None) -> list[dict]:
    current: dict[str, list] = {}
    for f in findings:
        current.setdefault(f.fingerprint, []).append(f)
    items: dict[str, dict] = {}

    def base(src, fp):
        return {"id": fp, "kind": "crypto", "fingerprint": fp, "signature": src.signature,
                "rule_id": src.rule_id, "title": src.title, "algorithm": src.algorithm,
                "operation": src.operation, "algorithm_risk": src.algorithm_risk, "file": src.file,
                "snippet": src.snippet, "context": src.context, "remediation": src.remediation}

    if history:
        for fp, rec in history.records.items():
            item = base(rec, fp)
            if fp in current:
                item["status"] = "current_test" if rec.context == "test" else "current_production"
            elif rec.present_at_head:
                item["status"] = "present_at_head_not_in_worktree"
            else:
                item["status"] = "historical_only"
            locs = current.get(fp, [])
            item["line"] = locs[0].line if locs else (rec.first_seen.line if rec.first_seen else None)
            item["locations"] = [{"file": f.file, "line": f.line} for f in locs]
            item["first_seen"] = _event_brief(rec.first_seen) if rec.first_seen else None
            item["removed_in"] = [_event_brief(e) for e in rec.removals]
            item["reintroduced_in"] = [_event_brief(e) for e in rec.reintroductions]
            item["events"] = [e.to_dict() for e in rec.events]
            item["exposure_days"] = rec.exposure_days(history.head_timestamp)
            item["reintroduced"] = bool(rec.reintroductions)
            items[fp] = item

    for fp, locs in current.items():
        if fp in items:
            continue
        item = base(locs[0], fp)
        if locs[0].context == "test":
            item["status"] = "current_test"
        else:
            item["status"] = "uncommitted" if history else "current_production"
        item.update(line=locs[0].line, locations=[{"file": f.file, "line": f.line} for f in locs],
                    first_seen=None, removed_in=[], reintroduced_in=[], events=[],
                    exposure_days=None if not history else 0.0,
                    reintroduced=None if not history else False)
        items[fp] = item

    for item in items.values():
        item["status_label"] = STATUS_LABELS[item["status"]]
        item["recommendation"] = _crypto_recommendation(item)
    return list(items.values())


def build_pqc_items(pqc: PQCResult) -> list[dict]:
    items = []
    for f in pqc.findings:
        d = f.to_dict()
        locs = f.code_locations
        usage = "none" if not locs else ("test" if all(l["context"] == "test" for l in locs) else "production")
        manifest_file = f.manifest.rsplit(":", 1)[0] if f.manifest else ""
        d.update(kind="pqc", title=f"{f.algorithm} via {f.library_name}", usage=usage,
                 file=locs[0]["file"] if locs else manifest_file,
                 line=locs[0]["line"] if locs else (int(f.manifest.rsplit(":", 1)[1]) if f.manifest else None),
                 rule_id="PQC-VALIDATOR", operation="pqc_implementation")
        items.append(d)
    return items


def run_audit(path, config_dir=None, ref: str = "HEAD", max_commits: int = 1000,
              risk_overrides: dict | None = None, include_history: bool = True,
              timeout: int = 120) -> AuditResult:
    root = validate_repo_path(path)
    ruleset = RuleSet.load(config_dir)
    validator = PQCValidator.load(config_dir, ruleset)
    policy = load_policy(config_dir, risk_overrides)
    warnings: list[str] = []

    stats = ScanStats()
    files = list(iter_worktree_files(root, ruleset.settings, stats))
    findings = scan_files(files, ruleset)
    pqc = validator.validate(files)
    warnings.extend(pqc.warnings)
    if stats.truncated:
        warnings.append(f"Scan stopped after {ruleset.settings.max_files} files (max_files limit).")

    history, history_error = None, None
    if include_history:
        try:
            top = git_toplevel(root)
            if top != root:
                history_error = (f"Historical audit skipped: {root} is inside the Git repository {top}. "
                                 "Point QuantumGuard at the repository root to audit history.")
            else:
                history = audit_history(root, ruleset, ref=ref, max_commits=max_commits, timeout=timeout)
                warnings.extend(history.warnings)
        except GitError as exc:
            history_error = f"Historical audit skipped: {exc}"
    else:
        history_error = "Historical audit disabled."

    repo_declared = read_repo_declared(root, warnings)
    items = build_crypto_items(findings, history) + build_pqc_items(pqc)
    apply_scores(items, policy, repo_declared)
    return AuditResult(repo=str(root), generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                       ref=ref, scan_stats=stats, current_findings=findings, history=history,
                       history_error=history_error, pqc=pqc, items=items, policy=policy,
                       repo_declared=repo_declared, warnings=warnings)


__all__ = ["AuditResult", "run_audit", "build_crypto_items", "build_pqc_items", "QGError"]
