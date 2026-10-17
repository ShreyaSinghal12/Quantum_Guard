"""Command-line interface: python -m quantumguard <command> ..."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import QGError
from .git_history import audit_history
from .pipeline import run_audit
from .policy_engine import emit_github, format_text, run_ci_gate
from .report_generator import to_csv, to_json, to_markdown
from .scanner import RuleSet, scan_repository


def _write(path: str | None, text: str) -> None:
    if path:
        Path(path).write_text(text, encoding="utf-8")
        print(f"Wrote {path}")


def cmd_scan(args) -> int:
    result = scan_repository(args.path, RuleSet.load(args.config))
    for f in result.findings:
        print(f"{f.file}:{f.line}  {f.rule_id}  [{f.context}]  {f.title}\n    > {f.snippet}")
    print(f"\n{len(result.findings)} finding(s) in {result.stats.files_scanned} file(s); "
          f"skipped: {dict(result.stats.skipped)}")
    _write(args.json, json.dumps([f.to_dict() for f in result.findings], indent=2))
    return 0


def cmd_history(args) -> int:
    h = audit_history(args.path, RuleSet.load(args.config), ref=args.ref, max_commits=args.max_commits)
    print(f"Audited {h.commits_scanned} commit(s) of {args.ref} ({h.head_commit[:8]})")
    for rec in h.records.values():
        state = "PRESENT" if rec.present_at_head else "HISTORICAL-ONLY"
        print(f"[{state}] {rec.file}  {rec.rule_id}  exposure {rec.exposure_days(h.head_timestamp)} days")
        for e in rec.events:
            print(f"    {e.to_dict()['date']}  {e.type:<13} {e.short}  {e.subject}")
    for w in h.warnings:
        print(f"note: {w}")
    _write(args.json, json.dumps(h.to_dict(), indent=2))
    return 0


def cmd_audit(args) -> int:
    overrides = json.loads(Path(args.risk_overrides).read_text()) if args.risk_overrides else None
    audit = run_audit(args.path, args.config, ref=args.ref, max_commits=args.max_commits,
                      risk_overrides=overrides, include_history=not args.no_history)
    report = audit.to_dict()
    s = report["summary"]
    print(f"QuantumGuard audit of {audit.repo}")
    print(f"{s['total']} finding(s): {s['by_severity']}  historical-only={s['historical_only']} "
          f"reintroduced={s['reintroduced']} pqc={s['pqc']}")
    if audit.history_error:
        print(f"note: {audit.history_error}")
    for i, item in enumerate(audit.items[: args.top], 1):
        print(f"{i:>2}. [{item['severity'].upper():<8}] {item['score']:>5g}  {item['title']}  "
              f"{item.get('file')}:{item.get('line')}  ({item.get('status_label', item.get('status'))})")
    _write(args.json, to_json(report))
    _write(args.csv, to_csv(audit.items))
    _write(args.md, to_markdown(report))
    return 0


def cmd_pqc(args) -> int:
    audit = run_audit(args.path, args.config, include_history=False)
    for item in (i for i in audit.items if i["kind"] == "pqc"):
        print(f"[{item['status_label']}] {item['title']}  confidence={item['confidence']}  "
              f"version={item['declared_version']}")
        for e in item["evidence"]:
            if e:
                print(f"    evidence: {e}")
        print(f"    action: {item['recommendation']}")
    return 0


def cmd_ci(args) -> int:
    overrides = {}
    if args.mode:
        overrides["mode"] = args.mode
    if args.fail_on_warn:
        overrides["fail_on_warn"] = True
    result = run_ci_gate(args.repo, args.base, None if args.worktree else args.head, args.config,
                         overrides, check_history=not args.no_history)
    print(format_text(result))
    emit_github(result)
    _write(args.json, json.dumps(result.to_dict(), indent=2))
    return result.exit_code


def cmd_demo(args) -> int:
    from .demo_builder import build_demo_repo
    info = build_demo_repo(args.target, force=args.force)
    print(f"Demo repository created at {info['path']}")
    for b in info["branches"]:
        print(f"  branch {b}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="quantumguard", description="Quantum-safe cryptography risk auditor")
    p.add_argument("--config", default=None, help="Config directory (default: bundled config/)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan current code")
    s.add_argument("path")
    s.add_argument("--json")
    s.set_defaults(func=cmd_scan)

    h = sub.add_parser("history", help="Audit Git history")
    h.add_argument("path")
    h.add_argument("--ref", default="HEAD")
    h.add_argument("--max-commits", type=int, default=1000)
    h.add_argument("--json")
    h.set_defaults(func=cmd_history)

    a = sub.add_parser("audit", help="Full audit with risk scores and reports")
    a.add_argument("path")
    a.add_argument("--ref", default="HEAD")
    a.add_argument("--max-commits", type=int, default=1000)
    a.add_argument("--no-history", action="store_true")
    a.add_argument("--risk-overrides", help="JSON file merged over config/risk_policy.json")
    a.add_argument("--top", type=int, default=15)
    a.add_argument("--json")
    a.add_argument("--csv")
    a.add_argument("--md")
    a.set_defaults(func=cmd_audit)

    q = sub.add_parser("pqc", help="PQC draft-versus-standard validation only")
    q.add_argument("path")
    q.set_defaults(func=cmd_pqc)

    c = sub.add_parser("ci", help="CI/CD gate for a change")
    c.add_argument("--repo", default=".")
    c.add_argument("--base", required=True, help="Base ref, e.g. origin/main")
    c.add_argument("--head", default="HEAD")
    c.add_argument("--worktree", action="store_true", help="Gate uncommitted working-tree changes")
    c.add_argument("--mode", choices=["enforce", "warn"])
    c.add_argument("--fail-on-warn", action="store_true")
    c.add_argument("--no-history", action="store_true", help="Skip the reintroduction check")
    c.add_argument("--json")
    c.set_defaults(func=cmd_ci)

    d = sub.add_parser("demo", help="Build the synthetic demo repository")
    d.add_argument("target")
    d.add_argument("--force", action="store_true")
    d.set_defaults(func=cmd_demo)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except QGError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
