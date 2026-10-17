"""Measure QuantumGuard on labelled data and synthetic changes.

Writes docs/evaluation_report.md and docs/evaluation_results.json.
Every number comes from running the code in this repository.

    python scripts/evaluate.py
"""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from quantumguard import __version__  # noqa: E402
from quantumguard.demo_builder import build_demo_repo  # noqa: E402
from quantumguard.policy_engine import run_ci_gate  # noqa: E402
from quantumguard.risk_engine import apply_scores, load_policy  # noqa: E402
from quantumguard.scanner import RuleSet, scan_text  # noqa: E402

CORPUS = ROOT / "tests" / "fixtures" / "labeled_corpus"


def detection_metrics(ruleset):
    labels = json.loads((CORPUS / "labels.json").read_text())
    expected = {tuple(x) for x in labels["expected"]}
    predicted = set()
    for path in sorted(CORPUS.iterdir()):
        if path.name == "labels.json":
            continue
        for f in scan_text(path.name, path.read_text(), ruleset):
            predicted.add((path.name, f.line, f.rule_id))
    tp, fp, fn = expected & predicted, predicted - expected, expected - predicted
    precision = len(tp) / len(predicted) if predicted else 0.0
    recall = len(tp) / len(expected) if expected else 0.0
    return {"labelled_positives": len(expected), "predicted": len(predicted), "true_positives": len(tp),
            "false_positives": sorted(fp), "false_negatives": sorted(fn),
            "precision": round(precision, 3), "recall": round(recall, 3)}


def _git(repo, *args, date="2025-01-01T00:00:00Z"):
    env = dict(os.environ, GIT_AUTHOR_NAME="Eval", GIT_AUTHOR_EMAIL="eval@example.invalid",
               GIT_COMMITTER_NAME="Eval", GIT_COMMITTER_EMAIL="eval@example.invalid",
               GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
    subprocess.run(["git", "-c", "commit.gpgsign=false", "-C", str(repo), *args], check=True,
                   capture_output=True, env=env)


CI_SCENARIOS = json.loads((ROOT / "tests" / "fixtures" / "ci_scenarios.json").read_text())


def ci_metrics():
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "r"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "main")
        for step in CI_SCENARIOS["base_history"]:
            for rel, content in step["files"].items():
                (repo / rel).parent.mkdir(parents=True, exist_ok=True)
                (repo / rel).write_text(content)
            _git(repo, "add", "-A")
            _git(repo, "commit", "-q", "-m", step["message"], date=step["date"])
        for i, sc in enumerate(CI_SCENARIOS["scenarios"]):
            name, files, unsafe, expected = sc["name"], sc["files"], sc["unsafe"], sc["expected"]
            branch = f"case{i}"
            _git(repo, "checkout", "-q", "-b", branch, "main")
            for rel, content in files.items():
                (repo / rel).parent.mkdir(parents=True, exist_ok=True)
                (repo / rel).write_text(content)
            _git(repo, "add", "-A")
            _git(repo, "commit", "-q", "-m", name, date="2025-03-01T00:00:00Z")
            _git(repo, "checkout", "-q", "main")
            res = run_ci_gate(repo, "main", branch)
            worst = max((d.decision for d in res.decisions), default="pass",
                        key=lambda d: {"pass": 0, "warn": 1, "block": 2}[d])
            rows.append({"scenario": name, "unsafe": unsafe, "expected": expected, "actual": worst,
                         "exit_code": res.exit_code, "correct": worst == expected})
    unsafe = [r for r in rows if r["unsafe"]]
    safe = [r for r in rows if not r["unsafe"]]
    return {"scenarios": rows,
            "unsafe_changes": len(unsafe),
            "unsafe_blocked": sum(1 for r in unsafe if r["actual"] == "block"),
            "safe_changes": len(safe),
            "safe_changes_blocked": sum(1 for r in safe if r["actual"] == "block"),
            "decisions_matching_expectation": sum(1 for r in rows if r["correct"])}


def demo_ci_metrics():
    with tempfile.TemporaryDirectory() as tmp:
        info = build_demo_repo(Path(tmp) / "demo")
        rows = []
        for branch, expected in info["expected_ci"].items():
            res = run_ci_gate(info["path"], "main", branch)
            rows.append({"branch": branch, "expected": expected, "actual": res.outcome, "exit_code": res.exit_code})
        return rows


def ranking_metrics():
    spec = importlib.util.spec_from_file_location("risk_tests", ROOT / "tests" / "test_risk_engine.py")
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT / "tests"))
    spec.loader.exec_module(mod)
    policy = load_policy(overrides={"data_sensitivity": {"paths": {"payments/": "high", "reports/": "low"}}})
    scored = apply_scores(copy.deepcopy(mod.SCENARIOS), policy)
    actual = [s["id"] for s in scored]
    pairs = [(a, b) for i, a in enumerate(mod.EXPECTED_ORDER) for b in mod.EXPECTED_ORDER[i + 1:]]
    pos = {k: i for i, k in enumerate(actual)}
    ok_pairs = sum(1 for a, b in pairs if pos[a] < pos[b])
    return {"expected_order": mod.EXPECTED_ORDER, "actual_order": actual,
            "scores": {s["id"]: s["score"] for s in scored},
            "ordered_pairs_correct": ok_pairs, "ordered_pairs_total": len(pairs)}


def main():
    ruleset = RuleSet.load()
    results = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
               "version": __version__, "detection": detection_metrics(ruleset), "ci": ci_metrics(),
               "demo_ci": demo_ci_metrics(), "ranking": ranking_metrics()}
    (ROOT / "docs" / "evaluation_results.json").write_text(json.dumps(results, indent=2))
    d, c, r = results["detection"], results["ci"], results["ranking"]
    md = [
        "# QuantumGuard evaluation report", "",
        f"Generated {results['generated_at']} by `python scripts/evaluate.py` (QuantumGuard {__version__}). "
        "All values are measured by running the code; the dataset is small and synthetic, so treat these as "
        "prototype sanity checks, not coverage claims.", "",
        "## 1. Detection on the labelled corpus (`tests/fixtures/labeled_corpus`)", "",
        "| Metric | Value |", "|---|---|",
        f"| Labelled positives | {d['labelled_positives']} |",
        f"| Predicted findings | {d['predicted']} |",
        f"| True positives | {d['true_positives']} |",
        f"| False positives | {len(d['false_positives'])} |",
        f"| False negatives | {len(d['false_negatives'])} |",
        f"| Precision | {d['precision']} |",
        f"| Recall | {d['recall']} |", "",
        "False positives:", ""] + [f"- `{f}:{l}` {rule}" for f, l, rule in d["false_positives"]] + [
        "", "False negatives (known limitations, kept in the corpus on purpose):", ""] + \
        [f"- `{f}:{l}` {rule}" for f, l, rule in d["false_negatives"]] + [
        "", "## 2. CI gate on synthetic changes", "",
        f"- Deliberately unsafe changes blocked: **{c['unsafe_blocked']} / {c['unsafe_changes']}**",
        f"- Safe changes wrongly blocked: **{c['safe_changes_blocked']} / {c['safe_changes']}**",
        f"- Decisions matching the documented expectation: {c['decisions_matching_expectation']} / "
        f"{len(c['scenarios'])}", "",
        "| Scenario | Unsafe | Expected | Actual | Exit |", "|---|---|---|---|---|"] + \
        [f"| {s['scenario']} | {'yes' if s['unsafe'] else 'no'} | {s['expected']} | {s['actual']} | "
         f"{s['exit_code']} |" for s in c["scenarios"]] + [
        "", "## 3. Demo repository CI branches", "", "| Branch | Expected | Actual | Exit |", "|---|---|---|---|"] + \
        [f"| `{x['branch']}` | {x['expected']} | {x['actual']} | {x['exit_code']} |" for x in results["demo_ci"]] + [
        "", "## 4. Risk ranking of documented scenarios", "",
        f"Correctly ordered pairs: **{r['ordered_pairs_correct']} / {r['ordered_pairs_total']}**", "",
        "| Rank | Scenario | Score |", "|---|---|---|"] + \
        [f"| {i} | {sid} | {r['scores'][sid]} |" for i, sid in enumerate(r["actual_order"], 1)] + [""]
    (ROOT / "docs" / "evaluation_report.md").write_text("\n".join(md))
    print("\n".join(md))


if __name__ == "__main__":
    main()
