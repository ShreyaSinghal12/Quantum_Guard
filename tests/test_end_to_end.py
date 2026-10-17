"""End-to-end demo scenario (README section 'Judge demo', steps A-G)."""
import csv
import io
import json
import subprocess
import sys

import pytest

from quantumguard.config import PROJECT_ROOT, QGError
from quantumguard.demo_builder import build_demo_repo
from quantumguard.pipeline import run_audit
from quantumguard.policy_engine import run_ci_gate
from quantumguard.report_generator import to_csv, to_json


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    return build_demo_repo(tmp_path_factory.mktemp("e2e") / "demo")


@pytest.fixture(scope="module")
def audit(demo):
    return run_audit(demo["path"])


def by(audit, rule_id, file):
    return next(i for i in audit.items if i.get("rule_id") == rule_id and i["file"] == file)


def test_A_B_historical_finding_still_reported_after_removal(audit):
    rsa = by(audit, "QG-RSA-001", "payments/token_exchange.py")
    assert rsa["status"] == "historical_only"
    assert rsa["first_seen"]["date"].startswith("2025-01-15")
    assert rsa["removed_in"][0]["date"].startswith("2025-06-10")
    assert rsa["exposure_days"] == 146.0
    assert "not confirmed compromise" in rsa["recommendation"]
    current_files = {f.file for f in audit.current_findings}
    assert "payments/token_exchange.py" not in current_files


def test_false_positive_controls_in_demo(audit):
    files = {i["file"] for i in audit.items}
    assert "utils/notes.py" not in files and "reports/export.py" not in files


def test_current_findings(audit):
    assert by(audit, "QG-ECDH-001", "partners/channel.py")["status"] == "current_production"
    assert by(audit, "QG-RSA-001", "tests/test_token_exchange.py")["status"] == "current_test"


def test_C_ci_gate_outcomes_match_plan(demo):
    for branch, expected in demo["expected_ci"].items():
        res = run_ci_gate(demo["path"], "main", branch)
        assert res.outcome == expected, (branch, [d.to_dict() for d in res.decisions])
    blocked = run_ci_gate(demo["path"], "main", "feature/legacy-partner-rsa")
    assert blocked.exit_code == 1 and blocked.decisions[0].reintroduced_from is not None


def test_D_pqc_verified_and_manual_cases(audit):
    pqc = {(i["library"], i["algorithm"]): i for i in audit.items if i["kind"] == "pqc"}
    draft = pqc[("liboqs", "ML-KEM")]
    assert (draft["status"], draft["confidence"]) == ("potentially_outdated_draft", "verified")
    manual = pqc[("liboqs-python", "Kyber")]
    assert manual["status"] == "needs_manual_verification"
    assert not any(i["status"] == "potentially_outdated_draft" for i in pqc.values() if i["library"] != "liboqs")


def test_E_scores_explained_and_ordered(audit):
    scores = [i["score"] for i in audit.items]
    assert scores == sorted(scores, reverse=True)
    for i in audit.items:
        assert i["factors"] and i["severity_reason"] and i["recommendation"]
    sens = next(f for f in by(audit, "QG-RSA-001", "payments/token_exchange.py")["factors"]
                if f["factor"] == "data_sensitivity")
    assert sens["basis"] == "repo_declared"


def test_feature_branch_history_shows_reintroduction(demo):
    res = run_audit(demo["path"], ref="feature/legacy-partner-rsa")
    rsa = by(res, "QG-RSA-001", "payments/token_exchange.py")
    assert rsa["reintroduced"] and [e["type"] for e in rsa["events"]] == ["introduced", "removed", "reintroduced"]


def test_G_exports(audit):
    report = json.loads(to_json(audit.to_dict()))
    assert report["summary"]["historical_only"] == 2 and report["disclaimer"]
    rows = list(csv.DictReader(io.StringIO(to_csv(audit.items))))
    assert len(rows) == len(audit.items) and rows[0]["score_factors"]


def test_non_git_directory_degrades_gracefully(tmp_path):
    (tmp_path / "a.py").write_text("k = RSA.generate(2048)\n")
    res = run_audit(tmp_path)
    assert res.history is None and "not a git repository" in res.history_error.lower()
    assert res.items[0]["status"] == "current_production" and "exposure_duration" in res.items[0]["unknowns"]


def test_demo_builder_refuses_foreign_directory(tmp_path):
    (tmp_path / "keep.txt").write_text("important")
    with pytest.raises(QGError):
        build_demo_repo(tmp_path, force=True)
    assert (tmp_path / "keep.txt").exists()


def run_cli(*args):
    return subprocess.run([sys.executable, "-m", "quantumguard", *args], cwd=PROJECT_ROOT,
                          capture_output=True, text=True, timeout=120)


def test_cli_exit_codes(demo, tmp_path):
    assert run_cli("ci", "--repo", demo["path"], "--base", "main", "--head", "feature/legacy-partner-rsa").returncode == 1
    assert run_cli("ci", "--repo", demo["path"], "--base", "main", "--head", "feature/upgrade-liboqs").returncode == 0
    bad = run_cli("ci", "--repo", demo["path"], "--base", "main", "--head", "no-such-branch")
    assert bad.returncode == 2 and "Unknown Git ref" in bad.stderr
    out = tmp_path / "r.json"
    assert run_cli("audit", demo["path"], "--json", str(out)).returncode == 0
    assert json.loads(out.read_text())["summary"]["total"] > 0
    assert run_cli("scan", str(tmp_path / "missing")).returncode == 2
