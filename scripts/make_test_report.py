"""Run the test suite and write docs/test_report.md from the actual output.

    python scripts/make_test_report.py
"""
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

proc = subprocess.run([sys.executable, "-m", "pytest", "-v", "--no-header", "-p", "no:cacheprovider"],
                      cwd=ROOT, capture_output=True, text=True)
lines = proc.stdout.strip().splitlines()
summary = lines[-1] if lines else "no output"
report = [
    "# Test report", "",
    f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by `python scripts/make_test_report.py` "
    f"on Python {platform.python_version()} ({platform.system()}).", "",
    f"**Result:** `{summary.strip('= ')}` (exit code {proc.returncode})", "",
    "## Coverage of the required scenarios", "",
    "| Requirement | Test file |", "|---|---|",
    "| Current-code findings, comments/docstrings, test paths, exclusions, invalid paths | tests/test_scanner.py |",
    "| Historical-only findings, removal, reintroduction, truncation, Git errors | tests/test_git_history.py |",
    "| PQC validation: verified, partial, synthetic, unknown evidence | tests/test_pqc_validator.py |",
    "| Risk scoring, explanations, ranking scenarios, overrides | tests/test_risk_engine.py |",
    "| CI warn/block policies, reintroduction, worktree mode, exit codes | tests/test_policy_engine.py |",
    "| JSON / CSV / Markdown export | tests/test_report.py |",
    "| Full demo scenario A-G and CLI | tests/test_end_to_end.py |",
    "| Dashboard pages, demo mode, CI run, re-scoring (headless) | tests/test_dashboard.py |",
    "", "## Full pytest output", "", "```", *lines, "```", ""]
(ROOT / "docs" / "test_report.md").write_text("\n".join(report))
print(summary)
sys.exit(proc.returncode)
