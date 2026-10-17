import csv
import io
import json

from quantumguard.report_generator import CSV_COLUMNS, to_csv, to_json, to_markdown


def item(**kw):
    base = {"id": "x1", "kind": "crypto", "severity": "high", "score": 70.0, "title": "RSA",
            "algorithm": "RSA", "operation": "encryption", "status": "current_production",
            "status_label": "Current (production code)", "file": "a.py", "line": 3,
            "snippet": "=HYPERLINK(\"http://evil\")", "first_seen": {"short": "abc12345", "date": "2025-01-01"},
            "removed_in": [{"short": "def67890"}], "reintroduced": True, "exposure_days": 12.5,
            "recommendation": "fix it", "assumptions": ["data_sensitivity"], "unknowns": [],
            "factors": [{"factor": "algorithm_risk", "points": 25, "max_points": 30, "basis": "fact",
                         "reason": "r"}]}
    base.update(kw)
    return base


def test_csv_roundtrip_and_formula_neutralised():
    rows = list(csv.DictReader(io.StringIO(to_csv([item(), item(id="x2", score=10.0)]))))
    assert list(rows[0].keys()) == CSV_COLUMNS
    assert rows[0]["rank"] == "1" and rows[1]["id"] == "x2"
    assert rows[0]["snippet"].startswith("'=")
    assert rows[0]["score_factors"] == "algorithm_risk=25/30 [fact]"
    assert rows[0]["removed_in"] == "def67890"


def test_json_and_markdown():
    report = {"tool": {"version": "0.1.0"}, "generated_at": "now", "repository": "/r", "ref": "HEAD",
              "disclaimer": "not a probability", "history_error": None,
              "summary": {"total": 1, "current": 1, "historical_only": 0, "reintroduced": 1, "pqc": 0,
                          "pqc_outdated": 0, "pqc_manual": 0,
                          "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}},
              "findings": [item()]}
    assert json.loads(to_json(report))["findings"][0]["id"] == "x1"
    md = to_markdown(report)
    assert "not a probability" in md and "algorithm_risk: 25/30 [fact]" in md
