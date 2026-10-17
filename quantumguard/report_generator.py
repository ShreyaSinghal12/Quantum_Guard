"""JSON / CSV / Markdown report export."""
from __future__ import annotations

import csv
import io
import json

CSV_COLUMNS = ["rank", "id", "kind", "severity", "score", "title", "algorithm", "operation", "status",
               "file", "line", "snippet", "first_seen_commit", "first_seen_date", "removed_in",
               "reintroduced", "exposure_days", "confidence", "declared_version", "standard",
               "recommendation", "score_factors", "assumptions", "unknowns"]


def _safe_cell(value) -> str:
    """Neutralise spreadsheet formula injection from untrusted snippets."""
    text = "" if value is None else str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, default=str)


def flatten(item: dict, rank: int) -> dict:
    first = item.get("first_seen") or {}
    return {
        "rank": rank, "id": item["id"], "kind": item["kind"], "severity": item["severity"],
        "score": item["score"], "title": item["title"], "algorithm": item["algorithm"],
        "operation": item.get("operation", ""),
        "status": item.get("status_label", item.get("status", "")),
        "file": item.get("file", ""), "line": item.get("line", ""),
        "snippet": item.get("snippet") or "; ".join(l.get("snippet", "") for l in item.get("code_locations", [])[:2]),
        "first_seen_commit": first.get("short", ""), "first_seen_date": first.get("date", ""),
        "removed_in": " ".join(e["short"] for e in item.get("removed_in", []) or []),
        "reintroduced": item.get("reintroduced", ""),
        "exposure_days": item.get("exposure_days", ""),
        "confidence": item.get("confidence", ""), "declared_version": item.get("declared_version", ""),
        "standard": item.get("standard", ""), "recommendation": item.get("recommendation", ""),
        "score_factors": "; ".join(f"{f['factor']}={f['points']:g}/{f['max_points']} [{f['basis']}]"
                                   for f in item.get("factors", [])),
        "assumptions": ", ".join(item.get("assumptions", [])),
        "unknowns": ", ".join(item.get("unknowns", [])),
    }


def to_csv(items: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    for rank, item in enumerate(items, 1):
        writer.writerow({k: _safe_cell(v) for k, v in flatten(item, rank).items()})
    return buf.getvalue()


def to_markdown(report: dict, limit: int = 50) -> str:
    s = report["summary"]
    lines = [
        f"# QuantumGuard report",
        "",
        f"- Repository: `{report['repository']}` (ref `{report['ref']}`)",
        f"- Generated: {report['generated_at']} by QuantumGuard {report['tool']['version']}",
        f"- Findings: {s['total']} (critical {s['by_severity']['critical']}, high {s['by_severity']['high']}, "
        f"medium {s['by_severity']['medium']}, low {s['by_severity']['low']}, info {s['by_severity']['info']})",
        f"- Current crypto findings: {s['current']}; historical-only: {s['historical_only']}; "
        f"reintroduced: {s['reintroduced']}",
        f"- PQC findings: {s['pqc']} (potentially outdated: {s['pqc_outdated']}, "
        f"needs manual verification: {s['pqc_manual']})",
        "",
        f"> {report['disclaimer']}",
        "",
    ]
    if report.get("history_error"):
        lines += [f"> Note: {report['history_error']}", ""]
    lines += ["| # | Severity | Score | Finding | Location | Status |", "|---|---|---|---|---|---|"]
    for i, item in enumerate(report["findings"][:limit], 1):
        loc = f"{item.get('file', '')}:{item.get('line', '')}"
        lines.append(f"| {i} | {item['severity']} | {item['score']:g} | {item['title']} | `{loc}` | "
                     f"{item.get('status_label', item.get('status'))} |")
    lines.append("")
    for i, item in enumerate(report["findings"][:limit], 1):
        lines += [f"## {i}. {item['title']} - {item['severity']} ({item['score']:g})", "",
                  f"- Location: `{item.get('file')}:{item.get('line')}`",
                  f"- Status: {item.get('status_label', item.get('status'))}"]
        if item["kind"] == "crypto" and item.get("first_seen"):
            lines.append(f"- First seen: {item['first_seen']['short']} ({item['first_seen']['date']})")
        if item["kind"] == "pqc":
            lines.append(f"- Standard: {item.get('standard')} ({item.get('standard_url')}); "
                         f"confidence: {item.get('confidence')}")
            lines += [f"  - Evidence: {e}" for e in item.get("evidence", []) if e]
        lines.append("- Score factors:")
        lines += [f"  - {f['factor']}: {f['points']:g}/{f['max_points']} [{f['basis']}] - {f['reason']}"
                  for f in item["factors"]]
        lines += [f"- Recommendation: {item.get('recommendation', '')}", ""]
    return "\n".join(lines)
