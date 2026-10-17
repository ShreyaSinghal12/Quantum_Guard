"""Explainable, configurable risk prioritisation.

Each finding receives a 0-100 *priority* score built from independent factors.
Every factor records its points, its maximum, and the basis of the input:

  fact           - derived from code / Git evidence
  user_supplied  - provided by the user (config file or dashboard)
  repo_declared  - declared by the scanned repository (.quantumguard.json)
  assumption     - a documented default used because the input is missing
  unknown        - the input is unavailable; the factor contributes 0

The score is a ranking aid, not a probability of compromise.
"""
from __future__ import annotations

from .config import deep_merge, load_json

BASIS = ("fact", "user_supplied", "repo_declared", "assumption", "unknown")


def load_policy(config_dir=None, overrides: dict | None = None) -> dict:
    return deep_merge(load_json("risk_policy.json", config_dir), overrides)


def _factor(name, points, max_points, basis, reason):
    return {"factor": name, "points": round(points, 1), "max_points": max_points, "basis": basis, "reason": reason}


def _longest_prefix(path: str, mapping: dict) -> tuple[str, str] | None:
    best = None
    for prefix, level in (mapping or {}).items():
        if path.startswith(prefix) and (best is None or len(prefix) > len(best[0])):
            best = (prefix, level)
    return best


def sensitivity_factor(path: str, policy: dict, repo_declared: dict | None = None,
                       context: str = "production") -> dict:
    cfg = policy["data_sensitivity"]
    pts = cfg["points"]
    max_pts = max(pts.values())
    hit = _longest_prefix(path, cfg.get("paths", {}))
    if hit and hit[1] in pts:
        return _factor("data_sensitivity", pts[hit[1]], max_pts, "user_supplied",
                       f"'{hit[0]}' is marked {hit[1]} sensitivity by the user.")
    hit = _longest_prefix(path, repo_declared or {})
    if hit and hit[1] in pts:
        return _factor("data_sensitivity", pts[hit[1]], max_pts, "repo_declared",
                       f"'{hit[0]}' is declared {hit[1]} sensitivity in the repository's .quantumguard.json.")
    if context == "test" and cfg.get("test_context_assumption") in pts:
        level = cfg["test_context_assumption"]
        return _factor("data_sensitivity", pts[level], max_pts, "assumption",
                       f"Test code with no sensitivity supplied; assumed '{level}' (configurable).")
    level = cfg.get("unknown_assumption")
    if level in pts:
        return _factor("data_sensitivity", pts[level], max_pts, "assumption",
                       f"No sensitivity supplied for this path; assumed '{level}' (configurable).")
    return _factor("data_sensitivity", 0, max_pts, "unknown", "No sensitivity supplied; factor not scored.")


def severity_for(score: float, policy: dict) -> tuple[str, str]:
    for label in ("critical", "high", "medium", "low"):
        threshold = policy["severity_thresholds"][label]
        if score >= threshold:
            return label, f"Score {score:g} >= {threshold} ({label} threshold)."
    return "info", f"Score {score:g} is below the low threshold ({policy['severity_thresholds']['low']})."


def score_crypto(item: dict, policy: dict, repo_declared: dict | None = None) -> list[dict]:
    factors = []
    ar = policy["algorithm_risk_points"]
    factors.append(_factor("algorithm_risk", ar.get(item["algorithm_risk"], 0), max(ar.values()), "fact",
                           f"Rule {item['rule_id']} ({item['algorithm']}) is classified "
                           f"'{item['algorithm_risk']}' algorithm risk."))
    op = policy["operation_points"]
    hndl = item["operation"] in ("key_exchange", "encryption")
    factors.append(_factor("operation_exposure", op.get(item["operation"], 0), max(op.values()), "fact",
                           f"Operation '{item['operation']}'" +
                           (" is exposed to harvest-now-decrypt-later." if hndl else
                            " (signatures are not decrypted retroactively)." if item["operation"] == "signature"
                            else ".")))
    factors.append(sensitivity_factor(item["file"], policy, repo_declared, item.get("context", "production")))

    pp = policy["presence_points"]
    status = item["status"]
    reasons = {
        "current_production": "Present in current production code.",
        "uncommitted": "Present in the working tree but not yet committed.",
        "present_at_head_not_in_worktree": "Present at the audited commit but not in the working tree.",
        "historical_only": "Found only in Git history; absent from current code (potential past exposure only).",
        "current_test": "Present only in test code.",
    }
    factors.append(_factor("current_presence", pp.get(status, 0), max(pp.values()), "fact",
                           reasons.get(status, status)))

    ex = policy["exposure"]
    days = item.get("exposure_days")
    if days is None:
        factors.append(_factor("exposure_duration", 0, ex["max_points"], "unknown",
                               "No Git history available for this finding."))
    else:
        pts = ex["max_points"] * min(1.0, days / ex["full_points_after_days"])
        factors.append(_factor("exposure_duration", pts, ex["max_points"], "fact",
                               f"Present for {days:g} days according to commit dates "
                               f"(full points at {ex['full_points_after_days']} days)."))

    rp = policy["reintroduction_points"]
    if item.get("reintroduced") is None:
        factors.append(_factor("reintroduction", 0, rp, "unknown", "No Git history available."))
    elif item["reintroduced"]:
        factors.append(_factor("reintroduction", rp, rp, "fact",
                               "Pattern was removed earlier and later reintroduced."))
    else:
        factors.append(_factor("reintroduction", 0, rp, "fact", "No reintroduction observed."))
    return factors


def score_pqc(item: dict, policy: dict, repo_declared: dict | None = None) -> list[dict]:
    cfg = policy["pqc"]
    sp, cp, up = cfg["status_points"], cfg["confidence_points"], cfg["usage_points"]
    factors = [
        _factor("implementation_status", sp.get(item["status"], 0), max(sp.values()), "fact",
                f"Validator status: {item['status_label']}."),
        _factor("evidence_confidence", cp.get(item["confidence"], 0), max(cp.values()),
                "fact" if item["confidence"] in ("verified", "partial") else
                "assumption" if item["confidence"] == "synthetic" else "unknown",
                f"Evidence confidence is '{item['confidence']}'."),
    ]
    usage = item.get("usage", "none")
    factors.append(_factor("code_usage", up.get(usage, 0), max(up.values()), "fact",
                           {"production": "Algorithm used in production code.",
                            "test": "Algorithm used only in test code.",
                            "none": "No direct code usage found; dependency declared only."}[usage]))
    factors.append(sensitivity_factor(item["file"], policy, repo_declared, item.get("context", "production")))
    return factors


def apply_scores(items: list[dict], policy: dict, repo_declared: dict | None = None) -> list[dict]:
    for item in items:
        factors = score_crypto(item, policy, repo_declared) if item["kind"] == "crypto" \
            else score_pqc(item, policy, repo_declared)
        score = float(round(min(100.0, sum(f["points"] for f in factors)), 1))
        item["factors"] = factors
        item["score"] = score
        item["severity"], item["severity_reason"] = severity_for(score, policy)
        item["assumptions"] = [f["factor"] for f in factors if f["basis"] == "assumption"]
        item["unknowns"] = [f["factor"] for f in factors if f["basis"] == "unknown"]
    items.sort(key=lambda i: (-i["score"], i["kind"], i.get("file", ""), i.get("line") or 0))
    return items
