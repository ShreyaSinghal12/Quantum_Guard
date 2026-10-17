"""Risk engine tests, including the documented ranking scenarios (docs/risk_model.md)."""
import pytest

from quantumguard.risk_engine import apply_scores, load_policy, severity_for


def crypto(name, **kw):
    item = {"id": name, "kind": "crypto", "rule_id": "QG-TEST", "algorithm": "RSA",
            "algorithm_risk": "high", "operation": "encryption", "file": "app/x.py",
            "context": "production", "status": "current_production", "exposure_days": 0.0,
            "reintroduced": False}
    item.update(kw)
    return item


def pqc(name, **kw):
    item = {"id": name, "kind": "pqc", "status": "needs_manual_verification", "confidence": "unknown",
            "status_label": "x", "usage": "production", "file": "app/k.py", "context": "production"}
    item.update(kw)
    return item


SCENARIOS = [
    crypto("S1_current_rsa_encryption_payments_reintroduced", file="payments/a.py",
           exposure_days=400, reintroduced=True),
    pqc("S2_verified_draft_mlkem_payments", status="potentially_outdated_draft", confidence="verified",
        file="payments/kem.c"),
    crypto("S3_current_ecdh_unknown_sensitivity", algorithm="ECDH", operation="key_exchange",
           file="partners/c.py", exposure_days=200),
    crypto("S4_historical_only_rsa_keygen_payments", operation="key_generation", file="payments/a.py",
           status="historical_only", exposure_days=146),
    pqc("S5_unknown_kyber_usage"),
    crypto("S6_current_ecdsa_signature_low_sensitivity", algorithm="ECDSA", algorithm_risk="medium",
           operation="signature", file="reports/s.py", exposure_days=30),
    crypto("S7_test_only_rsa_keygen", operation="key_generation", file="tests/t.py",
           context="test", status="current_test", exposure_days=10),
]
EXPECTED_ORDER = [s["id"] for s in SCENARIOS]


@pytest.fixture
def policy():
    return load_policy(overrides={"data_sensitivity": {"paths": {"payments/": "high", "reports/": "low"}}})


def test_documented_scenarios_rank_in_expected_order(policy):
    import copy
    scored = apply_scores(copy.deepcopy(SCENARIOS), policy)
    assert [s["id"] for s in scored] == EXPECTED_ORDER, [(s["id"], s["score"]) for s in scored]


def test_factors_sum_to_score_and_are_explained(policy):
    import copy
    for item in apply_scores(copy.deepcopy(SCENARIOS), policy):
        assert abs(sum(f["points"] for f in item["factors"]) - item["score"]) < 0.11
        assert 0 <= item["score"] <= 100
        for f in item["factors"]:
            assert f["basis"] in ("fact", "user_supplied", "repo_declared", "assumption", "unknown")
            assert f["reason"] and f["points"] <= f["max_points"]
        assert item["severity_reason"]


def test_sensitivity_basis_labels(policy):
    items = apply_scores([crypto("a", file="payments/p.py"), crypto("b", file="other/p.py"),
                          crypto("c", file="declared/p.py")], policy, repo_declared={"declared/": "high"})
    basis = {i["id"]: next(f for f in i["factors"] if f["factor"] == "data_sensitivity")["basis"] for i in items}
    assert basis == {"a": "user_supplied", "b": "assumption", "c": "repo_declared"}
    assert next(i for i in items if i["id"] == "b")["assumptions"] == ["data_sensitivity"]


def test_unknown_history_is_marked_unknown(policy):
    (item,) = apply_scores([crypto("x", exposure_days=None, reintroduced=None)], policy)
    assert set(item["unknowns"]) == {"exposure_duration", "reintroduction"}


def test_policy_override_changes_score_without_code_changes():
    base = apply_scores([crypto("x")], load_policy())[0]["score"]
    boosted = apply_scores([crypto("x")], load_policy(overrides={"operation_points": {"encryption": 0}}))[0]["score"]
    assert boosted == base - 15


def test_score_capped_at_100():
    pol = load_policy(overrides={"algorithm_risk_points": {"high": 90}})
    assert apply_scores([crypto("x", exposure_days=999, reintroduced=True)], pol)[0]["score"] == 100


def test_severity_thresholds():
    pol = load_policy()
    assert severity_for(80, pol)[0] == "critical"
    assert severity_for(79.9, pol)[0] == "high"
    assert severity_for(5, pol)[0] == "info"


def test_disclaimer_present():
    assert "not a probability" in load_policy()["disclaimer"]
