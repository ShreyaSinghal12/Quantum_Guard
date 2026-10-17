"""Smoke-tests the Streamlit dashboard headlessly with streamlit.testing.AppTest."""
import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

from quantumguard.config import PROJECT_ROOT  # noqa: E402

APP = str(PROJECT_ROOT / "app.py")
PAGES = ["Overview", "Repository scan", "Historical audit", "PQC validation",
         "Risk prioritization", "CI/CD gate", "Reports"]


def button(at, label):
    return next(b for b in list(at.sidebar.button) + list(at.button) if b.label == label)


def test_empty_state_renders_on_every_page():
    at = AppTest.from_file(APP, default_timeout=60).run()
    for page in PAGES:
        at.sidebar.radio[0].set_value(page).run()
        assert not at.exception, (page, at.exception)


def test_invalid_path_shows_error(tmp_path):
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.sidebar.text_input[0].set_value(str(tmp_path / "missing")).run()
    button(at, "Run audit").click().run()
    assert any("does not exist" in e.value for e in at.sidebar.error)


def test_demo_mode_end_to_end():
    at = AppTest.from_file(APP, default_timeout=120).run()
    button(at, "Build and audit demo repository").click().run()
    assert not at.exception
    assert at.session_state["audit"] is not None
    assert any("DEMO MODE" in m.value for m in at.markdown)
    for page in PAGES:
        at.sidebar.radio[0].set_value(page).run()
        assert not at.exception, (page, at.exception)

    at.sidebar.radio[0].set_value("CI/CD gate").run()
    head = next(s for s in at.selectbox if s.label.startswith("Head"))
    head.set_value("feature/legacy-partner-rsa").run()
    button(at, "Run CI gate").click().run()
    assert not at.exception
    res = at.session_state["ci_result"]
    assert res.outcome == "BLOCKED" and res.exit_code == 1

    at.sidebar.radio[0].set_value("Risk prioritization").run()
    at.text_area[0].set_value("payments/=low").run()
    before = {i["id"]: i["score"] for i in at.session_state["scored"]}
    button(at, "Apply and re-score").click().run()
    after = {i["id"]: i["score"] for i in at.session_state["scored"]}
    assert not at.exception and before != after
