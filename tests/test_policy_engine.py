import pytest

from quantumguard.git_history import GitError
from quantumguard.policy_engine import (_parse_added_lines, format_markdown, github_annotations,
                                        run_ci_gate)

RSA = "    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
BASE = "def f():\n    return 1\n"


@pytest.fixture
def repo(make_repo):
    r = make_repo()
    r.write("app/keys.py", BASE)
    r.write("app/old.py", "def g():\n" + RSA)      # pre-existing finding: must not be gated
    r.commit("base", "2025-01-01T00:00:00Z")
    return r


def branch(r, name, files, date="2025-02-01T00:00:00Z"):
    r.git("checkout", "-q", "-b", name, "main")
    for path, content in files.items():
        r.write(path, content)
    r.commit(name, date)
    r.git("checkout", "-q", "main")


def decisions(result):
    return [(d.decision, d.file, d.rule_id) for d in result.decisions if d.decision != "pass"]


def test_blocks_added_rsa_only(repo):
    branch(repo, "pr", {"app/keys.py": "def f():\n" + RSA})
    res = run_ci_gate(repo.path, "main", "pr")
    assert decisions(res) == [("block", "app/keys.py", "QG-RSA-001")]
    assert res.exit_code == 1 and res.outcome == "BLOCKED"


def test_comment_only_change_passes(repo):
    branch(repo, "pr", {"app/keys.py": BASE + "# rsa.generate_private_key( was removed\n"})
    res = run_ci_gate(repo.path, "main", "pr")
    assert decisions(res) == [] and res.exit_code == 0 and res.outcome == "PASSED"


def test_test_fixture_warns_not_blocks(repo):
    branch(repo, "pr", {"tests/test_k.py": "def make():\n" + RSA})
    res = run_ci_gate(repo.path, "main", "pr")
    assert decisions(res) == [("warn", "tests/test_k.py", "QG-RSA-001")] and res.exit_code == 0


def test_test_paths_ignore_policy(repo):
    branch(repo, "pr", {"tests/test_k.py": "def make():\n" + RSA})
    res = run_ci_gate(repo.path, "main", "pr", policy_overrides={"test_paths": "ignore"})
    assert decisions(res) == []


def test_signature_warns(repo):
    branch(repo, "pr", {"app/sig.py": "def s(k, d):\n    return k.sign(d, ec.ECDSA(hashes.SHA256()))\n"})
    res = run_ci_gate(repo.path, "main", "pr")
    assert decisions(res) == [("warn", "app/sig.py", "QG-ECDSA-001")] and res.exit_code == 0


def test_fail_on_warn_and_warn_mode(repo):
    branch(repo, "sig", {"app/sig.py": "x = ec.ECDSA(hashes.SHA256())\n"})
    assert run_ci_gate(repo.path, "main", "sig", policy_overrides={"fail_on_warn": True}).exit_code == 1
    branch(repo, "rsa", {"app/keys.py": "def f():\n" + RSA})
    res = run_ci_gate(repo.path, "main", "rsa", policy_overrides={"mode": "warn"})
    assert res.exit_code == 0 and decisions(res)[0][0] == "warn"
    assert any("Would block" in r for r in res.decisions[0].reasons)


def test_allow_rules(repo):
    branch(repo, "pr", {"app/keys.py": "def f():\n" + RSA})
    res = run_ci_gate(repo.path, "main", "pr", policy_overrides={"allow_rules": ["QG-RSA-001"]})
    assert decisions(res) == [] and res.exit_code == 0


def test_reintroduction_detected_and_signature_policy_overridden(make_repo):
    r = make_repo()
    sig_line = "    return k.sign(d, ec.ECDSA(hashes.SHA256()))\n"
    r.write("app/sig.py", "def s(k, d):\n" + sig_line)
    r.commit("add", "2025-01-01T00:00:00Z")
    r.write("app/sig.py", "def s(k, d):\n    return None\n")
    r.commit("remove", "2025-02-01T00:00:00Z")
    branch(r, "pr", {"app/other.py": "def s(k, d):\n" + sig_line}, "2025-03-01T00:00:00Z")
    res = run_ci_gate(r.path, "main", "pr")
    (d,) = [d for d in res.decisions if d.decision != "pass"]
    assert d.decision == "block" and d.reintroduced_from["file"] == "app/sig.py"
    assert "Reintroduces" in d.reasons[0]


def test_pqc_manifest_change_is_reported(repo):
    branch(repo, "pr", {"native/CMakeLists.txt":
                        "FetchContent_Declare(liboqs\n GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs\n"
                        " GIT_TAG 0.10.1\n)\n",
                        "native/k.c": "OQS_KEM *k = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);\n"})
    res = run_ci_gate(repo.path, "main", "pr")
    pqc = [d for d in res.decisions if d.kind == "pqc"]
    assert len(pqc) == 1 and pqc[0].decision == "warn" and "ML-KEM" in pqc[0].title
    assert res.exit_code == 0


def test_worktree_mode_includes_untracked_files(repo):
    repo.write("app/new.py", "def f():\n" + RSA)
    res = run_ci_gate(repo.path, "main", None)
    assert decisions(res) == [("block", "app/new.py", "QG-RSA-001")] and res.head == "WORKTREE"


def test_errors(repo, tmp_path):
    with pytest.raises(GitError):
        run_ci_gate(repo.path, "main", "nope")
    with pytest.raises(GitError):
        run_ci_gate(repo.path, "--upload-pack=x", "HEAD")
    with pytest.raises(GitError):
        run_ci_gate(tmp_path / "missing", "main", "HEAD")


def test_parse_added_lines():
    diff = ("+++ b/a.py\n@@ -1,0 +2,3 @@\n+x\n+y\n+z\n@@ -9 +12 @@\n-a\n+b\n"
            "+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n+++ b/c.py\n@@ -3,2 +3,0 @@\n")
    assert _parse_added_lines(diff) == {"a.py": {2, 3, 4, 12}, "c.py": set()}


def test_annotation_and_summary_escaping(repo):
    branch(repo, "pr", {"app/keys.py": "def f():\n" + RSA})
    res = run_ci_gate(repo.path, "main", "pr")
    ann = github_annotations(res)
    assert ann.startswith("::error file=app/keys.py,line=2,title=QuantumGuard QG-RSA-001::")
    assert "\n" not in ann
    assert "BLOCK" in format_markdown(res)
