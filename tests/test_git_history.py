import pytest

from quantumguard.git_history import GitError, audit_history, resolve_commit, validate_ref

RSA_LINE = "    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
SAFE = "def make_key():\n    return None\n"
VULN = "def make_key():\n" + RSA_LINE + "    return key\n"


def test_introduce_remove_reintroduce(make_repo, ruleset):
    r = make_repo()
    r.write("app/keys.py", VULN)
    c1 = r.commit("add rsa", "2025-01-01T00:00:00Z")
    r.write("app/keys.py", SAFE)
    c2 = r.commit("remove rsa", "2025-01-11T00:00:00Z")
    r.write("README.txt", "docs\n")
    r.commit("docs", "2025-02-01T00:00:00Z")
    r.write("app/keys.py", VULN)
    c4 = r.commit("bring rsa back", "2025-03-01T00:00:00Z")

    h = audit_history(r.path, ruleset)
    assert h.commits_scanned == 4 and not h.truncated
    (rec,) = h.records.values()
    assert [e.type for e in rec.events] == ["introduced", "removed", "reintroduced"]
    assert [e.commit for e in rec.events] == [c1, c2, c4]
    assert rec.events[0].line == 2
    assert rec.present_at_head
    assert rec.exposure_days(h.head_timestamp) == 10.0


def test_historical_only_and_exposure(make_repo, ruleset):
    r = make_repo()
    r.write("app/keys.py", VULN)
    r.commit("add", "2025-01-01T00:00:00Z")
    r.write("app/keys.py", SAFE)
    r.commit("remove", "2025-01-31T00:00:00Z")
    h = audit_history(r.path, ruleset)
    (rec,) = h.records.values()
    assert not rec.present_at_head
    assert rec.exposure_days(h.head_timestamp) == 30.0
    assert len(h.removed_signatures()) == 1


def test_whitespace_edit_and_line_move_do_not_create_events(make_repo, ruleset):
    r = make_repo()
    r.write("a.py", VULN)
    r.commit("add", "2025-01-01T00:00:00Z")
    r.write("a.py", "\n\n# moved down\n" + VULN.replace("key = rsa", "key  =  rsa"))
    r.commit("reformat", "2025-01-02T00:00:00Z")
    (rec,) = audit_history(r.path, ruleset).records.values()
    assert [e.type for e in rec.events] == ["introduced"]


def test_file_deletion_counts_as_removal(make_repo, ruleset):
    r = make_repo()
    r.write("a.py", VULN)
    r.commit("add", "2025-01-01T00:00:00Z")
    r.delete("a.py")
    r.commit("delete", "2025-01-05T00:00:00Z")
    (rec,) = audit_history(r.path, ruleset).records.values()
    assert [e.type for e in rec.events] == ["introduced", "removed"]


def test_comment_only_history_is_ignored(make_repo, ruleset):
    r = make_repo()
    r.write("a.py", "# rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    r.commit("comment", "2025-01-01T00:00:00Z")
    assert audit_history(r.path, ruleset).records == {}


def test_truncated_window_is_seeded(make_repo, ruleset):
    r = make_repo()
    r.write("a.py", VULN)
    r.commit("add", "2025-01-01T00:00:00Z")
    for i in range(3):
        r.write(f"n{i}.txt", "x\n")
        r.commit(f"noise {i}", f"2025-01-0{i + 2}T00:00:00Z")
    r.write("a.py", SAFE)
    r.commit("remove", "2025-01-09T00:00:00Z")
    h = audit_history(r.path, ruleset, max_commits=2)
    assert h.truncated and h.warnings
    (rec,) = h.records.values()
    assert [e.type for e in rec.events] == ["present_at_window_start", "removed"]


def test_history_of_other_ref(make_repo, ruleset):
    r = make_repo()
    r.write("a.py", SAFE)
    r.commit("base", "2025-01-01T00:00:00Z")
    r.git("checkout", "-q", "-b", "feature")
    r.write("a.py", VULN)
    r.commit("feature", "2025-01-02T00:00:00Z")
    r.git("checkout", "-q", "main")
    assert audit_history(r.path, ruleset, ref="main").records == {}
    assert len(audit_history(r.path, ruleset, ref="feature").records) == 1


def test_errors(tmp_path, make_repo, ruleset):
    with pytest.raises(GitError, match="Not a Git repository"):
        audit_history(tmp_path, ruleset)
    r = make_repo()
    r.write("a.py", SAFE)
    r.commit("x", "2025-01-01T00:00:00Z")
    with pytest.raises(GitError, match="Unknown Git ref"):
        resolve_commit(r.path, "does-not-exist")
    for bad in ["--output=/tmp/x", "a b", "main..evil", ""]:
        with pytest.raises(GitError, match="Invalid Git ref"):
            validate_ref(bad)


def test_empty_repository(make_repo, ruleset):
    r = make_repo()
    with pytest.raises(GitError):
        audit_history(r.path, ruleset)
