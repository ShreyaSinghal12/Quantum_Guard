import pytest

from quantumguard.config import QGError
from quantumguard.scanner import RuleSet, is_test_path, scan_repository, scan_text, validate_repo_path


def ids(findings):
    return sorted(f.rule_id for f in findings)


@pytest.mark.parametrize("path,code,expected", [
    ("a.py", "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)", "QG-RSA-001"),
    ("a.py", "k = RSA.generate(2048)", "QG-RSA-002"),
    ("a.py", "c = PKCS1_OAEP.new(pub)", "QG-RSA-003"),
    ("A.java", 'KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");', "QG-RSA-004"),
    ("a.js", "const { publicKey } = crypto.generateKeyPairSync('rsa', {});", "QG-RSA-005"),
    ("a.go", "k, err := rsa.GenerateKey(rand.Reader, 2048)", "QG-RSA-006"),
    ("a.py", "priv = ec.generate_private_key(ec.SECP256R1())", "QG-EC-001"),
    ("a.py", "shared = priv.exchange(ec.ECDH(), peer)", "QG-ECDH-001"),
    ("a.go", "curve := ecdh.P256()", "QG-ECDH-002"),
    ("a.py", "sig = priv.sign(data, ec.ECDSA(hashes.SHA256()))", "QG-ECDSA-001"),
    ("a.py", "params = dh.generate_parameters(generator=2, key_size=2048)", "QG-DH-001"),
    ("a.py", "k = Ed25519PrivateKey.generate()", "QG-EDDSA-001"),
    ("a.pem", "-----BEGIN RSA PRIVATE KEY-----", "QG-KEY-001"),
])
def test_detects_each_rule(ruleset, path, code, expected):
    assert expected in ids(scan_text(path, code + "\n", ruleset))


def test_weak_key_size_reported_in_addition(ruleset):
    found = ids(scan_text("a.py", "rsa.generate_private_key(public_exponent=3, key_size=1024)\n", ruleset))
    assert found == ["QG-RSA-001", "QG-WEAK-001"]


def test_comments_docstrings_and_suppression_are_ignored(ruleset):
    code = (
        '"""Module docs: we used to call rsa.generate_private_key( here."""\n'
        "def f():\n"
        "    '''\n"
        "    Example: rsa.generate_private_key(\n"
        "    '''\n"
        "    # rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "    x = 1  # rsa.generate_private_key(\n"
        "    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # quantumguard: ignore\n"
        "    return x\n"
    )
    assert scan_text("svc/a.py", code, ruleset) == []


def test_c_style_comments_ignored(ruleset):
    code = "// rsa.GenerateKey(rand.Reader, 2048)\n/* ecdh.P256()\n rsa.GenerateKey( */\nx := 1\n"
    assert scan_text("main.go", code, ruleset) == []


def test_hash_inside_string_is_not_a_comment(ruleset):
    code = 'label = "#tag"; k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n'
    assert ids(scan_text("a.py", code, ruleset)) == ["QG-RSA-001"]


def test_similar_names_do_not_match(ruleset):
    code = ("def rsa_generate_private_key_report():\n    pass\n"
            "myrsa.generate_private_keys = None\n"
            "label = 'RSA'\n")
    assert scan_text("a.py", code, ruleset) == []


def test_test_context_and_fingerprints(ruleset):
    line = "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    prod = scan_text("payments/a.py", line, ruleset)[0]
    test = scan_text("tests/test_a.py", line, ruleset)[0]
    moved = scan_text("payments/a.py", "\n\n" + line, ruleset)[0]
    assert prod.context == "production" and test.context == "test"
    assert prod.fingerprint == moved.fingerprint and prod.line != moved.line
    assert prod.signature == test.signature and prod.fingerprint != test.fingerprint


def test_is_test_path(ruleset):
    s = ruleset.settings
    assert is_test_path("tests/x.py", s) and is_test_path("pkg/test_x.py", s)
    assert is_test_path("pkg/x_test.go", s) and not is_test_path("pkg/contest.py", s)


def test_repository_scan_skips_excluded_binary_and_large(tmp_path, ruleset):
    line = "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "a.py").write_text(line)
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "b.py").write_text(line)
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "c.py").write_text(line)
    (tmp_path / "app" / "bin.py").write_bytes(b"\x00\x01" + line.encode())
    (tmp_path / "app" / "big.py").write_text(line * 60000)
    (tmp_path / "app" / "image.png").write_bytes(b"\x89PNG")
    result = scan_repository(tmp_path, ruleset)
    assert [f.file for f in result.findings] == ["app/a.py"]
    assert result.stats.skipped["binary"] == 1
    assert result.stats.skipped["too_large"] == 1
    assert result.stats.skipped["unsupported_extension"] == 1


def test_symlinks_not_followed(tmp_path, ruleset):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.py").write_text("RSA.generate(2048)\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    try:
        (repo / "link.py").symlink_to(outside / "a.py")
        (repo / "linkdir").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Creating symlinks is not permitted here (Windows needs Developer Mode or admin).")
    assert scan_repository(repo, ruleset).findings == []


@pytest.mark.parametrize("bad", ["", "   ", None, "/definitely/not/here", "bad\x00path"])
def test_invalid_paths(bad):
    with pytest.raises(QGError):
        validate_repo_path(bad)


def test_file_path_rejected(tmp_path):
    f = tmp_path / "x.py"
    f.write_text("x")
    with pytest.raises(QGError, match="not a directory"):
        validate_repo_path(f)


def test_bad_rule_regex_rejected():
    with pytest.raises(QGError, match="invalid regex"):
        RuleSet({"rules": [{"id": "X", "title": "t", "algorithm": "a", "operation": "o",
                            "algorithm_risk": "high", "pattern": "(", "extensions": ["py"]}]})


def test_labeled_corpus_regression():
    """Guards the measured metrics in docs/evaluation_report.md against silent regressions."""
    import importlib.util
    from quantumguard.config import PROJECT_ROOT
    spec = importlib.util.spec_from_file_location("evaluate", PROJECT_ROOT / "scripts" / "evaluate.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    m = mod.detection_metrics(RuleSet.load())
    assert m["true_positives"] >= 25 and len(m["false_positives"]) <= 1
    assert ("py_negative.py", 8, "QG-ECDH-001") in m["false_positives"]


# ---------------------------------------------------------------- IBM Z / ICSF

COBOL = (
    "       IDENTIFICATION DIVISION.\n"
    "      * CALL 'CSNDPKG' USING A B.\n"
    "      / CALL 'CSNDEDH' USING A B.\n"
    "       01  WS-KEY-TYPE  PIC X(8) VALUE 'RSA-CRT'.\n"
    "           CALL 'CSNDEDH' USING A B.\n"
    "           call \"csndpke\" using a b.\n"
    "           CALL 'CSNFSYX' USING A B.\n"
    "           MOVE 1 TO X. *> CALL 'CSNDDSG' in an inline comment\n"
    "           DISPLAY 'CALL CSNDPKG IS DOCUMENTED ELSEWHERE'.\n"
)


def test_cobol_icsf_rules_and_comments(ruleset):
    found = [(f.line, f.rule_id) for f in scan_text("batch/SETTLE.cbl", COBOL, ruleset)]
    assert found == [(4, "QG-ICSF-006"), (5, "QG-ICSF-001"), (6, "QG-ICSF-002"), (7, "QG-ICSF-003")]


@pytest.mark.parametrize("path,code,expected", [
    ("x.pli", "CALL CSNDPKG(RC, RS);", ["QG-ICSF-004"]),
    ("x.pli", "/* CALL CSNDPKG(RC, RS); */", []),
    ("x.asm", "         CALL  CSNDDSG,(RC,RS)", ["QG-ICSF-005"]),
    ("x.asm", "*        CALL  CSNDDSG,(RC,RS)", []),
    ("x.cpy", "       01  K  PIC X(8) VALUE 'ECC-PAIR'.", ["QG-ICSF-006"]),
    ("x.cpy", "       01  K  PIC X(8) VALUE 'ECC-PUBL'.", []),
])
def test_other_mainframe_languages(ruleset, path, code, expected):
    assert ids(scan_text(path, code + "\n", ruleset)) == expected
