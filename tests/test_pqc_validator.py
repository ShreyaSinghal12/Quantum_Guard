import copy

import pytest

from quantumguard.config import load_json
from quantumguard.pqc_validator import PQCValidator, parse_manifest, parse_version


def cmake(tag):
    return ("include(FetchContent)\nFetchContent_Declare(\n  liboqs\n"
            "  GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs.git\n"
            f"  GIT_TAG {tag}\n)\n")


C_MLKEM = '#include <oqs/oqs.h>\nOQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);\n'
C_MLDSA = 'OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);\n'


@pytest.fixture(scope="module")
def validator(ruleset):
    return PQCValidator.load(ruleset=ruleset)


def one(result, algorithm=None):
    found = [f for f in result.findings if algorithm is None or f.algorithm == algorithm]
    assert len(found) == 1, [f.to_dict() for f in result.findings]
    return found[0]


@pytest.mark.parametrize("tag,algo,code,status,confidence", [
    ("0.10.1", "ML-KEM", C_MLKEM, "potentially_outdated_draft", "verified"),
    ("v0.11.0", "ML-KEM", C_MLKEM, "standard_aligned", "verified"),
    ("0.11.0", "ML-DSA", C_MLDSA, "potentially_outdated_draft", "verified"),
    ("0.12.0", "ML-DSA", C_MLDSA, "standard_aligned", "verified"),
])
def test_liboqs_exact_versions(validator, tag, algo, code, status, confidence):
    f = one(validator.validate([("native/CMakeLists.txt", cmake(tag)), ("native/kem.c", code)]), algo)
    assert (f.status, f.confidence) == (status, confidence)
    assert f.sources and f.standard in ("FIPS 203", "FIPS 204") and f.standard_url.startswith("https://csrc.nist.gov")
    assert f.code_locations[0]["file"] == "native/kem.c"


def test_branch_tag_needs_manual_verification(validator):
    f = one(validator.validate([("CMakeLists.txt", cmake("main")), ("kem.c", C_MLKEM)]))
    assert f.status == "needs_manual_verification" and f.confidence == "unknown"


def test_dependency_without_usage_is_partial(validator):
    res = validator.validate([("CMakeLists.txt", cmake("0.10.1"))])
    assert {f.algorithm for f in res.findings} == {"ML-KEM", "ML-DSA"}
    assert all(f.confidence == "partial" for f in res.findings)


def test_kyber_name_alone_is_not_flagged_unsafe(validator):
    res = validator.validate([("app/kem.py", 'kem = oqs.KeyEncapsulation("Kyber768")\n')])
    f = one(res)
    assert f.algorithm == "Kyber" and f.status == "needs_manual_verification"
    assert any("not interoperable" in e for e in f.evidence)


def test_kyber_in_comment_is_ignored(validator):
    assert validator.validate([("a.py", "# migrated away from Kyber768\nx = 1\n")]).findings == []


def test_unpinned_python_wrapper_needs_manual_verification(validator):
    res = validator.validate([("requirements.txt", "liboqs-python\nrequests==2.0\n"),
                              ("pqc/client.py", 'kem = oqs.KeyEncapsulation("Kyber768")\n')])
    f = one(res)
    assert f.library == "liboqs-python" and f.algorithm == "Kyber"
    assert f.status == "needs_manual_verification"
    assert any("oqs_version" in e for e in f.evidence)


def test_go_stdlib_mlkem_is_aligned(validator):
    code = 'package main\nimport "crypto/mlkem"\nfunc f() { k, _ := mlkem.GenerateKey768(); _ = k }\n'
    f = one(validator.validate([("go.mod", "module x\n\ngo 1.24\n"), ("main.go", code)]))
    assert f.library == "go-stdlib-mlkem" and f.status == "standard_aligned" and f.confidence == "verified"


def test_python_indicator_not_attributed_to_c_library(validator):
    res = validator.validate([("native/CMakeLists.txt", cmake("0.10.1")), ("native/kem.c", C_MLKEM),
                              ("app/client.py", 'k = "Kyber768"\n')])
    libs = {(f.library, f.algorithm) for f in res.findings}
    assert ("liboqs", "ML-KEM") in libs and ("unknown", "Kyber") in libs
    assert ("liboqs", "Kyber") not in libs


def test_synthetic_library_is_labelled(ruleset):
    rules = copy.deepcopy(load_json("pqc_library_rules.json"))
    rules["libraries"].append({
        "id": "examplepqc", "name": "examplepqc (SYNTHETIC)", "synthetic": True, "languages": ["py"],
        "match": {"pypi": ["examplepqc"]},
        "version_rules": [{"algorithm": "ML-KEM", "lt": "2.0.0", "status": "potentially_outdated_draft",
                           "evidence": "SYNTHETIC rule for tests."}],
        "sources": [{"title": "synthetic", "url": "about:blank"}]})
    v = PQCValidator(rules, ruleset)
    f = one(v.validate([("requirements.txt", "examplepqc==1.4.0\n"), ("a.py", 'x = "ML-KEM-768"\n')]))
    assert f.synthetic and f.confidence == "synthetic" and f.status == "potentially_outdated_draft"
    assert f.evidence[0].startswith("SYNTHETIC")


def test_manifest_parsers():
    assert parse_manifest("requirements.txt", "liboqs-python==0.12.0 ; python_version>'3'\n")[0].exact_version == "0.12.0"
    assert parse_manifest("requirements.txt", "liboqs-python>=0.10\n")[0].exact_version is None
    pj = parse_manifest("package.json", '{"dependencies": {"a": "1.2.3", "b": "^1.0.0"}}')
    assert [d.exact_version for d in pj] == ["1.2.3", None]
    gm = parse_manifest("go.mod", "module x\ngo 1.24\nrequire (\n  github.com/a/b v1.2.3\n)\n")
    assert [(d.name, d.exact_version) for d in gm] == [("go", "1.24"), ("github.com/a/b", "1.2.3")]
    cn = parse_manifest("conanfile.txt", "[requires]\nliboqs/0.10.1\n")
    assert cn[0].exact_version == "0.10.1"
    vc = parse_manifest("vcpkg.json", '{"dependencies": [{"name": "liboqs", "version>=": "0.11.0"}]}')
    assert vc[0].spec == ">=0.11.0" and vc[0].exact_version is None
    pp = parse_manifest("pyproject.toml", '[project]\nname="x"\ndependencies=["liboqs-python==0.10.0"]\n')
    assert pp[0].exact_version == "0.10.0"


def test_vcpkg_range_lower_bound_gives_partial_confidence(validator):
    res = validator.validate([("vcpkg.json", '{"dependencies": [{"name": "liboqs", "version>=": "0.11.0"}]}'),
                              ("kem.c", C_MLKEM)])
    f = one(res)
    assert (f.status, f.confidence) == ("standard_aligned", "partial")


def test_bad_manifest_is_a_warning_not_a_crash(validator):
    res = validator.validate([("package.json", "{not json")])
    assert res.findings == [] and res.warnings


def test_parse_version():
    assert parse_version("v0.10.1") == (0, 10, 1, 0)
    assert parse_version("main") is None
