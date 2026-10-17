"""Draft-versus-standard PQC validator.

Evidence sources, in order of strength:
1. An exactly pinned dependency version matched against a cited version rule.
2. A declared version range whose lower bound already falls in an
   open-ended rule (reported with "partial" confidence).
3. API names in code (Kyber / ML-KEM / Dilithium / ML-DSA). Names alone never
   make a finding "outdated"; without version evidence they produce
   "needs_manual_verification".

Nothing here downloads packages or runs code; it only reads manifests and
source text.
"""
from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath
from typing import Iterable

from .config import QGError, load_json
from .scanner import RuleSet, code_view, file_extension, is_test_path

STATUS_LABELS = {
    "potentially_outdated_draft": "Potentially outdated draft / pre-standard - review",
    "needs_manual_verification": "Needs manual verification",
    "standard_aligned": "Aligned with final standard (per cited evidence)",
}

MANUAL_RECOMMENDATION = ("Pin an exact version, check its release notes for final FIPS 203/204 alignment, "
                         "confirm the algorithm identifier used at runtime, and run known-answer tests "
                         "(e.g. NIST ACVP test vectors) against the implementation.")


@dataclass
class Dependency:
    ecosystem: str          # pypi | npm | go | cargo | cmake | vcpkg | conan
    name: str
    spec: str
    exact_version: str | None
    file: str
    line: int
    source_hint: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class Indicator:
    algorithm: str
    indicator_id: str
    file: str
    line: int
    snippet: str
    context: str
    library: str | None = None


@dataclass
class PQCFinding:
    id: str
    library: str
    library_name: str
    algorithm: str
    standard: str
    standard_url: str
    status: str
    confidence: str          # verified | partial | unknown | synthetic
    declared_version: str
    manifest: str
    code_locations: list
    evidence: list
    sources: list
    recommendation: str
    context: str = "production"
    synthetic: bool = False

    @property
    def status_label(self) -> str:
        return STATUS_LABELS.get(self.status, self.status)

    def to_dict(self):
        d = asdict(self)
        d["status_label"] = self.status_label
        return d


@dataclass
class PQCResult:
    dependencies: list
    indicators: list
    findings: list
    manifests: list
    warnings: list = field(default_factory=list)

    def to_dict(self):
        return {"manifests": self.manifests, "warnings": self.warnings,
                "dependencies": [d.to_dict() for d in self.dependencies],
                "indicator_count": len(self.indicators),
                "findings": [f.to_dict() for f in self.findings]}


# ---------------------------------------------------------------- versions

def parse_version(text: str | None) -> tuple | None:
    if not text:
        return None
    m = re.match(r"^\s*v?(\d+(?:\.\d+){0,3})", str(text))
    if not m:
        return None
    parts = [int(p) for p in m.group(1).split(".")]
    return tuple((parts + [0, 0, 0])[:4])


def lower_bound(spec: str) -> tuple | None:
    m = re.search(r"(>=|~=|\^|~)\s*v?(\d[\w.]*)", spec or "")
    return parse_version(m.group(2)) if m else None


def _in_rule(v: tuple, rule: dict) -> bool:
    ge, lt = parse_version(rule.get("ge", "0")), parse_version(rule.get("lt"))
    return v >= ge and (lt is None or v < lt)


# ---------------------------------------------------------------- manifest parsing

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$")


def _pep508(text: str, file: str, line: int) -> Dependency | None:
    text = text.split(";")[0].split(" #")[0].strip()
    m = _REQ_LINE.match(text)
    if not m:
        return None
    name, spec = m.group(1).lower().replace("_", "-"), m.group(3).strip()
    exact = re.fullmatch(r"===?\s*v?(\d[\w.+-]*)", spec)
    return Dependency("pypi", name, spec, exact.group(1) if exact else None, file, line)


def _line_of(text: str, needle: str) -> int:
    for i, ln in enumerate(text.splitlines(), 1):
        if needle in ln:
            return i
    return 1


def parse_manifest(path: str, text: str) -> list[Dependency]:
    name = PurePosixPath(path).name
    deps: list[Dependency] = []
    if re.fullmatch(r"requirements.*\.txt", name):
        for i, raw in enumerate(text.splitlines(), 1):
            s = raw.strip()
            if not s or s.startswith(("#", "-", "git+", "http")):
                continue
            dep = _pep508(s, path, i)
            if dep:
                deps.append(dep)
    elif name == "pyproject.toml":
        data = tomllib.loads(text)
        for req in data.get("project", {}).get("dependencies", []) or []:
            dep = _pep508(req, path, _line_of(text, req))
            if dep:
                deps.append(dep)
        for pkg, val in (data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}).items():
            spec = val if isinstance(val, str) else (val or {}).get("version", "")
            exact = re.fullmatch(r"=?=?\s*(\d[\w.]*)", spec or "")
            deps.append(Dependency("pypi", pkg.lower(), spec, exact.group(1) if exact else None,
                                   path, _line_of(text, pkg)))
    elif name == "package.json":
        data = json.loads(text)
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for pkg, spec in (data.get(section) or {}).items():
                exact = re.fullmatch(r"v?(\d+\.\d+\.\d+[\w.-]*)", str(spec).strip())
                deps.append(Dependency("npm", pkg.lower(), str(spec), exact.group(1) if exact else None,
                                       path, _line_of(text, f'"{pkg}"')))
    elif name == "go.mod":
        in_block = False
        for i, raw in enumerate(text.splitlines(), 1):
            s = raw.split("//")[0].strip()
            if s.startswith("go ") and not in_block:
                ver = s.split()[1]
                deps.append(Dependency("go", "go", ver, ver, path, i, "go directive"))
            elif s.startswith("require ("):
                in_block = True
            elif in_block and s == ")":
                in_block = False
            elif in_block or s.startswith("require "):
                parts = s.replace("require ", "").split()
                if len(parts) >= 2:
                    deps.append(Dependency("go", parts[0].lower(), parts[1], parts[1].lstrip("v"), path, i))
    elif name == "Cargo.toml":
        data = tomllib.loads(text)
        for pkg, val in (data.get("dependencies", {}) or {}).items():
            spec = val if isinstance(val, str) else (val or {}).get("version", "")
            exact = re.fullmatch(r"=\s*(\d[\w.]*)", spec or "")
            deps.append(Dependency("cargo", pkg.lower(), spec, exact.group(1) if exact else None,
                                   path, _line_of(text, pkg)))
    elif name == "CMakeLists.txt" or name.endswith(".cmake"):
        for m in re.finditer(r"(FetchContent_Declare|ExternalProject_Add)\s*\(\s*(\w+)(.*?)\)", text, re.S):
            body = m.group(3)
            repo = re.search(r"GIT_REPOSITORY\s+\"?([^\s\")]+)", body)
            tag = re.search(r"GIT_TAG\s+\"?([^\s\")]+)", body)
            if not repo:
                continue
            tag_value = tag.group(1) if tag else ""
            exact = re.fullmatch(r"v?(\d+\.\d+\.\d+)", tag_value)
            deps.append(Dependency("cmake", repo.group(1).lower(), tag_value,
                                   exact.group(1) if exact else None, path,
                                   text[:m.start()].count("\n") + 1, f"CMake {m.group(1)} GIT_TAG"))
    elif name == "vcpkg.json":
        data = json.loads(text)
        overrides = {o.get("name"): o.get("version") for o in data.get("overrides", []) or []}
        for entry in data.get("dependencies", []) or []:
            pkg = entry if isinstance(entry, str) else entry.get("name", "")
            spec = "" if isinstance(entry, str) else (">=" + entry["version>="] if "version>=" in entry else "")
            exact = overrides.get(pkg)
            deps.append(Dependency("vcpkg", pkg.lower(), exact or spec, exact, path, _line_of(text, f'"{pkg}"')))
    elif name == "conanfile.txt":
        section = ""
        for i, raw in enumerate(text.splitlines(), 1):
            s = raw.split("#")[0].strip()
            if s.startswith("["):
                section = s
            elif section == "[requires]" and "/" in s:
                pkg, ver = s.split("/", 1)
                ver = ver.split("@")[0]
                exact = ver if re.fullmatch(r"\d+\.\d+\.\d+", ver) else None
                deps.append(Dependency("conan", pkg.lower(), ver, exact, path, i))
    return deps


MANIFEST_RE = re.compile(r"(requirements.*\.txt|pyproject\.toml|package\.json|go\.mod|Cargo\.toml|"
                         r"CMakeLists\.txt|.*\.cmake|vcpkg\.json|conanfile\.txt)$")


# ---------------------------------------------------------------- validator

class PQCValidator:
    def __init__(self, rules: dict, ruleset: RuleSet):
        self.rules = rules
        self.ruleset = ruleset
        self.standards = rules.get("standards", {})
        self.algorithms = rules.get("algorithms", {})
        self.libraries = {lib["id"]: lib for lib in rules.get("libraries", [])}
        self.indicators = []
        for ind in rules.get("api_indicators", []):
            try:
                self.indicators.append((ind, re.compile(ind["pattern"])))
            except re.error as exc:
                raise QGError(f"PQC indicator {ind.get('id')} has an invalid regex: {exc}") from exc

    @classmethod
    def load(cls, config_dir=None, ruleset: RuleSet | None = None):
        return cls(load_json("pqc_library_rules.json", config_dir), ruleset or RuleSet.load(config_dir))

    # -- discovery
    def _match_library(self, dep: Dependency) -> dict | None:
        for lib in self.libraries.values():
            match = lib.get("match", {})
            if dep.ecosystem == "cmake":
                if any(r in dep.name for r in match.get("cmake_repo", [])):
                    return lib
            elif dep.name in [n.lower() for n in match.get(dep.ecosystem, [])]:
                return lib
        return None

    def _find_indicators(self, path: str, text: str) -> list[Indicator]:
        ext = file_extension(path)
        if ext not in ("py", "pyi", "go", "c", "h", "cc", "cpp", "hpp", "rs", "java", "kt", "js", "ts",
                       "mjs", "cjs", "jsx", "tsx", "cs", "swift", "rb", "php"):
            return []
        lines = text.splitlines()
        code = code_view(lines, ext)
        ctx = "test" if is_test_path(path, self.ruleset.settings) else "production"
        marker = self.ruleset.settings.suppression_marker
        found = []
        for i, (orig, c) in enumerate(zip(lines, code), 1):
            if not c.strip() or marker in orig.lower():
                continue
            for ind, rx in self.indicators:
                if ind.get("extensions") and ext not in ind["extensions"]:
                    continue
                if rx.search(c):
                    found.append(Indicator(ind["algorithm"], ind["id"], path, i, orig.strip()[:200],
                                           ctx, ind.get("library")))
        return found

    # -- evaluation helpers
    def _standard(self, algorithm: str) -> tuple[str, str]:
        std = self.algorithms.get(algorithm, {}).get("standard", "")
        return std, self.standards.get(std, {}).get("url", "")

    def _finding(self, lib_id, lib_name, algorithm, status, confidence, version, manifest,
                 locations, evidence, sources, recommendation, synthetic=False) -> PQCFinding:
        std, url = self._standard(algorithm)
        contexts = {loc["context"] for loc in locations}
        context = "test" if contexts == {"test"} else "production"
        key = f"{lib_id}|{algorithm}|{manifest}|{','.join(sorted(l['file'] for l in locations))}"
        return PQCFinding(
            id="PQC-" + hashlib.sha1(key.encode()).hexdigest()[:10], library=lib_id, library_name=lib_name,
            algorithm=algorithm, standard=std, standard_url=url, status=status, confidence=confidence,
            declared_version=version, manifest=manifest, code_locations=locations, evidence=evidence,
            sources=sources, recommendation=recommendation, context=context, synthetic=synthetic)

    def _recommend(self, lib: dict, algorithm: str, status: str) -> str:
        if status == "standard_aligned":
            return "No upgrade indicated by the cited evidence; keep the version pinned and monitor release notes."
        if status == "potentially_outdated_draft":
            target = lib.get("upgrade", {}).get(algorithm, "")
            std = self._standard(algorithm)[0]
            if algorithm in ("Kyber", "Dilithium"):
                final = "ML-KEM" if algorithm == "Kyber" else "ML-DSA"
                return (f"Switch from the pre-standard {algorithm} algorithm to {final} ({std}) and coordinate "
                        "with peers - the two are not interoperable. Re-run interoperability tests afterwards.")
            return (f"Upgrade {lib['name']} to {target} or later, then re-run interoperability and known-answer "
                    f"tests. Do not assume keys or ciphertexts from a draft implementation interoperate with "
                    f"{std} peers.")
        return MANUAL_RECOMMENDATION

    def _evaluate_dependency(self, dep: Dependency, lib: dict, observed: dict) -> list[PQCFinding]:
        rules = lib.get("version_rules", [])
        rule_algos = sorted({r["algorithm"] for r in rules})
        algos = [a for a in observed if a in rule_algos] or [a for a in observed]
        usage_seen = bool(algos)
        if not algos:
            algos = [a for a in ("ML-KEM", "ML-DSA") if a in rule_algos] or ["ML-KEM"]
        manifest = f"{dep.file}:{dep.line}"
        version_text = dep.exact_version or dep.spec or "unspecified"
        synthetic = bool(lib.get("synthetic"))
        out = []
        for algo in algos:
            locations = observed.get(algo, [])
            evidence = [f"Dependency {dep.name} declared in {manifest} ({dep.source_hint or dep.ecosystem}): "
                        f"{version_text}."]
            if not usage_seen:
                evidence.append("No direct API usage attributed to this dependency was found in scanned code.")
            elif locations:
                evidence.append(f"{algo} API usage found in {len(locations)} location(s), "
                                f"e.g. {locations[0]['file']}:{locations[0]['line']}.")
            algo_note = self.algorithms.get(algo, {}).get("note")
            if algo_note:
                evidence.append(algo_note)
            algo_rules = [r for r in rules if r["algorithm"] == algo]
            status, confidence = "needs_manual_verification", "unknown"
            v = parse_version(dep.exact_version)
            if not algo_rules:
                evidence.append(lib.get("manual_note") or
                                f"No verified version rule for {algo} in {lib['name']}.")
            elif v is not None:
                rule = next((r for r in algo_rules if _in_rule(v, r)), None)
                if rule:
                    status = rule["status"]
                    confidence = "verified" if usage_seen else "partial"
                    evidence.append(rule["evidence"])
                else:
                    evidence.append(f"Version {dep.exact_version} is outside every documented rule for {algo}.")
            else:
                lb = lower_bound(dep.spec)
                rule = next((r for r in algo_rules if lb and _in_rule(lb, r)), None) if lb else None
                if rule and "lt" not in rule and not re.search(r"<", dep.spec):
                    status, confidence = rule["status"], "partial"
                    evidence.append(rule["evidence"])
                    evidence.append("Declared as a range whose lower bound already satisfies this rule; "
                                    "confirm the resolved version in the lockfile.")
                else:
                    evidence.append("Exact version could not be established from the manifest "
                                    "(unpinned, range, branch or commit).")
            if synthetic:
                confidence = "synthetic"
                evidence.insert(0, "SYNTHETIC library used only for testing - not a real package.")
            out.append(self._finding(lib["id"], lib["name"], algo, status, confidence, version_text, manifest,
                                     locations, evidence, lib.get("sources", []),
                                     self._recommend(lib, algo, status), synthetic))
        return out

    # -- main entry
    def validate(self, files: Iterable[tuple[str, str]]) -> PQCResult:
        deps, indicators, manifests, warnings = [], [], [], []
        for path, text in files:
            if MANIFEST_RE.search(PurePosixPath(path).name):
                try:
                    found = parse_manifest(path, text)
                    manifests.append(path)
                    deps.extend(found)
                except (ValueError, tomllib.TOMLDecodeError) as exc:
                    warnings.append(f"Could not parse {path}: {exc}")
            indicators.extend(self._find_indicators(path, text))

        matched = [(d, self._match_library(d)) for d in deps]
        matched = [(d, lib) for d, lib in matched if lib]
        attributed: dict[int, dict] = {i: {} for i in range(len(matched))}
        loose: list[Indicator] = []
        direct: dict[str, list[Indicator]] = {}

        for ind in indicators:
            if ind.library:
                direct.setdefault(ind.library, []).append(ind)
                continue
            ext = file_extension(ind.file)
            best, depth = None, -1
            for idx, (dep, lib) in enumerate(matched):
                base = str(PurePosixPath(dep.file).parent)
                base = "" if base == "." else base + "/"
                if ind.file.startswith(base) and ext in lib.get("languages", []) and len(base) > depth:
                    best, depth = idx, len(base)
            loc = {"file": ind.file, "line": ind.line, "snippet": ind.snippet, "context": ind.context}
            if best is None:
                loose.append(ind)
            else:
                attributed[best].setdefault(ind.algorithm, []).append(loc)

        findings: list[PQCFinding] = []
        for idx, (dep, lib) in enumerate(matched):
            findings.extend(self._evaluate_dependency(dep, lib, attributed[idx]))

        for lib_id, inds in direct.items():
            lib = self.libraries.get(lib_id, {})
            fixed = lib.get("indicator_status", {})
            by_algo: dict[str, list] = {}
            for ind in inds:
                by_algo.setdefault(ind.algorithm, []).append(
                    {"file": ind.file, "line": ind.line, "snippet": ind.snippet, "context": ind.context})
            for algo, locs in by_algo.items():
                status = fixed.get("status", "needs_manual_verification")
                findings.append(self._finding(
                    lib_id, lib.get("name", lib_id), algo, status, fixed.get("confidence", "unknown"),
                    "standard library", "", locs,
                    [f"Import found at {locs[0]['file']}:{locs[0]['line']}.", fixed.get("evidence", "")],
                    lib.get("sources", []), self._recommend(lib, algo, status)))

        grouped: dict[str, list] = {}
        for ind in loose:
            grouped.setdefault(ind.algorithm, []).append(
                {"file": ind.file, "line": ind.line, "snippet": ind.snippet, "context": ind.context})
        for algo, locs in grouped.items():
            info = self.algorithms.get(algo, {})
            evidence = [f"{algo} identifier found in {len(locs)} location(s), e.g. "
                        f"{locs[0]['file']}:{locs[0]['line']}.",
                        "No dependency manifest entry could be linked to this code, so the implementation "
                        "and its version are unknown."]
            if info.get("note"):
                evidence.append(info["note"])
            findings.append(self._finding("unknown", "Unidentified implementation", algo,
                                          "needs_manual_verification", "unknown", "unknown", "", locs,
                                          evidence, [], MANUAL_RECOMMENDATION))

        order = {"potentially_outdated_draft": 0, "needs_manual_verification": 1, "standard_aligned": 2}
        findings.sort(key=lambda f: (order.get(f.status, 3), f.library, f.algorithm))
        return PQCResult(dependencies=deps, indicators=indicators, findings=findings,
                         manifests=manifests, warnings=warnings)
