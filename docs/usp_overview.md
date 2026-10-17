# The four USPs in short

## 1. Historical cryptography auditor
Scans every changed file at every first-parent commit with the same engine as the live scanner. Each finding gets a fingerprint (rule + file + normalised code), so QuantumGuard can say *when* a pattern appeared, *when* it was removed, whether it *came back*, and how long it existed (exposure window). Findings are classed as current, test-only or **historical-only**. Historical findings are labelled potential exposure: the tool never claims data was captured or decrypted.

## 2. Quantum-safe CI/CD guard
A GitHub Actions job that scans only the lines a pull request adds. Policy (`config/ci_policy.json`) decides block versus warn per operation or rule; test paths are downgraded; comments, docstrings and suppressed lines are ignored. Because it reads the base branch's history, a vulnerable pattern that was removed earlier and is added back is blocked as a **reintroduction**, even in another file. Exit code 1 fails the check; annotations point to the exact line.

## 3. Draft-versus-standard PQC validator
Reads dependency manifests and PQC identifiers, then applies version rules that each cite a source. Example: liboqs 0.10.x shipped the *Initial Public Draft* of ML-KEM; 0.11.0 updated it to final FIPS 203 (per the liboqs release notes). An exact pin plus observed usage gives **verified** confidence; ranges give **partial**; anything else gives **Needs manual verification**. The word "Kyber" alone is never treated as unsafe.

## 4. Explainable risk-based prioritisation
A 0-100 priority built from configurable factors. Each factor shows points, maximum, a reason, and whether the input is a **fact**, **user-supplied**, **repository-declared**, an **assumption** or **unknown**. Users change weights and sensitivity in the dashboard without touching code. A test checks that documented higher-risk scenarios rank above lower-risk ones.

## Mainframe coverage
The same scanner understands COBOL, PL/I and assembler comments and detects IBM ICSF calls (CSNDEDH, CSNDPKE, CSNDSYX, CSNDPKG, CSNDDSG and classical key-token keywords), so mainframe source in Git gets the same history audit, CI gate and scoring.

## What connects them
History tells the CI gate what was removed. PQC evidence, history (exposure, reintroduction) and sensitivity all flow into one score. One dashboard and one report show the chain from evidence to recommended action.

## How it complements existing tools
Cryptographic inventory / CBOM tools, SAST rules, dependency scanners and secret scanners already cover parts of this. QuantumGuard is a small, transparent glue layer: it can be run alongside them, its rules are plain JSON, and its outputs (JSON/CSV) can feed an existing inventory or ticketing process.
