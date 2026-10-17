# Limitations

QuantumGuard is a hackathon prototype. It does not provide production-grade coverage or any form of cryptographic certification.

## Detection (false negatives)

- **Pattern matching, not program analysis.** Import aliases (`import rsa as r`), dynamic calls (`getattr`), algorithm names held in variables (`KeyPairGenerator.getInstance(algo)`), wrappers and configuration-driven crypto are missed. These cases are kept in the evaluation corpus and show up as false negatives.
- **Limited rule set.** 21 rules covering common Python, Java/Kotlin, Go and Node.js APIs, PEM headers and IBM ICSF calls in COBOL / PL/I / assembler. No rules yet for TLS/SSH configuration files, certificates, C/OpenSSL calls, .NET, Rust crates, Node `createECDH`, or binary artefacts.
- **Multi-line calls** are detected only if the identifying part (for example `rsa.generate_private_key(`) is on one line.
- Files over 1 MB, binaries, symlinks, and excluded folders (`node_modules`, virtual environments, `vendor`, `build`, ...) are skipped.

## IBM Z / mainframe

- Static source scanning only. No connection to z/OS, ICSF, Crypto Express adapters, SMF records or IBM Quantum Safe tools; no runtime inventory of which keys actually exist.
- Dynamic calls (`CALL WS-SERVICE-NAME`), copybook expansion, JCL and load modules are not analysed (one dynamic call is a deliberate false negative in the corpus).
- PKA Key Generate and Digital Signature Generate are algorithm-agnostic services: the finding says the key type must be verified, because newer ICSF levels can also generate quantum-safe keys.
- No PQC version rules for ICSF / Crypto Express levels yet; those would need cited IBM documentation.

## Detection (false positives)

- String literals are kept (needed for `getInstance("RSA")`), so text such as `"call ec.ECDH()"` inside a string is reported. This appears as the one false positive in the corpus.
- Comment detection is lexical. Unusual syntax (Rust lifetimes, PHP `#` comments, heredocs) can confuse it.
- Test-path detection uses folder and file-name conventions.

## Git history

- Only the **first-parent** history of the audited ref is analysed. Work that existed only on side branches and was never merged is not seen.
- Renames are treated as delete + add, so a moved file starts a new fingerprint.
- Exposure windows use commit timestamps, which authors can set arbitrarily, and they describe when code existed in the repository - not when it was deployed or executed.
- **Presence of vulnerable code does not mean data was captured, keys were leaked, or anything was decrypted.** Historical findings are potential exposure only.
- Very large histories are bounded by `max_commits`; when truncated, the state before the window is seeded and flagged.
- Rewritten history (force pushes) cannot be recovered.

## PQC validation

- The rules database covers liboqs (C), the liboqs-python wrapper (always manual verification) and Go's `crypto/mlkem`. Everything else becomes "Needs manual verification".
- Lockfiles are not resolved; ranges get at most "partial" confidence.
- Code identifiers are linked to the nearest manifest of a matching language, which can be wrong in unusual layouts.
- Release notes can be incomplete; rules record what the cited source says and should be re-reviewed (`last_reviewed` in the rules file).
- No known-answer testing is performed; the tool recommends it.

## Risk score

- The score is a configurable ranking aid, not a probability of compromise or a measure of business impact.
- Weights are judgement calls documented in `config/risk_policy.json`. The ranking test checks consistency with the documented scenarios; it does not prove the weights are "right".
- Data sensitivity is unknown unless supplied; the default assumption is visible in every explanation.
- `.quantumguard.json` is controlled by the scanned repository, so a pull request could change declared sensitivity. CI blocking does not depend on the score.

## CI gate

- Only added lines are gated; pre-existing findings are reported by the audit, not blocked.
- The reintroduction check needs full history (`fetch-depth: 0`).
- An allow-list or `quantumguard: ignore` marker can suppress findings; review those in code review.

## Evaluation

- The labelled corpus (33 positives) and the CI scenarios (14 changes) are small and synthetic and were written by the same team that wrote the rules. Real-world precision and recall will be lower.
