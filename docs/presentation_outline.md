# Presentation outline (7 slides, ~5 minutes + live demo)

1. **The problem** - Harvest-now-decrypt-later means today's RSA/ECC traffic matters. Migration has four gaps: old crypto hides in Git history, new commits reintroduce it, "PQC" code may be a pre-standard draft, and teams cannot triage hundreds of findings.

2. **QuantumGuard in one line** - Discover (present and past) -> Validate PQC evidence -> Prevent reintroduction in CI -> Prioritise with an explainable score. One shared detection engine; standard-library core.

3. **Architecture** - the diagram from `docs/architecture.md`. Emphasise: same scanner everywhere, read-only git, evidence-cited PQC rules, configurable JSON policies.

3b. **IBM Z coverage** - the same engine reads COBOL / PL/I / assembler and finds IBM ICSF calls (ECC Diffie-Hellman, PKA Encrypt, key export, classical key tokens). A COBOL change that exports a key under a public key is blocked in CI. Be clear it is source analysis, not a live z/OS connection.

4. **Live demo** - follow `docs/demo_script.md`: historical-only RSA (146-day window) -> liboqs 0.10.1 ML-KEM flagged as draft with cited evidence, "Kyber" left as manual verification -> factor breakdown and re-scoring -> the reintroduced RSA branch blocked in CI (exit 1) while the docs/test branch passes.

5. **Honesty by design** - potential exposure is never called compromise; scores are priorities, not probabilities; every factor is labelled fact / user-supplied / assumption / unknown; no evidence means "Needs manual verification".

6. **Measured results** - from `scripts/evaluate.py`: precision 0.966, recall 0.848 on a small labelled corpus (misses shown on purpose), 8/8 unsafe changes blocked, 0/6 safe changes blocked, 21/21 ranking pairs; 100 automated tests. State that the data is synthetic and small.

7. **Limitations and next steps** - regex detection (next: AST/semgrep rules, CBOM export), more PQC libraries (OpenSSL 3.5, BoringSSL, Bouncy Castle) once evidence is verified, TLS/certificate scanning, lockfile resolution, SARIF output for GitHub code scanning; IBM Z next steps: cited ICSF / Crypto Express PQC rules, importing IBM Quantum Safe tool inventories, copybook and JCL analysis.

## Likely judge questions

- *How is this different from existing tools?* It does not claim new detection; it connects history, CI and PQC evidence into one score and workflow, and is designed to sit next to inventory/SAST tools.
- *Why not flag every "Kyber"?* The name does not show the version; flagging it would be a false claim. We flag only with version evidence.
- *Can a developer bypass the gate?* Allow-lists and ignore markers exist and are visible in review; branch protection makes the check required.
