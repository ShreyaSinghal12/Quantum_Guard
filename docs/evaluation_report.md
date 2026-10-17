# QuantumGuard evaluation report

Generated 2026-10-17 12:19 UTC by `python scripts/evaluate.py` (QuantumGuard 0.1.0). All values are measured by running the code; the dataset is small and synthetic, so treat these as prototype sanity checks, not coverage claims.

## 1. Detection on the labelled corpus (`tests/fixtures/labeled_corpus`)

| Metric | Value |
|---|---|
| Labelled positives | 33 |
| Predicted findings | 29 |
| True positives | 28 |
| False positives | 1 |
| False negatives | 5 |
| Precision | 0.966 |
| Recall | 0.848 |

False positives:

- `py_negative.py:8` QG-ECDH-001

False negatives (known limitations, kept in the corpus on purpose):

- `JavaCases.java:9` QG-RSA-004
- `MFCASES.cbl:12` QG-ICSF-001
- `js_cases.js:6` QG-ECDH-JS
- `py_hard.py:2` QG-RSA-001
- `py_hard.py:3` QG-RSA-001

## 2. CI gate on synthetic changes

- Deliberately unsafe changes blocked: **8 / 8**
- Safe changes wrongly blocked: **0 / 6**
- Decisions matching the documented expectation: 14 / 14

| Scenario | Unsafe | Expected | Actual | Exit |
|---|---|---|---|---|
| add RSA key generation | yes | block | block | 1 |
| add RSA-OAEP encryption | yes | block | block | 1 |
| add ECDH key agreement | yes | block | block | 1 |
| add finite-field DH | yes | block | block | 1 |
| commit a classical private key | yes | block | block | 1 |
| add 1024-bit RSA (Go) | yes | block | block | 1 |
| reintroduce removed ECDSA signing | yes | block | block | 1 |
| add RSA in Java | yes | block | block | 1 |
| new ECDSA signing (policy: warn) | no | warn | warn | 0 |
| comment mentioning RSA | no | pass | pass | 0 |
| docstring mentioning ECDH | no | pass | pass | 0 |
| RSA in a test fixture | no | warn | warn | 0 |
| suppressed line | no | pass | pass | 0 |
| unrelated code | no | pass | pass | 0 |

## 3. Demo repository CI branches

| Branch | Expected | Actual | Exit |
|---|---|---|---|
| `feature/legacy-partner-rsa` | BLOCKED | BLOCKED | 1 |
| `feature/add-ecdsa-receipts` | PASSED WITH WARNINGS | PASSED WITH WARNINGS | 0 |
| `feature/docs-and-tests` | PASSED WITH WARNINGS | PASSED WITH WARNINGS | 0 |
| `feature/upgrade-liboqs` | PASSED | PASSED | 0 |
| `feature/mainframe-key-export` | BLOCKED | BLOCKED | 1 |

## 4. Risk ranking of documented scenarios

Correctly ordered pairs: **21 / 21**

| Rank | Scenario | Score |
|---|---|---|
| 1 | S1_current_rsa_encryption_payments_reintroduced | 95.0 |
| 2 | S2_verified_draft_mlkem_payments | 95.0 |
| 3 | S3_current_ecdh_unknown_sensitivity | 75.5 |
| 4 | S4_historical_only_rsa_keygen_payments | 67.0 |
| 5 | S5_unknown_kyber_usage | 51.0 |
| 6 | S6_current_ecdsa_signature_low_sensitivity | 46.8 |
| 7 | S7_test_only_rsa_keygen | 42.3 |
