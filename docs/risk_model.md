# Risk model

All weights live in `config/risk_policy.json` and can be overridden from the dashboard or with `--risk-overrides file.json`. The score is a **remediation-priority score**, not a probability of compromise.

## Crypto findings (maximum 100)

| Factor | Default points | Basis | Notes |
|---|---|---|---|
| Algorithm risk | critical 30, high 25, medium 18, low 10 | fact | From the rule's classification |
| Operation exposure | key exchange 15, encryption 15, private key material 12, key generation 10, signature 5 | fact | Key exchange / encryption are exposed to harvest-now-decrypt-later |
| Data sensitivity | high 20, medium 10, low 3 | user_supplied / repo_declared / assumption / unknown | Longest path-prefix match; unknown production paths assume *medium*, test paths assume *low* (both configurable) |
| Current presence | production 20, uncommitted 20, at commit not in tree 12, historical-only 8, test-only 4 | fact | |
| Exposure duration | up to 10, linear to 365 days | fact or unknown | From commit timestamps |
| Reintroduction | 5 | fact or unknown | Removed earlier and added back |

## PQC findings (maximum 95)

| Factor | Default points |
|---|---|
| Implementation status | potentially outdated draft 40, needs manual verification 18, aligned 0 |
| Evidence confidence | verified 15, partial 8, synthetic 5, unknown 3 |
| Code usage | production 20, none (declared only) 6, test 4 |
| Data sensitivity | as above |

## Severity

critical >= 80, high >= 60, medium >= 40, low >= 20, otherwise info. Ties are broken by type (crypto before PQC), then file and line.

## Documented scenarios (checked by `tests/test_risk_engine.py`)

With `payments/` = high and `reports/` = low supplied by the user:

| Rank | Scenario | Score |
|---|---|---|
| 1 | Current RSA-OAEP encryption in payments, 400 days, reintroduced | 95 |
| 2 | Verified draft ML-KEM in payments code | 95 |
| 3 | Current ECDH, sensitivity unknown (assumed medium), 200 days | 75.5 |
| 4 | Historical-only RSA key generation in payments, 146 days | 67 |
| 5 | Kyber identifier, implementation unknown | 51 |
| 6 | Current ECDSA signing in low-sensitivity reports, 30 days | 46.8 |
| 7 | RSA key generation in a test fixture, 10 days | 42.3 |

This test confirms the implementation matches the documented intent. It does not prove the weights are correct for a real organisation - that calibration belongs to the security team.
