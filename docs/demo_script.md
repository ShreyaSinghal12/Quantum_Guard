# Judge demo script (about 6 minutes)

All results below come from running QuantumGuard on the generated **synthetic** demo repository. The repository's commit dates are fixed, so the numbers are reproducible. Commit hashes will differ between machines.

## Setup (before judges arrive)

```bash
pip install -r requirements.txt
python -m pytest -q                 # expect: 92 passed
streamlit run app.py
```

Open http://localhost:8501. Keep a terminal open in the project folder.

## Demo repository story

| Date | Branch | Commit | What it does |
|---|---|---|---|
| 2025-01-15 | main | Initial payments service | `payments/token_exchange.py` uses RSA key generation + RSA-OAEP; ECDSA signing in `auth/`; RSA in a test fixture; notes mentioning RSA in comments/docstrings |
| 2025-02-20 | main | Partner channel | ECDH key agreement in `partners/channel.py` |
| 2025-04-02 | main | Native ML-KEM | `native/CMakeLists.txt` pins **liboqs 0.10.1**, `kem_demo.c` uses ML-KEM-768 |
| 2025-06-10 | main | Migration | RSA removed from `payments/token_exchange.py` |
| 2025-08-05 | main | Python PQC experiment | unpinned `liboqs-python`, code uses `"Kyber768"` |
| 2025-09-12 | feature/legacy-partner-rsa | | re-adds the removed RSA key generation line |
| 2025-09-13 | feature/add-ecdsa-receipts | | new ECDSA signing |
| 2025-09-14 | feature/docs-and-tests | | comment mentioning RSA + RSA in a test fixture |
| 2025-09-15 | feature/upgrade-liboqs | | liboqs 0.10.1 -> 0.11.0 |

## Steps and expected results

**1. Build and audit (A).** Sidebar -> *Demo mode (synthetic data)* -> **Build and audit demo repository**.
Expected: yellow DEMO MODE banner; Overview shows **8 findings: 1 critical, 5 high, 2 medium; 2 historical-only; 2 PQC needing review**. Point out "Files scanned / Commits audited: 5" at the bottom - this is a live scan.

**2. Current vs history (B).** *Repository scan*: `payments/token_exchange.py` is **not** listed (RSA was removed), and `utils/notes.py` is not listed either (comments/docstrings only). Then *Historical audit*: the exposure chart shows two grey bars for `payments/token_exchange.py` (QG-RSA-001 and QG-RSA-003) from **2025-01-15 to 2025-06-10**. Expand the historical-only finding: **exposure 146 days**, first seen / removed commits, and the recommendation that says this is *potential exposure, not confirmed compromise*.

**3. PQC validation (D).** *PQC validation*:
- **ML-KEM via liboqs - Potentially outdated draft, confidence verified.** Evidence: liboqs 0.10.1 is pinned in CMake; liboqs 0.10.0 added the *Initial Public Draft* of ML-KEM and final FIPS 203 arrived in 0.11.0. Sources are linked.
- **Kyber via liboqs-python - Needs manual verification.** The wrapper is unpinned and its version does not prove which C library is loaded. The word "Kyber" alone is never marked unsafe.

**4. Risk prioritisation (E).** *Risk prioritization*: click the top row (ML-KEM, 85, critical). Show the factor bars and the table: each factor has points, maximum, **basis** (fact / repo_declared / assumption / unknown) and a reason. Open *Adjust scoring factors*, type `native/=low` in the sensitivity map, press **Apply and re-score** - the item drops and the basis changes to *user_supplied*. Point out the disclaimer: the score is a priority, not a probability.

**5. CI gate (C, F).** *CI/CD gate*: Base `main`, Head **feature/legacy-partner-rsa**, **Run CI gate**.
Expected: **BLOCKED, exit code 1**, `payments/token_exchange.py:21`, reasons "Reintroduces a pattern removed in <commit> (2025-06-10)" and "Policy blocks key_generation".
Then show the others (or run them in the terminal):

```bash
D=/tmp/quantumguard-demo-repo        # path shown in the sidebar
for b in feature/legacy-partner-rsa feature/add-ecdsa-receipts feature/docs-and-tests feature/upgrade-liboqs; do
  python -m quantumguard ci --repo $D --base main --head $b > /dev/null; echo "$b -> exit $?"; done
```

Expected: `1`, `0` (warn: signatures), `0` (warn: test fixture only; the comment is ignored), `0` (PASS: ML-KEM now aligned with FIPS 203 per liboqs 0.11.0 notes).

**6. Reports (G).** *Reports* -> download JSON and CSV. The JSON contains evidence, Git events, every score factor and the policy used.

**7. Proof it is real.** In the terminal: `python scripts/evaluate.py` - prints measured precision/recall (including the deliberate misses), 8/8 unsafe changes blocked, 0/6 safe changes blocked.

## If something goes wrong

- "Not a Git repository": point the sidebar at the repository root.
- "dubious ownership": git's safety check - the repository belongs to another user; run as the owner.
- Port in use: `streamlit run app.py --server.port 8502`.
