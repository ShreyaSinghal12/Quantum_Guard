# Test report

Generated 2026-10-17 12:19 UTC by `python scripts/make_test_report.py` on Python 3.13.16 (Linux).

**Result:** `100 passed in 5.59s` (exit code 0)

## Coverage of the required scenarios

| Requirement | Test file |
|---|---|
| Current-code findings, comments/docstrings, test paths, exclusions, invalid paths | tests/test_scanner.py |
| Historical-only findings, removal, reintroduction, truncation, Git errors | tests/test_git_history.py |
| PQC validation: verified, partial, synthetic, unknown evidence | tests/test_pqc_validator.py |
| Risk scoring, explanations, ranking scenarios, overrides | tests/test_risk_engine.py |
| CI warn/block policies, reintroduction, worktree mode, exit codes | tests/test_policy_engine.py |
| JSON / CSV / Markdown export | tests/test_report.py |
| Full demo scenario A-G and CLI | tests/test_end_to_end.py |
| Dashboard pages, demo mode, CI run, re-scoring (headless) | tests/test_dashboard.py |

## Full pytest output

```
============================= test session starts ==============================
collecting ... collected 100 items

tests/test_dashboard.py::test_empty_state_renders_on_every_page PASSED   [  1%]
tests/test_dashboard.py::test_invalid_path_shows_error PASSED            [  2%]
tests/test_dashboard.py::test_demo_mode_end_to_end PASSED                [  3%]
tests/test_end_to_end.py::test_A_B_historical_finding_still_reported_after_removal PASSED [  4%]
tests/test_end_to_end.py::test_false_positive_controls_in_demo PASSED    [  5%]
tests/test_end_to_end.py::test_current_findings PASSED                   [  6%]
tests/test_end_to_end.py::test_C_ci_gate_outcomes_match_plan PASSED      [  7%]
tests/test_end_to_end.py::test_mainframe_icsf_findings PASSED            [  8%]
tests/test_end_to_end.py::test_D_pqc_verified_and_manual_cases PASSED    [  9%]
tests/test_end_to_end.py::test_E_scores_explained_and_ordered PASSED     [ 10%]
tests/test_end_to_end.py::test_feature_branch_history_shows_reintroduction PASSED [ 11%]
tests/test_end_to_end.py::test_G_exports PASSED                          [ 12%]
tests/test_end_to_end.py::test_non_git_directory_degrades_gracefully PASSED [ 13%]
tests/test_end_to_end.py::test_demo_builder_refuses_foreign_directory PASSED [ 14%]
tests/test_end_to_end.py::test_cli_exit_codes PASSED                     [ 15%]
tests/test_git_history.py::test_introduce_remove_reintroduce PASSED      [ 16%]
tests/test_git_history.py::test_historical_only_and_exposure PASSED      [ 17%]
tests/test_git_history.py::test_whitespace_edit_and_line_move_do_not_create_events PASSED [ 18%]
tests/test_git_history.py::test_file_deletion_counts_as_removal PASSED   [ 19%]
tests/test_git_history.py::test_comment_only_history_is_ignored PASSED   [ 20%]
tests/test_git_history.py::test_truncated_window_is_seeded PASSED        [ 21%]
tests/test_git_history.py::test_history_of_other_ref PASSED              [ 22%]
tests/test_git_history.py::test_errors PASSED                            [ 23%]
tests/test_git_history.py::test_empty_repository PASSED                  [ 24%]
tests/test_policy_engine.py::test_blocks_added_rsa_only PASSED           [ 25%]
tests/test_policy_engine.py::test_comment_only_change_passes PASSED      [ 26%]
tests/test_policy_engine.py::test_test_fixture_warns_not_blocks PASSED   [ 27%]
tests/test_policy_engine.py::test_test_paths_ignore_policy PASSED        [ 28%]
tests/test_policy_engine.py::test_signature_warns PASSED                 [ 29%]
tests/test_policy_engine.py::test_fail_on_warn_and_warn_mode PASSED      [ 30%]
tests/test_policy_engine.py::test_allow_rules PASSED                     [ 31%]
tests/test_policy_engine.py::test_reintroduction_detected_and_signature_policy_overridden PASSED [ 32%]
tests/test_policy_engine.py::test_pqc_manifest_change_is_reported PASSED [ 33%]
tests/test_policy_engine.py::test_worktree_mode_includes_untracked_files PASSED [ 34%]
tests/test_policy_engine.py::test_errors PASSED                          [ 35%]
tests/test_policy_engine.py::test_parse_added_lines PASSED               [ 36%]
tests/test_policy_engine.py::test_annotation_and_summary_escaping PASSED [ 37%]
tests/test_pqc_validator.py::test_liboqs_exact_versions[0.10.1-ML-KEM-#include <oqs/oqs.h>\nOQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);\n-potentially_outdated_draft-verified] PASSED [ 38%]
tests/test_pqc_validator.py::test_liboqs_exact_versions[v0.11.0-ML-KEM-#include <oqs/oqs.h>\nOQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);\n-standard_aligned-verified] PASSED [ 39%]
tests/test_pqc_validator.py::test_liboqs_exact_versions[0.11.0-ML-DSA-OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);\n-potentially_outdated_draft-verified] PASSED [ 40%]
tests/test_pqc_validator.py::test_liboqs_exact_versions[0.12.0-ML-DSA-OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);\n-standard_aligned-verified] PASSED [ 41%]
tests/test_pqc_validator.py::test_branch_tag_needs_manual_verification PASSED [ 42%]
tests/test_pqc_validator.py::test_dependency_without_usage_is_partial PASSED [ 43%]
tests/test_pqc_validator.py::test_kyber_name_alone_is_not_flagged_unsafe PASSED [ 44%]
tests/test_pqc_validator.py::test_kyber_in_comment_is_ignored PASSED     [ 45%]
tests/test_pqc_validator.py::test_unpinned_python_wrapper_needs_manual_verification PASSED [ 46%]
tests/test_pqc_validator.py::test_go_stdlib_mlkem_is_aligned PASSED      [ 47%]
tests/test_pqc_validator.py::test_python_indicator_not_attributed_to_c_library PASSED [ 48%]
tests/test_pqc_validator.py::test_synthetic_library_is_labelled PASSED   [ 49%]
tests/test_pqc_validator.py::test_manifest_parsers PASSED                [ 50%]
tests/test_pqc_validator.py::test_vcpkg_range_lower_bound_gives_partial_confidence PASSED [ 51%]
tests/test_pqc_validator.py::test_bad_manifest_is_a_warning_not_a_crash PASSED [ 52%]
tests/test_pqc_validator.py::test_parse_version PASSED                   [ 53%]
tests/test_report.py::test_csv_roundtrip_and_formula_neutralised PASSED  [ 54%]
tests/test_report.py::test_json_and_markdown PASSED                      [ 55%]
tests/test_risk_engine.py::test_documented_scenarios_rank_in_expected_order PASSED [ 56%]
tests/test_risk_engine.py::test_factors_sum_to_score_and_are_explained PASSED [ 57%]
tests/test_risk_engine.py::test_sensitivity_basis_labels PASSED          [ 58%]
tests/test_risk_engine.py::test_unknown_history_is_marked_unknown PASSED [ 59%]
tests/test_risk_engine.py::test_policy_override_changes_score_without_code_changes PASSED [ 60%]
tests/test_risk_engine.py::test_score_capped_at_100 PASSED               [ 61%]
tests/test_risk_engine.py::test_severity_thresholds PASSED               [ 62%]
tests/test_risk_engine.py::test_disclaimer_present PASSED                [ 63%]
tests/test_scanner.py::test_detects_each_rule[a.py-key = rsa.generate_private_key(public_exponent=65537, key_size=2048)-QG-RSA-001] PASSED [ 64%]
tests/test_scanner.py::test_detects_each_rule[a.py-k = RSA.generate(2048)-QG-RSA-002] PASSED [ 65%]
tests/test_scanner.py::test_detects_each_rule[a.py-c = PKCS1_OAEP.new(pub)-QG-RSA-003] PASSED [ 66%]
tests/test_scanner.py::test_detects_each_rule[A.java-KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");-QG-RSA-004] PASSED [ 67%]
tests/test_scanner.py::test_detects_each_rule[a.js-const { publicKey } = crypto.generateKeyPairSync('rsa', {});-QG-RSA-005] PASSED [ 68%]
tests/test_scanner.py::test_detects_each_rule[a.go-k, err := rsa.GenerateKey(rand.Reader, 2048)-QG-RSA-006] PASSED [ 69%]
tests/test_scanner.py::test_detects_each_rule[a.py-priv = ec.generate_private_key(ec.SECP256R1())-QG-EC-001] PASSED [ 70%]
tests/test_scanner.py::test_detects_each_rule[a.py-shared = priv.exchange(ec.ECDH(), peer)-QG-ECDH-001] PASSED [ 71%]
tests/test_scanner.py::test_detects_each_rule[a.go-curve := ecdh.P256()-QG-ECDH-002] PASSED [ 72%]
tests/test_scanner.py::test_detects_each_rule[a.py-sig = priv.sign(data, ec.ECDSA(hashes.SHA256()))-QG-ECDSA-001] PASSED [ 73%]
tests/test_scanner.py::test_detects_each_rule[a.py-params = dh.generate_parameters(generator=2, key_size=2048)-QG-DH-001] PASSED [ 74%]
tests/test_scanner.py::test_detects_each_rule[a.py-k = Ed25519PrivateKey.generate()-QG-EDDSA-001] PASSED [ 75%]
tests/test_scanner.py::test_detects_each_rule[a.pem------BEGIN RSA PRIVATE KEY------QG-KEY-001] PASSED [ 76%]
tests/test_scanner.py::test_weak_key_size_reported_in_addition PASSED    [ 77%]
tests/test_scanner.py::test_comments_docstrings_and_suppression_are_ignored PASSED [ 78%]
tests/test_scanner.py::test_c_style_comments_ignored PASSED              [ 79%]
tests/test_scanner.py::test_hash_inside_string_is_not_a_comment PASSED   [ 80%]
tests/test_scanner.py::test_similar_names_do_not_match PASSED            [ 81%]
tests/test_scanner.py::test_test_context_and_fingerprints PASSED         [ 82%]
tests/test_scanner.py::test_is_test_path PASSED                          [ 83%]
tests/test_scanner.py::test_repository_scan_skips_excluded_binary_and_large PASSED [ 84%]
tests/test_scanner.py::test_symlinks_not_followed PASSED                 [ 85%]
tests/test_scanner.py::test_invalid_paths[] PASSED                       [ 86%]
tests/test_scanner.py::test_invalid_paths[   ] PASSED                    [ 87%]
tests/test_scanner.py::test_invalid_paths[None] PASSED                   [ 88%]
tests/test_scanner.py::test_invalid_paths[/definitely/not/here] PASSED   [ 89%]
tests/test_scanner.py::test_invalid_paths[bad\x00path] PASSED            [ 90%]
tests/test_scanner.py::test_file_path_rejected PASSED                    [ 91%]
tests/test_scanner.py::test_bad_rule_regex_rejected PASSED               [ 92%]
tests/test_scanner.py::test_labeled_corpus_regression PASSED             [ 93%]
tests/test_scanner.py::test_cobol_icsf_rules_and_comments PASSED         [ 94%]
tests/test_scanner.py::test_other_mainframe_languages[x.pli-CALL CSNDPKG(RC, RS);-expected0] PASSED [ 95%]
tests/test_scanner.py::test_other_mainframe_languages[x.pli-/* CALL CSNDPKG(RC, RS); */-expected1] PASSED [ 96%]
tests/test_scanner.py::test_other_mainframe_languages[x.asm-         CALL  CSNDDSG,(RC,RS)-expected2] PASSED [ 97%]
tests/test_scanner.py::test_other_mainframe_languages[x.asm-*        CALL  CSNDDSG,(RC,RS)-expected3] PASSED [ 98%]
tests/test_scanner.py::test_other_mainframe_languages[x.cpy-       01  K  PIC X(8) VALUE 'ECC-PAIR'.-expected4] PASSED [ 99%]
tests/test_scanner.py::test_other_mainframe_languages[x.cpy-       01  K  PIC X(8) VALUE 'ECC-PUBL'.-expected5] PASSED [100%]

============================= 100 passed in 5.59s ==============================
```
