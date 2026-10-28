# Planned comparative evaluation — 20-run study pending

## Protocol specified for the research paper

**Benchmark plan: Plaintext vs. full-corpus encryption vs. staged PPDF • 1k / 5k / 10k records • 20 runs per setting.**

**Metrics: execution time, peak RAM, ciphertext ratio, precision/recall, unrelated sensitive records exposed. Results pending.**

Three implementations: `plaintext`, `full_encryption`, `staged_ppdf`. Three input sizes: 1,000, 5,000 and 10,000 deterministic synthetic evidence records. Run 20 measured repetitions **per system per size**, giving **180 measured trials** overall. Use identical data labels, OR/AND keywords, system hardware, Python interpreter and crypto settings. Run at least one warm-up per setting. Store the raw files, execution environment, exact software versions, seed and code revision alongside results.

Run from project root:

```bash
python -m pip install -r requirements.txt
python -m pytest -q
python -m ppdf_eval --sizes 1000 5000 10000 --repeats 20 --warmups 1 --seed 2026 --out outputs/study
python -m ppdf_eval.plot_results --input outputs/study/summary.csv --output outputs/study/comparison.png
```

**Status:** The complete 20-run experiment has **not** been completed here. `outputs/pilot/` contains prior 3-repeat smoke/pilot measurements only. The pilot predates the added psutil RSS field and therefore is not a full RAM-measurement report. Do not interpret or cite the pilot as a 20-repetition result.

## Metrics and operational definitions

| Requested metric | Field(s) in `raw_runs.csv` | Reporting rule / limitation |
|---|---|---|
| Execution time | `total_ms`, `keygen_ms`, `build_index_ms`, `first_or_filter_ms`, `encrypt_ms`, `second_and_query_ms`, `authorize_decrypt_ms` | Use median total time and IQR per condition; stage times are individually measured. |
| Peak RAM | `sampled_peak_rss_mb`, `sampled_rss_increase_mb`, `peak_python_allocations_mb` | RSS samples are taken at stage boundaries; values include pre-loaded dataset and may miss transient peaks. `peak_python_allocations_mb` is not RSS. |
| Ciphertext ratio | `ciphertext_to_original_ratio`, `encrypted_storage_to_original_ratio` | First = ciphertext + nonce bytes divided by original input bytes. Second adds approximate protected-index storage. Plaintext system has zero ciphertext. |
| Precision | `precision` | True positives divided by all returned hits, zero when no hits. |
| Recall | `recall` | True positives divided by all labeled relevant records, zero when no relevant records. |
| Unrelated sensitive records exposed | `unrelated_sensitive_visible_to_investigator`, `unrelated_sensitive_disclosed_as_query_hits` | Explicit access-based privacy **proxy**, not a formal leakage guarantee. For plaintext baseline, investigator is assumed to see all records; for encrypted systems, approved hits only. |

For fair comparisons, verify the exact retrieved record IDs match across systems with the same OR and AND queries, not just precision/recall. The 3 methods are expected to have identical retrieval quality under this matched setup; the study examines overhead and modeled exposure, not an improvement in retrieval algorithms.

## Results table to complete after running study

| Record count | System | Measured runs | Median time (ms) | Median sampled peak RSS (MB) | Ciphertext ratio | Precision | Recall | Unrelated sensitive records exposed |
|---:|---|---:|---|---|---|---|---|---|
| 1,000 | Plaintext | Pending (target: 20) | Pending | Pending | Pending | Pending | Pending | Pending |
| 1,000 | Full-corpus encryption | Pending (target: 20) | Pending | Pending | Pending | Pending | Pending | Pending |
| 1,000 | Staged PPDF | Pending (target: 20) | Pending | Pending | Pending | Pending | Pending | Pending |
| 5,000 | Plaintext | Pending (target: 20) | Pending | Pending | Pending | Pending | Pending | Pending |
| 5,000 | Full-corpus encryption | Pending (target: 20) | Pending | Pending | Pending | Pending | Pending | Pending |
| 5,000 | Staged PPDF | Pending (target: 20) | Pending | Pending | Pending | Pending | Pending | Pending |
| 10,000 | Plaintext | Pending (target: 20) | Pending | Pending | Pending | Pending | Pending | Pending |
| 10,000 | Full-corpus encryption | Pending (target: 20) | Pending | Pending | Pending | Pending | Pending | Pending |
| 10,000 | Staged PPDF | Pending (target: 20) | Pending | Pending | Pending | Pending | Pending | Pending |

## Interpretation safeguards

- This is a prototype comparison of AES-GCM and a keyed HMAC inverted index, not a validated fully homomorphic encrypted-search implementation or the original authors' encrypted K-means scheme.
- Results for encryption overhead do **not** establish that the staged design is cryptographically superior.
- Record both elapsed time and the cost of creating each dataset outside the timed processing stages.
- Preserve raw output and explain the RSS measurement method and privacy visibility model in the paper.
