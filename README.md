# PPDF_Experimental_Systems_Crypto_SEM5

# Experimental Realization of the Four-Stage PPDF Model

Runnable research prototype comparing **three evidence-processing systems** derived from the conceptual stages in Ogunseyi and Adedayo (2023), *Cryptographic Techniques for Data Privacy in Digital Forensics*, IEEE Access, DOI: 10.1109/ACCESS.2023.3343360.

The original publication proposes a four-stage conceptual framework. This repository is an independent experimental **interpretation**, not the original authors' implementation, and does not claim to reproduce their proposed encrypted K-means algorithm.

## Semester 5 cryptography project · Research paper and presentation

**GitHub repository name:** `PPDF_Experimental_Systems_Crypto_SEM5`  
**Course:** Cryptography (Semester 5)  
**Project direction:** Experimental realization and benchmarking of a conceptual Privacy-Preserving Digital Forensics (PPDF) model.

### Research basis

- **Original research paper:** Taiwo Blessing Ogunseyi and Oluwasola Mary Adedayo, *Cryptographic Techniques for Data Privacy in Digital Forensics*, **IEEE Access**, vol. 11, pp. 142392–142410 (2023). [DOI: 10.1109/ACCESS.2023.3343360](https://doi.org/10.1109/ACCESS.2023.3343360).
- **PDF provided for this project:** [`research/Ogunseyi_Adedayo_2023_IEEE_Access.pdf`](research/Ogunseyi_Adedayo_2023_IEEE_Access.pdf) (unaltered copy; original authors retain attribution and rights; check the paper's CC BY-NC-ND 4.0 terms before redistribution).
- **Offline presentation file:** [`research/Literature_Comparison_Offline_Draft.pptx`](research/Literature_Comparison_Offline_Draft.pptx). This is a **single-slide literature-comparison draft**, **not** an export of the current 3-slide Canva deck. Use the Canva link for the latest title + comparison + methodology slides.

**Presentation outline:** (1) Original title slide, (2) Literature comparison of existing cryptographic approaches and experimental PPDF, and (3) Methodology covering key generation, selective encryption, encrypted retrieval/computation, decryption and the benchmark plan.

**Academic attribution:** The four-stage PPDF concept originates with Ogunseyi and Adedayo (2023). This student project is a separate experimental prototype; it neither replaces nor claims authorship of the published conceptual model.

---

## Systems implemented

| System | Evidence handling | Query search | Investigator's exposure assumption |
|---|---|---|---|
| `plaintext` | Complete readable corpus and plain inverted index | OR then AND | Investigator can inspect the complete corpus |
| `full_encryption` | Encrypt **all** records using AES-256-GCM; build keyed-HMAC index before encryption | AND query tokens over protected index, with OR logical eligibility from all records | Only supervisor-approved hits decrypted |
| `staged_ppdf` | Custodian searches local plaintext OR; AES-256-GCM encrypts **selected subset**; builds keyed-HMAC index | Second AND query over protected index | Only supervisor-approved hits decrypted |

The HMAC-based index is a **functional approximation**, not a proven SSE construction. It leaks stable query-token equality, keyword-document relationships/postings, result sizes, and access patterns to an index server. Because the prototype runs in one process, roles and permissions are logically simulated, **not isolated security domains**.

**Do not use with real sensitive forensic records or for court evidence.** The examples are entirely synthetic.

## Official planned evaluation — results pending

**Benchmark plan:** Plaintext vs. full-corpus encryption vs. staged PPDF **• 1k / 5k / 10k records • 20 measured runs per setting.**

**Metrics:** execution time, peak RAM, ciphertext/plaintext byte ratio, precision/recall, and number of unrelated sensitive records exposed. **Full 20-run study results are pending.**

This means **9 experimental conditions** (3 systems × 3 dataset sizes) and **180 measured trials** (9 × 20), plus configurable warm-ups. All three systems use the same synthetic records, OR/AND query terms and ground-truth labels. A three-run verification pilot is provided under `outputs/pilot/`, and a separate one-run RAM-metric smoke test under `outputs/smoke_updated/`; **neither is the planned 20-run study**.

See `BENCHMARK_PLAN.md` for the exact metric definitions, a publication-ready pending-results matrix, and the evaluation protocol.

## Quick start

From the root of your `PPDF_Experimental_Systems_Crypto_SEM5` repository:

```bash
python -m pip install -r requirements.txt
python -m pytest -q
python -m ppdf_eval --sizes 1000 --repeats 3 --warmups 1 --out outputs/pilot
```

Run the proposed study configuration (20 measured runs, 1k, 5k, 10k records):

```bash
python -m ppdf_eval --sizes 1000 5000 10000 --repeats 20 --warmups 1 --seed 2026 --out outputs/study
```

Generate a deterministic JSONL example dataset:

```bash
python -m ppdf_eval --sizes 1000 --repeats 1 --warmups 0 --generate-jsonl outputs/example_synthetic.jsonl --out outputs/example_run
```

Custom query terms:

```bash
python -m ppdf_eval --sizes 1000 --repeats 3 --or-keywords invoice,transfer,refund --and-keywords invoice,transfer --out outputs/custom
```

## Files produced

- `raw_runs.csv`: one row per system/size/repetition; stage-level times in **milliseconds**; dataset fingerprint, storage and retrieval metrics.
- `summary.csv`: descriptive medians (including peak sampled RSS) and interquartile range (IQR when 4+ runs); not a statistical hypothesis test.
- `manifest.json`: environment, seed, queries, repetitions, threat-model and implementation notes.

## Optional Paillier homomorphic-sum demonstration

```bash
python -m pip install phe
python -m ppdf_eval.he_demo --values 100 200 300 400
```

This uses the external `python-paillier` package and performs **genuine encrypted addition**. It is **not integrated into the core 3-system timing comparison**, which contains AES-GCM and HMAC-index work only. K-means and general encrypted-text computation are not implemented. If `phe` is unavailable, the core experiments still run.

## What is (and is not) measured

- **Performance:** measured per-stage elapsed times, tracked Python allocations (`peak_python_allocations_mb`), and **sampled peak process RAM** (`sampled_peak_rss_mb`) at stage boundaries using `psutil`. Sampled RSS includes the preloaded input and may miss brief between-stage peaks; it is not an exact process-isolated high-water mark.
- **Storage:** `ciphertext_to_original_ratio` = ciphertext+nonce bytes / original dataset bytes. The separately reported `encrypted_storage_to_original_ratio` also includes approximate protected-index bytes. No claims of wire-protocol cost.
- **Retrieval:** relevance labels created *before* searching; precision and recall are measured against those labels. Identical query logic should produce identical result quality in all 3 systems. A difference indicates a bug, not an automatic cryptographic improvement.
- **Privacy:** unrelated sensitive records visible in the investigator's workspace under explicit role assumptions, plus unrelated sensitive *false-positive query hits*. These are **operational exposure proxies**, not differential-privacy guarantees or a quantitative security proof.
- **Custodian access:** the custodian necessarily handles plaintext to construct the index and perform local OR filtering. The prototype **does not remove that exposure**. The full-encryption baseline must also index plaintext before encryption.
- **Custody:** SHA-256 fingerprint of canonical serialized evidence; no external chain-of-custody validation, digital signatures, or litigation-ready record handling.

## Research interpretation

This implementation is intended to test the paper's **filter-then-encrypt** concept, and to illustrate a working two-stage query/release pipeline. Expected results should **not** be assumed: run the full experiment. Full-corpus encryption necessarily stores more encrypted bytes than selective encryption in this setup, but differences in total runtime, search efficiency, memory and privacy exposure depend on the selected scheme and threat assumptions. The plaintext and encrypted systems can have identical precision and recall.

See `METHODOLOGY.md` and `SECURITY_LIMITATIONS.md` for details.

## Plot a benchmark summary

```bash
python -m ppdf_eval.plot_results --input outputs/study/summary.csv --output outputs/study/comparison.png
```

The chart displays measured medians, not theoretical predictions. A three-run pilot is included only to verify the evaluation pipeline; **use full repeated measurements on your own documented hardware before publishing**.

## Run a single system on a small synthetic case

```bash
python -m ppdf_eval.demo --system plaintext --size 100
python -m ppdf_eval.demo --system full_encryption --size 100
python -m ppdf_eval.demo --system staged_ppdf --size 100
```

These demos print system metrics, not raw sensitive synthetic messages.

**Full-study status:** PENDING. Run the 20-repeat command on your target machine to generate the paper-ready comparison; no final 20-run experimental findings are claimed in this repository.
