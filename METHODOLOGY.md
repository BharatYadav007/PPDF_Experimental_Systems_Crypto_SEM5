# Research methodology / paper-ready implementation outline

**Study origin:** T. B. Ogunseyi and O. M. Adedayo, "Cryptographic Techniques for Data Privacy in Digital Forensics," *IEEE Access* 11 (2023), pp. 142392–142410, DOI 10.1109/ACCESS.2023.3343360. Specifically see Figure 3, Section IV (stages), Section V (principle evaluation), and Section VI (implementation proposed as future work).

## Objectives

1. Implement a reproducible four-stage prototype with selective encryption and two keyword passes.
2. Compare identical datasets and search terms in plaintext, full-corpus encryption, and staged-selective-encryption settings.
3. Measure storage, processing cost, retrieval effectiveness and investigator exposure proxies.
4. State implementation departures from the conceptual design (HMAC index versus formally analyzed searchable encryption; no integrated HE/K-means).

## Four-stage mapping

1. **Preparation / key generation:** define an investigation scope and a synthetic evidence population; SHA-256 hash record bytes; generate random AES-GCM and HMAC keys. Investigators and supervisors are simulated by software interfaces.
2. **Preservation / encryption:** preserve original synthetic records. In staged PPDF, a custodian applies a local plaintext OR search and encrypts only matching records with AES-256-GCM. In full-corpus baseline all records are encrypted.
3. **Extraction / computation:** build a keyed HMAC inverted index, then perform a protected AND search. This is *functional encrypted-document retrieval* but **not** computation on arbitrary encrypted numerical features. Paillier sums are available as an optional standalone demonstration.
4. **Presentation / decryption:** an approval module authorizes the matched record identifiers and decrypts matched AES-GCM records with authenticated associated data (record ID); compare hits with labeled plaintext ground truth.

## Dataset composition

Seeded synthetic records have IDs, content, transaction amounts, case-relevance labels, sensitivity labels and one of six classes: exact relevant, broader relevant, ambiguous irrelevant, single-term irrelevant, private irrelevant, public irrelevant. The synthetic fraud scenario intentionally includes both false-positive keyword matches and relevant records not captured by the narrow AND search. The class weights are defined in `dataset.py` and are a **research assumption**, not an empirical fraud distribution.

## Controls

- Same dataset, canonical record bytes, tokenization, keywords and random seed for every system.
- Same hardware, operating system, Python and cryptography library versions.
- Run warm-ups; make 20 measured repetitions per system and dataset size; report median and IQR rather than single fastest timing.
- No use of real users' emails, private financial records, or criminal evidence.
- Compare output record ID sets (not only counts), and retain raw timing logs and code version identifiers.

## Prespecified benchmarking plan and status

**Benchmark plan:** Plaintext vs. full-corpus encryption vs. staged PPDF • 1k / 5k / 10k records • 20 runs per setting.

**Metrics:** execution time, peak RAM, ciphertext ratio, precision/recall, unrelated sensitive records exposed. **Full 20-run results pending.**

- 3 systems × 3 record counts × 20 measured runs = 180 measured conditions/trials; 1 warm-up per setting is the default.
- Analyze 9 system-by-size conditions; report medians and IQR for elapsed time; use identical seed, queries, environment, and dataset composition.
- `sampled_peak_rss_mb` is **approximate process resident RAM** sampled after processing stages, not a continuously sampled isolated high-water mark; `peak_python_allocations_mb` is separate.
- `ciphertext_to_original_ratio` excludes index storage; report index-inclusive ratio separately.
- The irrelevant-sensitive exposure metric depends on explicit investigator-visibility assumptions; it is not a cryptographic privacy proof.

## Independent variables

- System: plaintext, full_encryption, staged_ppdf.
- Corpus size: 1,000 / 5,000 / 10,000 records.
- Keyword selection, match prevalence, and number of keywords may be studied separately by controlled alterations.

## Dependent variables

- Latency per stage and total time (ms), sampled peak process RSS (MB), and tracked Python allocations (MB).
- Number of encrypted records, ciphertext bytes, ciphertext-to-plaintext ratio, serialized protected-index bytes, index-inclusive storage ratio.
- Precision and recall against ground-truth relevance.
- Unrelated sensitive records with investigator-visible plaintext under stated access assumptions; irrelevant-sensitive false-positive hits.

## Proposed result tables

1. Per-size per-system median total execution times and IQR.
2. Ciphertext/index storage and selective-encryption reduction.
3. Precision, recall and false-positive counts.
4. Investigator exposure proxy and threat-model assumptions.

## Critical caveats

- **This is not an empirical validation of the original paper's homomorphic K-means algorithm.**
- HMAC-search tokens are not a formally analyzed SSE design.
- The first OR search in staged PPDF is performed on plaintext by the custodian.
- The three systems use different trust assumptions for who can see plaintext; leakage must be interpreted under those assumptions.
- The implementations are in one Python process: access separation is logical rather than enforced through independent administrative domains.
- No significance claims based on pilot runs or fewer than the prespecified repetitions.
