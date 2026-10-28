# Security, correctness and forensic limitations

**Research prototype only. It must not be described as a complete realization of the 2023 paper's encrypted K-means design.**

- AES-GCM provides confidentiality and authenticity for sealed record contents if keys are protected and nonces unique. It does not make the keyword index secret.
- HMAC-SHA-256 tokens hide the literal keyword from an index observer without the key, but stable tokens and raw posting lists reveal repeated queries, matching record IDs, result sizes, correlation, and access patterns. This is not a formal secure searchable-encryption scheme.
- Real service-provider/investigator/supervisor isolation would require separate processes, key-management services, authentication, and external enforcement. The `ApprovalAuthority` class is an in-process simulator only.
- The custodian reads plaintext to build the search index, and in staged PPDF to perform the first disjunctive search. The model does **not** guarantee the custodian learns nothing or that irrelevant private data are never touched.
- The initial stage is a broad keyword search; case-related does not automatically imply case-relevant. Irrelevant sensitive false-positive query hits can still be decrypted if approved.
- The plaintext baseline deliberately assumes direct investigator visibility over the entire corpus. This makes its exposure proxy larger by design. Real forensic organizations often restrict investigator access; this comparison does not establish a universally superior privacy level.
- All three systems use the same narrow AND query, so precision and recall should be identical. Encryption alone does not raise retrieval accuracy.
- `peak_python_allocations_mb` uses `tracemalloc`; it does not capture all native allocations or process RSS. `sampled_peak_rss_mb` uses psutil at processing-stage boundaries, includes preloaded data and other process memory, and may miss transient peaks; these are distinct measurements.
- SHA-256 digital fingerprints are not a complete evidentiary chain of custody, and generated trial data have no court admissibility status.
- Optional Paillier `he_demo` permits additive ciphertext computation only. Ciphertext keyword search, secure comparisons, encrypted nearest-centroid assignment and K-means clustering require more than Paillier additive homomorphism.
- If published, report hardware, OS, Python versions, package versions, random seeds, repetitions, security parameters and raw experimental data.

Recommended background: Oya & Kerschbaum (USENIX Security 2021), "Hiding the Access Pattern is Not Enough" (search pattern leakage); Gui et al. (PoPETs 2024), "SWiSSSE: System-Wide Security for Searchable Symmetric Encryption".
