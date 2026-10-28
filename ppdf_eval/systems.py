"""Comparable experiment runners for three baseline forensic workflows."""
from __future__ import annotations
import time
import tracemalloc

import psutil
from typing import Sequence

from .dataset import Record, tokenize, dataset_digest, DEFAULT_OR, DEFAULT_AND
from .security import Keys, PlainIndex, ProtectedIndex, ApprovalAuthority, seal, search_token

SYSTEMS = ('plaintext', 'full_encryption', 'staged_ppdf')


def _bytes(records: Sequence[Record]) -> int:
    return sum(len(x.canonical_bytes()) for x in records)


def _evaluate(records: Sequence[Record], matched: set[str], visible_ids: set[str],
              *, mode: str, n_encrypted: int, encrypted_bytes: int,
              protected_index_bytes: int, timings: dict[str, float],
              python_peak_bytes: int, sampled_peak_rss_bytes: int, rss_start_bytes: int) -> dict:
    lookup = {r.record_id: r for r in records}
    truth = {r.record_id for r in records if r.label_relevant}
    retrieved = matched & set(lookup)
    true_positive = len(truth & retrieved)
    unrelated_sensitive = {r.record_id for r in records if r.sensitive and not r.label_relevant}
    disclosed_false_positives = len(retrieved & unrelated_sensitive)
    visible_unrelated_sensitive = len(visible_ids & unrelated_sensitive)
    baseline_bytes = _bytes(records)
    results = {
        'system': mode, 'dataset_size': len(records),
        'dataset_sha256': dataset_digest(records),
        'encrypted_record_count': n_encrypted,
        'matched_record_count': len(retrieved),
        'true_positive': true_positive,
        'false_positive': len(retrieved - truth),
        'false_negative': len(truth - retrieved),
        'precision': true_positive / len(retrieved) if retrieved else 0.0,
        'recall': true_positive / len(truth) if truth else 0.0,
        'unrelated_sensitive_disclosed_as_query_hits': disclosed_false_positives,
        'unrelated_sensitive_visible_to_investigator': visible_unrelated_sensitive,
        'visibility_model': ('entire plaintext corpus accessible to investigator'
                             if mode == 'plaintext' else 'authorized query hits only'),
        'plaintext_dataset_bytes': baseline_bytes,
        'ciphertext_bytes': encrypted_bytes,
        'protected_index_bytes': protected_index_bytes,
        'total_protected_storage_bytes': encrypted_bytes + protected_index_bytes,
        'encrypted_storage_to_original_ratio':
            (encrypted_bytes + protected_index_bytes) / baseline_bytes if baseline_bytes else 0,
        # This ratio is ciphertext bytes only; no index bytes included.
        'ciphertext_to_original_ratio':
            encrypted_bytes / baseline_bytes if baseline_bytes else 0,
        'peak_python_allocations_mb': python_peak_bytes / (1024**2),
        # Process resident set size (RSS), sampled at stage boundaries, including
        # the pre-loaded corpus. Transient peaks between samples may be missed.
        'sampled_peak_rss_mb': sampled_peak_rss_bytes / (1024**2),
        'initial_rss_mb': rss_start_bytes / (1024**2),
        'sampled_rss_increase_mb': max(0, sampled_peak_rss_bytes - rss_start_bytes) / (1024**2),
    }
    for name in ('keygen', 'build_index', 'first_or_filter', 'encrypt', 'second_and_query', 'authorize_decrypt'):
        results[f'{name}_ms'] = 1000 * timings.get(name, 0.0)
    results['total_ms'] = 1000 * sum(timings.values())
    return results


def run_system(mode: str, records: Sequence[Record],
               first_keywords: Sequence[str] = DEFAULT_OR,
               second_keywords: Sequence[str] = DEFAULT_AND) -> dict:
    if mode not in SYSTEMS:
        raise ValueError(f'unknown mode: {mode!r}')
    if not first_keywords or not second_keywords:
        raise ValueError('two nonempty keyword sets required')
    if len({r.record_id for r in records}) != len(records):
        raise ValueError('duplicate evidence record identifiers')

    checkpoints: dict[str, float] = {}
    process = psutil.Process()
    rss_start_bytes = process.memory_info().rss
    sampled_peak_rss_bytes = rss_start_bytes

    def measure(label, fn):
        nonlocal sampled_peak_rss_bytes
        start = time.perf_counter_ns()
        result = fn()
        checkpoints[label] = (time.perf_counter_ns() - start) / 1e9
        sampled_peak_rss_bytes = max(sampled_peak_rss_bytes, process.memory_info().rss)
        return result

    tracemalloc.start()
    try:
        universe = {r.record_id: r for r in records}
        all_ids = set(universe)
        if mode == 'plaintext':
            idx = measure('build_index', lambda: PlainIndex(records))
            broad = measure('first_or_filter', lambda: idx.match(first_keywords, 'or'))
            matched = measure('second_and_query', lambda: idx.match(second_keywords, 'and') & broad)
            # Investigator has direct access to full plaintext corpus in this baseline.
            visible = all_ids
            encrypted_bytes = 0
            index_bytes = 0
            encrypted_count = 0
            checkpoints['authorize_decrypt'] = 0.0
        else:
            keys = measure('keygen', Keys.new)
            if mode == 'staged_ppdf':
                # PPDF first pass happens on plaintext in a restricted custodian environment.
                # This is NOT ciphertext keyword search. Do not represent it as such.
                broad = measure('first_or_filter', lambda: {
                    r.record_id for r in records if tokenize(r.text).intersection(first_keywords)
                })
                selected = [r for r in records if r.record_id in broad]
            else:
                broad = all_ids
                selected = list(records)
                # Full-corpus OR search is applied to a keyed index below.
            idx = measure('build_index', lambda: ProtectedIndex(selected, keys.index_key))
            sealed = measure('encrypt', lambda: {
                r.record_id: seal(r, keys.encryption_key) for r in selected
            })
            if mode == 'full_encryption':
                first_tokens = [search_token(w, keys.index_key) for w in first_keywords]
                broad = measure('first_or_filter',
                                lambda: idx.match_tokens(first_tokens, 'or'))
            # Query token generation by investigator; server sees stable tokens.
            search_terms = [search_token(w, keys.index_key) for w in second_keywords]
            matched = measure('second_and_query',
                              lambda: idx.match_tokens(search_terms, 'and') & broad)
            def approved_release():
                authority = ApprovalAuthority()
                authority.approve('synthetic_case_001', matched)
                retrieved = [authority.decrypt_authorized('synthetic_case_001', sealed[i], keys.encryption_key)
                             for i in sorted(matched)]
                return {r.record_id for r in retrieved}
            visible = measure('authorize_decrypt', approved_release)
            encrypted_bytes = sum(item.storage_bytes for item in sealed.values())
            index_bytes = idx.size_bytes()
            encrypted_count = len(sealed)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()  # Metadata and metrics calculations are not system memory usage.
        return _evaluate(records, matched, visible, mode=mode,
                         n_encrypted=encrypted_count, encrypted_bytes=encrypted_bytes,
                         protected_index_bytes=index_bytes, timings=checkpoints,
                         python_peak_bytes=peak,
                         sampled_peak_rss_bytes=sampled_peak_rss_bytes,
                         rss_start_bytes=rss_start_bytes)
    finally:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
