import pytest
from cryptography.exceptions import InvalidTag
from ppdf_eval.dataset import generate_records, dataset_digest, tokenize
from ppdf_eval.security import Keys, seal, unseal, PlainIndex, ProtectedIndex, search_token, ApprovalAuthority
from ppdf_eval.systems import run_system, SYSTEMS


def test_generator_reproducible():
    a, b = generate_records(200, 5), generate_records(200, 5)
    assert dataset_digest(a) == dataset_digest(b)
    assert dataset_digest(a) != dataset_digest(generate_records(200, 6))


def test_aesgcm_authenticity_and_aad():
    record = generate_records(1)[0]
    k = Keys.new()
    sealed = seal(record, k.encryption_key)
    assert unseal(sealed, k.encryption_key) == record
    assert len(sealed.nonce) == 12
    with pytest.raises((InvalidTag, ValueError)):
        unseal(type(sealed)(record.record_id, sealed.nonce, sealed.ciphertext[:-1] + b'0'), k.encryption_key)
    with pytest.raises(InvalidTag):
        unseal(type(sealed)('tampered-id', sealed.nonce, sealed.ciphertext), k.encryption_key)


def test_plain_and_protected_query_equivalence():
    data = generate_records(225, seed=55)
    key = Keys.new()
    plaintext, encrypted = PlainIndex(data), ProtectedIndex(data, key.index_key)
    for terms, op in [(('invoice', 'transfer'), 'and'), (('invoice','refund'), 'or')]:
        assert plaintext.match(terms, op) == encrypted.match_tokens(
            (search_token(t, key.index_key) for t in terms), op)


def test_all_systems_return_same_hits_and_relevance():
    data = generate_records(400, seed=777)
    outputs = {system: run_system(system, data) for system in SYSTEMS}
    for result in outputs.values():
        assert result['dataset_size'] == 400
        assert result['matched_record_count'] > 0
        assert 0 <= result['precision'] <= 1
        assert 0 <= result['recall'] <= 1
        assert result['sampled_peak_rss_mb'] > 0
        assert result['sampled_peak_rss_mb'] >= result['initial_rss_mb']
        assert result['sampled_rss_increase_mb'] >= 0
        assert result['ciphertext_to_original_ratio'] >= 0
    for field in ('matched_record_count','true_positive','false_positive',
                  'false_negative','precision','recall',
                  'unrelated_sensitive_disclosed_as_query_hits'):
        assert len({result[field] for result in outputs.values()}) == 1, field
    assert outputs['plaintext']['encrypted_record_count'] == 0
    assert outputs['full_encryption']['encrypted_record_count'] == len(data)
    assert outputs['staged_ppdf']['encrypted_record_count'] < len(data)
    assert outputs['staged_ppdf']['ciphertext_bytes'] < outputs['full_encryption']['ciphertext_bytes']
    assert outputs['plaintext']['unrelated_sensitive_visible_to_investigator'] >= outputs['staged_ppdf']['unrelated_sensitive_visible_to_investigator']


def test_approval_required():
    rec = generate_records(1)[0]
    key = Keys.new()
    encrypted = seal(rec, key.encryption_key)
    approval = ApprovalAuthority()
    with pytest.raises(PermissionError):
        approval.decrypt_authorized('case', encrypted, key.encryption_key)
    approval.approve('case', {rec.record_id})
    assert approval.decrypt_authorized('case', encrypted, key.encryption_key) == rec
    assert len(approval.audit) == 2


def test_invalid_mode_and_keywords():
    data = generate_records(10)
    with pytest.raises(ValueError):
        run_system('wrong', data)
    with pytest.raises(ValueError):
        run_system('plaintext', data, first_keywords=())


def test_nonoverlapping_keyword_conditions_are_equivalent():
    records = generate_records(400, seed=112)
    kw_or = ('refund',)
    kw_and = ('invoice', 'transfer')
    results = [run_system(system, records, kw_or, kw_and) for system in SYSTEMS]
    assert all(r['matched_record_count'] == 0 for r in results)
    assert len({r['precision'] for r in results}) == 1


def test_experimental_plan_summaries_include_all_requested_metrics(tmp_path):
    import csv
    import json
    from ppdf_eval.benchmark import run_benchmarks

    rows, summary = run_benchmarks(
        sizes=[30], repeats=1, warmups=0, seed=2026, outdir=tmp_path
    )
    assert len(rows) == 3
    assert len(summary) == 3
    required = {
        'total_ms', 'sampled_peak_rss_mb', 'ciphertext_to_original_ratio',
        'precision', 'recall', 'unrelated_sensitive_visible_to_investigator'
    }
    assert required <= rows[0].keys()
    assert {x['system'] for x in rows} == set(SYSTEMS)
    assert {x['runs'] for x in summary} == {1}
    with (tmp_path / 'raw_runs.csv').open(newline='', encoding='utf-8') as f:
        assert len(list(csv.DictReader(f))) == 3
    manifest = json.loads((tmp_path / 'manifest.json').read_text())
    assert manifest['repeats'] == 1
