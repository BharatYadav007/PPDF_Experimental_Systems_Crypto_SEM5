"""CLI: run matched workloads, export raw CSV and descriptive summary."""
from __future__ import annotations
import argparse
import csv
import json
import platform
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

from .dataset import generate_records, import_jsonl, export_jsonl, DEFAULT_AND, DEFAULT_OR
from .systems import run_system, SYSTEMS


def _positive_int(arg):
    value = int(arg)
    if value < 1:
        raise argparse.ArgumentTypeError('value must be > 0')
    return value


def _keywords(arg):
    vals = tuple(x.strip().lower() for x in arg.split(',') if x.strip())
    if not vals:
        raise argparse.ArgumentTypeError('at least one keyword required')
    return vals


def _save_csv(path, rows):
    if not rows:
        return
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run_benchmarks(sizes, repeats, warmups, seed, outdir,
                   first_keywords=DEFAULT_OR, second_keywords=DEFAULT_AND):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    raws = []
    for size in sizes:
        records = generate_records(size, seed)
        for mode in SYSTEMS:
            for _ in range(warmups):
                run_system(mode, records, first_keywords, second_keywords)
            for repetition in range(repeats):
                row = run_system(mode, records, first_keywords, second_keywords)
                row['repetition'] = repetition + 1
                row['seed'] = seed
                row['first_or_keywords'] = ','.join(first_keywords)
                row['second_and_keywords'] = ','.join(second_keywords)
                raws.append(row)
                print(f'{mode:17s} n={size:>6,d} repetition={repetition+1:>2} '
                      f'total={row["total_ms"]:>9.2f} ms '
                      f'precision={row["precision"]:.3f} recall={row["recall"]:.3f}',
                      flush=True)
    _save_csv(outdir / 'raw_runs.csv', raws)
    groups = {}
    for x in raws:
        groups.setdefault((x['dataset_size'], x['system']), []).append(x)
    summary = []
    for (size, system), group in groups.items():
        totals = [r['total_ms'] for r in group]
        item = {'dataset_size': size, 'system': system,
                'runs': len(group), 'median_total_ms': statistics.median(totals),
                'min_total_ms': min(totals), 'max_total_ms': max(totals),
                'median_tracked_python_mb': statistics.median(
                    r['peak_python_allocations_mb'] for r in group),
                'median_sampled_peak_rss_mb': statistics.median(
                    r['sampled_peak_rss_mb'] for r in group),
                'median_sampled_rss_increase_mb': statistics.median(
                    r['sampled_rss_increase_mb'] for r in group)}
        for fld in ('precision', 'recall', 'ciphertext_bytes',
                    'protected_index_bytes', 'encrypted_record_count',
                    'unrelated_sensitive_visible_to_investigator',
                    'unrelated_sensitive_disclosed_as_query_hits',
                    'encrypted_storage_to_original_ratio',
                    'ciphertext_to_original_ratio'):
            item[fld] = statistics.median(r[fld] for r in group)
        if len(totals) >= 4:
            q = statistics.quantiles(totals, n=4, method='inclusive')
            item['iqr_total_ms'] = q[2] - q[0]
        else:
            item['iqr_total_ms'] = ''
        summary.append(item)
    _save_csv(outdir / 'summary.csv', summary)
    manifest = {
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'python_version': sys.version, 'platform': platform.platform(),
        'dataset': 'entirely synthetic, seeded generator',
        'sizes': list(sizes), 'repeats': repeats, 'warmups': warmups,
        'systems': list(SYSTEMS),
        'measured_trials': len(raws),
        'benchmark_status': ('full_planned_configuration_completed'
                             if sorted(sizes) == [1000, 5000, 10000] and repeats == 20
                             else 'pilot_or_custom_configuration'),
        'requested_metrics': [
            'total_ms', 'sampled_peak_rss_mb', 'ciphertext_to_original_ratio',
            'precision', 'recall', 'unrelated_sensitive_visible_to_investigator'
        ],
        'seed': seed, 'first_or_keywords': first_keywords,
        'second_and_keywords': second_keywords,
        'security_notes': ['in-process role separation',
                           'HMAC index leaks search/access patterns',
                           'no HE in core benchmarks',
                           'not production-forensic validated',
                           'tracked Python allocations are not process peak RSS',
                           'sampled peak RSS includes preloaded dataset and may miss transient peaks'],
    }
    (outdir / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(f'\nSaved {len(raws)} raw trials to {outdir / "raw_runs.csv"}')
    print(f'Saved comparison summary to {outdir / "summary.csv"}')
    return raws, summary


def main():
    parser = argparse.ArgumentParser(description='Experimental PPDF baseline comparison')
    parser.add_argument('--sizes', type=_positive_int, nargs='+', default=[1000, 5000, 10000])
    parser.add_argument('--repeats', type=_positive_int, default=20)
    parser.add_argument('--warmups', type=int, default=1)
    parser.add_argument('--seed', type=int, default=2026)
    parser.add_argument('--or-keywords', type=_keywords, default=DEFAULT_OR)
    parser.add_argument('--and-keywords', type=_keywords, default=DEFAULT_AND)
    parser.add_argument('--out', default='outputs')
    parser.add_argument('--generate-jsonl', help='write a synthetic JSONL file of first dataset size')
    args = parser.parse_args()
    if args.warmups < 0:
        parser.error('--warmups must be >= 0')
    if args.generate_jsonl:
        export_jsonl(generate_records(args.sizes[0], args.seed), args.generate_jsonl)
    run_benchmarks(args.sizes, args.repeats, args.warmups, args.seed,
                   args.out, args.or_keywords, args.and_keywords)


if __name__ == '__main__':
    main()
