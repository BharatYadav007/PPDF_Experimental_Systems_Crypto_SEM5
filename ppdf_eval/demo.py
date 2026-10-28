"""Readable demonstration of the three implemented processing systems."""
from __future__ import annotations
import argparse
import json
from .dataset import generate_records, dataset_digest
from .systems import SYSTEMS, run_system


def main():
    parser = argparse.ArgumentParser(description='Demonstrate each PPDF baseline')
    parser.add_argument('--system', choices=SYSTEMS, default='staged_ppdf')
    parser.add_argument('--size', type=int, default=100)
    parser.add_argument('--seed', type=int, default=2026)
    args = parser.parse_args()
    result = run_system(args.system, generate_records(args.size, args.seed))
    shown = ('system', 'dataset_size', 'dataset_sha256', 'encrypted_record_count',
             'matched_record_count', 'precision', 'recall',
             'unrelated_sensitive_visible_to_investigator',
             'unrelated_sensitive_disclosed_as_query_hits',
             'ciphertext_bytes', 'protected_index_bytes', 'total_ms')
    print(json.dumps({k: result[k] for k in shown}, indent=2))

if __name__ == '__main__':
    main()
