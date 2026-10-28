"""Create publication-draft plots from benchmark CSV (not a scientific proof)."""
from __future__ import annotations
import argparse
import csv
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description='Plot benchmark medians from summary.csv')
    parser.add_argument('--input', required=True, help='path to summary.csv')
    parser.add_argument('--output', default='outputs/comparison.png')
    args = parser.parse_args()
    import matplotlib.pyplot as plt
    with open(args.input, newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    labels = {'plaintext': 'Plaintext', 'full_encryption': 'Full-corpus encryption',
              'staged_ppdf': 'Staged PPDF'}
    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    for system, name in labels.items():
        rr = sorted((r for r in rows if r['system'] == system),
                    key=lambda r: int(r['dataset_size']))
        if rr:
            ax.plot([int(r['dataset_size']) for r in rr],
                    [float(r['median_total_ms']) for r in rr], 'o-', label=name)
    ax.set_xlabel('Number of synthetic evidence records')
    ax.set_ylabel('Median elapsed processing time (ms)')
    ax.set_title('PPDF experimental prototype: measured processing time')
    ax.grid(True, alpha=.2)
    ax.legend()
    fig.tight_layout()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=170)
    print(path)


if __name__ == '__main__':
    main()
