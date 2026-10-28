"""Deterministically generated, entirely synthetic fraud-investigation records."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from hashlib import sha256
import json
import random
import re
from typing import Iterable

TOKEN_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)
DEFAULT_OR = ('invoice', 'transfer', 'refund')
DEFAULT_AND = ('invoice', 'transfer')

@dataclass(frozen=True)
class Record:
    record_id: str
    text: str
    amount_cents: int
    label_relevant: bool
    sensitive: bool
    category: str

    def canonical_bytes(self) -> bytes:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True,
                          separators=(',', ':')).encode('utf-8')


def tokenize(text: str) -> set[str]:
    return set(TOKEN_RE.findall(text.lower()))


def dataset_digest(records: Iterable[Record]) -> str:
    digest = sha256()
    for record in records:
        payload = record.canonical_bytes()
        digest.update(len(payload).to_bytes(8, 'big'))
        digest.update(payload)
    return digest.hexdigest()


# Category proportions intentionally make keyword retrieval imperfect.
# 'relevant_broad' includes genuinely relevant documents missed by the AND query.
# 'irrelevant_ambiguous' contains keyword false positives.
DISTRIBUTION = (
    ('relevant_exact', 16), ('relevant_broad', 6),
    ('irrelevant_ambiguous', 13), ('irrelevant_related', 18),
    ('irrelevant_private', 25), ('irrelevant_public', 22),
)
TEMPLATES = {
    'relevant_exact': 'invoice transfer diversion suspicious beneficiary ledger id{num}',
    'relevant_broad': 'payment redirection unauthorized bank beneficiary id{num}',
    'irrelevant_ambiguous': 'invoice transfer for legitimate family expense id{num}',
    'irrelevant_related': 'refund invoice for routine subscription id{num}',
    'irrelevant_private': 'confidential health appointment family diary id{num}',
    'irrelevant_public': 'community notice public library schedule id{num}',
}


def generate_records(n: int, seed: int = 2026) -> list[Record]:
    if n < 1:
        raise ValueError('number of records must be positive')
    rng = random.Random(seed)
    choices = [x for x, weight in DISTRIBUTION for _ in range(weight)]
    records: list[Record] = []
    for i in range(n):
        category = rng.choice(choices)
        relevant = category.startswith('relevant_')
        sensitive = category not in ('irrelevant_public',)
        if category == 'relevant_broad':
            sensitive = rng.random() < .9
        amount = rng.randint(100, 700_000)
        text = TEMPLATES[category].format(num=f'{i:08d}')
        records.append(Record(f'R{i:07d}', text, amount, relevant, sensitive, category))
    return records


def export_jsonl(records: Iterable[Record], path: str) -> None:
    with open(path, 'w', encoding='utf-8') as out:
        for record in records:
            out.write(record.canonical_bytes().decode('utf-8') + '\n')


def import_jsonl(path: str) -> list[Record]:
    result = []
    with open(path, encoding='utf-8') as inp:
        for line in inp:
            if line.strip():
                result.append(Record(**json.loads(line)))
    ids = [x.record_id for x in result]
    if len(ids) != len(set(ids)):
        raise ValueError('duplicate record IDs')
    return result
