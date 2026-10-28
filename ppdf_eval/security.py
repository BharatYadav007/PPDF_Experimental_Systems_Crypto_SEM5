"""AES-GCM envelope encryption and research-only keyed inverted index.

The keyed index is NOT a formally analyzed searchable-encryption construction.
It leaks result sizes, stable search tokens, posting lists and access patterns.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
import os
from collections import defaultdict
from typing import Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .dataset import Record, tokenize


@dataclass(frozen=True)
class Keys:
    encryption_key: bytes
    index_key: bytes

    @classmethod
    def new(cls) -> 'Keys':
        return cls(AESGCM.generate_key(bit_length=256), os.urandom(32))


@dataclass(frozen=True)
class SealedRecord:
    record_id: str
    nonce: bytes
    ciphertext: bytes  # Includes the 16-byte authentication tag.

    @property
    def storage_bytes(self) -> int:
        return len(self.nonce) + len(self.ciphertext)


def seal(record: Record, key: bytes) -> SealedRecord:
    nonce = os.urandom(12)  # fresh 96-bit GCM nonce; NEVER reuse with same key
    blob = AESGCM(key).encrypt(nonce, record.canonical_bytes(), record.record_id.encode())
    return SealedRecord(record.record_id, nonce, blob)


def unseal(encrypted: SealedRecord, key: bytes) -> Record:
    raw = AESGCM(key).decrypt(encrypted.nonce, encrypted.ciphertext,
                              encrypted.record_id.encode())
    decoded = Record(**json.loads(raw))
    if decoded.record_id != encrypted.record_id:
        raise ValueError('evidence ID differs from authentication binding')
    return decoded


def search_token(word: str, key: bytes) -> str:
    return hmac.new(key, word.lower().encode('utf-8'), sha256).hexdigest()


class PlainIndex:
    def __init__(self, records: Iterable[Record]):
        self.postings: dict[str, set[str]] = defaultdict(set)
        for record in records:
            for word in tokenize(record.text):
                self.postings[word].add(record.record_id)

    def match(self, words: Iterable[str], mode: str = 'and') -> set[str]:
        terms = [w.lower() for w in words]
        if not terms:
            return set()
        sets = [self.postings.get(term, set()) for term in terms]
        return set().union(*sets) if mode == 'or' else set.intersection(*sets)


class ProtectedIndex:
    def __init__(self, records: Iterable[Record], key: bytes):
        self.postings: dict[str, set[str]] = defaultdict(set)
        for record in records:
            for word in tokenize(record.text):
                token = search_token(word, key)
                self.postings[token].add(record.record_id)

    def match_tokens(self, tokens: Iterable[str], mode: str = 'and') -> set[str]:
        terms = list(tokens)
        if not terms:
            return set()
        sets = [self.postings.get(token, set()) for token in terms]
        return set().union(*sets) if mode == 'or' else set.intersection(*sets)

    def size_bytes(self) -> int:
        # Actual bytes of a serializable representation, not a cryptographic proof.
        normalized = {k: sorted(v) for k, v in self.postings.items()}
        return len(json.dumps(normalized, separators=(',', ':')).encode('utf-8'))


class ApprovalAuthority:
    """In-process approval simulator, NOT independent enforcement/secure key custody."""
    def __init__(self):
        self.approvals: dict[str, set[str]] = {}
        self.audit: list[dict[str, str]] = []

    def approve(self, case_id: str, record_ids: Iterable[str], reviewer: str = 'supervisor'):
        ids = set(record_ids)
        self.approvals[case_id] = ids
        self.audit.append({'action': 'approve', 'case_id': case_id,
                           'reviewer': reviewer, 'count': str(len(ids))})

    def decrypt_authorized(self, case_id: str, item: SealedRecord, key: bytes) -> Record:
        if item.record_id not in self.approvals.get(case_id, set()):
            raise PermissionError('evidence not approved for this case')
        record = unseal(item, key)
        self.audit.append({'action': 'decrypt', 'case_id': case_id,
                           'reviewer': 'investigator', 'count': '1'})
        return record
