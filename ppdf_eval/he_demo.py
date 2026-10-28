"""Optional REAL additive homomorphic computation with python-paillier (phe).

Paillier supports encrypted sums, NOT encrypted comparisons, general keyword
search, arbitrary encrypted analytics, or K-means without further protocols.
Install separately: pip install phe
"""
from __future__ import annotations
import argparse
import json
import time


def demonstrate(values: list[int], key_bits: int = 2048) -> dict:
    try:
        from phe import paillier
    except ImportError as exc:
        raise RuntimeError('Optional dependency missing. Install with: pip install phe') from exc
    t0 = time.perf_counter()
    public, private = paillier.generate_paillier_keypair(n_length=key_bits)
    t1 = time.perf_counter()
    encrypted = [public.encrypt(v) for v in values]
    t2 = time.perf_counter()
    # Actual addition operates on ciphertext. Decryption is performed only after sum.
    encrypted_sum = sum(encrypted)
    t3 = time.perf_counter()
    decrypted_sum = private.decrypt(encrypted_sum)
    t4 = time.perf_counter()
    if decrypted_sum != sum(values):
        raise AssertionError('homomorphic sum disagrees with plaintext')
    return {'n_values': len(values), 'key_bits': key_bits,
            'expected_sum': sum(values), 'decrypted_sum': decrypted_sum,
            'keygen_ms': 1000*(t1-t0), 'encrypt_ms': 1000*(t2-t1),
            'ciphertext_sum_ms': 1000*(t3-t2), 'decrypt_ms': 1000*(t4-t3),
            'claim': 'only additive homomorphic aggregation demonstrated'}


def main():
    parser = argparse.ArgumentParser(description='Optional Paillier encrypted-sum experiment')
    parser.add_argument('--values', nargs='+', type=int, default=[100, 200, 300, 400])
    parser.add_argument('--key-bits', type=int, default=2048)
    args = parser.parse_args()
    print(json.dumps(demonstrate(args.values, args.key_bits), indent=2))


if __name__ == '__main__':
    main()
