"""Exact finite checks, not a cryptographic implementation or a general proof.

All arithmetic inputs are synthetic. No remote systems, keys, datasets, or
protocol implementations are targeted by the negative controls.
"""
from __future__ import annotations

from collections import Counter
from itertools import combinations, product
from typing import Iterable


def replicated(secret: int, r0: int, r1: int, modulus: int) -> tuple[int, int, int]:
    """Three additive components; each replicated-share server holds two."""
    return r0 % modulus, r1 % modulus, (secret - r0 - r1) % modulus


def interpolate_zero(points: tuple[int, ...], values: tuple[int, ...], q: int) -> int:
    if len(points) != len(values) or not points or len(set(points)) != len(points):
        raise ValueError('distinct, nonempty, matching interpolation inputs required')
    if any(x % q == 0 for x in points):
        raise ValueError('zero is not a shareholder coordinate')
    answer = 0
    for i, (x, y) in enumerate(zip(points, values)):
        numerator, denominator = 1, 1
        for j, other in enumerate(points):
            if j != i:
                numerator = numerator * (-other) % q
                denominator = denominator * (x - other) % q
        answer = (answer + y * numerator * pow(denominator, -1, q)) % q
    return answer


def replicated_checks(q: int) -> tuple[list[dict], int]:
    """Enumerate two generations, all three component selectors, all secrets.

    One obligation = one selected component vector compared with the expected
    secret. Per-selector counts are retained, not just an aggregate pass count.
    """
    if q not in (3, 5):
        raise ValueError('the frozen exhaustive domains are q=3 (pilot), q=5 (main)')
    rows: list[dict] = []
    obligations = 0
    # The oracle here uses the source secret, not a production verifier.
    for selector in product((0, 1), repeat=3):
        for secret in range(q):
            errors: Counter[int] = Counter()
            for masks in product(range(q), repeat=4):
                a = replicated(secret, masks[0], masks[1], q)
                b = replicated(secret, masks[2], masks[3], q)
                vector = tuple((a, b)[selector[i]][i] for i in range(3))
                errors[(sum(vector) - secret) % q] += 1
                obligations += 1
            homogeneous = len(set(selector)) == 1
            expected = {0: q**4} if homogeneous else {e: q**3 for e in range(q)}
            if dict(errors) != expected:
                raise AssertionError(('replicated distribution', selector, secret, dict(errors), expected))
            rows.append(dict(scheme='replicated-additive', modulus=q,
                             selector=''.join(map(str, selector)), points='components-012',
                             secret=secret, assignments=q**4, correct=errors[0],
                             incorrect=q**4-errors[0], homogeneous=int(homogeneous),
                             error_histogram=';'.join(f'{e}:{errors[e]}' for e in range(q))))
    return rows, obligations


def shamir_checks(q: int) -> tuple[list[dict], int]:
    if q not in (3, 5):
        raise ValueError('unsupported exhaustive field')
    rows: list[dict] = []
    obligations = 0
    available = tuple(range(1, min(q, 4)))
    for points in combinations(available, 2):
        for selector in product((0, 1), repeat=2):
            for secret in range(q):
                errors: Counter[int] = Counter()
                for a, b in product(range(q), repeat=2):
                    values = tuple((secret + (a, b)[selector[i]] * x) % q
                                   for i, x in enumerate(points))
                    errors[(interpolate_zero(points, values, q) - secret) % q] += 1
                    obligations += 1
                homogeneous = len(set(selector)) == 1
                expected = {0:q*q} if homogeneous else {e:q for e in range(q)}
                if dict(errors) != expected:
                    raise AssertionError(('Shamir distribution', points, selector, secret, dict(errors)))
                rows.append(dict(scheme='Shamir-2-of-3' if q==5 else 'Shamir-2-of-2',
                                 modulus=q, selector=''.join(map(str,selector)),
                                 points='-'.join(map(str,points)), secret=secret,
                                 assignments=q*q, correct=errors[0], incorrect=q*q-errors[0],
                                 homogeneous=int(homogeneous),
                                 error_histogram=';'.join(f'{e}:{errors[e]}' for e in range(q))))
    return rows, obligations


def ring_checks() -> tuple[list[dict], int]:
    """A non-field control: error distribution is uniform on its image ideal.

    This checks the important distinction between an arbitrary linear sharing
    over Z/(2^w) and replicated additive sharing, whose mixed coefficients
    include a unit. These are arithmetic checks, not refresh/leakage studies.
    """
    from math import gcd
    rows = []
    obligations = 0
    for modulus in (4, 8, 16):
        for coefficient in (0, 1, 2, 4):
            errors = Counter(coefficient*r % modulus for r in range(modulus))
            d = gcd(modulus, coefficient)
            expected = {e:d for e in range(0,modulus,d)}
            if dict(errors) != expected:
                raise AssertionError(('ring image', modulus, coefficient))
            obligations += modulus
            rows.append(dict(modulus=modulus, coefficient=coefficient, image_step=d,
                             assignments=modulus, correct=errors[0],
                             correct_fraction=f'{d}/{modulus}',
                             error_histogram=';'.join(f'{e}:{errors[e]}' for e in range(modulus))))
    return rows, obligations


def mixed_counterexample() -> dict:
    # Two successful generations for the same scalar, same content commitment.
    secret, q = 37, 101
    a = replicated(secret, 10, 20, q)
    b = replicated(secret, 11, 22, q)
    selected = (a[0], a[1], b[2])
    return dict(modulus=q, secret=secret, generation_a=list(a), generation_b=list(b),
                selector='001', selected=list(selected), reconstruction=sum(selected)%q)
