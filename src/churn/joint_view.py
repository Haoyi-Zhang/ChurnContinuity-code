"""Independent joint-view checks for the one-replacement privacy argument.

The checker is deliberately separate from ``continuity.py``.  It models one
scalar coordinate of the replicated sharing in exponent space for a cyclic
prime-order Pedersen group.  If ``h`` is a generator and ``g=h**alpha``, then
``Com(v;r)`` is represented by ``r + alpha*v (mod q)``.  Mapping that exponent
back to a group element is bijective, so equality of exponent-view
histograms is equality of the corresponding group-element transcripts.

This is a finite/model-conformance check, not a proof of discrete-log hardness
or signature security.  Actual signature bytes are excluded: for fixed keys
independent of the secret, signing is post-processing of the statement bodies
already represented by the public commitments and constant context metadata.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from itertools import product
from typing import Iterable


ROLES = ("retiring", "survivor-a", "survivor-b", "replacement")
VARIABLES = ("z0", "z1", "r0", "r1", "r2", "delta1", "delta2", "tau1", "tau2")


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _commit(value: int, blinding: int, *, q: int, alpha: int) -> int:
    return (blinding + alpha * value) % q


def joint_view(
    secret: int,
    randomness: Iterable[int],
    *,
    role: str,
    q: int,
    alpha: int,
) -> tuple[int, ...]:
    """Return the private openings plus the correlated public transcript.

    The replaced slot is k=0, with survivors a=1 and b=2.  The public suffix is
    ``(C0,C1,C2,D1,D2,C0',C1',C2')``.  The private prefix is exactly the
    opening/mask material delivered to the named protocol-following role.
    Constant context, signer, target, and receipt labels are omitted because
    they are identical for every secret.
    """
    if role not in ROLES:
        raise ValueError("unknown role")
    if type(q) is not int or q < 2 or type(alpha) is not int or not 0 < alpha < q:
        raise ValueError("prime-order field and nonzero generator logarithm required")
    values = tuple(randomness)
    if len(values) != len(VARIABLES) or any(type(value) is not int or not 0 <= value < q for value in values):
        raise ValueError("nine canonical field elements required")
    if type(secret) is not int or not 0 <= secret < q:
        raise ValueError("canonical secret required")

    z0, z1, r0, r1, r2, delta1, delta2, tau1, tau2 = values
    z2 = (secret - z0 - z1) % q

    new0 = (z0 - delta1 - delta2) % q
    new1 = (z1 + delta1) % q
    new2 = (z2 + delta2) % q
    new_r0 = (r0 - tau1 - tau2) % q
    new_r1 = (r1 + tau1) % q
    new_r2 = (r2 + tau2) % q

    c0 = _commit(z0, r0, q=q, alpha=alpha)
    c1 = _commit(z1, r1, q=q, alpha=alpha)
    c2 = _commit(z2, r2, q=q, alpha=alpha)
    d1 = _commit(delta1, tau1, q=q, alpha=alpha)
    d2 = _commit(delta2, tau2, q=q, alpha=alpha)
    new_c0 = _commit(new0, new_r0, q=q, alpha=alpha)
    new_c1 = _commit(new1, new_r1, q=q, alpha=alpha)
    new_c2 = _commit(new2, new_r2, q=q, alpha=alpha)

    if new_c1 != (c1 + d1) % q:
        raise AssertionError("C1' link failed")
    if new_c2 != (c2 + d2) % q:
        raise AssertionError("C2' link failed")
    if new_c0 != (c0 - d1 - d2) % q:
        raise AssertionError("C0' link failed")
    if (new0 + new1 + new2) % q != secret:
        raise AssertionError("resharing changed the secret")

    if role == "retiring":
        private = (z1, r1, z2, r2)
        opening_checks = (
            _commit(z1, r1, q=q, alpha=alpha) == c1,
            _commit(z2, r2, q=q, alpha=alpha) == c2,
        )
    elif role == "survivor-a":
        # Physical P1 holds components 0 and 2, samples mask 2, and receives mask 1.
        private = (
            z0, r0, z2, r2,
            delta1, tau1, delta2, tau2,
            new0, new_r0, new2, new_r2,
        )
        opening_checks = (
            _commit(z0, r0, q=q, alpha=alpha) == c0,
            _commit(z2, r2, q=q, alpha=alpha) == c2,
            _commit(delta1, tau1, q=q, alpha=alpha) == d1,
            _commit(delta2, tau2, q=q, alpha=alpha) == d2,
            _commit(new0, new_r0, q=q, alpha=alpha) == new_c0,
            _commit(new2, new_r2, q=q, alpha=alpha) == new_c2,
        )
    elif role == "survivor-b":
        # Physical P2 holds components 0 and 1, samples mask 1, and receives mask 2.
        private = (
            z0, r0, z1, r1,
            delta1, tau1, delta2, tau2,
            new0, new_r0, new1, new_r1,
        )
        opening_checks = (
            _commit(z0, r0, q=q, alpha=alpha) == c0,
            _commit(z1, r1, q=q, alpha=alpha) == c1,
            _commit(delta1, tau1, q=q, alpha=alpha) == d1,
            _commit(delta2, tau2, q=q, alpha=alpha) == d2,
            _commit(new0, new_r0, q=q, alpha=alpha) == new_c0,
            _commit(new1, new_r1, q=q, alpha=alpha) == new_c1,
        )
    else:
        # The replacement receives two mask-plus-component openings.
        private = (
            delta1, tau1, new1, new_r1,
            delta2, tau2, new2, new_r2,
        )
        opening_checks = (
            _commit(delta1, tau1, q=q, alpha=alpha) == d1,
            _commit(delta2, tau2, q=q, alpha=alpha) == d2,
            _commit(new1, new_r1, q=q, alpha=alpha) == new_c1,
            _commit(new2, new_r2, q=q, alpha=alpha) == new_c2,
        )

    if not all(opening_checks):
        raise AssertionError("a visible opening failed in the generated view")
    public = (c0, c1, c2, d1, d2, new_c0, new_c1, new_c2)
    return private + public


def _rank(matrix: list[list[int]], q: int) -> int:
    work = [[entry % q for entry in row] for row in matrix]
    if not work:
        return 0
    rows = len(work)
    columns = len(work[0])
    pivot_row = 0
    for column in range(columns):
        pivot = next((row for row in range(pivot_row, rows) if work[row][column] % q), None)
        if pivot is None:
            continue
        work[pivot_row], work[pivot] = work[pivot], work[pivot_row]
        inverse = pow(work[pivot_row][column], -1, q)
        work[pivot_row] = [(entry * inverse) % q for entry in work[pivot_row]]
        for row in range(rows):
            if row == pivot_row:
                continue
            factor = work[row][column] % q
            if factor:
                work[row] = [
                    (left - factor * right) % q
                    for left, right in zip(work[row], work[pivot_row])
                ]
        pivot_row += 1
        if pivot_row == rows:
            break
    return pivot_row


def _solve(matrix: list[list[int]], target: list[int], q: int) -> list[int] | None:
    """Solve A*x=target over F_q, returning one canonical solution."""
    rows = len(matrix)
    columns = len(matrix[0]) if rows else 0
    augmented = [
        [matrix[row][column] % q for column in range(columns)] + [target[row] % q]
        for row in range(rows)
    ]
    pivot_columns: list[int] = []
    pivot_row = 0
    for column in range(columns):
        pivot = next((row for row in range(pivot_row, rows) if augmented[row][column] % q), None)
        if pivot is None:
            continue
        augmented[pivot_row], augmented[pivot] = augmented[pivot], augmented[pivot_row]
        inverse = pow(augmented[pivot_row][column], -1, q)
        augmented[pivot_row] = [(entry * inverse) % q for entry in augmented[pivot_row]]
        for row in range(rows):
            if row == pivot_row:
                continue
            factor = augmented[row][column] % q
            if factor:
                augmented[row] = [
                    (left - factor * right) % q
                    for left, right in zip(augmented[row], augmented[pivot_row])
                ]
        pivot_columns.append(column)
        pivot_row += 1
        if pivot_row == rows:
            break
    for row in range(rows):
        if all(augmented[row][column] % q == 0 for column in range(columns)) and augmented[row][-1] % q:
            return None
    solution = [0] * columns
    for row, column in enumerate(pivot_columns):
        solution[column] = augmented[row][-1] % q
    return solution


@dataclass(frozen=True)
class RankCheck:
    role: str
    field_modulus: int
    generator_log: int
    view_dimension: int
    randomness_rank: int
    augmented_rank: int
    secret_shift_witness: tuple[int, ...]


def rank_check(*, role: str, q: int, alpha: int) -> RankCheck:
    zero_randomness = (0,) * len(VARIABLES)
    origin = joint_view(0, zero_randomness, role=role, q=q, alpha=alpha)
    columns: list[tuple[int, ...]] = []
    for index in range(len(VARIABLES)):
        basis = [0] * len(VARIABLES)
        basis[index] = 1
        current = joint_view(0, basis, role=role, q=q, alpha=alpha)
        columns.append(tuple((right - left) % q for left, right in zip(origin, current)))
    secret_view = joint_view(1, zero_randomness, role=role, q=q, alpha=alpha)
    secret_shift = [(right - left) % q for left, right in zip(origin, secret_view)]
    matrix = [list(row) for row in zip(*columns)]
    randomness_rank = _rank(matrix, q)
    augmented = [row + [secret_shift[index]] for index, row in enumerate(matrix)]
    augmented_rank = _rank(augmented, q)
    witness = _solve(matrix, secret_shift, q)
    if randomness_rank != augmented_rank or witness is None:
        raise AssertionError(("joint view depends on the secret", role, q, alpha))
    # Directly verify A*w equals the secret-shift column.
    reconstructed = [
        sum(matrix[row][column] * witness[column] for column in range(len(witness))) % q
        for row in range(len(matrix))
    ]
    if reconstructed != secret_shift:
        raise AssertionError("rank witness failed")
    return RankCheck(
        role=role,
        field_modulus=q,
        generator_log=alpha,
        view_dimension=len(origin),
        randomness_rank=randomness_rank,
        augmented_rank=augmented_rank,
        secret_shift_witness=tuple(witness),
    )


def exact_histogram_rows(q: int = 2) -> tuple[list[dict[str, object]], int]:
    """Enumerate all full joint views in a small exact field.

    F_2 keeps this auxiliary check below the project's frozen enumeration budget:
    4 roles * 2 secrets * 2^9 randomness assignments = 4,096 views.
    """
    if q != 2:
        raise ValueError("the retained exact joint-transcript domain is F_2")
    alpha = 1
    histograms: dict[tuple[str, int], Counter[tuple[int, ...]]] = {}
    assignments = 0
    for role in ROLES:
        for secret in range(q):
            counter: Counter[tuple[int, ...]] = Counter()
            for randomness in product(range(q), repeat=len(VARIABLES)):
                counter[joint_view(secret, randomness, role=role, q=q, alpha=alpha)] += 1
                assignments += 1
            histograms[(role, secret)] = counter

    rows: list[dict[str, object]] = []
    for role in ROLES:
        reference = histograms[(role, 0)]
        for secret in range(q):
            current = histograms[(role, secret)]
            if current != reference:
                raise AssertionError(("full joint histogram differs", role, secret))
            digest = hashlib.sha256(
                _canonical(sorted((list(view), count) for view, count in current.items()))
            ).hexdigest()
            rows.append({
                "role": role,
                "secret": secret,
                "field_modulus": q,
                "generator_log": alpha,
                "randomness_assignments": q ** len(VARIABLES),
                "distinct_joint_views": len(current),
                "maximum_multiplicity": max(current.values()),
                "distribution_digest": digest,
                "matches_secret_zero": 1,
                "includes_private_openings": 1,
                "includes_blindings": 1,
                "includes_correlated_commitments": 1,
                "includes_signature_bytes": 0,
            })
    return rows, assignments


def compute_report() -> tuple[list[dict[str, object]], dict[str, object]]:
    rows, assignments = exact_histogram_rows()
    rank_rows: list[dict[str, object]] = []
    for q, alphas in (
        (3, range(1, 3)),
        (5, range(1, 5)),
        (7, range(1, 7)),
        (1019, (1, 2, 17, 511)),
    ):
        for alpha in alphas:
            for role in ROLES:
                result = rank_check(role=role, q=q, alpha=alpha)
                rank_rows.append({
                    "role": result.role,
                    "field_modulus": result.field_modulus,
                    "generator_log": result.generator_log,
                    "view_dimension": result.view_dimension,
                    "randomness_rank": result.randomness_rank,
                    "augmented_rank": result.augmented_rank,
                    "secret_shift_witness": list(result.secret_shift_witness),
                })
    report: dict[str, object] = {
        "checker": "joint-private-public-view",
        "scope": "one scalar, one replacement at slot 0, four protocol-following physical roles",
        "exact_field": 2,
        "exact_assignments": assignments,
        "exact_distribution_comparisons": len(rows),
        "all_exact_distributions_equal": all(row["matches_secret_zero"] for row in rows),
        "rank_checks": len(rank_rows),
        "all_rank_checks_passed": all(
            row["randomness_rank"] == row["augmented_rank"] for row in rank_rows
        ),
        "roles": list(ROLES),
        "random_variables": list(VARIABLES),
        "view_includes": [
            "role-visible component values and component blindings",
            "role-visible mask values and mask blindings",
            "C0,C1,C2,D1,D2,C0-prime,C1-prime,C2-prime",
            "all three commitment-link relations",
        ],
        "view_excludes": [
            "actual signature bytes (fixed-key signing is post-processing of represented statements)",
            "cryptographic hardness of the tiny cyclic group",
            "multiple vector coordinates",
            "malicious deviations and mobile corruption",
        ],
        "rank_results": rank_rows,
        "interpretation": (
            "The exact F_2 histograms and finite-field rank witnesses are model-conformance "
            "checks for the written role simulators. They do not replace the general proof."
        ),
    }
    return rows, report
