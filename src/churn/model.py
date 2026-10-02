"""A local transition model of idealized control/storage interfaces.

This is not a distributed service, a private resharing implementation, a
Byzantine agreement implementation, or a Nudge patch. "Durable" means a
separate dictionary that the explicit crash transition does not clear.
"Content" is an opaque ideal commitment token, not a deployed commitment.
"Slot" means an additive component, not a complete replicated-share server.
"Ready" authentication is assumed here; real signatures are checked separately.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import TypeAlias
from pathlib import Path
import json

Request: TypeAlias = tuple[str, int]
Content: TypeAlias = tuple[tuple[Request, str], ...]

class Conflict(ValueError):
    pass

@dataclass(frozen=True)
class Seal:
    service: str
    epoch: int
    membership: tuple[str, ...]
    cut: int
    content: Content

@dataclass(frozen=True)
class Descriptor:
    seal: Seal
    attempt: str
    generation: str

@dataclass(frozen=True)
class Share:
    descriptor: Descriptor
    slot: int
    values: tuple[int, ...]

@dataclass(frozen=True)
class Ready:
    descriptor: Descriptor
    slot: int

class Ledger:
    """Ideal linearizable, indefinitely durable log; no garbage collection."""
    def __init__(self, service: str = 'service') -> None:
        self.service = service
        self.receipts: dict[Request, tuple[str, int]] = {}
        self.seals: dict[int, Seal] = {}
        self.active: dict[int, Descriptor] = {}

    def admit(self, request: Request, commitment: str) -> int:
        if len(request) != 2 or not isinstance(request[0], str) or not request[0] or type(request[1]) is not int or request[1] < 0:
            raise ValueError('stable client label and nonnegative sequence required')
        if not isinstance(commitment, str) or not commitment:
            raise ValueError('nonempty ideal commitment token required')
        if request in self.receipts:
            old, receipt = self.receipts[request]
            if old != commitment:
                raise Conflict('identifier already bound to a different commitment')
            return receipt
        receipt = len(self.receipts) + 1
        self.receipts[request] = commitment, receipt
        return receipt

    def seal(self, epoch: int, membership: tuple[str, ...]) -> Seal:
        if type(epoch) is not int or epoch < 0 or len(membership) != 3 or len(set(membership)) != 3:
            raise ValueError('this frozen model requires three distinct slots')
        if epoch in self.seals:
            old = self.seals[epoch]
            if old.membership != membership:
                raise Conflict('epoch membership is immutable')
            return old
        if self.seals and epoch <= max(self.seals):
            raise Conflict('new epochs must be sealed in increasing order')
        # A seal is a snapshot, not a view of the mutable admission dictionary.
        content = tuple(sorted((r, c) for r, (c, _) in self.receipts.items()))
        result = Seal(self.service, epoch, membership, len(self.receipts), content)
        self.seals[epoch] = result
        return result

    def activate(self, descriptor: Descriptor, ready: tuple[Ready, ...]) -> Descriptor:
        epoch = descriptor.seal.epoch
        if self.seals.get(epoch) != descriptor.seal:
            raise Conflict('foreign or stale sealed context')
        if len(ready) != 3 or {r.slot for r in ready} != {0, 1, 2}:
            raise Conflict('exactly one authenticated readiness statement per required slot')
        if any(r.descriptor != descriptor for r in ready):
            raise Conflict('readiness is not bound to one full generation context')
        if epoch in self.active and self.active[epoch] != descriptor:
            raise Conflict('an epoch cannot change generation after activation')
        # No reads of participant storage: durability is an algorithm/primitive obligation.
        self.active[epoch] = descriptor
        return descriptor

class Store:
    def __init__(self, slot: int) -> None:
        if slot not in (0, 1, 2):
            raise ValueError('slot outside the frozen model')
        self.slot = slot
        self.volatile: dict[Descriptor, Share] = {}
        self.durable: dict[Descriptor, Share] = {}
        self.latest: Share | None = None

    def stage(self, share: Share) -> None:
        if share.slot != self.slot:
            raise Conflict('wrong destination slot')
        old = self.durable.get(share.descriptor) or self.volatile.get(share.descriptor)
        if old is not None and old != share:
            raise Conflict('immutable generation slot cannot be overwritten')
        self.volatile[share.descriptor] = share
        # This separate pointer exists only for the deliberately weak baselines.
        self.latest = share

    def persist(self, descriptor: Descriptor) -> None:
        if descriptor in self.volatile:
            share = self.volatile.pop(descriptor)
            old = self.durable.get(descriptor)
            if old is not None and old != share:
                raise Conflict('durable overwrite')
            self.durable[descriptor] = share
        elif descriptor not in self.durable:
            raise Conflict('nothing to persist')

    def ready(self, descriptor: Descriptor) -> Ready:
        if descriptor not in self.durable:
            raise Conflict('READY requires persisted state')
        return Ready(descriptor, self.slot)

    def crash(self) -> None:
        self.volatile.clear()
        self.latest = None

    def read(self, descriptor: Descriptor) -> Share:
        return self.durable[descriptor]


def reconstruct(shares: tuple[Share, ...], modulus: int) -> tuple[int, ...]:
    """Arithmetic decoder only; callers implement their own acceptance policy."""
    if len(shares) != 3 or {s.slot for s in shares} != {0, 1, 2}:
        raise ValueError('three distinct component slots required')
    width = len(shares[0].values)
    if any(len(s.values) != width for s in shares):
        raise ValueError('mismatched vector widths')
    return tuple(sum(s.values[j] for s in shares) % modulus for j in range(width))


def fixture() -> tuple[Ledger, Descriptor, Descriptor, tuple[Share, ...], tuple[Share, ...], tuple[int, ...]]:
    """Trusted test-input generator stands in for a jointly consistent resharing oracle.

    The central generator knows all secrets and masks. This code offers no
    privacy: that is why the primitive is explicit rather than hidden here.
    """
    data = json.loads((Path(__file__).resolve().parents[2]/'inputs'/'sparse_ratings.json').read_text())
    ratings = data['ratings']
    if data['modulus'] != 101 or len(ratings) != 8 or data['clients'] != 4 or data['items'] != 8:
        raise ValueError('input does not match the frozen finite domain')
    ids = [(r['client'], r['sequence']) for r in ratings]
    cells = [(r['client'], r['item']) for r in ratings]
    if len(set(ids)) != 8 or len(set(cells)) != 8:
        raise ValueError('duplicate input ID or sparse coordinate')
    if any(r['client'] not in {f'client-{i}' for i in range(4)} or type(r['item']) is not int or not 0 <= r['item'] < 8 or r['value'] != 1 for r in ratings):
        raise ValueError('input outside the declared binary sparse fixture')
    ledger = Ledger()
    for r in ratings:
        ledger.admit((r['client'], r['sequence']), r['commitment'])
    seal = ledger.seal(0, ('slot-0', 'slot-1', 'slot-2'))
    d_a = Descriptor(seal, 'attempt', 'joint-output-A')
    d_b = Descriptor(seal, 'attempt', 'joint-output-B')
    # Eight admitted binary ratings occupy eight cells in a 4 x 8 oracle matrix.
    secrets = tuple(r['value'] for r in ratings)
    comps_a = (tuple(10+j for j in range(8)), tuple(20+2*j for j in range(8)),
               tuple((1-(10+j)-(20+2*j)) % 101 for j in range(8)))
    comps_b = (tuple((x+1) % 101 for x in comps_a[0]),
               tuple((x+2) % 101 for x in comps_a[1]),
               tuple((x-3) % 101 for x in comps_a[2]))
    a = tuple(Share(d_a, i, comps_a[i]) for i in range(3))
    b = tuple(Share(d_b, i, comps_b[i]) for i in range(3))
    return ledger, d_a, d_b, a, b, secrets
