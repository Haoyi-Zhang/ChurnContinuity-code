"""Continuity certificates for one replacement in 2-of-3 replicated sharing.

This module is a benign, local reference model.  It instantiates the algebra in
an intentionally tiny safe-prime group so exhaustive checks are cheap.  The
small group is *not* a production security parameter; computational binding in
the paper is a standard assumption for a real large group with independently
derived generators.

Replicated layout for additive components z_0,z_1,z_2:
    physical server i stores every component except z_i.
Replacing slot k leaves survivors a=(k+1) mod 3 and b=(k+2) mod 3.  Survivor a
refreshes z_b by +delta_b, survivor b refreshes z_a by +delta_a, and both
refresh their common z_k by -delta_a-delta_b.  No party receives all three
components.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from functools import lru_cache
from typing import Any, Iterable
import copy
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .evidence import fixture_key, public_bytes


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _hash_hex(domain: str, value: Any) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + _canonical(value)).hexdigest()


def vec_add(left: Iterable[int], right: Iterable[int], q: int) -> tuple[int, ...]:
    a, b = tuple(left), tuple(right)
    if len(a) != len(b):
        raise ValueError("vector dimensions differ")
    return tuple((x + y) % q for x, y in zip(a, b))


def vec_sub(left: Iterable[int], right: Iterable[int], q: int) -> tuple[int, ...]:
    a, b = tuple(left), tuple(right)
    if len(a) != len(b):
        raise ValueError("vector dimensions differ")
    return tuple((x - y) % q for x, y in zip(a, b))


def vec_sum(*values: Iterable[int], q: int) -> tuple[int, ...]:
    values = tuple(tuple(v) for v in values)
    if not values:
        return ()
    out = (0,) * len(values[0])
    for value in values:
        out = vec_add(out, value, q)
    return out


@dataclass(frozen=True)
class TinyVectorPedersen:
    """Deterministic toy vector-Pedersen group for structural checks only."""

    p: int = 2039
    q: int = 1019

    def _generator(self, label: str) -> int:
        # Hash a field element and square it into the order-q subgroup.  Unlike
        # g**H(label), this does not publish a discrete-log relation to a fixed
        # base.  The group itself remains tiny and therefore non-secure.
        counter = 0
        while True:
            raw = hashlib.sha256(f"continuity-generator:{label}:{counter}".encode("ascii")).digest()
            x = int.from_bytes(raw, "big") % self.p
            y = (x * x) % self.p
            if y not in (0, 1) and pow(y, self.q, self.p) == 1:
                return y
            counter += 1

    @property
    def h(self) -> int:
        if type(self) is TinyVectorPedersen and type(self.p) is int and type(self.q) is int:
            return _public_generator(self.p, self.q, "blinding")
        return self._generator("blinding")

    def g(self, index: int) -> int:
        if type(index) is not int or index < 0:
            raise ValueError("nonnegative generator index required")
        if (index < 64 and type(self) is TinyVectorPedersen and
                type(self.p) is int and type(self.q) is int):
            return _public_generator(self.p, self.q, f"coordinate:{index}")
        return self._generator(f"coordinate:{index}")

    def validate_vector(self, values: Iterable[int]) -> tuple[int, ...]:
        result = tuple(values)
        if not result:
            raise ValueError("nonempty vector required")
        if any(type(v) is not int or not 0 <= v < self.q for v in result):
            raise ValueError("vector entries must be canonical field elements")
        return result

    def commit(self, values: Iterable[int], blinding: int) -> int:
        values = self.validate_vector(values)
        if type(blinding) is not int or not 0 <= blinding < self.q:
            raise ValueError("canonical blinding required")
        out = pow(self.h, blinding, self.p)
        for i, value in enumerate(values):
            out = (out * pow(self.g(i), value, self.p)) % self.p
        return out

    def is_subgroup_element(self, element: int) -> bool:
        return (type(element) is int and 1 <= element < self.p and
                pow(element, self.q, self.p) == 1)

    def mul(self, *elements: int) -> int:
        out = 1
        for element in elements:
            if type(element) is not int or not 1 <= element < self.p:
                raise ValueError("invalid group element")
            out = out * element % self.p
        return out

    def inv(self, element: int) -> int:
        if type(element) is not int or not 1 <= element < self.p:
            raise ValueError("invalid group element")
        return pow(element, -1, self.p)

    def div(self, numerator: int, denominator: int) -> int:
        return self.mul(numerator, self.inv(denominator))


@lru_cache(maxsize=256)
def _public_generator(p: int, q: int, label: str) -> int:
    """Reuse only public group/label constants, using the unchanged derivation.

    h and coordinates 0..63 use this bounded cache; other coordinates and
    customized subclasses retain their uncached behavior. No opening, mask,
    blinding, signed statement, or verification result enters the cache.
    """
    return TinyVectorPedersen(p, q)._generator(label)


@dataclass(frozen=True)
class TransferContext:
    service: str
    epoch: int
    cut_root: str
    old_members: tuple[str, str, str]
    new_members: tuple[str, str, str]
    replaced_slot: int
    session: str
    generation: str
    dimension: int
    field_modulus: int = 1019
    group_modulus: int = 2039

    def validate(self) -> None:
        labels = (self.service, self.cut_root, self.session, self.generation)
        if any(not isinstance(value, str) or not 0 < len(value) <= 128 for value in labels):
            raise ValueError("context labels must contain 1--128 characters")
        if type(self.epoch) is not int or not 0 <= self.epoch < 2**63:
            raise ValueError("bounded nonnegative epoch required")
        if type(self.replaced_slot) is not int or self.replaced_slot not in (0, 1, 2):
            raise ValueError("replacement slot must be 0, 1, or 2")
        if (not isinstance(self.old_members, tuple) or not isinstance(self.new_members, tuple) or
                len(self.old_members) != 3 or len(self.new_members) != 3 or
                any(not isinstance(member, str) or not 0 < len(member) <= 128
                    for member in self.old_members + self.new_members) or
                len(set(self.old_members)) != 3 or len(set(self.new_members)) != 3):
            raise ValueError("three distinct bounded old and new member labels required")
        changed = [i for i in range(3) if self.old_members[i] != self.new_members[i]]
        if changed != [self.replaced_slot]:
            raise ValueError("exactly the declared physical slot must change")
        if type(self.dimension) is not int or self.dimension <= 0 or self.dimension > 64:
            raise ValueError("dimension outside frozen bound")
        if (type(self.field_modulus) is not int or type(self.group_modulus) is not int or
                (self.field_modulus, self.group_modulus) != (1019, 2039)):
            raise ValueError("this reference implementation uses the frozen toy group")

    def identifier(self) -> str:
        self.validate()
        return _hash_hex("continuity-context", asdict(self))


def validate_serial_contexts(contexts: Iterable[TransferContext]) -> tuple[TransferContext, ...]:
    """Validate an activated serial chain and its static-identity privacy scope.

    Every transition must consume the exact prior membership and keep the same
    service, epoch, cut, dimension, and arithmetic domain.  Server identities
    are permanently bound to one physical slot for the analyzed chain: once an
    identity leaves, it cannot re-enter.  This explicit no-reentry condition is
    what prevents a nominally static corrupt identity from accumulating views
    from different replicated slots.
    """
    chain = tuple(contexts)
    if not chain:
        raise ValueError("nonempty serial context chain required")
    for context in chain:
        context.validate()

    first = chain[0]
    invariant = (
        first.service, first.epoch, first.cut_root, first.dimension,
        first.field_modulus, first.group_modulus,
    )
    current = first.old_members
    historical_slots = {member: slot for slot, member in enumerate(current)}
    seen_contexts: set[str] = set()
    seen_sessions: set[str] = set()
    seen_generations: set[str] = set()

    for context in chain:
        if (context.service, context.epoch, context.cut_root, context.dimension,
                context.field_modulus, context.group_modulus) != invariant:
            raise ValueError("serial chain changed its epoch, cut, dimension, or arithmetic domain")
        if context.old_members != current:
            raise ValueError("serial chain does not consume the prior activated membership")
        context_id = context.identifier()
        if (context_id in seen_contexts or context.session in seen_sessions or
                context.generation in seen_generations):
            raise ValueError("activated transitions require fresh context, session, and generation identifiers")
        seen_contexts.add(context_id)
        seen_sessions.add(context.session)
        seen_generations.add(context.generation)

        slot = context.replaced_slot
        removed = context.old_members[slot]
        incoming = context.new_members[slot]
        if historical_slots.get(removed) != slot:
            raise ValueError("server identity migrated across physical slots")
        if incoming in historical_slots:
            raise ValueError("retired or previously seen server identity cannot re-enter the chain")
        historical_slots[incoming] = slot
        current = context.new_members

    return chain


@dataclass(frozen=True)
class Opening:
    values: tuple[int, ...]
    blinding: int


@dataclass(frozen=True)
class ReplicatedState:
    members: tuple[str, str, str]
    components: tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...]]
    blindings: tuple[int, int, int]
    commitments: tuple[int, int, int]

    def validate(self, group: TinyVectorPedersen) -> None:
        if len(set(self.members)) != 3:
            raise ValueError("three distinct members required")
        dimension = len(self.components[0])
        if dimension <= 0 or any(len(component) != dimension for component in self.components):
            raise ValueError("component dimensions differ")
        for component, blinding, commitment in zip(self.components, self.blindings, self.commitments):
            if group.commit(component, blinding) != commitment:
                raise ValueError("component does not open its commitment")

    def secret(self, q: int) -> tuple[int, ...]:
        return vec_sum(*self.components, q=q)

    def holdings(self, slot: int) -> dict[int, Opening]:
        if slot not in (0, 1, 2):
            raise ValueError("invalid physical slot")
        return {index: Opening(self.components[index], self.blindings[index])
                for index in range(3) if index != slot}


@dataclass(frozen=True)
class Statement:
    context_id: str
    kind: str
    signer: str
    role: str
    body: dict[str, Any]

    def encode(self) -> bytes:
        return b"continuity-statement\x00" + _canonical(asdict(self))


@dataclass(frozen=True)
class SignedStatement:
    statement: Statement
    signature: bytes

    def export(self) -> dict[str, Any]:
        return {"statement": asdict(self.statement), "signature_hex": self.signature.hex()}


def sign_statement(statement: Statement, key: Ed25519PrivateKey) -> SignedStatement:
    return SignedStatement(statement, key.sign(statement.encode()))


def verify_signed(statement: SignedStatement, authorization: dict[str, bytes]) -> bool:
    key = authorization.get(statement.statement.signer)
    if key is None:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(statement.signature, statement.statement.encode())
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def fixture_authorization(members: Iterable[str]) -> tuple[dict[str, Ed25519PrivateKey], dict[str, bytes]]:
    names = tuple(members)
    if len(names) != len(set(names)):
        raise ValueError("duplicate signer")
    private = {name: fixture_key("continuity:" + name) for name in names}
    public = {name: public_bytes(key) for name, key in private.items()}
    return private, public


class DurableServer:
    """Explicit durable session/component/outbox model.

    A crash clears only ``volatile``.  Session masks, signed outbound messages,
    verified component openings, and receipts are immutable durable facts.
    """

    def __init__(self, name: str, physical_slot: int, group: TinyVectorPedersen) -> None:
        if physical_slot not in (0, 1, 2):
            raise ValueError("invalid physical slot")
        self.name = name
        self.physical_slot = physical_slot
        self.group = group
        self.durable_masks: dict[tuple[str, int], Opening] = {}
        self.durable_components: dict[tuple[str, int], Opening] = {}
        self.durable_outbox: dict[tuple[str, str], SignedStatement] = {}
        self.volatile: dict[str, Any] = {}

    def persist_mask(self, context: TransferContext, target_component: int,
                     opening: Opening, commitment: int) -> None:
        context.validate()
        if context.old_members[self.physical_slot] != self.name:
            raise ValueError("old server identity/slot mismatch")
        k = context.replaced_slot
        a, b = (k + 1) % 3, (k + 2) % 3
        expected_target = b if self.physical_slot == a else a if self.physical_slot == b else None
        if target_component != expected_target:
            raise ValueError("server is not the sampler for this target component")
        if len(opening.values) != context.dimension:
            raise ValueError("mask dimension does not match transfer context")
        if self.group.commit(opening.values, opening.blinding) != commitment:
            raise ValueError("mask opening does not match commitment")
        key = (context.identifier(), target_component)
        old = self.durable_masks.get(key)
        if old is not None and old != opening:
            raise ValueError("durable session mask is immutable")
        self.durable_masks[key] = opening

    def prepare_survivor_transfer(
        self,
        context: TransferContext,
        target_component: int,
        old_opening: Opening,
        old_commitment: int,
        mask_opening: Opening,
        mask_commitment: int,
        new_commitment: int,
        peer: str,
        replacement: str,
        key: Ed25519PrivateKey,
    ) -> tuple[SignedStatement, SignedStatement, SignedStatement]:
        """Persist one survivor session completely before exposing messages.

        The replacement component is derived only from the sender's local old
        opening and its own persisted mask.  No expected global new opening is
        accepted as input.  The method returns only after the mask and all three
        signed outbox entries are durable in this reference transition system.
        """
        self.persist_mask(context, target_component, mask_opening, mask_commitment)
        return self.resume_survivor_transfer(
            context, target_component, old_opening, old_commitment,
            mask_commitment, new_commitment, peer, replacement, key,
        )

    def _build_survivor_transfer(
        self,
        context: TransferContext,
        target_component: int,
        old_opening: Opening,
        old_commitment: int,
        mask_commitment: int,
        new_commitment: int,
        peer: str,
        replacement: str,
        key: Ed25519PrivateKey,
    ) -> tuple[SignedStatement, SignedStatement, SignedStatement]:
        """Reconstruct the deterministic session messages from durable state."""
        context.validate()
        if context.old_members[self.physical_slot] != self.name:
            raise ValueError("old server identity/slot mismatch")
        k = context.replaced_slot
        a, b = (k + 1) % 3, (k + 2) % 3
        if self.physical_slot == a:
            expected_target, expected_peer = b, context.old_members[b]
        elif self.physical_slot == b:
            expected_target, expected_peer = a, context.old_members[a]
        else:
            raise ValueError("retiring server cannot prepare a survivor transfer")
        if target_component != expected_target or peer != expected_peer:
            raise ValueError("incorrect target or peer for survivor slot")
        if replacement != context.new_members[k]:
            raise ValueError("incorrect replacement identity")
        if len(old_opening.values) != context.dimension:
            raise ValueError("old component dimension does not match context")
        if self.group.commit(old_opening.values, old_opening.blinding) != old_commitment:
            raise ValueError("local old opening does not match certified commitment")
        try:
            persisted_mask = self.durable_masks[(context.identifier(), target_component)]
        except KeyError as exc:
            raise ValueError("cannot build messages before the session mask is durable") from exc
        if self.group.commit(persisted_mask.values, persisted_mask.blinding) != mask_commitment:
            raise ValueError("durable mask does not match the proposed commitment")
        component_opening = Opening(
            vec_add(old_opening.values, persisted_mask.values, self.group.q),
            (old_opening.blinding + persisted_mask.blinding) % self.group.q,
        )
        if self.group.commit(component_opening.values, component_opening.blinding) != new_commitment:
            raise ValueError("locally derived replacement component misses new commitment")

        context_id = context.identifier()
        proposal = sign_statement(
            _statement(
                context_id, "MASK_COMMIT", self.name, "SURVIVOR_PROPOSAL",
                target_component=target_component,
                mask_commitment=mask_commitment,
                dimension=context.dimension,
            ),
            key,
        )
        peer_opening = sign_statement(
            _statement(
                context_id, "MASK_OPENING", self.name, "PRIVATE_OPENING",
                target_component=target_component, recipient=peer,
                values=list(persisted_mask.values), blinding=persisted_mask.blinding,
                mask_commitment=mask_commitment, dimension=context.dimension,
            ),
            key,
        )
        replacement_opening = sign_statement(
            _statement(
                context_id, "MASK_COMPONENT_OPENING", self.name, "PRIVATE_OPENING",
                target_component=target_component, recipient=replacement,
                values=list(persisted_mask.values), blinding=persisted_mask.blinding,
                mask_commitment=mask_commitment, dimension=context.dimension,
                component=target_component,
                component_values=list(component_opening.values),
                component_blinding=component_opening.blinding,
                component_commitment=new_commitment,
            ),
            key,
        )
        return proposal, peer_opening, replacement_opening

    def persist_survivor_outbox_item(
        self,
        context: TransferContext,
        target_component: int,
        old_opening: Opening,
        old_commitment: int,
        mask_commitment: int,
        new_commitment: int,
        peer: str,
        replacement: str,
        key: Ed25519PrivateKey,
        label: str,
    ) -> SignedStatement:
        """Persist one deterministically reconstructed sender-side message."""
        messages = self._build_survivor_transfer(
            context, target_component, old_opening, old_commitment,
            mask_commitment, new_commitment, peer, replacement, key,
        )
        labels = (
            f"proposal:{target_component}",
            f"peer-mask:{target_component}",
            f"replacement-component:{target_component}",
        )
        try:
            index = labels.index(label)
        except ValueError as exc:
            raise ValueError("unknown survivor outbox label") from exc
        context_id = context.identifier()
        self.persist_outbox(context_id, label, messages[index])
        return copy.deepcopy(self.durable_outbox[(context_id, label)])

    def resume_survivor_transfer(
        self,
        context: TransferContext,
        target_component: int,
        old_opening: Opening,
        old_commitment: int,
        mask_commitment: int,
        new_commitment: int,
        peer: str,
        replacement: str,
        key: Ed25519PrivateKey,
    ) -> tuple[SignedStatement, SignedStatement, SignedStatement]:
        """Complete a partially prepared session from its durable mask."""
        messages = self._build_survivor_transfer(
            context, target_component, old_opening, old_commitment,
            mask_commitment, new_commitment, peer, replacement, key,
        )
        labels = (
            f"proposal:{target_component}",
            f"peer-mask:{target_component}",
            f"replacement-component:{target_component}",
        )
        context_id = context.identifier()
        for label, message in zip(labels, messages):
            self.persist_outbox(context_id, label, message)
        return self.replay_survivor_transfer(context, target_component)

    def replay_survivor_transfer(
        self, context: TransferContext, target_component: int
    ) -> tuple[SignedStatement, SignedStatement, SignedStatement]:
        """Return byte-identical prepared messages from durable state only."""
        context_id = context.identifier()
        if (context_id, target_component) not in self.durable_masks:
            raise ValueError("survivor session mask is not durable")
        labels = (
            f"proposal:{target_component}",
            f"peer-mask:{target_component}",
            f"replacement-component:{target_component}",
        )
        try:
            return tuple(copy.deepcopy(self.durable_outbox[(context_id, label)])
                         for label in labels)  # type: ignore[return-value]
        except KeyError as exc:
            raise ValueError("survivor outbox is incomplete") from exc

    def persist_component(self, context_id: str, component: int, opening: Opening, commitment: int,
                          *, expected_dimension: int | None = None) -> None:
        if component == self.physical_slot:
            raise ValueError("server cannot store the component omitted by its slot")
        if expected_dimension is not None and len(opening.values) != expected_dimension:
            raise ValueError("component dimension does not match context")
        if self.group.commit(opening.values, opening.blinding) != commitment:
            raise ValueError("opening does not match commitment")
        key = (context_id, component)
        old = self.durable_components.get(key)
        if old is not None and old != opening:
            raise ValueError("durable component slot is immutable")
        self.durable_components[key] = opening

    def persist_outbox(self, context_id: str, label: str, signed: SignedStatement) -> None:
        key = (context_id, label)
        old = self.durable_outbox.get(key)
        if old is not None and old != signed:
            raise ValueError("durable outbox entry is immutable")
        # Frozen dataclasses do not freeze nested statement dictionaries/lists.
        # Persist a detached snapshot, not the caller's mutable message body.
        self.durable_outbox[key] = copy.deepcopy(signed)

    def has_component(self, context_id: str, component: int, commitment: int,
                      *, expected_dimension: int | None = None) -> bool:
        opening = self.durable_components.get((context_id, component))
        return (opening is not None and
                (expected_dimension is None or len(opening.values) == expected_dimension) and
                self.group.commit(opening.values, opening.blinding) == commitment)

    def issue_receipt(self, context: TransferContext, component: int, commitment: int,
                      key: Ed25519PrivateKey) -> SignedStatement:
        """Sign only after the named component is durably present."""
        context.validate()
        if context.new_members[self.physical_slot] != self.name:
            raise ValueError("server identity/slot mismatch")
        if component == self.physical_slot:
            raise ValueError("server does not hold its omitted component")
        context_id = context.identifier()
        if not self.has_component(
            context_id, component, commitment, expected_dimension=context.dimension
        ):
            raise ValueError("receipt requires a durable verified component")
        statement = _statement(
            context_id, "PERSIST_RECEIPT", self.name, "DURABLE_COMPONENT",
            component=component, commitment=commitment, generation=context.generation
        )
        signed = sign_statement(statement, key)
        label = f"receipt:{component}"
        self.persist_outbox(context_id, label, signed)
        return copy.deepcopy(self.durable_outbox[(context_id, label)])

    def crash(self) -> None:
        self.volatile.clear()


@dataclass
class TransferBundle:
    context: TransferContext
    old_state: ReplicatedState
    new_state: ReplicatedState
    mask_openings: dict[int, Opening]
    mask_commitments: dict[int, int]
    preparation_servers: dict[str, DurableServer]
    proposal_statements: list[SignedStatement]
    private_opening_statements: list[SignedStatement]
    receipt_statements: list[SignedStatement]
    certificate: dict[str, Any]


def _statement(context_id: str, kind: str, signer: str, role: str, **body: Any) -> Statement:
    return Statement(context_id=context_id, kind=kind, signer=signer, role=role, body=body)


def initial_state(secret: Iterable[int], members: tuple[str, str, str], seed: str,
                  group: TinyVectorPedersen | None = None) -> ReplicatedState:
    group = group or TinyVectorPedersen()
    secret = group.validate_vector(secret)
    if len(set(members)) != 3:
        raise ValueError("distinct members required")

    def scalar(label: str) -> int:
        return int.from_bytes(hashlib.sha256((seed + ":" + label).encode("ascii")).digest(), "big") % group.q

    z0 = tuple(scalar(f"z0:{i}") for i in range(len(secret)))
    z1 = tuple(scalar(f"z1:{i}") for i in range(len(secret)))
    z2 = vec_sub(vec_sub(secret, z0, group.q), z1, group.q)
    blindings = tuple(scalar(f"rho:{i}") for i in range(3))
    components = (z0, z1, z2)
    commitments = tuple(group.commit(component, blind) for component, blind in zip(components, blindings))
    state = ReplicatedState(members, components, blindings, commitments)
    state.validate(group)
    return state


def make_transfer(context: TransferContext, old_state: ReplicatedState,
                  private_keys: dict[str, Ed25519PrivateKey], seed: str,
                  group: TinyVectorPedersen | None = None) -> TransferBundle:
    group = group or TinyVectorPedersen()
    context.validate()
    old_state.validate(group)
    if old_state.members != context.old_members or len(old_state.components[0]) != context.dimension:
        raise ValueError("state does not match transfer context")
    if set(private_keys) != set(context.old_members) | set(context.new_members):
        raise ValueError("keys must cover exactly the old/new member union")
    context_id = context.identifier()
    k = context.replaced_slot
    a, b = (k + 1) % 3, (k + 2) % 3
    survivor_a, survivor_b = context.old_members[a], context.old_members[b]

    def scalar(label: str) -> int:
        return int.from_bytes(hashlib.sha256((seed + ":" + label).encode("ascii")).digest(), "big") % group.q

    # Survivor a refreshes component b; survivor b refreshes component a.
    delta_a = tuple(scalar(f"delta-a:{i}") for i in range(context.dimension))
    delta_b = tuple(scalar(f"delta-b:{i}") for i in range(context.dimension))
    tau_a, tau_b = scalar("tau-a"), scalar("tau-b")
    masks = {a: Opening(delta_a, tau_a), b: Opening(delta_b, tau_b)}
    mask_commitments = {a: group.commit(delta_a, tau_a), b: group.commit(delta_b, tau_b)}

    components = list(old_state.components)
    blindings = list(old_state.blindings)
    components[a] = vec_add(components[a], delta_a, group.q)
    blindings[a] = (blindings[a] + tau_a) % group.q
    components[b] = vec_add(components[b], delta_b, group.q)
    blindings[b] = (blindings[b] + tau_b) % group.q
    components[k] = vec_sub(vec_sub(components[k], delta_a, group.q), delta_b, group.q)
    blindings[k] = (blindings[k] - tau_a - tau_b) % group.q
    # Put the common-component equation at k and the additive equations at a,b.
    new_commitments = list(old_state.commitments)
    new_commitments[k] = group.div(old_state.commitments[k], group.mul(mask_commitments[a], mask_commitments[b]))
    new_commitments[a] = group.mul(old_state.commitments[a], mask_commitments[a])
    new_commitments[b] = group.mul(old_state.commitments[b], mask_commitments[b])
    new_state = ReplicatedState(context.new_members, tuple(components), tuple(blindings), tuple(new_commitments))
    new_state.validate(group)
    if new_state.secret(group.q) != old_state.secret(group.q):
        raise AssertionError("resharing changed the shared vector")

    # Each survivor prepares its session using only the old component it
    # physically holds and its own sampled mask.  The returned messages are
    # exposed only after the mask and all signed outbox entries are durable.
    preparation_servers: dict[str, DurableServer] = {}
    proposals: list[SignedStatement] = []
    openings: list[SignedStatement] = []
    for slot, target, signer, peer in (
        (a, b, survivor_a, survivor_b),
        (b, a, survivor_b, survivor_a),
    ):
        server = DurableServer(signer, slot, group)
        local_old = old_state.holdings(slot)[target]
        proposal, peer_opening, replacement_opening = server.prepare_survivor_transfer(
            context=context,
            target_component=target,
            old_opening=local_old,
            old_commitment=old_state.commitments[target],
            mask_opening=masks[target],
            mask_commitment=mask_commitments[target],
            new_commitment=new_state.commitments[target],
            peer=peer,
            replacement=context.new_members[k],
            key=private_keys[signer],
        )
        preparation_servers[signer] = server
        proposals.append(proposal)
        openings.extend((peer_opening, replacement_opening))

    # Receipts are intentionally absent here.  They are emitted by
    # DurableServer.issue_receipt only after the corresponding verified
    # component has been persisted.
    receipts: list[SignedStatement] = []

    certificate = {
        "context": asdict(context),
        "context_id": context_id,
        "old_commitments": list(old_state.commitments),
        "new_commitments": list(new_state.commitments),
        "mask_commitments": {str(index): value for index, value in sorted(mask_commitments.items())},
        "proposals": [statement.export() for statement in proposals],
        "receipts": [statement.export() for statement in receipts],
        "certificate_version": "continuity-certificate",
    }
    return TransferBundle(context, old_state, new_state, masks, mask_commitments,
                          preparation_servers, proposals, openings, receipts, certificate)


def assemble_certificate(
    bundle: TransferBundle,
    proposals: Iterable[SignedStatement],
    receipts: Iterable[SignedStatement],
) -> dict[str, Any]:
    """Assemble a certificate only from caller-supplied durable statements.

    ``make_transfer`` constructs a deterministic reference prefix so tests can
    inspect the intended transcript.  A real execution must not inherit those
    prebuilt proposal envelopes: both survivor proposals and all six receipts
    are collected from the executing servers' durable outboxes and supplied
    here explicitly.  Sorting gives one canonical public encoding without
    changing the signed statements.
    """
    ordered_proposals = sorted(
        tuple(proposals),
        key=lambda signed: (
            signed.statement.body.get("target_component", -1),
            signed.statement.signer,
        ),
    )
    ordered_receipts = sorted(
        tuple(receipts),
        key=lambda signed: (
            signed.statement.body.get("component", -1),
            signed.statement.signer,
        ),
    )
    certificate = copy.deepcopy(bundle.certificate)
    certificate["proposals"] = [statement.export() for statement in ordered_proposals]
    certificate["receipts"] = [statement.export() for statement in ordered_receipts]
    return certificate


def import_signed(raw: dict[str, Any]) -> SignedStatement:
    if type(raw) is not dict:
        raise ValueError("signed envelope must be an object")
    if set(raw) != {"statement", "signature_hex"}:
        raise ValueError("invalid signed envelope")
    statement = raw["statement"]
    if type(statement) is not dict:
        raise ValueError("statement must be an object")
    if set(statement) != {"context_id", "kind", "signer", "role", "body"}:
        raise ValueError("invalid statement schema")
    if not all(isinstance(statement[name], str) and 0 < len(statement[name]) <= 128
               for name in ("context_id", "kind", "signer", "role")):
        raise ValueError("invalid bounded statement labels")
    if type(statement["body"]) is not dict:
        raise ValueError("statement body must be an object")
    signature_hex = raw["signature_hex"]
    if (type(signature_hex) is not str or len(signature_hex) != 128 or
            any(character not in "0123456789abcdef" for character in signature_hex)):
        raise ValueError("signature must use canonical lowercase hexadecimal")
    signature = bytes.fromhex(signature_hex)
    if len(signature) != 64:
        raise ValueError("invalid Ed25519 signature")
    return SignedStatement(Statement(**statement), signature)


def _parse_certificate(certificate: dict[str, Any]) -> tuple[TransferContext, list[int], list[int], dict[int, int], list[SignedStatement], list[SignedStatement]]:
    if type(certificate) is not dict:
        raise ValueError("certificate must be an object")
    required = {"context", "context_id", "old_commitments", "new_commitments",
                "mask_commitments", "proposals", "receipts", "certificate_version"}
    if set(certificate) != required or certificate["certificate_version"] != "continuity-certificate":
        raise ValueError("invalid certificate schema")
    if type(certificate["context"]) is not dict:
        raise ValueError("certificate context must be an object")
    context_keys = {
        "service", "epoch", "cut_root", "old_members", "new_members",
        "replaced_slot", "session", "generation", "dimension",
        "field_modulus", "group_modulus",
    }
    if set(certificate["context"]) != context_keys:
        raise ValueError("invalid context schema")
    raw_context = dict(certificate["context"])
    if (type(raw_context["old_members"]) not in (list, tuple) or
            type(raw_context["new_members"]) not in (list, tuple)):
        raise ValueError("member vectors must be arrays")
    raw_context["old_members"] = tuple(raw_context["old_members"])
    raw_context["new_members"] = tuple(raw_context["new_members"])
    context = TransferContext(**raw_context)
    context.validate()
    if type(certificate["context_id"]) is not str or certificate["context_id"] != context.identifier():
        raise ValueError("context identifier mismatch")
    if type(certificate["old_commitments"]) is not list or type(certificate["new_commitments"]) is not list:
        raise ValueError("commitment vectors must be JSON arrays")
    old = list(certificate["old_commitments"])
    new = list(certificate["new_commitments"])
    if len(old) != 3 or len(new) != 3 or any(type(x) is not int for x in old + new):
        raise ValueError("invalid commitment vector")
    if type(certificate["mask_commitments"]) is not dict:
        raise ValueError("mask commitments must be an object")
    masks: dict[int, int] = {}
    for raw_index, value in certificate["mask_commitments"].items():
        if not isinstance(raw_index, str):
            raise ValueError("mask commitment keys must be canonical decimal strings")
        index = int(raw_index)
        if raw_index != str(index) or index in masks or type(value) is not int:
            raise ValueError("invalid mask commitment")
        masks[index] = value
    if type(certificate["proposals"]) is not list or type(certificate["receipts"]) is not list:
        raise ValueError("proposal and receipt collections must be JSON arrays")
    proposals = [import_signed(raw) for raw in certificate["proposals"]]
    receipts = [import_signed(raw) for raw in certificate["receipts"]]
    return context, old, new, masks, proposals, receipts


def verify_certificate(certificate: dict[str, Any], authorization: dict[str, bytes],
                       group: TinyVectorPedersen | None = None,
                       *, check_links: bool = True, check_generation: bool = True,
                       require_all_receipts: bool = True) -> bool:
    """Publicly verify the certificate.

    Optional switches exist only to construct explicit negative controls.  The
    protocol verifier uses all defaults.
    """
    group = group or TinyVectorPedersen()
    try:
        context, old, new, masks, proposals, receipts = _parse_certificate(certificate)
        context_id = context.identifier()
        k = context.replaced_slot
        a, b = (k + 1) % 3, (k + 2) % 3
        if set(masks) != {a, b}:
            return False
        if not all(group.is_subgroup_element(value)
                   for value in old + new + list(masks.values())):
            return False
        if check_links:
            if new[a] != group.mul(old[a], masks[a]):
                return False
            if new[b] != group.mul(old[b], masks[b]):
                return False
            if new[k] != group.div(old[k], group.mul(masks[a], masks[b])):
                return False
        expected_proposals = {
            (context.old_members[b], a, masks[a]),
            (context.old_members[a], b, masks[b]),
        }
        observed_proposals: set[tuple[str, int, int]] = set()
        for signed in proposals:
            statement = signed.statement
            if (statement.context_id != context_id or statement.kind != "MASK_COMMIT" or
                    statement.role != "SURVIVOR_PROPOSAL" or not verify_signed(signed, authorization)):
                return False
            if set(statement.body) != {"target_component", "mask_commitment", "dimension"}:
                return False
            if (type(statement.body["target_component"]) is not int or
                    statement.body["target_component"] not in (a, b) or
                    type(statement.body["mask_commitment"]) is not int or
                    not group.is_subgroup_element(statement.body["mask_commitment"]) or
                    type(statement.body["dimension"]) is not int or
                    statement.body["dimension"] != context.dimension):
                return False
            observed_proposals.add((statement.signer, statement.body["target_component"],
                                    statement.body["mask_commitment"]))
        if observed_proposals != expected_proposals or len(proposals) != 2:
            return False

        expected_receipts = {(context.new_members[slot], component, new[component])
                             for component in range(3) for slot in range(3) if slot != component}
        observed_receipts: set[tuple[str, int, int]] = set()
        for signed in receipts:
            statement = signed.statement
            if (statement.context_id != context_id or statement.kind != "PERSIST_RECEIPT" or
                    statement.role != "DURABLE_COMPONENT" or not verify_signed(signed, authorization)):
                return False
            if set(statement.body) != {"component", "commitment", "generation"}:
                return False
            if (type(statement.body["component"]) is not int or
                    statement.body["component"] not in (0, 1, 2) or
                    type(statement.body["commitment"]) is not int or
                    not group.is_subgroup_element(statement.body["commitment"]) or
                    type(statement.body["generation"]) is not str or
                    not 0 < len(statement.body["generation"]) <= 128):
                return False
            if check_generation and statement.body["generation"] != context.generation:
                return False
            observed_receipts.add((statement.signer, statement.body["component"],
                                   statement.body["commitment"]))
        if len(observed_receipts) != len(receipts):
            return False
        if require_all_receipts:
            return observed_receipts == expected_receipts and len(receipts) == 6
        return observed_receipts.issubset(expected_receipts)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def verify_certificate_chain(
    certificates: Iterable[dict[str, Any]],
    authorization: dict[str, bytes],
    group: TinyVectorPedersen | None = None,
) -> bool:
    """Verify a bounded activated chain, including exact commitment handoff."""
    group = group or TinyVectorPedersen()
    chain = tuple(certificates)
    if not chain:
        return False
    contexts: list[TransferContext] = []
    prior_new: list[int] | None = None
    try:
        for certificate in chain:
            if not verify_certificate(certificate, authorization, group):
                return False
            context, old, new, _, _, _ = _parse_certificate(certificate)
            if prior_new is not None and old != prior_new:
                return False
            contexts.append(context)
            prior_new = new
        validate_serial_contexts(contexts)
        return True
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def verify_private_delivery(
    signed: SignedStatement,
    context: TransferContext,
    mask_commitments: dict[int, int],
    new_commitments: tuple[int, int, int] | list[int],
    authorization: dict[str, bytes],
    group: TinyVectorPedersen | None = None,
) -> tuple[Opening, tuple[int, Opening] | None] | None:
    """Verify one authenticated private mask/component delivery.

    Peer-survivor messages carry only the sender's random mask opening.  The
    replacement-directed messages additionally carry the refreshed component
    opening that the replacement cannot derive from old state.  The return
    value is ``(mask_opening, optional(component, opening))``; malformed,
    misrouted, unauthenticated, or algebraically invalid messages return None.
    """
    group = group or TinyVectorPedersen()
    try:
        if (not isinstance(signed, SignedStatement) or
                type(mask_commitments) is not dict or
                type(new_commitments) not in (tuple, list) or len(new_commitments) != 3):
            return None
        context.validate()
        k = context.replaced_slot
        a, b = (k + 1) % 3, (k + 2) % 3
        if (set(mask_commitments) != {a, b} or
                any(type(index) is not int for index in mask_commitments) or
                any(not group.is_subgroup_element(value) for value in mask_commitments.values()) or
                any(not group.is_subgroup_element(value) for value in new_commitments)):
            return None
        statement = signed.statement
        if type(statement.body) is not dict:
            return None
        if (statement.context_id != context.identifier() or
                statement.role != "PRIVATE_OPENING" or
                not verify_signed(signed, authorization)):
            return None
        expected_signer = {
            a: context.old_members[b],  # survivor b samples delta_a
            b: context.old_members[a],  # survivor a samples delta_b
        }
        target = statement.body.get("target_component")
        if (type(target) is not int or target not in (a, b) or
                statement.signer != expected_signer[target]):
            return None
        mask_commitment = statement.body.get("mask_commitment")
        if (type(mask_commitment) is not int or
                mask_commitment != mask_commitments.get(target)):
            return None
        if (type(statement.body.get("dimension")) is not int or
                statement.body.get("dimension") != context.dimension):
            return None
        if (type(statement.body.get("values")) is not list or
                type(statement.body.get("blinding")) is not int):
            return None
        mask = Opening(tuple(statement.body["values"]), statement.body["blinding"])
        if len(mask.values) != context.dimension:
            return None
        if group.commit(mask.values, mask.blinding) != mask_commitments[target]:
            return None

        replacement = context.new_members[k]
        peer = context.old_members[a] if target == a else context.old_members[b]
        # target a is sampled by survivor b and sent to peer survivor a; target
        # b is sampled by survivor a and sent to peer survivor b.
        if statement.kind == "MASK_OPENING":
            expected_keys = {"target_component", "recipient", "values", "blinding", "mask_commitment", "dimension"}
            if set(statement.body) != expected_keys or statement.body["recipient"] != peer:
                return None
            return mask, None

        if statement.kind != "MASK_COMPONENT_OPENING":
            return None
        expected_keys = {
            "target_component", "recipient", "values", "blinding", "mask_commitment", "dimension",
            "component", "component_values", "component_blinding", "component_commitment",
        }
        if set(statement.body) != expected_keys or statement.body["recipient"] != replacement:
            return None
        if type(statement.body["component"]) is not int or statement.body["component"] != target:
            return None
        if (type(statement.body["component_commitment"]) is not int or
                statement.body["component_commitment"] != new_commitments[target]):
            return None
        if (type(statement.body["component_values"]) is not list or
                type(statement.body["component_blinding"]) is not int):
            return None
        component_opening = Opening(
            tuple(statement.body["component_values"]), statement.body["component_blinding"]
        )
        if len(component_opening.values) != context.dimension:
            return None
        if group.commit(component_opening.values, component_opening.blinding) != new_commitments[target]:
            return None
        return mask, (target, component_opening)
    except (KeyError, TypeError, ValueError, OverflowError):
        return None


def derive_survivor_opening(
    context: TransferContext,
    server_slot: int,
    component: int,
    old_opening: Opening,
    own_mask: Opening,
    mask_commitments: dict[int, int],
    old_commitments: tuple[int, int, int] | list[int],
    new_commitments: tuple[int, int, int] | list[int],
    authorization: dict[str, bytes],
    peer_message: SignedStatement | None = None,
    group: TinyVectorPedersen | None = None,
) -> Opening | None:
    """Derive one survivor-held refreshed component from its local inputs.

    A survivor holds exactly the common component ``k`` and the non-common
    component refreshed by its own mask.  It derives the latter locally from
    its old opening and own mask; for ``k`` it additionally verifies the
    authenticated peer mask opening.  No expected new opening is supplied.
    """
    group = group or TinyVectorPedersen()
    try:
        context.validate()
        k = context.replaced_slot
        a, b = (k + 1) % 3, (k + 2) % 3
        if server_slot == a:
            own_target, peer_target = b, a
        elif server_slot == b:
            own_target, peer_target = a, b
        else:
            return None
        if component not in (k, own_target):
            return None
        if len(old_commitments) != 3 or len(new_commitments) != 3:
            return None
        if len(old_opening.values) != context.dimension or len(own_mask.values) != context.dimension:
            return None
        if group.commit(old_opening.values, old_opening.blinding) != old_commitments[component]:
            return None
        if group.commit(own_mask.values, own_mask.blinding) != mask_commitments.get(own_target):
            return None

        if component == own_target:
            if peer_message is not None:
                return None
            derived = Opening(
                vec_add(old_opening.values, own_mask.values, group.q),
                (old_opening.blinding + own_mask.blinding) % group.q,
            )
        else:
            if peer_message is None:
                return None
            verified = verify_private_delivery(
                peer_message, context, mask_commitments, new_commitments,
                authorization, group
            )
            if verified is None or verified[1] is not None:
                return None
            peer_mask = verified[0]
            if peer_message.statement.body.get("target_component") != peer_target:
                return None
            derived = Opening(
                vec_sub(vec_sub(old_opening.values, own_mask.values, group.q),
                        peer_mask.values, group.q),
                (old_opening.blinding - own_mask.blinding - peer_mask.blinding) % group.q,
            )
        if group.commit(derived.values, derived.blinding) != new_commitments[component]:
            return None
        return derived
    except (KeyError, TypeError, ValueError, OverflowError):
        return None


def verify_invalid_opening(signed: SignedStatement, context: TransferContext,
                           authorization: dict[str, bytes],
                           group: TinyVectorPedersen | None = None) -> bool:
    """Accept only a canonical signed invalid peer-mask opening.

    A replacement-directed ``MASK_COMPONENT_OPENING`` envelope also contains a
    refreshed component opening.  Its Ed25519 signature covers the entire
    envelope, so it cannot be truncated into a mask-only public proof.  Such an
    envelope is therefore a private reject/abort object, never public blame
    evidence under this predicate.
    """
    group = group or TinyVectorPedersen()
    try:
        if not isinstance(signed, SignedStatement):
            return False
        context.validate()
        statement = signed.statement
        if (statement.context_id != context.identifier() or
                statement.kind != "MASK_OPENING" or
                statement.role != "PRIVATE_OPENING" or
                not verify_signed(signed, authorization)):
            return False
        body = statement.body
        if type(body) is not dict:
            return False
        expected_schema = {
            "target_component", "recipient", "values", "blinding",
            "mask_commitment", "dimension",
        }
        if (set(body) != expected_schema or type(body["dimension"]) is not int or
                body["dimension"] != context.dimension):
            return False
        k = context.replaced_slot
        a, b = (k + 1) % 3, (k + 2) % 3
        target = body["target_component"]
        expected_signer = {
            a: context.old_members[b],
            b: context.old_members[a],
        }
        if (type(target) is not int or target not in expected_signer or
                statement.signer != expected_signer[target]):
            return False
        peer = context.old_members[a] if target == a else context.old_members[b]
        if type(body["recipient"]) is not str or body["recipient"] != peer:
            return False
        if (type(body["values"]) is not list or
                len(body["values"]) != context.dimension or
                type(body["blinding"]) is not int or
                type(body["mask_commitment"]) is not int or
                not group.is_subgroup_element(body["mask_commitment"])):
            return False
        actual = group.commit(tuple(body["values"]), body["blinding"])
    except (KeyError, TypeError, ValueError, OverflowError):
        return False
    return actual != body["mask_commitment"]


def verify_equivocation(left: SignedStatement, right: SignedStatement,
                         context: TransferContext, authorization: dict[str, bytes],
                         group: TinyVectorPedersen | None = None) -> bool:
    """Accept role-authorized same-context mask proposals for different roots."""
    group = group or TinyVectorPedersen()
    try:
        context.validate()
        a, b = left.statement, right.statement
        if not (verify_signed(left, authorization) and verify_signed(right, authorization)):
            return False
        if (a.context_id, a.kind, a.signer, a.role) != (b.context_id, b.kind, b.signer, b.role):
            return False
        if (a.context_id != context.identifier() or
                a.kind != "MASK_COMMIT" or a.role != "SURVIVOR_PROPOSAL"):
            return False
        expected = {"target_component", "mask_commitment", "dimension"}
        if set(a.body) != expected or set(b.body) != expected:
            return False
        for body in (a.body, b.body):
            if (type(body["target_component"]) is not int or
                    type(body["dimension"]) is not int):
                return False
        if (a.body["target_component"] != b.body["target_component"] or
                a.body["dimension"] != context.dimension or
                b.body["dimension"] != context.dimension):
            return False
        k = context.replaced_slot
        x, y = (k + 1) % 3, (k + 2) % 3
        target = a.body["target_component"]
        expected_signer = {
            x: context.old_members[y],
            y: context.old_members[x],
        }
        if target not in expected_signer or a.signer != expected_signer[target]:
            return False
        if (not group.is_subgroup_element(a.body["mask_commitment"]) or
                not group.is_subgroup_element(b.body["mask_commitment"])):
            return False
        return a.body["mask_commitment"] != b.body["mask_commitment"]
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def deep_copy_certificate(certificate: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(certificate)
