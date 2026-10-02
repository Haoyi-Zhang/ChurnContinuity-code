"""Frozen exact checks for the physical 2-of-3 continuity protocol."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict
import copy
import hashlib
import json
from itertools import product
from typing import Any

from .evidence import public_bytes
from .continuity import (
    DurableServer,
    Opening,
    ReplicatedState,
    SignedStatement,
    Statement,
    TinyVectorPedersen,
    TransferBundle,
    TransferContext,
    assemble_certificate,
    deep_copy_certificate,
    derive_survivor_opening,
    fixture_authorization,
    initial_state,
    make_transfer,
    sign_statement,
    vec_add,
    vec_sub,
    verify_certificate,
    verify_equivocation,
    verify_invalid_opening,
    verify_private_delivery,
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _fixture(dimension: int = 8, *, generation: str = "generation-7", seed: str = "fixture"):
    group = TinyVectorPedersen()
    old_members = ("retiring-0", "survivor-1", "survivor-2")
    new_members = ("replacement-0", "survivor-1", "survivor-2")
    context = TransferContext(
        service="recommendation-service",
        epoch=7,
        cut_root=hashlib.sha256(b"eight-stable-rating-identifiers").hexdigest(),
        old_members=old_members,
        new_members=new_members,
        replaced_slot=0,
        session="session-7-0",
        generation=generation,
        dimension=dimension,
    )
    secret = tuple((17 * i + 23) % group.q for i in range(dimension))
    old_state = initial_state(secret, old_members, "initial:" + seed, group)
    keys, authorization = fixture_authorization(set(old_members) | set(new_members))
    bundle = make_transfer(context, old_state, keys, "transfer:" + seed, group)
    return group, context, secret, keys, authorization, bundle


def _servers(bundle: TransferBundle, group: TinyVectorPedersen) -> dict[str, DurableServer]:
    """Create a fresh committee with no protocol facts preinstalled."""
    return {
        name: DurableServer(name, slot, group)
        for slot, name in enumerate(bundle.context.new_members)
    }


def _component_steps(bundle: TransferBundle, servers: dict[str, DurableServer], keys):
    context_id = bundle.context.identifier()
    group = next(iter(servers.values())).group
    steps = []
    replacement_slot = bundle.context.replaced_slot
    a, b = (replacement_slot + 1) % 3, (replacement_slot + 2) % 3
    survivor_specs = (
        (a, b, bundle.context.old_members[a], bundle.context.old_members[b]),
        (b, a, bundle.context.old_members[b], bundle.context.old_members[a]),
    )

    # Two mask-only preparation boundaries followed by six sender outbox
    # boundaries.  Every outbox message is reconstructed from the durable mask
    # and the sender's local old component; no prebuilt fixture message is
    # installed into the fresh server.
    for slot, target, signer, _peer in survivor_specs:
        server = servers[signer]
        steps.append((
            server,
            lambda s=server, t=target: s.persist_mask(
                bundle.context, t, bundle.mask_openings[t], bundle.mask_commitments[t]
            ),
            f"mask-{target}-{signer}",
        ))

    for slot, target, signer, peer in survivor_specs:
        server = servers[signer]
        old_opening = bundle.old_state.holdings(slot)[target]
        common_args = dict(
            context=bundle.context,
            target_component=target,
            old_opening=old_opening,
            old_commitment=bundle.old_state.commitments[target],
            mask_commitment=bundle.mask_commitments[target],
            new_commitment=bundle.new_state.commitments[target],
            peer=peer,
            replacement=bundle.context.new_members[replacement_slot],
            key=keys[signer],
        )
        for label in (
            f"proposal:{target}",
            f"peer-mask:{target}",
            f"replacement-component:{target}",
        ):
            steps.append((
                server,
                lambda s=server, args=common_args, lab=label:
                    s.persist_survivor_outbox_item(**args, label=lab),
                f"prepared-{label}",
            ))

    # Six durable component copies, two holders per component.  Survivors
    # derive their new holdings locally from old state plus verified masks.  The
    # replacement's two copies must come from authenticated private component
    # deliveries; it cannot read them from the experiment fixture.
    sender_for_target = {target: signer for _slot, target, signer, _peer in survivor_specs}
    authorization = {name: public_bytes(key) for name, key in keys.items()}
    for component, commitment in enumerate(bundle.new_state.commitments):
        for slot, signer in enumerate(bundle.context.new_members):
            if slot == component:
                continue
            server = servers[signer]
            if slot == replacement_slot:
                sender = sender_for_target[component]
                def persist_delivered(s=server, source=sender, c=component, m=commitment):
                    msg = servers[source].durable_outbox[
                        (context_id, f"replacement-component:{c}")
                    ]
                    verified = verify_private_delivery(
                        msg, bundle.context, bundle.mask_commitments,
                        bundle.new_state.commitments, authorization, group
                    )
                    if verified is None or verified[1] is None or verified[1][0] != c:
                        raise ValueError("replacement component delivery rejected")
                    s.persist_component(
                        context_id, c, verified[1][1], m,
                        expected_dimension=bundle.context.dimension,
                    )
                steps.append((server, persist_delivered, f"component-{component}-{signer}"))
            else:
                # A survivor derives its refreshed holding from only the old
                # component it already held, its own sampled mask, and (for the
                # common component k) one authenticated peer mask opening.
                k = replacement_slot
                a, b = (k + 1) % 3, (k + 2) % 3
                own_target = b if slot == a else a
                old_opening = Opening(
                    bundle.old_state.components[component],
                    bundle.old_state.blindings[component],
                )
                own_mask = bundle.mask_openings[own_target]
                def persist_local(s=server, c=component, old=old_opening, own=own_mask,
                                  m=commitment, physical_slot=slot):
                    msg = None
                    if c == replacement_slot:
                        peer_target = a if physical_slot == a else b
                        source = sender_for_target[peer_target]
                        msg = servers[source].durable_outbox[
                            (context_id, f"peer-mask:{peer_target}")
                        ]
                    derived = derive_survivor_opening(
                        bundle.context, physical_slot, c, old, own,
                        bundle.mask_commitments, bundle.old_state.commitments,
                        bundle.new_state.commitments, authorization, msg, group
                    )
                    if derived is None:
                        raise ValueError("survivor local derivation rejected")
                    s.persist_component(
                        context_id, c, derived, m,
                        expected_dimension=bundle.context.dimension,
                    )
                steps.append((server, persist_local, f"component-{component}-{signer}"))
    # Six receipt durability boundaries, one for each holder/component pair.
    # Each signed receipt is an independent durable outbox fact, so crash
    # injection must be possible between the two receipts produced by one
    # physical server rather than treating that pair as atomic.
    for signer in bundle.context.new_members:
        server = servers[signer]
        held = [component for component in range(3) if component != server.physical_slot]
        for component in held:
            steps.append((
                server,
                lambda s=server, c=component, who=signer: s.issue_receipt(
                    bundle.context, c, bundle.new_state.commitments[c], keys[who]
                ),
                f"receipt-{component}-{signer}",
            ))
    assert len(steps) == 20
    return steps


def _finalize(bundle: TransferBundle, servers: dict[str, DurableServer]) -> dict[str, Any]:
    """Collect the public certificate entirely from executing durable outboxes."""
    context_id = bundle.context.identifier()
    k = bundle.context.replaced_slot
    a, b = (k + 1) % 3, (k + 2) % 3
    proposals = [
        servers[bundle.context.old_members[b]].durable_outbox[(context_id, f"proposal:{a}")],
        servers[bundle.context.old_members[a]].durable_outbox[(context_id, f"proposal:{b}")],
    ]
    receipts = []
    for component in range(3):
        for slot, signer in enumerate(bundle.context.new_members):
            if slot == component:
                continue
            receipts.append(servers[signer].durable_outbox[(context_id, f"receipt:{component}")])
    bundle.proposal_statements = proposals
    bundle.receipt_statements = receipts
    bundle.certificate = assemble_certificate(bundle, proposals, receipts)
    return bundle.certificate


def complete_transfer(bundle: TransferBundle, keys, group: TinyVectorPedersen) -> dict[str, DurableServer]:
    """Execute the honest durable path and materialize its public certificate."""
    servers = _servers(bundle, group)
    for _, action, _ in _component_steps(bundle, servers, keys):
        action()
    _finalize(bundle, servers)
    return servers


def _all_available(bundle: TransferBundle, servers: dict[str, DurableServer]) -> bool:
    context_id = bundle.context.identifier()
    for component, commitment in enumerate(bundle.new_state.commitments):
        for slot, signer in enumerate(bundle.context.new_members):
            if slot != component and not servers[signer].has_component(
                context_id, component, commitment, expected_dimension=bundle.context.dimension
            ):
                return False
    return True


def _resign_receipts(certificate: dict[str, Any], keys, *, generation: str | None = None,
                     keep_one_per_component: bool = False) -> None:
    context = TransferContext(**{
        **certificate["context"],
        "old_members": tuple(certificate["context"]["old_members"]),
        "new_members": tuple(certificate["context"]["new_members"]),
    })
    context_id = context.identifier()
    receipts = []
    for component, commitment in enumerate(certificate["new_commitments"]):
        holders = [slot for slot in range(3) if slot != component]
        if keep_one_per_component:
            holders = holders[:1]
        for slot in holders:
            signer = context.new_members[slot]
            body_generation = context.generation if generation is None else generation
            statement = Statement(context_id, "PERSIST_RECEIPT", signer, "DURABLE_COMPONENT",
                                  {"component": component, "commitment": commitment,
                                   "generation": body_generation})
            receipts.append(sign_statement(statement, keys[signer]).export())
    certificate["receipts"] = receipts


def protocol_cases() -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]], int]:
    """Return exactly 32 generated protocol/fault cases.

    1 honest execution + 20 crash boundaries + 5 certificate mutations +
    3 ablations + 1 unchanged cross-context transplant + 2 positive evidence
    cases = 32.  Other evidence negative controls remain mandatory assertions
    and unit tests but are not counted as generated cases.
    """
    group, context, secret, keys, authorization, bundle = _fixture()
    rows: list[dict[str, Any]] = []

    def add(kind: str, name: str, observed: bool, expected: bool, note: str) -> None:
        if observed != expected:
            raise AssertionError((kind, name, observed, expected))
        rows.append({"case": f"continuity-{len(rows):02}", "kind": kind, "name": name,
                     "observed": int(observed), "expected": int(expected), "note": note})

    servers = _servers(bundle, group)
    for _, action, _ in _component_steps(bundle, servers, keys):
        action()
    _finalize(bundle, servers)
    honest = (verify_certificate(bundle.certificate, authorization, group) and
              _all_available(bundle, servers) and bundle.new_state.secret(group.q) == secret)
    add("honest", "valid-certificate-and-durable-copies", honest, True,
        "The public certificate verifies, all six replicas are durable, and the vector is unchanged.")

    # Crash/replay after each of 20 durability boundaries: two durable masks,
    # six sender outbox records, six verified component copies, and six
    # individual receipts.  Fresh server objects start with none of these facts.
    steps = _component_steps(bundle, _servers(bundle, group), keys)
    for boundary in range(len(steps)):
        crash_servers = _servers(bundle, group)
        crash_steps = _component_steps(bundle, crash_servers, keys)
        for index in range(boundary + 1):
            crash_steps[index][1]()
        crash_steps[boundary][0].crash()
        for _, action, _ in crash_steps:
            action()
        crash_context_id = context.identifier()
        k = context.replaced_slot
        a, b = (k + 1) % 3, (k + 2) % 3
        crash_proposals = [
            crash_servers[context.old_members[b]].durable_outbox[(crash_context_id, f"proposal:{a}")],
            crash_servers[context.old_members[a]].durable_outbox[(crash_context_id, f"proposal:{b}")],
        ]
        crash_receipts = [
            crash_servers[signer].durable_outbox[(crash_context_id, f"receipt:{component}")]
            for component in range(3)
            for slot, signer in enumerate(context.new_members) if slot != component
        ]
        crash_certificate = assemble_certificate(bundle, crash_proposals, crash_receipts)
        ok = verify_certificate(crash_certificate, authorization, group) and _all_available(bundle, crash_servers)
        add("crash-replay", f"after-{crash_steps[boundary][2]}", ok, True,
            "A crash clears volatile state; replay of the persisted deterministic session completes safely.")

    # Five independent mutation classes are retained in the generated campaign;
    # the unit suite additionally checks non-subgroup encodings, signer/body
    # substitutions, noncanonical keys, and malformed contexts.  Keeping five
    # here leaves room for crash injection at every individual durable receipt
    # while preserving the bounded physical-case family.
    mutations: list[tuple[str, dict[str, Any]]] = []
    cert = deep_copy_certificate(bundle.certificate)
    cert["new_commitments"][0] = group.mul(cert["new_commitments"][0], group.g(0))
    mutations.append(("changed-new-commitment", cert))
    cert = deep_copy_certificate(bundle.certificate)
    key = sorted(cert["mask_commitments"])[0]
    cert["mask_commitments"][key] = group.mul(cert["mask_commitments"][key], group.g(1))
    mutations.append(("changed-mask-commitment", cert))
    cert = deep_copy_certificate(bundle.certificate)
    raw = bytearray.fromhex(cert["proposals"][0]["signature_hex"]); raw[0] ^= 1
    cert["proposals"][0]["signature_hex"] = bytes(raw).hex()
    mutations.append(("proposal-signature-bitflip", cert))
    cert = deep_copy_certificate(bundle.certificate); cert["receipts"].pop()
    mutations.append(("missing-receipt", cert))
    cert = deep_copy_certificate(bundle.certificate); cert["context"]["epoch"] += 1
    mutations.append(("context-epoch-substitution", cert))
    for name, mutated in mutations:
        add("mutation", name, verify_certificate(mutated, authorization, group), False,
            "The full verifier rejects this independently generated mutation class.")

    # Ablation 1: if algebraic continuity equations are skipped, an all-signed
    # certificate can bind a different committed vector.
    broken = deep_copy_certificate(bundle.certificate)
    broken["new_commitments"][0] = group.mul(broken["new_commitments"][0], group.g(0))
    _resign_receipts(broken, keys)
    weak_accept = verify_certificate(broken, authorization, group, check_links=False)
    full_reject = not verify_certificate(broken, authorization, group)
    add("ablation", "omit-algebraic-links", weak_accept and full_reject, True,
        "A weak verifier accepts an authenticated but secret-changing commitment vector; the full verifier rejects it.")

    # Ablation 2: re-signed statements whose redundant body generation conflicts
    # with the signed context become usable when that equality check is disabled.
    # This is deliberately not described as a replay from another context: the
    # statements retain the current context identifier and are freshly signed.
    wrong_generation = deep_copy_certificate(bundle.certificate)
    _resign_receipts(wrong_generation, keys, generation="other-generation")
    weak_accept = verify_certificate(wrong_generation, authorization, group, check_generation=False)
    full_reject = not verify_certificate(wrong_generation, authorization, group)
    add("ablation", "omit-receipt-body-generation-consistency", weak_accept and full_reject, True,
        "Freshly re-signed receipts whose body generation conflicts with their current signed context are accepted only by the weakened equality check.")

    # Ablation 3: one receipt per component is insufficient against one later
    # unavailable signer; the full certificate requires both physical holders.
    one_copy = deep_copy_certificate(bundle.certificate)
    _resign_receipts(one_copy, keys, keep_one_per_component=True)
    weak_accept = verify_certificate(one_copy, authorization, group, require_all_receipts=False)
    full_reject = not verify_certificate(one_copy, authorization, group)
    add("ablation", "single-receipt-per-component", weak_accept and full_reject, True,
        "A weak availability certificate has no surviving copy guarantee after its sole signer becomes unavailable.")

    # A genuine replay keeps the old signed bytes unchanged.  Even the weakened
    # verifier above rejects such receipts because every signature is bound to
    # the other transfer's context identifier.
    other_group, _, _, other_keys, _, other_bundle = _fixture(
        dimension=context.dimension, generation="generation-8", seed="cross-context-replay"
    )
    if (other_group.p, other_group.q) != (group.p, group.q):
        raise AssertionError("cross-context fixture changed arithmetic domain")
    complete_transfer(other_bundle, other_keys, other_group)
    transplanted = deep_copy_certificate(bundle.certificate)
    transplanted["receipts"] = copy.deepcopy(other_bundle.certificate["receipts"])
    full_reject = not verify_certificate(transplanted, authorization, group)
    weak_reject = not verify_certificate(
        transplanted, authorization, group, check_generation=False
    )
    add("replay-control", "unaltered-cross-context-receipt-transplant",
        full_reject and weak_reject, True,
        "Unmodified receipts from another signed context are rejected by context_id even when the redundant body-generation check is disabled.")

    evidence_exports = []
    valid_opening = bundle.private_opening_statements[0]
    if verify_invalid_opening(valid_opening, context, authorization, group):
        raise AssertionError("valid mask opening was misclassified as blame")
    body = copy.deepcopy(valid_opening.statement.body)
    body["values"][0] = (body["values"][0] + 1) % group.q
    invalid_statement = Statement(valid_opening.statement.context_id, valid_opening.statement.kind,
                                  valid_opening.statement.signer, valid_opening.statement.role, body)
    invalid_opening = sign_statement(invalid_statement, keys[invalid_statement.signer])
    add("evidence", "invalid-signed-mask-opening", verify_invalid_opening(invalid_opening, context, authorization, group), True,
        "The evidence exposes only a signed random mask opening and its failed commitment equation.")
    first = bundle.proposal_statements[0]
    changed_body = copy.deepcopy(first.statement.body)
    changed_body["mask_commitment"] = group.mul(changed_body["mask_commitment"], group.g(3))
    second_statement = Statement(first.statement.context_id, first.statement.kind, first.statement.signer,
                                 first.statement.role, changed_body)
    second = sign_statement(second_statement, keys[second_statement.signer])
    add("evidence", "same-session-mask-equivocation", verify_equivocation(first, second, context, authorization, group), True,
        "Two authentic roots for one sender, target and context are publicly contradictory.")
    _, _, _, _keys2, auth2, other = _fixture(generation="generation-8", seed="other")
    combined_auth = dict(authorization); combined_auth.update(auth2)
    if verify_equivocation(first, other.proposal_statements[0], context, combined_auth, group):
        raise AssertionError("different contexts were misclassified as equivocation")
    evidence_exports.extend([valid_opening.export(), invalid_opening.export(), first.export(), second.export()])

    if len(rows) != 32:
        raise AssertionError(("frozen continuity case count", len(rows)))
    sample = {
        "certificate": bundle.certificate,
        "old_secret": list(secret),
        "new_secret": list(bundle.new_state.secret(group.q)),
        "public_authorization": {name: value.hex() for name, value in sorted(authorization.items())},
        "toy_group_warning": "2039/1019 is an exhaustive-check fixture, not a production security parameter",
    }
    return rows, sample, evidence_exports, len(rows)


def privacy_checks(q: int = 5) -> tuple[list[dict[str, Any]], int]:
    """Exact single-server view equality for the algebraic resharing core.

    Commitments, blindings, and signatures are not enumerated here.  The
    separate joint-view checker covers correlated commitments and blindings;
    signature post-processing and the general claim remain in the written proof.
    """
    if q != 5:
        raise ValueError("the frozen exact privacy domain is q=5")
    histograms: dict[tuple[int, int], Counter] = {}
    obligations = 0
    for secret in range(q):
        for slot in range(3):
            counter: Counter[tuple[int, ...]] = Counter()
            for z0, z1, delta1, delta2 in product(range(q), repeat=4):
                z2 = (secret - z0 - z1) % q
                new0 = (z0 - delta1 - delta2) % q
                new1 = (z1 + delta1) % q
                new2 = (z2 + delta2) % q
                if slot == 0:  # replacement sees both new shares and both random masks
                    view = (new1, new2, delta1, delta2)
                elif slot == 1:  # survivor 1: its two old components and both masks
                    view = (z0, z2, delta1, delta2)
                else:
                    view = (z0, z1, delta1, delta2)
                counter[view] += 1
                obligations += 1
            histograms[(slot, secret)] = counter
    rows = []
    for slot in range(3):
        reference = histograms[(slot, 0)]
        for secret in range(q):
            current = histograms[(slot, secret)]
            if current != reference:
                raise AssertionError(("single-server view depends on secret", slot, secret))
            digest = hashlib.sha256(_canonical(sorted((list(key), count) for key, count in current.items()))).hexdigest()
            rows.append({"server_slot": slot, "secret": secret, "assignments": q ** 4,
                         "distinct_views": len(current), "maximum_multiplicity": max(current.values()),
                         "distribution_digest": digest, "matches_secret_zero": 1})
    return rows, obligations


def size_checks() -> tuple[list[dict[str, Any]], int]:
    rows = []
    obligations = 0
    for dimension in (1, 8, 32, 64):
        group, _, _, keys, authorization, bundle = _fixture(dimension=dimension, seed=f"size-{dimension}")
        complete_transfer(bundle, keys, group)
        if not verify_certificate(bundle.certificate, authorization, group):
            raise AssertionError("size fixture certificate rejected")
        public_bytes = len(_canonical(bundle.certificate))
        private_bytes = sum(len(statement.statement.encode()) + len(statement.signature)
                            for statement in bundle.private_opening_statements)
        stored_scalars = 2 * 3 * dimension
        rows.append({"dimension": dimension, "public_certificate_json_bytes": public_bytes,
                     "private_opening_statement_bytes": private_bytes,
                     "durable_component_scalars_across_six_copies": stored_scalars,
                     "public_commitments": 8, "public_signatures": 8,
                     "certificate_verified": 1})
        obligations += 1
    return rows, obligations


def continuity_checks():
    cases, sample, evidence, case_obligations = protocol_cases()
    privacy, privacy_obligations = privacy_checks()
    sizes, size_obligations = size_checks()
    return cases, privacy, sizes, sample, evidence, case_obligations + privacy_obligations + size_obligations
