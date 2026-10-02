"""Frozen benign experiments. Predetermined counts are checks, not fit targets."""
from __future__ import annotations
from collections import Counter
from dataclasses import asdict, replace
from itertools import permutations, product
from .model import Conflict, Descriptor, Ledger, Ready, Share, Store, fixture, reconstruct
from .evidence import Binding, Signed, export, fixture_key, public_bytes, sign, verify_contradiction


def _install(stores: list[Store], shares: tuple[Share, ...]) -> None:
    for store, share in zip(stores, shares):
        store.stage(share)
        store.persist(share.descriptor)


def schedule_checks() -> tuple[list[dict], list[dict], int]:
    rows, traces = [], []
    for case, order in enumerate(permutations(('A0', 'A1', 'A2', 'B0', 'B1', 'B2'))):
        ledger, da, db, a, b, expected = fixture()
        stores = [Store(i) for i in range(3)]
        for event in order:
            generation, slot = event[0], int(event[1])
            share = (a if generation == 'A' else b)[slot]
            stores[slot].stage(share)
            stores[slot].persist(share.descriptor)
        ledger.activate(da, tuple(s.ready(da) for s in stores))
        latest = tuple(s.latest for s in stores)
        assert all(v is not None for v in latest)
        traces.append({'case': f'order-{case:03}', 'events': ' '.join(order),
                       'latest_generations': ''.join('A' if s.descriptor == da else 'B' for s in latest)})
        for variant in ('content-latest', 'attempt-latest', 'pinned-latest', 'immutable-pinned'):
            if variant == 'immutable-pinned':
                selected = tuple(s.read(ledger.active[0]) for s in stores)
                accepted = all(x.descriptor == ledger.active[0] for x in selected)
            else:
                selected = latest
                if variant == 'content-latest':
                    accepted = all(x.descriptor.seal == da.seal for x in selected)
                elif variant == 'attempt-latest':
                    accepted = all(x.descriptor.seal == da.seal and x.descriptor.attempt == da.attempt for x in selected)
                else:
                    accepted = all(x.descriptor == ledger.active[0] for x in selected)
            decoded = reconstruct(selected, 101) if accepted else None
            correct = decoded == expected if accepted else False
            outcome = 'correct' if accepted and correct else 'wrong' if accepted else 'reject'
            rows.append({'case': f'order-{case:03}', 'variant': variant, 'outcome': outcome,
                         'accepted': int(accepted), 'content_correct': int(correct),
                         'active_generation_honored': int(accepted and all(s.descriptor == da for s in selected)),
                         'decoded': '' if decoded is None else ';'.join(map(str, decoded))})
    counts = {v: dict(Counter(r['outcome'] for r in rows if r['variant'] == v)) for v in
              ('content-latest', 'attempt-latest', 'pinned-latest', 'immutable-pinned')}
    predicted = {'content-latest': {'correct':180, 'wrong':540},
                 'attempt-latest': {'correct':180, 'wrong':540},
                 'pinned-latest': {'correct':90, 'reject':630},
                 'immutable-pinned': {'correct':720}}
    if counts != predicted:
        raise AssertionError(('permutation oracle discrepancy', counts, predicted))
    return rows, traces, len(rows)


def crash_checks() -> tuple[list[dict], int]:
    rows = []
    for bits, target, boundary in product(product((0, 1), repeat=3), range(3), range(4)):
        ledger, da, db, a, b, expected = fixture()
        stores = [Store(i) for i in range(3)]
        readiness: dict[int, Ready] = {}
        # The three bits only vary irrelevant B arrival timing around the A work.
        for i in range(3):
            if bits[i] == 0:
                stores[i].stage(b[i]); stores[i].persist(db)
        for i in range(3):
            if i != target:
                stores[i].stage(a[i]); stores[i].persist(da)
                readiness[i] = stores[i].ready(da)
        if boundary >= 1:
            stores[target].stage(a[target])
        if boundary >= 2:
            stores[target].persist(da)
        if boundary >= 3:
            readiness[target] = stores[target].ready(da)
        stores[target].crash()
        before = False
        try:
            ledger.activate(da, tuple(readiness.values()))
            before = True
        except Conflict:
            pass
        if before != (boundary == 3):
            raise AssertionError('activation before replay differs from readiness oracle')
        for i in range(3):
            if bits[i] == 1:
                stores[i].stage(b[i]); stores[i].persist(db)
        # One exact replay is allowed, with the old generation identity and values.
        stores[target].stage(a[target]); stores[target].persist(da)
        readiness[target] = stores[target].ready(da)
        ledger.activate(da, tuple(readiness.values()))
        decoded = reconstruct(tuple(s.read(da) for s in stores), 101)
        if decoded != expected:
            raise AssertionError('crash/replay oracle disagreement')
        rows.append({'case': f'crash-{len(rows):03}', 'background_order': ''.join(map(str,bits)),
                     'target_slot': target, 'boundary': boundary,
                     'active_before_replay': int(before), 'active_after_replay':1,
                     'content_correct_after_replay':1})
    return rows, 2*len(rows)


def semantic_checks() -> tuple[list[dict], int]:
    rows = []
    def observe(name: str, value: bool, note: str) -> None:
        if not value:
            raise AssertionError(('semantic predicate', name))
        rows.append({'case': f'semantic-{len(rows):02}', 'name': name, 'predicate_true':1, 'meaning':note})
    def raises(operation, exception=Conflict) -> bool:
        try: operation()
        except exception: return True
        return False

    l = Ledger(); r = l.admit(('c',0),'x')
    observe('stable-id-retry', l.admit(('c',0),'x') == r and len(l.receipts)==1, 'Retry returns original receipt, no second admission.')
    observe('conflicting-id', raises(lambda:l.admit(('c',0),'y')), 'Same request cannot change commitment.')
    l.seal(0,('a','b','c'))
    observe('retry-after-cut', l.admit(('c',0),'x')==r and len(l.seals[0].content)==1, 'Retry after sealing is idempotent.')
    l.admit(('d',0),'z')
    observe('late-admission', len(l.seals[0].content)==1 and len(l.receipts)==2, 'Sealed content does not include later input.')
    s1=l.seal(1,('d','e','f'))
    observe('next-snapshot', len(s1.content)==2, 'An admitted ID may legitimately appear once in each later snapshot.')
    observe('membership-is-ordered', raises(lambda:l.seal(0,('b','a','c'))), 'Permutation changes the fixed membership context.')
    observe('new-id-not-deduplicated-by-value', l.admit(('c',1),'x')==3, 'Equal payload tokens under distinct IDs are different admissions.')
    observe('invalid-request', raises(lambda:l.admit(('c',-1),'x'), ValueError), 'Invalid sequence is rejected.')
    l,da,db,a,b,secret=fixture(); stores=[Store(i) for i in range(3)]; _install(stores,a)
    ready=tuple(s.ready(da) for s in stores); l.activate(da,ready)
    observe('activation-replay', l.activate(da,ready)==da, 'Repeated identical activation is idempotent.')
    _install(stores,b)
    observe('activation-immutable', raises(lambda:l.activate(db,tuple(s.ready(db) for s in stores))), 'A second generation cannot replace the active one.')
    observe('duplicate-ready-slot', raises(lambda:l.activate(da,(ready[0],ready[0],ready[2]))), 'Repeated signature identity is not an extra slot.')
    foreign=replace(da,seal=replace(da.seal,service='foreign'))
    observe('foreign-context', raises(lambda:l.activate(foreign,tuple(Ready(foreign,i) for i in range(3)))), 'Activation checks the full sealed context.')
    observe('wrong-share-slot', raises(lambda:stores[0].stage(a[1])), 'Share destination is enforced.')
    changed=replace(a[0],values=tuple((x+1)%101 for x in a[0].values))
    observe('immutable-slot-write', raises(lambda:stores[0].stage(changed)), 'One generation slot cannot change its value.')
    empty=Store(0); empty.stage(a[0])
    observe('ready-requires-persistence', raises(lambda:empty.ready(da)), 'A staged but unpersisted value cannot issue READY.')
    empty.crash()
    observe('crash-discards-volatile', raises(lambda:empty.read(da),KeyError), 'The crash transition discards staged values.')
    empty.stage(a[0]); empty.persist(da); empty.crash()
    observe('crash-keeps-durable', empty.read(da)==a[0], 'Durability here is the model definition, not a hardware measurement.')
    empty.stage(a[0]); empty.persist(da)
    observe('replay-same-generation', empty.read(da)==a[0], 'Exact replay preserves the immutable slot.')
    observe('no-cross-generation-fallback', raises(lambda:empty.read(db),KeyError), 'Missing pinned state is not replaced by a different generation.')
    _install(stores,b)
    observe('pin-not-latest', reconstruct(tuple(s.read(da) for s in stores),101)==secret, 'A newer arrival cannot alter a pinned read.')
    # A deliberately broken oracle is outside the primitive contract. The wrapper
    # has no implemented proof that binds private values to public commitments.
    l2, da2, _, a2, _, secret2=fixture(); ss=[Store(i) for i in range(3)]
    broken=(replace(a2[0],values=tuple((x+1)%101 for x in a2[0].values)),a2[1],a2[2])
    _install(ss,broken); l2.activate(da2,tuple(s.ready(da2) for s in ss))
    observe('invalid-primitive-negative-control', reconstruct(tuple(s.read(da2) for s in ss),101)!=secret2,
            'A bad private share passes the wrapper when the assumed resharing primitive is violated. This is an intentional limitation, not a security PASS.')
    for target in range(3):
        lx, dx, _, ax, _, sx=fixture(); xs=[Store(i) for i in range(3)]
        for i in range(3):
            xs[i].stage(ax[i])
            if i != target: xs[i].persist(dx)
        # Fault injection: forge a truthfully authenticated but prematurely issued
        # READY through the model constructor. No signature forgery is attempted.
        early=tuple(Ready(dx,i) for i in range(3)); lx.activate(dx,early); xs[target].crash()
        observe(f'early-ready-crash-{target}', raises(lambda:xs[target].read(dx),KeyError),
                'Premature READY allows an activated epoch with missing data after a crash.')
    if len(rows)!=24: raise AssertionError(('frozen semantic count',len(rows)))
    return rows,len(rows)


def evidence_checks() -> tuple[list[dict], list[dict], int]:
    rows, transcripts = [], []
    families=('contradiction','equal-root','different-generation','different-attempt',
              'different-service','tampered-signature','outsider','different-membership')
    key=fixture_key('authorized'); outsider=fixture_key('outsider')
    for family, i in product(families,range(16)):
        base=Binding('service',i,('alice','bob','carol'),8,f'content-{i}','attempt','generation','BIND','alice','root-left')
        other=replace(base,root='root-right')
        auth={(base.service,base.epoch,base.membership,base.signer):public_bytes(key)}
        signing_key=key
        if family=='equal-root': other=base
        elif family=='different-generation': other=replace(other,generation='other-generation')
        elif family=='different-attempt': other=replace(other,attempt='other-attempt')
        elif family=='different-service': other=replace(other,service='other-service')
        elif family=='outsider': signing_key=outsider
        elif family=='different-membership': other=replace(other,membership=('bob','alice','carol'))
        left=sign(base,signing_key); right=sign(other,signing_key)
        if family=='tampered-signature':
            right=Signed(right.statement,bytes([right.signature[0]^1])+right.signature[1:])
        observed=verify_contradiction(left,right,auth)
        expected=family=='contradiction'
        if observed!=expected: raise AssertionError(('signed evidence oracle',family,i))
        case=f'evidence-{len(rows):03}'
        encoded=len(left.statement.encode())+len(right.statement.encode())+len(left.signature)+len(right.signature)
        rows.append({'case':case,'family':family,'accepted':int(observed),'expected':int(expected),'statement_and_signature_bytes':encoded})
        transcripts.append({'case':case,'left':export(left),'right':export(right),
                            'authorization':[{'context':[base.service,base.epoch,list(base.membership),base.signer],
                                             'public_key_hex':public_bytes(key).hex()}],
                            'expected':expected})
    return rows,transcripts,len(rows)
