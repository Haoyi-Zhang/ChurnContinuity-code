import sys
import unittest
from pathlib import Path
from dataclasses import replace
from collections import Counter
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from churn.algebra import replicated,interpolate_zero
from churn.model import Conflict,Ledger,Store,Ready,fixture,reconstruct
from churn.evidence import Binding,Signed,fixture_key,public_bytes,sign,verify_contradiction
from churn.continuity import (
    DurableServer, Opening, Statement, TinyVectorPedersen, TransferContext,
    deep_copy_certificate, derive_survivor_opening, fixture_authorization, import_signed, initial_state, make_transfer,
    sign_statement, validate_serial_contexts, verify_certificate, verify_certificate_chain, verify_equivocation, verify_invalid_opening,
    verify_private_delivery, vec_add,
)
from churn.continuity_experiments import _component_steps, _finalize, _servers, complete_transfer, privacy_checks
from churn.joint_view import compute_report as joint_view_report

class ContractTests(unittest.TestCase):
    def bindings(self):
        b=Binding('s',0,('a','b','c'),8,'root','a','g','BIND','a','x')
        k=fixture_key('unit');auth={('s',0,('a','b','c'),'a'):public_bytes(k)}
        return b,k,auth
    def test_additive_reconstruction(self):
        self.assertEqual(sum(replicated(37,10,20,101))%101,37)
    def test_shamir_reconstruction(self):
        self.assertEqual(interpolate_zero((1,3),(44,58),101),37)
    def test_decomposable_scheme_allows_mixing(self):
        # Independent zero-sum blocks refute a universal same-generation necessity.
        self.assertEqual(sum((10,-10,37+22,-22))%101,37)
    def test_nonunit_ring_image(self):
        self.assertEqual(Counter(2*x%8 for x in range(8)),{0:2,2:2,4:2,6:2})
    def test_bad_interpolation_input(self):
        with self.assertRaises(ValueError):interpolate_zero((1,1),(3,4),5)
    def test_receipt_idempotence(self):
        l=Ledger();self.assertEqual(l.admit(('c',0),'x'),l.admit(('c',0),'x'))
    def test_conflicting_commitment(self):
        l=Ledger();l.admit(('c',0),'x')
        with self.assertRaises(Conflict):l.admit(('c',0),'y')
    def test_cut_is_immutable(self):
        l=Ledger();l.admit(('c',0),'x');s=l.seal(0,('a','b','c'));l.admit(('c',1),'y')
        self.assertEqual(len(s.content),1)
    def test_readiness_not_persisted(self):
        _,d,_,a,_,_=fixture();s=Store(0);s.stage(a[0])
        with self.assertRaises(Conflict):s.ready(d)
    def test_durable_crash_read(self):
        _,d,_,a,_,_=fixture();s=Store(0);s.stage(a[0]);s.persist(d);s.crash()
        self.assertEqual(s.read(d),a[0])
    def test_activation_needs_all_component_slots(self):
        l,d,_,_,_,_=fixture()
        with self.assertRaises(Conflict):l.activate(d,(Ready(d,0),Ready(d,1)))
    def test_positive_contradiction(self):
        b,k,auth=self.bindings();self.assertTrue(verify_contradiction(sign(b,k),sign(replace(b,root='y'),k),auth))
    def test_mutated_plaintext_signature(self):
        b,k,auth=self.bindings();r=sign(replace(b,root='y'),k);r=Signed(replace(r.statement,root='z'),r.signature)
        self.assertFalse(verify_contradiction(sign(b,k),r,auth))
    def test_authorization_is_not_self_certifying(self):
        b,k,auth=self.bindings();foreign=fixture_key('foreign')
        self.assertFalse(verify_contradiction(sign(b,foreign),sign(replace(b,root='y'),foreign),auth))
    def test_different_generation_not_equivocation(self):
        b,k,auth=self.bindings()
        self.assertFalse(verify_contradiction(sign(b,k),sign(replace(b,root='y',generation='other'),k),auth))
    def test_rollback_witness_does_not_establish_malice(self):
        b,k,auth=self.bindings()
        # Two stateless honest signing invocations after lost binding state can
        # produce the same positive witness. Intent is not a verifier output.
        before=sign(b,k);after=sign(replace(b,root='y'),k)
        self.assertTrue(verify_contradiction(before,after,auth))

    def test_new_seals_require_increasing_epoch(self):
        l=Ledger();l.admit(('c',0),'x');l.seal(4,('a','b','c'))
        with self.assertRaises(Conflict):l.seal(3,('a','b','c'))
    def test_epoch_prefix_inclusion(self):
        l=Ledger();l.admit(('c',0),'x');old=l.seal(0,('a','b','c'))
        l.admit(('c',1),'y');new=l.seal(2,('d','e','f'))
        self.assertTrue(set(old.content).issubset(set(new.content)))
        self.assertLessEqual(old.cut,new.cut)
    def test_old_seal_retry_after_new_epoch(self):
        l=Ledger();old=l.seal(0,('a','b','c'));l.seal(1,('d','e','f'))
        self.assertEqual(l.seal(0,('a','b','c')),old)
    def test_exact_sparse_inputs_are_consumed(self):
        l,da,_,a,_,secret=fixture()
        self.assertEqual(len(l.receipts),8)
        self.assertEqual(reconstruct(a,101),secret)

    def continuity_fixture(self, dimension=4):
        group=TinyVectorPedersen()
        old=('old-0','stay-1','stay-2');new=('new-0','stay-1','stay-2')
        context=TransferContext('svc',3,'cut',old,new,0,'session','generation',dimension)
        secret=tuple(range(1,dimension+1))
        state=initial_state(secret,old,'unit-state',group)
        keys,auth=fixture_authorization(set(old)|set(new))
        bundle=make_transfer(context,state,keys,'unit-transfer',group)
        complete_transfer(bundle,keys,group)
        return group,context,secret,keys,auth,bundle

    def test_replicated_physical_layout(self):
        group,_,_,_,_,bundle=self.continuity_fixture()
        for slot in range(3):
            self.assertEqual(set(bundle.new_state.holdings(slot)),{0,1,2}-{slot})
        bundle.new_state.validate(group)

    def test_continuity_preserves_vector(self):
        group,_,secret,_,_,bundle=self.continuity_fixture()
        self.assertEqual(bundle.new_state.secret(group.q),secret)

    def test_continuity_certificate_verifies(self):
        group,_,_,_,auth,bundle=self.continuity_fixture()
        self.assertTrue(verify_certificate(bundle.certificate,auth,group))

    def test_continuity_link_mutation_rejected(self):
        group,_,_,_,auth,bundle=self.continuity_fixture()
        cert=deep_copy_certificate(bundle.certificate)
        cert['new_commitments'][0]=group.mul(cert['new_commitments'][0],group.g(0))
        self.assertFalse(verify_certificate(cert,auth,group))
        outside=deep_copy_certificate(bundle.certificate)
        outside['mask_commitments'][sorted(outside['mask_commitments'])[0]]=group.p-1
        self.assertFalse(verify_certificate(outside,auth,group))

    def test_continuity_missing_receipt_rejected(self):
        group,_,_,_,auth,bundle=self.continuity_fixture()
        cert=deep_copy_certificate(bundle.certificate);cert['receipts'].pop()
        self.assertFalse(verify_certificate(cert,auth,group))

    def test_full_certificate_mutation_matrix_rejected(self):
        group,_,_,_,auth,bundle=self.continuity_fixture()
        mutations=[]
        cert=deep_copy_certificate(bundle.certificate)
        cert['new_commitments'][0]=group.mul(cert['new_commitments'][0],group.g(0))
        mutations.append(('new-commitment',cert))
        cert=deep_copy_certificate(bundle.certificate)
        key=sorted(cert['mask_commitments'])[0]
        cert['mask_commitments'][key]=group.mul(cert['mask_commitments'][key],group.g(1))
        mutations.append(('mask-commitment',cert))
        cert=deep_copy_certificate(bundle.certificate)
        raw=bytearray.fromhex(cert['proposals'][0]['signature_hex']);raw[0]^=1
        cert['proposals'][0]['signature_hex']=bytes(raw).hex()
        mutations.append(('proposal-signature',cert))
        cert=deep_copy_certificate(bundle.certificate);cert['receipts'].pop()
        mutations.append(('missing-receipt',cert))
        cert=deep_copy_certificate(bundle.certificate);cert['receipts'][0]['statement']['signer']='new-0'
        mutations.append(('receipt-signer',cert))
        cert=deep_copy_certificate(bundle.certificate);cert['receipts'][0]['statement']['body']['component']=2
        mutations.append(('receipt-component',cert))
        cert=deep_copy_certificate(bundle.certificate);cert['context']['epoch']+=1
        mutations.append(('context-epoch',cert))
        cert=deep_copy_certificate(bundle.certificate)
        cert['old_commitments'][1]=group.mul(cert['old_commitments'][1],group.g(2))
        mutations.append(('old-commitment',cert))
        for name,cert in mutations:
            with self.subTest(name=name):
                self.assertFalse(verify_certificate(cert,auth,group))

    def test_toy_commitment_generators_are_distinct_in_frozen_dimension(self):
        group=TinyVectorPedersen()
        generators=(group.h,)+tuple(group.g(i) for i in range(64))
        self.assertEqual(len(generators),len(set(generators)))
        self.assertTrue(all(group.is_subgroup_element(value) for value in generators))

    def test_durable_component_requires_valid_opening(self):
        group,context,_,_,_,bundle=self.continuity_fixture()
        server=DurableServer(context.new_members[0],0,group)
        opening=Opening(bundle.new_state.components[1],bundle.new_state.blindings[1])
        with self.assertRaises(ValueError):
            server.persist_component(context.identifier(),1,opening,group.mul(bundle.new_state.commitments[1],group.g(0)))

    def test_durable_component_survives_model_crash(self):
        group,context,_,_,_,bundle=self.continuity_fixture()
        server=DurableServer(context.new_members[0],0,group)
        opening=Opening(bundle.new_state.components[1],bundle.new_state.blindings[1])
        server.persist_component(context.identifier(),1,opening,bundle.new_state.commitments[1])
        server.crash()
        self.assertTrue(server.has_component(context.identifier(),1,bundle.new_state.commitments[1]))

    def test_certificate_prefix_has_no_preissued_receipts(self):
        group=TinyVectorPedersen();old=('old-0','stay-1','stay-2');new=('new-0','stay-1','stay-2')
        context=TransferContext('svc',3,'cut',old,new,0,'session','generation',1)
        state=initial_state((7,),old,'prefix-state',group)
        keys,auth=fixture_authorization(set(old)|set(new))
        bundle=make_transfer(context,state,keys,'prefix-transfer',group)
        self.assertEqual(bundle.certificate['receipts'],[])
        self.assertFalse(verify_certificate(bundle.certificate,auth,group))

    def test_receipt_cannot_precede_durable_component(self):
        group=TinyVectorPedersen();old=('old-0','stay-1','stay-2');new=('new-0','stay-1','stay-2')
        context=TransferContext('svc',3,'cut',old,new,0,'session','generation',1)
        state=initial_state((7,),old,'receipt-state',group)
        keys,_=fixture_authorization(set(old)|set(new))
        bundle=make_transfer(context,state,keys,'receipt-transfer',group)
        server=DurableServer(new[0],0,group)
        with self.assertRaises(ValueError):
            server.issue_receipt(context,1,bundle.new_state.commitments[1],keys[new[0]])

    def test_replacement_receives_authenticated_component_openings(self):
        group,context,_,_,auth,bundle=self.continuity_fixture()
        replacement=context.new_members[context.replaced_slot]
        delivered=[]
        for message in bundle.private_opening_statements:
            result=verify_private_delivery(message,context,bundle.mask_commitments,
                                           bundle.new_state.commitments,auth,group)
            self.assertIsNotNone(result)
            if message.statement.body['recipient']==replacement:
                self.assertEqual(message.statement.kind,'MASK_COMPONENT_OPENING')
                self.assertIsNotNone(result[1]);delivered.append(result[1][0])
            else:
                self.assertEqual(message.statement.kind,'MASK_OPENING')
                self.assertIsNone(result[1])
        self.assertEqual(set(delivered),{1,2})

    def test_survivor_local_derivation_matches_committed_state(self):
        group,context,_,_,auth,bundle=self.continuity_fixture()
        k=context.replaced_slot;a,b=(k+1)%3,(k+2)%3
        peer_messages={m.statement.body['recipient']:m for m in bundle.private_opening_statements
                       if m.statement.kind=='MASK_OPENING'}
        for slot in (a,b):
            own_target=b if slot==a else a
            for component in (k,own_target):
                old_opening=Opening(bundle.old_state.components[component],bundle.old_state.blindings[component])
                message=peer_messages[context.new_members[slot]] if component==k else None
                derived=derive_survivor_opening(
                    context,slot,component,old_opening,bundle.mask_openings[own_target],
                    bundle.mask_commitments,bundle.old_state.commitments,
                    bundle.new_state.commitments,auth,message,group)
                self.assertEqual(derived,Opening(bundle.new_state.components[component],
                                                 bundle.new_state.blindings[component]))

    def test_tampered_peer_mask_blocks_common_derivation(self):
        group,context,_,keys,auth,bundle=self.continuity_fixture()
        k=context.replaced_slot;a,b=(k+1)%3,(k+2)%3
        message=next(m for m in bundle.private_opening_statements
                     if m.statement.kind=='MASK_OPENING' and
                        m.statement.body['recipient']==context.new_members[a])
        body=dict(message.statement.body);values=list(body['values']);values[0]=(values[0]+1)%group.q
        body['values']=values
        bad=Statement(message.statement.context_id,message.statement.kind,
                      message.statement.signer,message.statement.role,body)
        signed=sign_statement(bad,keys[bad.signer])
        old_opening=Opening(bundle.old_state.components[k],bundle.old_state.blindings[k])
        self.assertIsNone(derive_survivor_opening(
            context,a,k,old_opening,bundle.mask_openings[b],bundle.mask_commitments,
            bundle.old_state.commitments,bundle.new_state.commitments,auth,signed,group))

    def test_tampered_replacement_component_opening_rejected(self):
        group,context,_,keys,auth,bundle=self.continuity_fixture()
        message=next(m for m in bundle.private_opening_statements
                     if m.statement.kind=='MASK_COMPONENT_OPENING')
        body=dict(message.statement.body)
        values=list(body['component_values']);values[0]=(values[0]+1)%group.q
        body['component_values']=values
        bad=Statement(message.statement.context_id,message.statement.kind,
                      message.statement.signer,message.statement.role,body)
        signed=sign_statement(bad,keys[bad.signer])
        self.assertIsNone(verify_private_delivery(signed,context,bundle.mask_commitments,
                                                  bundle.new_state.commitments,auth,group))

    def test_invalid_mask_opening_is_positive_evidence(self):
        group,context,_,keys,auth,bundle=self.continuity_fixture()
        valid=bundle.private_opening_statements[0]
        body=dict(valid.statement.body);values=list(body['values']);values[0]=(values[0]+1)%group.q;body['values']=values
        bad=Statement(valid.statement.context_id,valid.statement.kind,valid.statement.signer,valid.statement.role,body)
        self.assertTrue(verify_invalid_opening(sign_statement(bad,keys[bad.signer]),context,auth,group))
        self.assertFalse(verify_invalid_opening(valid,context,auth,group))
        outsider=TransferContext('svc',3,'cut',('x','stay-1','stay-2'),
                                 ('new-x','stay-1','stay-2'),0,'other','other-generation',4)
        self.assertFalse(verify_invalid_opening(sign_statement(bad,keys[bad.signer]),outsider,auth,group))

    def test_replacement_component_envelope_is_not_public_mask_evidence(self):
        group,context,_,keys,auth,bundle=self.continuity_fixture()
        message=next(m for m in bundle.private_opening_statements
                     if m.statement.kind=='MASK_COMPONENT_OPENING')
        body=dict(message.statement.body);body['values']=list(body['values'])
        body['values'][0]=(body['values'][0]+1)%group.q
        bad=Statement(message.statement.context_id,message.statement.kind,
                      message.statement.signer,message.statement.role,body)
        signed=sign_statement(bad,keys[bad.signer])
        self.assertIsNone(verify_private_delivery(
            signed,context,bundle.mask_commitments,bundle.new_state.commitments,auth,group))
        self.assertFalse(verify_invalid_opening(signed,context,auth,group))

    def test_mask_equivocation_context_bound(self):
        group,context,_,keys,auth,bundle=self.continuity_fixture()
        first=bundle.proposal_statements[0];body=dict(first.statement.body)
        body['mask_commitment']=group.mul(body['mask_commitment'],group.g(3))
        changed=Statement(first.statement.context_id,first.statement.kind,first.statement.signer,first.statement.role,body)
        self.assertTrue(verify_equivocation(first,sign_statement(changed,keys[changed.signer]),context,auth,group))
        malformed_body=dict(first.statement.body);malformed_body['dimension']+=1
        malformed=Statement(first.statement.context_id,first.statement.kind,first.statement.signer,first.statement.role,malformed_body)
        self.assertFalse(verify_equivocation(first,sign_statement(malformed,keys[malformed.signer]),context,auth,group))

    def test_exact_single_server_privacy_views(self):
        rows,obligations=privacy_checks()
        self.assertEqual(len(rows),15)
        self.assertEqual(obligations,9375)
        self.assertTrue(all(row['matches_secret_zero'] for row in rows))

    def test_joint_private_public_view_checker(self):
        rows,report=joint_view_report()
        self.assertEqual(len(rows),8)
        self.assertEqual(report['exact_assignments'],4096)
        self.assertEqual(report['rank_checks'],64)
        self.assertTrue(report['all_exact_distributions_equal'])
        self.assertTrue(report['all_rank_checks_passed'])

    def test_prepared_replacement_opening_is_locally_derived(self):
        group,context,_,_,_,bundle=self.continuity_fixture()
        k=context.replaced_slot
        a,b=(k+1)%3,(k+2)%3
        slot_by_signer={context.old_members[a]:a,context.old_members[b]:b}
        for message in bundle.private_opening_statements:
            if message.statement.kind!='MASK_COMPONENT_OPENING':
                continue
            target=message.statement.body['target_component']
            slot=slot_by_signer[message.statement.signer]
            old=bundle.old_state.holdings(slot)[target]
            mask=bundle.mask_openings[target]
            expected_values=vec_add(old.values,mask.values,group.q)
            expected_blinding=(old.blinding+mask.blinding)%group.q
            self.assertEqual(tuple(message.statement.body['component_values']),expected_values)
            self.assertEqual(message.statement.body['component_blinding'],expected_blinding)

    def test_partial_sender_preparation_resumes_from_durable_mask(self):
        group,context,_,keys,_,bundle=self.continuity_fixture()
        k=context.replaced_slot;a,b=(k+1)%3,(k+2)%3
        for proposal in bundle.proposal_statements:
            signer=proposal.statement.signer;target=proposal.statement.body['target_component']
            source=bundle.preparation_servers[signer]
            expected=source.replay_survivor_transfer(context,target)
            labels=(f'proposal:{target}',f'peer-mask:{target}',f'replacement-component:{target}')
            slot=source.physical_slot
            peer=context.old_members[b] if slot==a else context.old_members[a]
            for prefix in range(4):
                with self.subTest(signer=signer,prefix=prefix):
                    server=DurableServer(signer,slot,group)
                    server.persist_mask(context,target,bundle.mask_openings[target],bundle.mask_commitments[target])
                    for label,message in zip(labels,expected[:prefix]):
                        server.persist_outbox(context.identifier(),label,message)
                    server.crash()
                    replay=server.resume_survivor_transfer(
                        context,target,bundle.old_state.holdings(slot)[target],
                        bundle.old_state.commitments[target],bundle.mask_commitments[target],
                        bundle.new_state.commitments[target],peer,context.new_members[k],keys[signer])
                    self.assertEqual(tuple(m.export() for m in replay),
                                     tuple(m.export() for m in expected))

    def test_sender_outbox_requires_durable_mask(self):
        group,context,_,keys,_,bundle=self.continuity_fixture()
        proposal=bundle.proposal_statements[0]
        signer=proposal.statement.signer;target=proposal.statement.body['target_component']
        source=bundle.preparation_servers[signer];slot=source.physical_slot
        k=context.replaced_slot;a,b=(k+1)%3,(k+2)%3
        peer=context.old_members[b] if slot==a else context.old_members[a]
        server=DurableServer(signer,slot,group)
        with self.assertRaises(ValueError):
            server.persist_survivor_outbox_item(
                context,target,bundle.old_state.holdings(slot)[target],
                bundle.old_state.commitments[target],bundle.mask_commitments[target],
                bundle.new_state.commitments[target],peer,context.new_members[k],keys[signer],
                f'proposal:{target}')

    def test_campaign_starts_empty_and_exposes_20_boundaries(self):
        group,_,_,keys,_,bundle=self.continuity_fixture()
        fresh=_servers(bundle,group)
        self.assertTrue(all(not s.durable_masks and not s.durable_outbox and not s.durable_components
                            for s in fresh.values()))
        steps=_component_steps(bundle,fresh,keys)
        self.assertEqual(len(steps),20)
        steps[0][1]()
        self.assertEqual(sum(len(s.durable_masks) for s in fresh.values()),1)
        self.assertEqual(sum(len(s.durable_outbox) for s in fresh.values()),0)

    def test_campaign_certificate_uses_fresh_durable_proposals(self):
        group,context,_,keys,auth,bundle=self.continuity_fixture()
        # Erase the deterministic inspection prefix: finalization must recover
        # both proposals from the executing servers, not from this fixture.
        bundle.certificate['proposals']=[]
        fresh=_servers(bundle,group)
        for _,action,_ in _component_steps(bundle,fresh,keys):
            action()
        certificate=_finalize(bundle,fresh)
        self.assertTrue(verify_certificate(certificate,auth,group))
        k=context.replaced_slot;a,b=(k+1)%3,(k+2)%3
        context_id=context.identifier()
        expected=[
            fresh[context.old_members[b]].durable_outbox[(context_id,f'proposal:{a}')].export(),
            fresh[context.old_members[a]].durable_outbox[(context_id,f'proposal:{b}')].export(),
        ]
        expected.sort(key=lambda raw:(raw['statement']['body']['target_component'],
                                      raw['statement']['signer']))
        self.assertEqual(certificate['proposals'],expected)
        del fresh[context.old_members[b]].durable_outbox[(context_id,f'proposal:{a}')]
        with self.assertRaises(KeyError):
            _finalize(bundle,fresh)

    def test_all_replacement_slots_are_symmetric(self):
        group=TinyVectorPedersen()
        for replaced_slot in range(3):
            with self.subTest(replaced_slot=replaced_slot):
                old=('old-0','old-1','old-2')
                new=list(old);new[replaced_slot]=f'new-{replaced_slot}';new=tuple(new)
                context=TransferContext('svc',9,'cut',old,new,replaced_slot,
                                        f'session-{replaced_slot}',f'generation-{replaced_slot}',4)
                secret=(4,8,15,16)
                state=initial_state(secret,old,f'all-slots-{replaced_slot}',group)
                keys,auth=fixture_authorization(set(old)|set(new))
                bundle=make_transfer(context,state,keys,f'transfer-{replaced_slot}',group)
                fresh=_servers(bundle,group)
                self.assertEqual(len(_component_steps(bundle,fresh,keys)),20)
                servers=complete_transfer(bundle,keys,group)
                self.assertTrue(verify_certificate(bundle.certificate,auth,group))
                self.assertEqual(bundle.new_state.secret(group.q),secret)
                for component,commitment in enumerate(bundle.new_state.commitments):
                    for slot,signer in enumerate(new):
                        if slot!=component:
                            self.assertTrue(servers[signer].has_component(
                                context.identifier(),component,commitment,
                                expected_dimension=context.dimension))

    def test_prepared_session_replays_and_rejects_resampling(self):
        group,context,_,keys,_,bundle=self.continuity_fixture()
        proposal=bundle.proposal_statements[0]
        signer=proposal.statement.signer
        target=proposal.statement.body['target_component']
        server=bundle.preparation_servers[signer]
        before=tuple(item.export() for item in server.replay_survivor_transfer(context,target))
        server.crash()
        after=tuple(item.export() for item in server.replay_survivor_transfer(context,target))
        self.assertEqual(before,after)
        altered=Opening(tuple((v+1)%group.q for v in bundle.mask_openings[target].values),
                        bundle.mask_openings[target].blinding)
        slot=server.physical_slot
        k=context.replaced_slot;a,b=(k+1)%3,(k+2)%3
        peer=context.old_members[b] if slot==a else context.old_members[a]
        with self.assertRaises(ValueError):
            server.prepare_survivor_transfer(
                context,target,bundle.old_state.holdings(slot)[target],
                bundle.old_state.commitments[target],altered,
                group.commit(altered.values,altered.blinding),
                bundle.new_state.commitments[target],peer,context.new_members[k],keys[signer])

    def test_private_delivery_dimension_is_context_bound(self):
        group,context,_,keys,auth,bundle=self.continuity_fixture()
        message=bundle.private_opening_statements[0]
        body=dict(message.statement.body);body['dimension']=context.dimension+1
        changed=Statement(message.statement.context_id,message.statement.kind,
                          message.statement.signer,message.statement.role,body)
        signed=sign_statement(changed,keys[changed.signer])
        self.assertIsNone(verify_private_delivery(signed,context,bundle.mask_commitments,
                                                 bundle.new_state.commitments,auth,group))

    def test_certificate_chain_binds_exact_prior_commitments(self):
        group=TinyVectorPedersen()
        m0=('a','b','c');m1=('d','b','c');m2=('d','e','c')
        all_keys,all_auth=fixture_authorization(set(m0)|set(m1)|set(m2))
        c1=TransferContext('svc',5,'cut',m0,m1,0,'s1','g1',3)
        s0=initial_state((11,12,13),m0,'chain-base',group)
        b1=make_transfer(c1,s0,{n:all_keys[n] for n in set(m0)|set(m1)},'chain-1',group)
        complete_transfer(b1,{n:all_keys[n] for n in set(m0)|set(m1)},group)
        c2=TransferContext('svc',5,'cut',m1,m2,1,'s2','g2',3)
        b2=make_transfer(c2,b1.new_state,{n:all_keys[n] for n in set(m1)|set(m2)},'chain-2',group)
        complete_transfer(b2,{n:all_keys[n] for n in set(m1)|set(m2)},group)
        self.assertTrue(verify_certificate_chain((b1.certificate,b2.certificate),all_auth,group))
        unrelated=initial_state((14,15,16),m1,'unrelated-base',group)
        bad=make_transfer(c2,unrelated,{n:all_keys[n] for n in set(m1)|set(m2)},'chain-bad',group)
        complete_transfer(bad,{n:all_keys[n] for n in set(m1)|set(m2)},group)
        self.assertFalse(verify_certificate_chain((b1.certificate,bad.certificate),all_auth,group))

    def test_serial_chain_enforces_no_identity_reentry(self):
        c1=TransferContext('svc',4,'cut',('a','b','c'),('d','b','c'),0,'s1','g1',2)
        c2=TransferContext('svc',4,'cut',('d','b','c'),('d','e','c'),1,'s2','g2',2)
        self.assertEqual(validate_serial_contexts((c1,c2)),(c1,c2))
        reentry=TransferContext('svc',4,'cut',('d','e','c'),('a','e','c'),0,'s3','g3',2)
        with self.assertRaises(ValueError):
            validate_serial_contexts((c1,c2,reentry))

    def test_wrong_dimension_component_cannot_receive_receipt(self):
        group,context,_,keys,_,bundle=self.continuity_fixture()
        server=DurableServer(context.new_members[0],0,group)
        short=Opening(bundle.new_state.components[1][:-1],bundle.new_state.blindings[1])
        with self.assertRaises(ValueError):
            server.persist_component(context.identifier(),1,short,
                                     group.commit(short.values,short.blinding),
                                     expected_dimension=context.dimension)
        with self.assertRaises(ValueError):
            server.issue_receipt(context,1,bundle.new_state.commitments[1],keys[context.new_members[0]])

    def test_context_rejects_two_replacements(self):
        with self.assertRaises(ValueError):
            TransferContext('svc',0,'cut',('a','b','c'),('x','y','c'),0,'s','g',1).validate()
        with self.assertRaises(ValueError):
            TransferContext('s'*129,0,'cut',('a','b','c'),('x','b','c'),0,'s','g',1).validate()
        group,_,_,_,auth,bundle=self.continuity_fixture()
        noncanonical=deep_copy_certificate(bundle.certificate)
        value=noncanonical['mask_commitments'].pop('1')
        noncanonical['mask_commitments']['01']=value
        self.assertFalse(verify_certificate(noncanonical,auth,group))

    def test_certificate_container_type_errors_return_false(self):
        group,_,_,_,auth,bundle=self.continuity_fixture()
        for field,values in {
            'context': (None, [], 'context'),
            'old_commitments': (None, {}, 'old'),
            'new_commitments': (None, {}, 'new'),
            'mask_commitments': (None, [], 'masks'),
            'proposals': (None, {}, 'proposals'),
            'receipts': (None, {}, 'receipts'),
        }.items():
            for value in values:
                with self.subTest(field=field,value_type=type(value).__name__):
                    cert=deep_copy_certificate(bundle.certificate);cert[field]=value
                    self.assertFalse(verify_certificate(cert,auth,group))

        for member_field in ('old_members','new_members'):
            for value in (None, {}, 'abc'):
                with self.subTest(context_field=member_field,value_type=type(value).__name__):
                    cert=deep_copy_certificate(bundle.certificate)
                    cert['context'][member_field]=value
                    self.assertFalse(verify_certificate(cert,auth,group))
        for context_field,value in (
            ('replaced_slot',True),('replaced_slot',0.0),
            ('dimension',True),('dimension',float(bundle.context.dimension)),
        ):
            with self.subTest(context_field=context_field,value=repr(value)):
                cert=deep_copy_certificate(bundle.certificate)
                cert['context'][context_field]=value
                self.assertFalse(verify_certificate(cert,auth,group))

        for collection in ('proposals','receipts'):
            for malformed in (None, [], 'message'):
                with self.subTest(collection=collection,message_type=type(malformed).__name__):
                    cert=deep_copy_certificate(bundle.certificate)
                    cert[collection][0]=malformed
                    self.assertFalse(verify_certificate(cert,auth,group))
            for malformed_body in (None, [], 'body'):
                with self.subTest(collection=collection,body_type=type(malformed_body).__name__):
                    cert=deep_copy_certificate(bundle.certificate)
                    cert[collection][0]['statement']['body']=malformed_body
                    self.assertFalse(verify_certificate(cert,auth,group))

    def test_re_signed_noncanonical_semantic_integers_are_rejected(self):
        group,_,_,keys,auth,bundle=self.continuity_fixture()

        cert=deep_copy_certificate(bundle.certificate)
        for index,raw in enumerate(cert['proposals']):
            signed=import_signed(raw)
            if signed.statement.body['target_component']==1:
                body=dict(signed.statement.body);body['target_component']=True
                cert['proposals'][index]=sign_statement(
                    Statement(signed.statement.context_id,signed.statement.kind,
                              signed.statement.signer,signed.statement.role,body),
                    keys[signed.statement.signer]).export()
        self.assertFalse(verify_certificate(cert,auth,group))

        cert=deep_copy_certificate(bundle.certificate)
        for index,raw in enumerate(cert['proposals']):
            signed=import_signed(raw);body=dict(signed.statement.body)
            body['dimension']=float(body['dimension'])
            cert['proposals'][index]=sign_statement(
                Statement(signed.statement.context_id,signed.statement.kind,
                          signed.statement.signer,signed.statement.role,body),
                keys[signed.statement.signer]).export()
        self.assertFalse(verify_certificate(cert,auth,group))

        cert=deep_copy_certificate(bundle.certificate)
        for index,raw in enumerate(cert['receipts']):
            signed=import_signed(raw)
            if signed.statement.body['component']==1:
                body=dict(signed.statement.body);body['component']=True
                cert['receipts'][index]=sign_statement(
                    Statement(signed.statement.context_id,signed.statement.kind,
                              signed.statement.signer,signed.statement.role,body),
                    keys[signed.statement.signer]).export()
        self.assertFalse(verify_certificate(cert,auth,group))

    def test_cross_context_receipt_transplant_rejected_with_generation_check_disabled(self):
        group,context,_,keys,auth,bundle=self.continuity_fixture()
        other_context=TransferContext(
            context.service,context.epoch,context.cut_root,context.old_members,
            context.new_members,context.replaced_slot,'other-session',
            'other-generation',context.dimension,
        )
        other=make_transfer(other_context,bundle.old_state,keys,'other-transfer',group)
        complete_transfer(other,keys,group)
        transplanted=deep_copy_certificate(bundle.certificate)
        transplanted['receipts']=deep_copy_certificate(other.certificate)['receipts']
        self.assertFalse(verify_certificate(transplanted,auth,group))
        self.assertFalse(verify_certificate(
            transplanted,auth,group,check_generation=False))

if __name__=='__main__':unittest.main()
