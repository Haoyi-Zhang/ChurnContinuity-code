# Assumptions, interfaces, and evidence map

| Object | Implemented | Assumed or excluded |
|---|---|---|
| Stable request admission | `Ledger.admit`: stable ID, immutable commitment, idempotent retry | Client authentication; indefinite identifier retention |
| Epoch cut | Immutable snapshot, increasing epoch numbers and nondecreasing contents | Consensus and authorization for the cut root |
| Replicated sharing | Three additive vectors; server `i` stores components `j != i` | Prime-field application state encoding |
| One-slot transfer | Two survivor masks, two peer mask openings, two replacement mask+component deliveries, refreshed physical holdings, no reconstruction | Confidential authenticated private channels; authorized one-slot membership change |
| Vector commitments | Homomorphic toy vector-Pedersen equations | Large secure group, unknown generator relations, binding assumption |
| Public certificate | 3 old + 3 new + 2 mask commitments; 2 proposals + 6 receipts | Public-key infrastructure and activation-log consensus |
| Durability | Immutable dictionaries unaffected by the explicit crash transition; `issue_receipt` requires a matching durable component first | Real `fsync`, media loss, rollback-resistant signing hardware |
| Crash replay | Session-bound deterministic outboxes and idempotent writes | Eventually resuming participants and message delivery |
| Static protocol-following privacy | Written role simulators; exact `F_5` algebraic subviews; independent one-coordinate joint-view checker | No malicious-receiver privacy, mobile corruption, two-server collusion, or traffic-analysis claim; declared metadata leakage |
| Positive blame | Independently signed invalid peer-mask opening; same-context equivocation | No complete blame for silence or unverifiable private behavior |
| Nudge integration | Threat-model and 2-of-3 layout used as motivation | No `Z_(2^b)` commitment instantiation; no recommendation engine patch |

## Certificate acceptance predicate

The verifier accepts only when all of the following hold:

1. The context hash recomputes from the service, epoch, cut root, ordered old and
   new membership, replaced slot, session, generation, dimension, and arithmetic
   domain.
2. Exactly one declared physical slot changes.
3. The two mask commitments are signed by the two correct survivors and target
   the correct refreshed components.
4. The three homomorphic equations connect the old and new component
   commitments.
5. Exactly six unique persistence receipts are present: the two physical holders
   of every component, for the same context, generation, and commitment.
6. Every signature verifies under a separately supplied authorized key.

Test-only switches in `verify_certificate` omit one predicate at a time solely
for negative controls.  The protocol verifier uses all checks.

## Private-delivery acceptance predicate

A recipient accepts a private envelope only when all of the following hold:

1. The Ed25519 signature verifies for the survivor assigned to the target
   component, and the statement carries the exact transfer context identifier.
2. The recipient is the unique peer survivor for `MASK_OPENING`, or the unique
   replacement identity for `MASK_COMPONENT_OPENING`; the two schemas are not
   interchangeable.
3. The mask opening recomputes the public mask commitment.
4. A replacement-directed envelope names the same target component and its
   component opening recomputes the corresponding new public commitment.
5. Only after these checks may the recipient persist the opening.  A persistence
   receipt is unavailable until that durable record exists.

The private component opening is deliberately not copied into the public
certificate or into the public blame sample.  A signed invalid *mask-labeled* opening
supports attribution, but authentication does not prove its distribution.
State-independent disclosure requires an independently sampled mask and a
state-independent fault transformation; refreshed component openings remain private.

## Frozen finite domains

- Mixed-generation replicated and Shamir checks: `F_5` main domain, `F_3` pilot.
- Cyclic-ring image controls: moduli 4, 8, and 16.
- Legacy schedule/fault cases: 968.
- Physical continuity cases: 32, bringing the generated case total to 1,000.
- Algebraic privacy oracle: `5^4` randomness assignments for each of five secrets
  and three active roles, or 9,375 private-subview obligations.
- Joint-view checker: 4,096 exact `F_2` role/secret/randomness views and 64
  finite-field rank checks.  It includes visible blindings and all eight
  correlated commitments for one scalar coordinate.
- Certificate-size points: vector dimensions 1, 8, 32, and 64.

The algebraic oracle excludes commitments, blindings, and signatures.  The
separate joint checker includes commitments and blindings but excludes actual
signature bytes and multi-coordinate vectors.  The written proof handles the
general vector view and treats signatures as post-processing under fixed keys
independent of the state; neither finite check replaces that proof.

## Selection and negative-control rules

The legacy A/B fixture differs by component deltas `(1,2,-3)` modulo 101 in
every coordinate.  Every nonempty proper subset has nonzero sum, so every mixed
latest-state selection is wrong while either homogeneous generation is correct.
This is a falsification fixture, not a random workload.

The continuity mutations are fixed by class rather than selected after seeing
results: changed new commitment, changed mask commitment, proposal signature
bit flip, missing receipt, signer substitution, component substitution, context
epoch substitution, and changed old commitment.  The three ablations remove algebraic linkage, redundant receipt-body/context
generation consistency, or the second physical receipt.  A separate control
transplants unchanged receipts from another context; both the full verifier and
the generation-consistency-weakened verifier reject those bytes because the
signed context identifier differs.
All are benign local transformations of synthetic material.

## Evidence privacy

The public continuity blame sample accepts only an independently signed
`MASK_OPENING` and exposes that random resharing mask and its blinding.  A
`MASK_COMPONENT_OPENING` replacement envelope is never accepted as mask-only
public evidence because its signature covers the component opening as well.  For the supplied synthetic fixture, an independently sampled mask undergoes a state-independent coordinate mutation. The verifier does not establish state-independence of an arbitrary signed invalid payload.  The
older generic contradiction corpus can expose opaque root strings only.  The
artifact does not claim that arbitrary diagnostic transcripts are safe to
publish, nor that repeated disclosures remain private under mobile corruption.
