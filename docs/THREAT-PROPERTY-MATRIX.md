# Threat–Property Matrix

This matrix is normative for the artifact.  A property is never interpreted under a stronger adversary than the corresponding row states.

| Property | Adversary / fault budget | Required honest mechanism | What is established | Explicitly not established |
|---|---|---|---|---|
| Algebraic continuity | At most one faulty physical server during one serial replacement | Honest holders verify authenticated openings before signing | Accepted old and new openings satisfy the stated additive resharing equations | Public commitments alone do not prove plaintext equality |
| Durable activation safety | Crashes at any reachable durable prefix; at most one Byzantine or unavailable server | At least one honest durable holder for every component; receipt only after persistence; linearizable activation record | An activated generation remains reconstructible after one additional server loss within the stated budget | Physical durability of a dishonest signer; torn-write behavior below the logical storage interface |
| View privacy | One static, protocol-following, honest-but-curious physical server | Private authenticated channels; independently uniform base-component blindings and fresh mask blindings; hiding commitments; identity remains bound to one share slot; departed identities do not re-enter | A role-defined joint simulator preserves every visible opening and all three commitment links; the auxiliary finite checker confirms the one-coordinate model | Two-server collusion, adaptive/mobile corruption, malicious-receiver privacy, traffic-analysis resistance |
| Integrity against malformed messages | At most one active faulty server | Canonical encodings, subgroup checks, signatures, commitment-opening checks, honest verifier | Malformed or context-shifted messages are rejected before an honest receipt | Availability when the faulty party withholds a required message |
| Positive accountability | A signer equivocates or signs an invalid, checkable statement | Unforgeable signatures and canonical context | A compact pair or transcript identifies a cryptographic contradiction attributable to the signer | Attribution from silence, delay, packet loss, or crash in an asynchronous network |
| Conditional completion | No permanent violation of the progress premises | Eventual delivery, retry, honest durable storage, and an available activation service | A valid transition can eventually activate | Unconditional asynchronous liveness or consensus |
| Request-cut continuity | Authenticated stable request identifiers and a sealed cut | Durable deduplication state and collision-free identifier discipline | The same accepted identifier is not applied twice across the sealed transition | Client equivocation, identifier collision, or global exactly-once semantics without the external ordering service |

## Composition rule

The one-fault budget is global, not per subprotocol.  Proofs may not simultaneously assume one corrupt sender and a different corrupt receiver.  Whenever a component has two receipt signers, at least one is honest under this single global budget.  The privacy row uses a narrower protocol-following adversary and must not be combined with the active-integrity row to claim malicious privacy.

## Time and corruption scope

The corruption set is static for the bounded serial chain.  A physical identity cannot migrate to another logical share slot, and an identity that leaves the chain cannot later re-enter.  These restrictions prevent a nominally single physical adversary from accumulating complementary shares over time.
