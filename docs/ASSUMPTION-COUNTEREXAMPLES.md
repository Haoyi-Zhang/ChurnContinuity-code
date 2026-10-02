# Assumption Necessity and Counterexamples

These examples document why the theorem premises are necessary.  They are specification tests, not optional prose caveats.

## Public equations without an honest opening witness

A homomorphic commitment equation can be satisfied by commitments to a self-consistent but wrong state.  Therefore the public verifier establishes algebraic consistency of committed values, while semantic continuity additionally depends on authenticated old openings and at least one honest post-persistence holder per component.

## Receipt before persistence

If a process signs a receipt and then crashes before the share reaches durable storage, an activation certificate can contain the nominal receipt set while the activated generation is not recoverable.  Hence the implementation and theorem both require persist-before-sign; the crash-prefix checker includes this ordering.

## Per-property rather than global fault counting

Assuming one faulty sender in one lemma and a different faulty receiver in another silently spends two faults.  The final proof uses one global faulty identity.  In every two-holder receipt pair, the other signer is consequently honest.

## Slot migration across serial churn

A static physical adversary that is permitted to move between logical share slots can accumulate complementary replicated shares in different epochs.  Identity-to-slot binding and departed-identity non-reentry are therefore privacy premises, not administrative conveniences.

## Silence as blame

In an asynchronous execution, a silent signer may be faulty, crashed, partitioned, or merely delayed.  Those executions are observationally indistinguishable to a finite-time observer.  The accountability claim is therefore positive: signed contradictions can be blamed, while silence cannot.

## Stable identifiers supplied by an equivocating client

Deduplication cannot provide exactly-once semantics when a client intentionally reuses an identifier for different operations or generates colliding identifiers.  The request-cut theorem requires authenticated, stable, collision-free identifiers and does not replace a client-admission policy.

## Logical durable writes versus device behavior

The model treats a successful persistence operation as atomic at the protocol interface.  Real devices can exhibit torn writes, lost flushes, or controller faults.  A deployment must implement the interface with checksums, write-ahead logging or copy-on-write, flush discipline, and recovery testing; the research artifact does not certify a storage stack.
