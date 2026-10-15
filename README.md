# Continuity certificates for secret-shared recommendation epochs

This standalone artifact models a three-server continuity-certificate layer
for serial replacement of one physical server in a 2-of-3
replicated-additive layout. It supplies certificate and receipt verification,
a logical durable-store/crash model, synthetic inputs, finite checks, written
proof arguments, and retained results. It has no dependency on the paper,
a private dataset, GPU, external service, or model API.

Two survivors refresh components using random masks. Authenticated private
envelopes carry openings; the public certificate binds commitment links,
signed mask commitments, and two persist-before-sign receipts per component.
The earlier mixed-generation controls remain part of the artifact.

## Setup

Use Python 3.11+ and install the runtime dependency from this repository root:

```sh
python -m pip install -r requirements.txt
```

`cryptography` provides Ed25519; it is not bundled or claimed as original work.
Linux is required for `run.py` and `validate.py`, which enforce affinity,
one worker, a 2-GiB address-space limit, a 110-second CPU limit, and a
120-second wall timer. The unit suite and focused symbolic/evidence checks
also run on Windows without those Linux driver limits.

## Reproduce

Use absent or empty output directories:

```sh
python reviewer_symbolic_check.py --out reproduced-joint-view --check-retained
python run.py --pilot --out reproduced-pilot
python run.py --out reproduced
python validate.py --out validation-reproduced --transcripts reproduced/signed_transcripts.json
python verify.py results/full reproduced
python check_evidence.py --authorization inputs/authorized_signers.json --transcripts reproduced/signed_transcripts.json
```

The bounded drivers reject nonempty output directories.
`verify.py` compares all 17 deterministic scientific files byte for byte and
checks frozen summary values. Timing, resident-memory, and profiler records
are host measurements, not deterministic outputs or service-performance data.
Do not overwrite `results/full/` with a replay.

Focused checks:

```sh
python -B -m unittest discover -s tests -v
python -B tests/regression_public_generators.py -v
python -B tests/regression_bibliography.py -v
python -B reviewer_symbolic_check.py --check-retained
python -B check_evidence.py --authorization inputs/authorized_signers.json --transcripts results/full/signed_transcripts.json
```

The discovery suite has 58 methods; the generator and bibliography regressions
are separate explicit CI steps. The scientific Actions workflow runs these,
both bounded campaigns, validation, and output comparison on Ubuntu 24.04,
with a 12-minute job limit and a 600-second whole-check limit.
Raw outputs are retained on success or failure.

## Inputs and retained results

`inputs/sparse_ratings.json` contains eight deliberately public synthetic
rating records, used as the transferred vector rather than training data.
`inputs/specification.json` defines the original arithmetic and fault domains;
the physical continuity cases add 32 cases to its 968 legacy cases.
`inputs/authorized_signers.json` is a separate toy authorization anchor;
fixture seeds are public and must not be used as deployment keys.
`inputs/resource-envelope.json` records resource intake and campaign limits.

`results/full/` retains:

- arithmetic/ring rows and the mixed-generation counterexample;
- schedule permutations, event orders, crash controls, and semantics rows;
- signed contradiction transcripts and their expected verdicts;
- 32 physical continuity cases, including crash/replay, mutations, ablations,
  context-transplant rejection, and positive evidence controls;
- private-subview distributions and joint private/public-view checks;
- certificate sizes at dimensions 1, 8, 32, and 64;
- a complete public certificate, bounded evidence samples, summary, and telemetry.

The frozen campaign has 43,407 counted obligations and 1,000 generated
schedule/fault/protocol cases. The private-subview oracle covers 9,375
`F_5` assignments; the separate joint-view checker covers 4,096 exact
one-coordinate `F_2` views and 64 finite-field rank checks.
The joint checker includes blindings and eight correlated commitments but
not actual signature bytes. These finite checks support, not replace,
the written arguments.

The legacy 720-order fixture intentionally distinguishes policies:
content-only and attempt-only selection each produce 540 wrong values,
while immutable generation pinning produces 720 correct values.
These are synthetic exact outcomes, not deployment failure-rate estimates.
Historical test counts and telemetry in `results/` describe their original runs.

## Code, assumptions, and licenses

`src/churn/continuity.py` implements the physical protocol and verifier;
`src/churn/continuity_experiments.py` supplies its finite controls.
`src/churn/joint_view.py` is the separate one-coordinate checker.
`src/churn/algebra.py`, `src/churn/model.py`, and `src/churn/evidence.py` retain the original arithmetic,
stable-ID ledger, durable-slot model, and signed contradiction predicate.

`proofs/arguments.md` gives the mathematical arguments.
`docs/interfaces.md`, `docs/THREAT-PROPERTY-MATRIX.md`, and
`docs/ASSUMPTION-COUNTEREXAMPLES.md` specify acceptance predicates,
adversary scopes, and necessary premises. In particular, receipt-backed
semantic continuity requires authenticated old openings and an honest durable
holder per component; public commitment consistency alone is not plaintext
equality. Exactly-once inclusion requires the sealed stable-ID cut premises.
Privacy is for one static protocol-following server under the declared
slot/non-reentry restrictions, not mobile or two-server corruption.
Positive signed contradictions can support accountability; silence cannot.

The tiny `(p,q)=(2039,1019)` group is an algebraic fixture, not a production
security parameter. The protocol uses a prime field; no Nudge power-of-two-ring
instantiation, network stack, Byzantine consensus, recommendation training,
or production `fsync` implementation is supplied. Written proofs and separate
code paths are not proof-assistant certification or independent human review.

`claim_evidence_ledger.csv` maps claims to proofs and raw evidence.
`reference-audit.csv` and `external_resources.csv` retain source identities
and access depth. Code and original fixtures use `LICENSE`;
`THIRD-PARTY-NOTICES.md` preserves dependency and external-resource notices.
Scholarly PDFs and third-party implementations are not redistributed.
