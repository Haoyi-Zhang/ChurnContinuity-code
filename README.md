# Accountable continuity for secret-shared recommendation epochs

This standalone repository contains the reference model, exact finite checks,
written proof arguments, synthetic inputs, and retained results for a
three-server continuity-certificate layer.  It does not require the paper
directory, a private dataset, a GPU, an external service, or a model API.

## Scope

The implemented refinement uses the physical 2-of-3 replicated-additive layout:
server `i` stores the two additive components whose indices differ from `i`.
One physical slot is replaced at a time.  Two survivors refresh the two
components delivered to the replacement and subtract the same random masks from
their common component.  The replacement obtains those components only through
two authenticated private envelopes, each binding a mask opening to the
corresponding refreshed component opening.  A public certificate contains
homomorphic commitment links, two signed mask commitments, and two durable
receipts per component.  Receipts can be issued only after the named server has
verified and durably stored the matching opening.

The general arguments establish, under the explicit assumptions in
`proofs/arguments.md`:

- receipt-backed preservation of the shared vector across one replacement and,
  under exact handoff and context invariants, across a bounded serial chain;
- exactly-once inclusion when the certified base vector is tied to a sealed
  stable-ID cut;
- static protocol-following one-server privacy for the continuity layer over a prime field, with a role-defined joint simulator;
- one-fault post-activation component availability from two-holder receipts;
- crash-safe deterministic replay under the modeled durable-store contract;
- positive evidence for an independently signed invalid peer-mask opening or
  same-context equivocation, but not for silence.

The repository also retains the earlier exact mixed-generation criterion and
negative controls.  Those checks show why logical content equality, an attempt
number, or “latest” storage does not replace full generation binding.

## Important non-claims

- The tiny `(p,q)=(2039,1019)` Pedersen fixture is for algebraic checking, not a
  production security parameter.
- The concrete protocol uses a prime field.  Nudge uses arithmetic over a
  power-of-two ring; a ring-compatible commitment/proof instantiation is not
  supplied here.
- No Byzantine consensus, membership authorization service, network stack,
  recommendation training, production `fsync`, mobile-corruption defense, or
  two-server privacy theorem is implemented.
- Local times are not service latency or throughput results.
- Written proofs and finite checks are not proof-assistant certification or
  independent peer review.

## Requirements

- Linux with Python 3.11 or later
- `cryptography` (see `requirements.txt`)
- one CPU worker; the runner enforces a 2 GiB address-space limit, a 110-second
  CPU limit, and a 120-second wall timer

The retained campaign used no GPU, swap, external compute, private input, or
external model/API execution.

## Reproduce

From the repository root:

```sh
python reviewer_symbolic_check.py --out reproduced-joint-view
python run.py --pilot --out reproduced-pilot
python run.py --out reproduced
python validate.py --out validation-reproduced \
  --transcripts reproduced/signed_transcripts.json
python verify.py results/full reproduced
python check_evidence.py \
  --authorization inputs/authorized_signers.json \
  --transcripts reproduced/signed_transcripts.json
```

Each output directory must be absent or empty.  The runner never silently
overwrites scientific results.

## Retained result inventory

`results/full/` contains the deterministic campaign outputs:

- `algebra.csv`, `rings.csv`, `counterexample.json`: exact mixed-generation
  checks and counterexample;
- `schedules.csv`, `event_orders.csv`, `crashes.csv`, `semantics.csv`: original
  generation-binding and crash controls;
- `evidence.csv`, `signed_transcripts.json`: the original signed contradiction
  corpus;
- `continuity_cases.csv`: 32 physical-layout cases (one honest path, 20
  persistence-boundary crash/replay cases, five certificate mutations, three
  verifier ablations, one unchanged cross-context receipt transplant, and two
  positive evidence cases);
- `privacy_views.csv`: exact algebraic private-subview distributions for all five
  secrets in the `F_5` oracle and all three active roles;
- `joint_view_privacy.csv`, `joint_view_privacy.json`: one-coordinate joint
  private/public views for four protocol-following roles, including blindings and
  all eight correlated commitments, plus finite-field rank witnesses;
- `certificate_sizes.csv`: dimensions 1, 8, 32, and 64;
- `continuity_certificate.json`, `continuity_evidence.json`: one complete public
  certificate and bounded evidence samples;
- `scientific_summary.json` and `telemetry.json`.

The complete campaign contains 43,407 counted obligations and 1,000 generated
schedule/fault/protocol cases.  All 32 continuity cases matched their frozen
oracles, and all 55 unit and boundary tests passed.  The algebraic privacy oracle
compared 9,375 private subviews and found the same exact distribution for every
secret in each active role.  The independent joint-view checker compared 4,096
exact `F_2` views across four roles and ran 64 finite-field rank checks; it
includes blindings and correlated commitments but not actual signature bytes.  The reference JSON
certificate is 3,708--3,717 bytes across the four vector dimensions, while the
four authenticated private envelopes grow from 1,630 to 3,130 bytes.

The legacy 720-order control remains intentionally discriminating: content-only
and attempt-only latest-state policies each return 540 wrong values; full
immutable generation pinning returns 720 correct values.  These are exact
outcomes of synthetic fixtures, not estimates of deployment failure rates.

## Repository map

```text
src/churn/continuity.py              physical protocol and certificate verifier
src/churn/continuity_experiments.py  algebraic privacy, crash, mutation, and size checks
src/churn/joint_view.py              independent one-coordinate joint-view checker
reviewer_symbolic_check.py           runnable joint-view checker entry point
src/churn/algebra.py                 mixed-generation arithmetic checks
src/churn/model.py                   stable-ID ledger and ideal durable-slot model
src/churn/evidence.py                original signed contradiction predicate
proofs/arguments.md                  theorem statements and written proofs
docs/interfaces.md                   assumption and evidence map
tests/test_contract.py               unit and boundary tests
claim_evidence_ledger.csv            claim-to-evidence ledger
external_resources.csv               scholarly/tool source ledger
reference-audit.csv                  all 67 bibliography records, locators, audit tier, and citation counts
```

## Evidence interpretation

A successful command establishes that the local checks completed and matched
their frozen oracles.  It does not by itself prove a general theorem.  The main
scientific claims must be read together with `proofs/arguments.md`, the explicit
assumptions, the negative controls, and the claim ledger.
