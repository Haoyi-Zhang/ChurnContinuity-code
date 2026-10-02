# Artifact Appendix

## Claims supported

The artifact supports protocol-state invariants, complete finite checks over the documented toy domains, reachable durable-prefix crash safety, two explicitly separated privacy checks, evidence classification, deterministic result regeneration, and encoding/parser rejection tests.  The `F_5` checker covers only the algebraic private subview.  `reviewer_symbolic_check.py` covers one scalar coordinate, all four protocol-following physical roles, visible component/mask blindings, and the eight correlated commitments; it omits actual signature bytes and is auxiliary evidence for the written joint simulator, not a general proof.

It does not empirically establish production throughput, production cryptographic strength, hardware durability, side-channel resistance, network anonymity, or external control-plane consensus.

## Exact entry points

```bash
python -m compileall -q .
python reviewer_symbolic_check.py --out reproduced-joint-view
python run.py --pilot --out reproduced-pilot
python run.py --out reproduced
python validate.py --out validation-reproduced --transcripts reproduced/signed_transcripts.json
python verify.py results/full reproduced
python check_evidence.py --authorization inputs/authorized_signers.json --transcripts reproduced/signed_transcripts.json
python -m unittest discover -s tests -v
```

## Determinism rule

Scientific JSON/CSV/text outputs are required to agree byte-for-byte across independent runs.  Timing, resident-memory, and profiler files are measurements of a particular host and are excluded explicitly rather than normalized after the fact.

## Interpretation of exhaustive checks

Exhaustive small-domain enumeration is a model-conformance and regression argument.  The 9,375-view `F_5` oracle deliberately omits commitments; the separate 4,096-view `F_2` checker includes correlated commitments and blindings and is supplemented by 64 rank witnesses.  Neither turns a toy field or toy group into production cryptography, covers malicious receivers, or replaces the written simulator and computational assumptions stated in the paper.
