# Exact local inputs

All rating records and key seeds are deliberately public synthetic fixtures. No private data, published recommendation benchmark, external model, or source-code baseline is consumed.

`sparse_ratings.json`: for client c in {0,1,2,3} and sequence t in {0,1}, place value 1 at item (c+3t) modulo 8. There are eight nonzero records and 24 unlisted zero cells in the conceptual 4 by 8 matrix. The continuity model transfers the ordered eight-record vector; it does not train on the matrix. The item coordinates are validated and retained to define the sparse fixture, not used as a leakage-hiding data structure.

`specification.json`: exact arithmetic fields/rings and finite case domains. Counts are limits and reproducibility checks, not evidence of workload representativeness.

`authorized_signers.json`: a separate toy public-key authorization anchor for the 16 epoch contexts in the signed corpus. Deterministic public seeds are generated only by `fixture_key` in `src/churn/evidence.py`. An application must not trust this fixture or self-certify a key supplied by an accusation.

`resource-envelope.json`: one-time resource intake and campaign limits. The failed 256 MiB import did not execute a scientific obligation. It was repaired to a 2,048 MiB address-space limit. Browser-side PDF retrieval traffic was not measured by the container; zero successful direct scholarly-PDF downloads is not a claim of zero web traffic. No scholarly PDFs are redistributed.
