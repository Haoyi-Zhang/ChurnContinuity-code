#!/usr/bin/env python3
"""Compare deterministic scientific outputs without treating timing as an invariant."""
import argparse
import json
from pathlib import Path


DETERMINISTIC_FILES = (
    "algebra.csv",
    "rings.csv",
    "counterexample.json",
    "event_orders.csv",
    "schedules.csv",
    "crashes.csv",
    "semantics.csv",
    "evidence.csv",
    "signed_transcripts.json",
    "continuity_cases.csv",
    "privacy_views.csv",
    "joint_view_privacy.csv",
    "joint_view_privacy.json",
    "certificate_sizes.csv",
    "continuity_certificate.json",
    "continuity_evidence.json",
    "scientific_summary.json",
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expected", type=Path)
    parser.add_argument("actual", type=Path)
    args = parser.parse_args()

    for name in DETERMINISTIC_FILES:
        if (args.expected / name).read_bytes() != (args.actual / name).read_bytes():
            raise SystemExit("scientific output differs: " + name)

    summary = json.loads((args.actual / "scientific_summary.json").read_text())
    frozen = {
        "generated_schedule_fault_cases": 1000,
        "total_obligations": 43407,
        "continuity_cases": 32,
        "continuity_case_failures": 0,
        "privacy_view_obligations": 9375,
        "privacy_distributions_equal": 15,
        "joint_view_exact_assignments": 4096,
        "joint_view_distribution_comparisons": 8,
        "joint_view_rank_checks": 64,
        "joint_view_checks_passed": 1,
        "certificate_size_points": 4,
        "crash_post_replay_correct": 96,
        "signed_contradictions_accepted": 16,
        "signed_negative_controls_rejected": 112,
        "public_certificate_json_bytes_min": 3708,
        "public_certificate_json_bytes_max": 3717,
        "private_opening_bytes_dimension_1": 1630,
        "private_opening_bytes_dimension_64": 3130,
    }
    for key, expected in frozen.items():
        if summary.get(key) != expected:
            raise SystemExit(f"unexpected frozen value for {key}: {summary.get(key)!r}")

    print(
        f"All {len(DETERMINISTIC_FILES)} deterministic scientific output files agree; "
        "timing is reported separately. This is a reproduction check, not an "
        "independent correctness proof."
    )


if __name__ == "__main__":
    main()
