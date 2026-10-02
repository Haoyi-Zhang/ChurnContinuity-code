#!/usr/bin/env python3
"""Run the independent joint private/public transcript checker."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from churn.joint_view import compute_report  # noqa: E402


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        help="write joint_view_privacy.csv/json to an absent or empty directory",
    )
    parser.add_argument(
        "--check-retained",
        action="store_true",
        help="compare the recomputed outputs with results/full",
    )
    args = parser.parse_args()

    rows, report = compute_report()
    csv_name = "joint_view_privacy.csv"
    json_name = "joint_view_privacy.json"

    if args.out is not None:
        output = args.out.resolve()
        if output.exists() and any(output.iterdir()):
            parser.error("output directory must be absent or empty")
        output.mkdir(parents=True, exist_ok=True)
        _write_csv(output / csv_name, rows)
        (output / json_name).write_bytes(_json_bytes(report))

    retained = ROOT / "results" / "full"
    if args.check_retained or args.out is None:
        import io

        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        expected_csv = (retained / csv_name).read_text(encoding="utf-8")
        if buffer.getvalue() != expected_csv:
            raise SystemExit("retained joint_view_privacy.csv differs")
        if _json_bytes(report) != (retained / json_name).read_bytes():
            raise SystemExit("retained joint_view_privacy.json differs")

    print(json.dumps({
        "success": True,
        "exact_assignments": report["exact_assignments"],
        "exact_distribution_comparisons": report["exact_distribution_comparisons"],
        "rank_checks": report["rank_checks"],
        "roles": report["roles"],
        "note": report["interpretation"],
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
