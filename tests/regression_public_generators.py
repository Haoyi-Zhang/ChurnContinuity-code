"""Portable public-generator and complete-transfer regressions (no timing)."""
import csv
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from churn import continuity as c
from churn import continuity_experiments as e


def literal_generator(p, q, label):
    # Independently implement the published hash/counter/subgroup definition,
    # not a call to the implementation's generator or a saved constant table.
    for counter in range(10000):
        payload = ("continuity-generator:" + label + ":" + str(counter)).encode("ascii")
        residue = int.from_bytes(hashlib.sha256(payload).digest(), "big") % p
        candidate = residue * residue % p
        if candidate != 0 and candidate != 1 and pow(candidate, q, p) == 1:
            return candidate
    raise AssertionError("finite test generator did not terminate")


def literal_commit(group, values, blinding):
    result = pow(literal_generator(group.p, group.q, "blinding"), blinding, group.p)
    for index, value in enumerate(values):
        result = result * pow(literal_generator(group.p, group.q, "coordinate:" + str(index)),
                              value, group.p) % group.p
    return result


def outcome(operation):
    try:
        return {"value": operation()}
    except (TypeError, ValueError, ZeroDivisionError) as error:
        return {"error": type(error).__name__, "message": str(error)}


def snapshot():
    group = c.TinyVectorPedersen()
    constants = [group.h] + [group.g(index) for index in range(66)]
    commitments = []
    for dimension in (1, 8, 64):
        for blinding in (0, 1, group.q - 1):
            values = tuple((index * 17 + blinding) % group.q for index in range(dimension))
            value = group.commit(values, blinding)
            assert value == literal_commit(group, values, blinding)
            commitments.append(value)
    invalid = [outcome(lambda index=index: group.g(index))
               for index in (-1, True, 0.0, "0", None)]
    invalid += [outcome(lambda values=values, blinding=blinding: group.commit(values, blinding))
                for values, blinding in (((), 0), ((True,), 0), ((-1,), 0),
                                         ((group.q,), 0), ((0,), True), ((0,), -1),
                                         ((0,), group.q), ((0,), 1.0))]
    slots = []
    for slot in range(3):
        old = ("old-0", "old-1", "old-2")
        new = list(old); new[slot] = "replacement-" + str(slot); new = tuple(new)
        context = c.TransferContext("public-generator-regression", 9, "cut", old, new,
                                    slot, "session-" + str(slot), "generation-" + str(slot), 8)
        state = c.initial_state(tuple(range(8)), old, "literal-base-" + str(slot), group)
        keys, auth = c.fixture_authorization(set(old) | set(new))
        bundle = c.make_transfer(context, state, keys, "literal-transfer-" + str(slot), group)
        assert not c.verify_certificate(bundle.certificate, auth, group)
        servers = e.complete_transfer(bundle, keys, group)
        assert c.verify_certificate(bundle.certificate, auth, group)
        assert bundle.new_state.secret(group.q) == tuple(range(8))
        for component in range(3):
            assert bundle.new_state.commitments[component] == literal_commit(
                group, bundle.new_state.components[component], bundle.new_state.blindings[component])
        slots.append({"certificate": bundle.certificate,
                      "private": [statement.export() for statement in bundle.private_opening_statements],
                      "outboxes": {name: [message.export() for _, message in sorted(server.durable_outbox.items())]
                                   for name, server in sorted(servers.items())},
                      "secret": list(bundle.new_state.secret(group.q))})
    cases, sample, evidence, obligations = e.protocol_cases()
    sizes, size_obligations = e.size_checks()
    return {"constants": constants, "commitments": commitments, "invalid": invalid,
            "slots": slots, "cases": cases, "sample": sample, "evidence": evidence,
            "obligations": obligations, "sizes": sizes, "size_obligations": size_obligations}


class PublicGeneratorRegression(unittest.TestCase):
    def test_independent_derivation_boundaries_and_group_isolation(self):
        for p, q in ((2039, 1019), (23, 11), (47, 23)):
            group = c.TinyVectorPedersen(p, q)
            self.assertEqual(group.h, literal_generator(p, q, "blinding"))
            for index in range(66):
                self.assertEqual(group.g(index), literal_generator(p, q, "coordinate:" + str(index)))
        group = c.TinyVectorPedersen()
        for index in (-1, True, 0.0, "0", None):
            with self.assertRaisesRegex(ValueError, "nonnegative generator index required"):
                group.g(index)
        class Customized(c.TinyVectorPedersen):
            def _generator(self, label):
                return 17
        self.assertEqual(Customized().h, 17)
        self.assertEqual(Customized().g(0), 17)
        self.assertEqual(outcome(lambda: c.TinyVectorPedersen(2039.0, 1019).h)["error"], "TypeError")

    def test_cache_is_bounded_public_only_and_outside_coordinates_uncached(self):
        cache = c._public_generator
        cache.cache_clear()
        try:
            group = c.TinyVectorPedersen()
            expected = [group.h] + [group.g(index) for index in range(64)]
            self.assertEqual(cache.cache_info().misses, 65)
            self.assertEqual([group.h] + [group.g(index) for index in range(64)], expected)
            self.assertEqual(cache.cache_info().hits, 65)
            before = cache.cache_info()
            group.g(64); group.g(65)
            self.assertEqual(cache.cache_info(), before)
            for multiplier in range(1, 6):
                other = c.TinyVectorPedersen(23, 11 * multiplier)
                self.assertEqual(other.h, literal_generator(other.p, other.q, "blinding"))
                for index in range(64):
                    self.assertEqual(other.g(index), literal_generator(other.p, other.q, "coordinate:" + str(index)))
            self.assertEqual(cache.cache_info().maxsize, 256)
            self.assertEqual(cache.cache_info().currsize, 256)
            self.assertEqual(group.h, expected[0])
        finally:
            cache.cache_clear()

    def test_complete_transfer_and_frozen_physical_outputs(self):
        result = snapshot()
        retained = ROOT / "results" / "full"
        for name, value in (("continuity_certificate.json", result["sample"]),
                            ("continuity_evidence.json", result["evidence"])):
            encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
            self.assertEqual(encoded, (retained / name).read_bytes())
        for name, rows in (("continuity_cases.csv", result["cases"]), ("certificate_sizes.csv", result["sizes"])):
            buffer = io.StringIO()
            writer = csv.DictWriter(buffer, fieldnames=list(rows[0]), lineterminator="\n")
            writer.writeheader(); writer.writerows(rows)
            self.assertEqual(buffer.getvalue(), (retained / name).read_text())
        self.assertEqual(result["obligations"], 32)
        self.assertEqual(result["size_obligations"], 4)
        self.assertEqual(len([row for row in result["cases"] if row["kind"] == "crash-replay"]), 20)


if __name__ == "__main__":
    unittest.main()
