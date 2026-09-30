import csv
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
from privledger.linkability import generate_pairs, run_linkability


class LinkabilityTests(unittest.TestCase):
    def test_pair_balance_rotation_and_unique_events(self):
        matrices, labels, events = generate_pairs()
        self.assertEqual(len(labels), 10000)
        self.assertEqual(int(labels.sum()), 5000)
        self.assertEqual(len(np.unique(events)), 20000)
        np.testing.assert_array_equal(matrices["static"][:, 0], labels)
        self.assertFalse(matrices["rotated"][:, 0].any())
        np.testing.assert_array_equal(matrices["static"][:, 1:], matrices["rotated"][:, 1:])
        again = generate_pairs()
        np.testing.assert_array_equal(matrices["rotated"], again[0]["rotated"])

    def test_invalid_pair_counts(self):
        for count in (0, 21, 19, True, 20.0):
            with self.assertRaises(ValueError):
                generate_pairs(count)

    def test_outputs_and_ablation(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = run_linkability(temporary, pairs=1000)
            path = Path(temporary)
            self.assertEqual(result["shared_train_test_events"], 0)
            self.assertEqual(len(result["results"]), 6)
            for row in result["results"]:
                self.assertEqual(sum(row[k] for k in ("tn", "fp", "fn", "tp")), 300)
                if row["ablation"] == "identifier_only":
                    self.assertEqual(row["roc_auc"], 1 if row["condition"] == "static" else .5)
            context = [row for row in result["results"] if row["ablation"] == "context_only"]
            self.assertEqual(context[0]["roc_auc"], context[1]["roc_auc"])
            with (path / "linkability_predictions.csv").open() as handle:
                predictions = list(csv.DictReader(handle))
            self.assertEqual(len(predictions), 1800)
            self.assertEqual(json.loads((path / "linkability_results.json").read_text())["seed"], 42)
            for name in ("roc_static_vs_rotated", "linkability_metric_comparison", "linkability_ablation"):
                for extension in ("png", "svg"):
                    self.assertGreater((path / "figures" / f"{name}.{extension}").stat().st_size, 100)


if __name__ == "__main__":
    unittest.main()
