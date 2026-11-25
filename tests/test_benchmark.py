import unittest

from vulnagent.bench import load_truth, evaluate
from vulnagent.pipeline import ScanOptions, run_scan
from vulnagent.bench import TARGETS


class BenchmarkRegression(unittest.TestCase):
    """Regression guard only: the detector was tuned on this app (see README)."""

    def test_vulnerable_target_recall_and_precision(self):
        result = evaluate(run_scan(TARGETS / "flask_vuln", ScanOptions(use_llm=False)), load_truth("flask_vuln"))
        self.assertGreaterEqual(result["items_found"], 28, result["missed"])
        self.assertGreaterEqual(result["precision"], 0.9, result["false_positive_list"])

    def test_clean_target_has_at_most_one_false_positive(self):
        report = run_scan(TARGETS / "flask_clean", ScanOptions(use_llm=False))
        self.assertLessEqual(len(report.active), 1, [f.title for f in report.active])


if __name__ == "__main__":
    unittest.main()
