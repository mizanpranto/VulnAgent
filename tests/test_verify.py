import unittest

from vulnagent.models import Finding, normalize_cwe
from vulnagent.verify import dedupe_and_merge, finding_from_llm, ground_finding

SOURCE = "import os\n\n\ndef run(cmd):\n    return os.system(cmd)\n\ndef other():\n    pass\n"
FILES = {"app.py": SOURCE}


def claim(**overrides):
    raw = {"title": "Command injection", "severity": "critical", "confidence": "high", "file": "app.py", "line": 99,
           "cwe": "CWE-78", "evidence": "return os.system(cmd)"}
    raw.update(overrides)
    return finding_from_llm(raw)


class Grounding(unittest.TestCase):
    def test_line_is_recomputed_from_evidence(self):
        finding, reason = ground_finding(claim(line=2), FILES)
        self.assertEqual(finding.line, 5)
        self.assertEqual(reason, "grounded")

    def test_nearest_duplicate_wins(self):
        source = "x = eval(a)\n\n\n\ny = eval(a)\n"
        finding, _ = ground_finding(claim(file="a.py", line=5, evidence="eval(a)"), {"a.py": source})
        self.assertEqual(finding.line, 5)

    def test_invented_evidence_is_rejected(self):
        finding, reason = ground_finding(claim(evidence="os.system(user_input + payload)"), FILES)
        self.assertIsNone(finding)
        self.assertIn("not found", reason)

    def test_unknown_file_and_missing_evidence_rejected(self):
        self.assertIsNone(ground_finding(claim(file="nope.py"), FILES)[0])
        self.assertIsNone(ground_finding(claim(evidence=""), FILES)[0])

    def test_basename_match_when_unambiguous(self):
        finding, _ = ground_finding(claim(file="src/app.py"), {"pkg/app.py": SOURCE})
        self.assertEqual(finding.file, "pkg/app.py")


class Sanitising(unittest.TestCase):
    def test_llm_fields_are_clamped(self):
        finding = claim(severity="catastrophic", confidence="certain", cwe="CWE-9999", title="SQL injection in login")
        self.assertEqual((finding.severity, finding.confidence), ("medium", "low"))
        self.assertEqual(finding.cwe, 89)  # repaired from the title, not trusted

    def test_wrong_cwe_from_model_is_replaced(self):
        # The first version let the model label an IDOR as CWE-621.
        finding = claim(title="Insecure direct object reference", cwe="CWE-621")
        self.assertEqual(finding.cwe, 639)

    def test_cwe_normalisation(self):
        self.assertEqual(normalize_cwe("CWE-89"), 89)
        self.assertEqual(normalize_cwe(" 79 "), 79)
        self.assertIsNone(normalize_cwe("CWE-99999", "something unrelated"))
        self.assertIsNone(normalize_cwe(None))

    def test_garbage_is_rejected(self):
        self.assertIsNone(finding_from_llm("nope"))
        self.assertIsNone(finding_from_llm({"severity": "high"}))


def f(line, cwe=798, origins=("taint",), title="Hard-coded credential", severity="high"):
    return Finding(title=title, severity=severity, file="a.py", line=line, cwe=cwe, origins=list(origins))


class Dedupe(unittest.TestCase):
    def test_consecutive_secrets_stay_separate(self):
        merged = dedupe_and_merge([f(15), f(16), f(17)])
        self.assertEqual(sorted(x.line for x in merged), [15, 16, 17])

    def test_same_line_merges_and_raises_confidence(self):
        merged = dedupe_and_merge([f(10, origins=("taint",)), f(10, origins=("llm-discovery",))])
        self.assertEqual(len(merged), 1)
        self.assertEqual(sorted(merged[0].origins), ["llm-discovery", "taint"])
        self.assertEqual(merged[0].confidence, "high")

    def test_ai_finding_near_deterministic_one_merges(self):
        merged = dedupe_and_merge([f(331, 489, ("taint",)), f(334, 489, ("llm-discovery",))])
        self.assertEqual(len(merged), 1)

    def test_different_cwe_same_line_is_two_findings(self):
        self.assertEqual(len(dedupe_and_merge([f(5, 89), f(5, 862)])), 2)

    def test_sorted_most_severe_first(self):
        merged = dedupe_and_merge([f(1, 1333, severity="low"), f(2, 78, severity="critical")])
        self.assertEqual(merged[0].severity, "critical")


if __name__ == "__main__":
    unittest.main()
