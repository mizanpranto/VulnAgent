import json
import tempfile
import unittest
from pathlib import Path

from vulnagent.models import CWE_CATALOG, Finding
from vulnagent.pipeline import ScanOptions, run_scan
from vulnagent.report import render_markdown, to_sarif
from vulnagent.standards import label, owasp_categories, tags_for, top25_rank


class Mapping(unittest.TestCase):
    def test_known_mappings(self):
        self.assertEqual(owasp_categories(89), ["A05"])
        self.assertEqual(owasp_categories(918), ["A01"])      # SSRF merged into access control in 2025
        self.assertEqual(owasp_categories(209), ["A10"])
        self.assertEqual(owasp_categories(1395), ["A03"])
        self.assertEqual(owasp_categories(798), ["A07"])
        self.assertEqual(owasp_categories(502), ["A08"])
        self.assertEqual(owasp_categories(532), ["A09"])

    def test_top25_ranks(self):
        self.assertEqual((top25_rank(79), top25_rank(89), top25_rank(918)), (1, 2, 22))
        self.assertIsNone(top25_rank(798))

    def test_unmapped_cwe_gets_no_tags_and_unofficial_is_labelled(self):
        self.assertEqual(label(1427), "")
        self.assertEqual(tags_for(1333)["owasp"], [])
        self.assertIn("(inferred)", tags_for(1336)["owasp"][0])

    def test_every_catalog_cwe_is_either_mapped_or_known_unmapped(self):
        unmapped = {c for c in CWE_CATALOG if not tags_for(c)["owasp"]}
        # These have no OWASP 2025 category in the official lists; if this set changes, review it.
        self.assertTrue(unmapped <= {400, 1333, 1427}, unmapped)


class InReports(unittest.TestCase):
    def report(self):
        root = Path(tempfile.mkdtemp(prefix="va-std-"))
        (root / "a.py").write_text("import os\nfrom flask import request\napp.secret_key = 'abcdefgh1234'\n"
                                   "def f():\n    os.system('x' + request.args['c'])\n")
        return run_scan(root, ScanOptions(use_llm=False))

    def test_stats_json_markdown_sarif(self):
        rep = self.report()
        self.assertEqual({r["id"] for r in rep.stats["owasp"]}, {"A05:2025", "A07:2025"})
        self.assertEqual(rep.stats["top25"], 1)  # command injection is #9
        data = json.loads(json.dumps(rep.to_dict()))
        cmd = next(f for f in data["findings"] if f["cwe"] == 78)
        self.assertEqual((cmd["owasp"], cmd["cwe_top25_rank"]), (["A05:2025 Injection"], 9))
        md = render_markdown(rep)
        self.assertIn("**Standards:** OWASP Top 10 A05:2025 Injection  ·  CWE Top 25 (2025) #9", md)
        self.assertIn("| A07:2025 Authentication Failures | 1 |", md)
        tags = next(r["properties"]["tags"] for r in to_sarif(rep)["runs"][0]["results"] if r["ruleId"] == "CWE-78")
        self.assertEqual(tags, ["external/owasp/2025/A05", "external/cwe/top25-2025"])


if __name__ == "__main__":
    unittest.main()
