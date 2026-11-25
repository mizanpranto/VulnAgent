import io
import json
import tempfile
import unittest
from pathlib import Path

from vulnagent.pipeline import ScanOptions, run_scan
from vulnagent.report import render_markdown, to_sarif
from vulnagent.pdf_report import build_pdf

CODE = ("import os\nfrom flask import request\napp.secret_key = 'hunter2-hunter2'\n"
        "def f():\n    os.system('ls ' + request.args['d'])\n")


def report():
    root = Path(tempfile.mkdtemp(prefix="va-report-"))
    (root / "app.py").write_text(CODE, encoding="utf-8")
    return run_scan(root, ScanOptions(use_llm=False), project_name="demo"), root


class Reports(unittest.TestCase):
    def test_markdown_is_clean(self):
        rep, root = report()
        text = render_markdown(rep)
        self.assertIn("app.py", text)
        self.assertNotIn("Not provided", text)
        self.assertNotIn(str(root), text)

    def test_json_has_schema_and_relative_paths(self):
        rep, root = report()
        data = json.loads(json.dumps(rep.to_dict()))
        self.assertEqual(data["schema_version"], "2.1")
        self.assertEqual({f["file"] for f in data["findings"]}, {"app.py"})
        self.assertNotIn(str(root), json.dumps(data))

    def test_sarif_structure(self):
        rep, _ = report()
        sarif = to_sarif(rep)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(len(run["results"]), len(rep.active))
        for result in run["results"]:
            loc = result["locations"][0]["physicalLocation"]
            self.assertEqual(loc["artifactLocation"]["uri"], "app.py")
            self.assertGreaterEqual(loc["region"]["startLine"], 1)

    def test_pdf_to_file_and_buffer(self):
        rep, _ = report()
        buf = io.BytesIO()
        build_pdf(rep, buf)
        self.assertTrue(buf.getvalue().startswith(b"%PDF"))
        path = Path(tempfile.mkdtemp()) / "r.pdf"
        build_pdf(rep, path)
        self.assertGreater(path.stat().st_size, 1500)


if __name__ == "__main__":
    unittest.main()
