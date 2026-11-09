import tempfile
import unittest

from pathlib import Path

from vulnagent.scanner import scan_project


class ScannerTests(unittest.TestCase):

    def test_detects_dynamic_execution(self):

        with tempfile.TemporaryDirectory() as tmp:

            root = Path(tmp)

            source = root / "app.py"

            source.write_text(
                "eval(user_input)\n",
                encoding="utf-8"
            )

            files, findings = scan_project(root)

            titles = [
                finding["title"]
                for finding in findings
            ]

            self.assertEqual(len(files), 1)

            self.assertIn(
                "Python Dynamic Execution",
                titles
            )

            self.assertIn(
                "Dynamic Code Execution",
                titles
            )

    def test_ignores_node_modules(self):

        with tempfile.TemporaryDirectory() as tmp:

            root = Path(tmp)

            vendor = root / "node_modules"

            vendor.mkdir()

            (vendor / "test.js").write_text(
                "eval(input)",
                encoding="utf-8"
            )

            files, findings = scan_project(root)

            self.assertEqual(len(files), 0)


if __name__ == "__main__":
    unittest.main()