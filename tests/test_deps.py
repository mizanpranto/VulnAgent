import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from vulnagent.deps import collect, parse_package_lock, parse_requirements, query_osv
from vulnagent.pipeline import ScanOptions, run_scan
from vulnagent.safe_zip import safe_extract

REQ = "# pins\nflask==0.12.2\nrequests>=2.0\nPyYAML[extra]==5.1  # old\n-r other.txt\n"
LOCK = json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.4"},
                                                       "node_modules/a/node_modules/b": {"version": "1.0.0"}}}, indent=2)


class FakeResponse:
    def __init__(self, payload, status=200):
        self.payload, self.status_code = payload, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("http")

    def json(self):
        return self.payload


class FakeOsv:
    def __init__(self, fail=False):
        self.fail, self.posts = fail, []

    def post(self, url, json=None, timeout=0):
        if self.fail:
            raise ConnectionError("offline")
        self.posts.append(json)
        results = [{"vulns": [{"id": "GHSA-1"}, {"id": "GHSA-2"}]} if q["package"]["name"] == "flask" else {}
                   for q in json["queries"]]
        return FakeResponse({"results": results})

    def get(self, url, timeout=0):
        vid = url.rsplit("/", 1)[1]
        return FakeResponse({"id": vid, "summary": f"bug {vid}", "aliases": ["CVE-2018-1000656"] if vid == "GHSA-1" else [],
                             "database_specific": {"severity": "HIGH" if vid == "GHSA-1" else "MODERATE"},
                             "affected": [{"package": {"name": "Flask"},
                                           "ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.12.3"}]}]}]})


class Parsing(unittest.TestCase):
    def test_requirements_only_exact_pins(self):
        deps = parse_requirements("requirements.txt", REQ)
        self.assertEqual([(d.name, d.version, d.line) for d in deps], [("flask", "0.12.2", 2), ("PyYAML", "5.1", 4)])

    def test_package_lock_v3_with_line_numbers(self):
        deps = parse_package_lock("package-lock.json", LOCK)
        self.assertEqual({(d.name, d.version) for d in deps}, {("lodash", "4.17.4"), ("b", "1.0.0")})
        self.assertEqual(next(d.line for d in deps if d.name == "lodash"), 5)

    def test_bad_json_is_ignored(self):
        self.assertEqual(parse_package_lock("package-lock.json", "{nope"), [])


class Querying(unittest.TestCase):
    def deps(self):
        return parse_requirements("requirements.txt", REQ)

    def test_every_advisory_is_its_own_finding(self):
        findings = query_osv(self.deps(), FakeOsv())
        self.assertEqual(len(findings), 2)
        self.assertEqual(sorted(f.severity for f in findings), ["high", "medium"])
        self.assertTrue(all(f.cwe == 1395 and f.line == 2 and f.file == "requirements.txt" for f in findings))
        self.assertIn("0.12.3", findings[0].fix)
        self.assertIn("CVE-2018-1000656", " ".join(f.title for f in findings))

    def test_sends_only_names_and_versions(self):
        osv = FakeOsv()
        query_osv(self.deps(), osv)
        self.assertEqual(set(osv.posts[0]["queries"][0]), {"package", "version"})

    def test_network_failure_raises_runtime_error(self):
        with self.assertRaises(RuntimeError):
            query_osv(self.deps(), FakeOsv(fail=True))


class Pipeline(unittest.TestCase):
    def project(self):
        root = Path(tempfile.mkdtemp(prefix="va-deps-"))
        (root / "requirements.txt").write_text(REQ)
        (root / "a.py").write_text("x = 1\n")
        return root

    def test_off_by_default_no_network(self):
        osv = FakeOsv()
        report = run_scan(self.project(), ScanOptions(use_llm=False, osv_session=osv))
        self.assertEqual(osv.posts, [])
        self.assertEqual(report.stats["total"], 0)

    def test_opt_in_adds_findings_and_survives_failure(self):
        report = run_scan(self.project(), ScanOptions(use_llm=False, deps=True, osv_session=FakeOsv()))
        self.assertEqual(report.stats["total"], 2)
        self.assertEqual(report.meta["dependencies"]["checked"], 2)
        down = run_scan(self.project(), ScanOptions(use_llm=False, deps=True, osv_session=FakeOsv(fail=True)))
        self.assertEqual(down.stats["total"], 0)
        self.assertTrue(any("Dependency check skipped" in n for n in down.notes))

    def test_zip_upload_keeps_manifests(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("requirements.txt", REQ)
            z.writestr("package-lock.json", LOCK)
            z.writestr("a.py", "x=1\n")
            z.writestr("notes.txt", "skip me")
        path = Path(tempfile.mkdtemp()) / "p.zip"
        path.write_bytes(buf.getvalue())
        dest = Path(tempfile.mkdtemp())
        safe_extract(path, dest)
        self.assertEqual(len(collect(dest)), 4)
        self.assertFalse((dest / "notes.txt").exists())


if __name__ == "__main__":
    unittest.main()
