import io
import time
import unittest
import zipfile

from tests import fake_ollama
from vulnagent.web.app import create_app

CODE = "import os\nfrom flask import request\ndef f():\n    os.system(request.args['c'])\n"


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    buf.seek(0)
    return buf


class WebTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.c = self.app.test_client()

    def upload(self, data, name="proj.zip", **form):
        return self.c.post("/api/scans", data={"archive": (data, name), **form},
                           content_type="multipart/form-data", base_url="http://localhost")

    def wait(self, job_id):
        for _ in range(100):
            info = self.c.get(f"/api/scans/{job_id}", base_url="http://localhost").get_json()
            if info["status"] in ("done", "error"):
                return info
            time.sleep(0.1)
        self.fail("scan did not finish")

    def test_upload_scan_and_all_downloads(self):
        r = self.upload(make_zip({"app.py": CODE}))
        self.assertEqual(r.status_code, 202)
        job_id = r.get_json()["id"]
        self.assertEqual(self.wait(job_id)["status"], "done")
        page = self.c.get(f"/scans/{job_id}", base_url="http://localhost")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"<svg", page.data)
        for ext, magic in (("pdf", b"%PDF"), ("json", b"{"), ("sarif", b"{"), ("md", b"#")):
            d = self.c.get(f"/scans/{job_id}/report.{ext}", base_url="http://localhost")
            self.assertEqual(d.status_code, 200, ext)
            self.assertTrue(d.data.lstrip().startswith(magic), ext)

    def test_security_headers(self):
        r = self.c.get("/", base_url="http://localhost")
        self.assertIn("default-src 'none'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["Cache-Control"], "no-store")

    def test_foreign_host_and_cross_origin_blocked(self):
        self.assertEqual(self.c.get("/", base_url="http://evil.example").status_code, 400)
        r = self.c.post("/api/scans", data={}, headers={"Origin": "http://evil.example"},
                        base_url="http://localhost")
        self.assertEqual(r.status_code, 403)

    def test_bad_uploads(self):
        self.assertEqual(self.c.post("/api/scans", data={}, base_url="http://localhost").status_code, 400)
        self.assertEqual(self.upload(io.BytesIO(b"x"), name="a.txt").status_code, 400)
        job = self.upload(io.BytesIO(b"not a zip"), name="a.zip").get_json()["id"]
        info = self.wait(job)
        self.assertEqual(info["status"], "error")

    def test_zip_slip_is_rejected_or_contained(self):
        job = self.upload(make_zip({"../../evil.py": CODE})).get_json()["id"]
        info = self.wait(job)
        self.assertIn(info["status"], ("error", "done"))
        if info["status"] == "done":
            self.assertEqual(self.c.get(f"/api/scans/{job}", base_url="http://localhost").get_json()["status"], "done")

    def test_unknown_and_traversal_ids_404(self):
        for path in ("/scans/nope", "/api/scans/nope", "/scans/nope/report.pdf", "/scans/../etc/passwd"):
            self.assertEqual(self.c.get(path, base_url="http://localhost").status_code, 404, path)

    def test_ai_option_uses_injected_client(self):
        server, state, url = fake_ollama.start()
        try:
            app = create_app(model=fake_ollama.MODEL, ollama_host=url)
            c = app.test_client()
            r = c.post("/api/scans", data={"archive": (make_zip({"app.py": CODE}), "p.zip"), "ai": "on"},
                       content_type="multipart/form-data", base_url="http://localhost")
            job = r.get_json()["id"]
            for _ in range(100):
                if c.get(f"/api/scans/{job}", base_url="http://localhost").get_json()["status"] == "done":
                    break
                time.sleep(0.1)
            self.assertTrue(state.requests)
        finally:
            server.shutdown()


if __name__ == "__main__":
    unittest.main()
