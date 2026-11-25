"""Local web app: upload a zip, watch the scan, view diagrams, download the PDF.

Security model (this tool takes uploads, so it has to be safe itself):
* binds to 127.0.0.1 by default; Host and Origin headers are checked so a
  website you visit cannot make your browser upload to or read from it;
* uploaded archives are extracted by ``safe_zip`` (zip-slip, symlink and
  zip-bomb protection) and only parsed, never executed;
* extracted source is deleted as soon as the scan ends, reports expire;
* all scanned text is HTML-escaped by Jinja; a strict CSP forbids inline script.
"""

from __future__ import annotations

import io
import re
import secrets
import shutil
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from flask import Flask, Response, abort, jsonify, redirect, render_template, request, url_for

from .. import __version__, charts
from ..ollama_client import OllamaClient, OllamaError
from ..pipeline import ScanOptions, run_scan
from ..engagement import CLASSIFICATIONS, DEFAULT_AGENT_AUTHOR, MAX_LOGO_BYTES, from_mapping, process_logo
from ..models import cwe_label
from ..report import ORIGIN_LABEL, render_markdown, to_sarif
from ..standards import label as standards_label
from ..safe_zip import UnsafeArchive, safe_extract
import json

JOB_TTL_SECONDS = 60 * 60
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_ACTIVE_JOBS = 6
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
STAGE_LABEL = {"queued": "Waiting to start", "extract": "Unpacking the archive", "scan": "Reading source files",
               "semgrep": "Running Semgrep", "deps": "Checking dependencies", "triage": "AI is checking each finding",
               "discovery": "AI is reviewing code for extra issues", "done": "Finished"}


@dataclass
class Job:
    id: str
    name: str
    options: ScanOptions
    created: float = field(default_factory=time.time)
    status: str = "queued"          # queued | running | done | error
    stage: str = "queued"
    done: int = 0
    total: int = 1
    message: str = ""
    error: str = ""
    report: object = None
    workdir: Optional[Path] = None
    pdf_bytes: Optional[bytes] = None
    docx_bytes: Optional[bytes] = None
    engagement: object = None

    def public(self) -> dict:
        return {"id": self.id, "status": self.status, "stage": self.stage,
                "stage_label": STAGE_LABEL.get(self.stage, self.stage), "done": self.done,
                "total": self.total, "message": self.message, "error": self.error}


class JobStore:
    def __init__(self):
        self.jobs: dict = {}
        self.lock = threading.Lock()

    def add(self, job: Job) -> None:
        with self.lock:
            self.jobs[job.id] = job

    def get(self, job_id: str) -> Optional[Job]:
        with self.lock:
            return self.jobs.get(job_id)

    def active(self) -> int:
        with self.lock:
            return sum(1 for j in self.jobs.values() if j.status in ("queued", "running"))

    def purge(self) -> None:
        cutoff = time.time() - JOB_TTL_SECONDS
        with self.lock:
            expired = [j for j in self.jobs.values() if j.created < cutoff and j.status in ("done", "error")]
            for job in expired:
                del self.jobs[job.id]
                if job.workdir:
                    shutil.rmtree(job.workdir, ignore_errors=True)


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")[:60] or "project"


def create_app(model: str = "qwen3:8b", ollama_host: str = "http://127.0.0.1:11434",
               local_only: bool = True, client_factory=None) -> Flask:
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES, JSON_SORT_KEYS=False)
    app.jinja_env.globals.update(cwe_label=cwe_label, origin_label=ORIGIN_LABEL, standards_label=standards_label)
    store = JobStore()
    pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scan")
    app.extensions["vulnagent_store"] = store
    make_client = client_factory or (lambda opts: OllamaClient(opts.host, opts.model, num_ctx=opts.num_ctx))

    # ---- request hardening ---------------------------------------------------
    @app.before_request
    def guard():
        store.purge()
        if local_only:
            host = request.host.rsplit(":", 1)[0] if not request.host.startswith("[") else request.host.split("]")[0] + "]"
            if host not in LOCAL_HOSTS:
                abort(400, "Unexpected Host header")
        if request.method == "POST":
            origin = request.headers.get("Origin")
            if origin and urlparse(origin).netloc != request.host:
                abort(403, "Cross-origin request blocked")

    @app.after_request
    def headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify(error=f"That file is larger than the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit."), 413

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    def plain_error(error):
        if request.path.startswith("/api/"):
            return jsonify(error=getattr(error, "description", "Request refused")), error.code
        return render_template("error.html", code=error.code, message=getattr(error, "description", ""),
                               version=__version__), error.code

    # ---- scan worker -----------------------------------------------------------
    def run_job(job: Job, archive: Path):
        job.status = "running"

        def progress(stage, done, total, message):
            job.stage, job.done, job.total, job.message = stage, done, max(total, 1), message

        try:
            job.stage, job.message = "extract", "Unpacking the archive"
            source_dir = job.workdir / "src"
            safe_extract(archive, source_dir)
            archive.unlink(missing_ok=True)
            job.report = run_scan(source_dir, job.options, client=make_client(job.options) if job.options.use_llm else None,
                                  progress=progress, project_name=job.name, engagement=job.engagement)
            job.status, job.stage = "done", "done"
        except UnsafeArchive as error:
            job.status, job.error = "error", str(error)
        except OllamaError as error:  # defensive: pipeline normally converts this to a note
            job.status, job.error = "error", str(error)
        except Exception:  # noqa: BLE001 - never leak internals to the browser
            app.logger.exception("scan failed")
            job.status, job.error = "error", "The scan failed unexpectedly. Check the server log."
        finally:
            # The uploaded source is never kept after the scan.
            shutil.rmtree(job.workdir / "src", ignore_errors=True)
            archive.unlink(missing_ok=True)

    # ---- routes ----------------------------------------------------------------
    @app.get("/")
    def index():
        return render_template("index.html", model=model, version=__version__,
                               max_mb=MAX_UPLOAD_BYTES // (1024 * 1024), today=date.today().isoformat(),
                               classifications=CLASSIFICATIONS, default_author=DEFAULT_AGENT_AUTHOR)

    @app.get("/api/status")
    def status():
        info = {"model": model, "ollama": False, "message": ""}
        try:
            OllamaClient(ollama_host, model).check()
            info["ollama"] = True
        except OllamaError as error:
            info["message"] = str(error)
        return jsonify(info)

    @app.post("/api/scans")
    def create_scan():
        upload = request.files.get("archive")
        if upload is None or not upload.filename:
            return jsonify(error="Choose a .zip file first."), 400
        if not upload.filename.lower().endswith(".zip"):
            return jsonify(error="Only .zip files are accepted."), 400
        if store.active() >= MAX_ACTIVE_JOBS:
            return jsonify(error="The server is busy. Try again in a minute."), 429
        job_id = secrets.token_urlsafe(16)
        workdir = Path(tempfile.mkdtemp(prefix="vulnagent-job-"))
        archive = workdir / "upload.zip"
        form = request.form
        logo = None
        logo_file = request.files.get("logo")
        if logo_file is not None and logo_file.filename:
            try:
                logo = process_logo(logo_file.read(MAX_LOGO_BYTES + 1))
            except ValueError as error:
                shutil.rmtree(workdir, ignore_errors=True)
                return jsonify(error=str(error)), 400
        upload.save(archive)
        engagement = from_mapping({k[len("report_"):]: v for k, v in form.items() if k.startswith("report_")}, logo)
        options = ScanOptions(use_llm=form.get("ai") == "on", discover=form.get("discover") == "on", deps=form.get("deps") == "on", a01_public_paths=tuple(x for x in form.get("a01_public", "").split() if x),
                              model=model, host=ollama_host, max_files=300, max_triage=30,
                              max_discovery_chunks=25)
        job = Job(id=job_id, name=_safe_name(Path(upload.filename).stem), options=options, workdir=workdir,
                  engagement=engagement)
        store.add(job)
        pool.submit(run_job, job, archive)
        return jsonify(id=job_id, url=url_for("scan_page", job_id=job_id)), 202

    @app.get("/api/scans/<job_id>")
    def scan_status(job_id):
        job = store.get(job_id)
        if job is None:
            abort(404, "That scan does not exist or has expired.")
        return jsonify(job.public())

    @app.get("/scans/<job_id>")
    def scan_page(job_id):
        job = store.get(job_id)
        if job is None:
            abort(404, "That scan does not exist or has expired. Reports are kept for one hour.")
        if job.status in ("queued", "running"):
            return render_template("progress.html", job=job.public(), version=__version__)
        if job.status == "error":
            return render_template("progress.html", job=job.public(), version=__version__), 200
        report = job.report
        return render_template(
            "report.html", report=report, job_id=job_id, version=__version__,
            sev_chart=charts.severity_bars(report.stats["severity"]),
            cwe_chart=charts.category_bars(report.stats["by_cwe"]),
            file_chart=charts.file_risk(report.findings), legend=charts.severity_legend(),
            pipeline=charts.pipeline_diagram(report),
            active_rows=[(f, charts.flow_diagram(f)) for f in report.active],
            dismissed_rows=[(f, charts.flow_diagram(f)) for f in report.dismissed],
            sev_label=charts.SEVERITY_LABEL, expires_minutes=JOB_TTL_SECONDS // 60)

    def _finished(job_id) -> Job:
        job = store.get(job_id)
        if job is None or job.status != "done":
            abort(404, "That report is not available.")
        return job

    @app.get("/scans/<job_id>/report.pdf")
    def download_pdf(job_id):
        job = _finished(job_id)
        if job.pdf_bytes is None:
            from ..pdf_report import build_pdf
            buffer = io.BytesIO()
            build_pdf(job.report, buffer)
            job.pdf_bytes = buffer.getvalue()
        return _download(job.pdf_bytes, "application/pdf", f"vulnagent-{job.name}.pdf")

    @app.get("/scans/<job_id>/report.docx")
    def download_docx(job_id):
        job = _finished(job_id)
        if job.docx_bytes is None:
            from ..docx_report import build_docx
            buffer = io.BytesIO()
            build_docx(job.report, buffer)
            job.docx_bytes = buffer.getvalue()
        return _download(job.docx_bytes, "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                         f"vulnagent-{job.name}.docx")

    @app.get("/scans/<job_id>/report.json")
    def download_json(job_id):
        job = _finished(job_id)
        return _download(json.dumps(job.report.to_dict(), indent=2).encode(), "application/json",
                         f"vulnagent-{job.name}.json")

    @app.get("/scans/<job_id>/report.sarif")
    def download_sarif(job_id):
        job = _finished(job_id)
        return _download(json.dumps(to_sarif(job.report), indent=2).encode(), "application/sarif+json",
                         f"vulnagent-{job.name}.sarif")

    @app.get("/scans/<job_id>/report.md")
    def download_md(job_id):
        job = _finished(job_id)
        return _download(render_markdown(job.report).encode(), "text/markdown; charset=utf-8",
                         f"vulnagent-{job.name}.md")

    def _download(data: bytes, mimetype: str, filename: str) -> Response:
        return Response(data, mimetype=mimetype,
                        headers={"Content-Disposition": f'attachment; filename="{_safe_name(filename)}"'})

    return app
