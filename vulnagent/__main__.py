"""Command line interface.

    python -m vulnagent PATH [options]      scan a directory or a .zip
    python -m vulnagent serve [options]     start the local web app
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

from . import __version__
from .models import SEVERITY_RANK
from .pipeline import ScanOptions, run_scan
from .engagement import DEFAULT_AGENT_AUTHOR, from_mapping, process_logo
from .report import write_json, write_markdown, write_sarif
from .safe_zip import UnsafeArchive, safe_extract

DEFAULT_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")


def build_scan_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vulnagent", description="Local, AI-assisted source code security scanner")
    p.add_argument("project", help="Directory or .zip file to analyze")
    p.add_argument("--model", default="qwen3:8b", help="Ollama model (default: qwen3:8b)")
    p.add_argument("--ollama-host", default=DEFAULT_HOST)
    p.add_argument("--no-llm", action="store_true", help="Deterministic analysis only (no Ollama needed)")
    p.add_argument("--discover", action="store_true", help="Also ask the model to find extra issues (verified)")
    p.add_argument("--semgrep", action="store_true", help="Also run Semgrep if installed")
    p.add_argument("--semgrep-config", default="auto")
    p.add_argument("--no-a01", action="store_true", help="Skip the OWASP A01 access-control analysis (entry-point / guard model)")
    p.add_argument("--public-path", action="append", default=[], metavar="REGEX",
                   help="Regex for an intentionally public route (repeatable); exempts it from the missing-authentication rule")
    p.add_argument("--deps", action="store_true", help="Check pinned dependencies against OSV (sends package names+versions to api.osv.dev)")
    p.add_argument("--max-files", type=int, default=150)
    p.add_argument("--max-triage", type=int, default=40, help="Max findings sent to AI triage")
    p.add_argument("--num-ctx", type=int, default=8192, help="Ollama context window")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="Skip paths matching GLOB")
    p.add_argument("--output", default="vulnagent-report", help="Output path without extension")
    p.add_argument("--format", default="md,json", help="Comma list: md,json,sarif,pdf,docx")
    g = p.add_argument_group("report cover page (all optional)")
    g.add_argument("--assessor", help="Name of the person doing the assessment")
    g.add_argument("--company", help="Assessor's company")
    g.add_argument("--client", help="Who the report is prepared for")
    g.add_argument("--application", help="Application name (default: project folder or zip name)")
    g.add_argument("--title", help="Report title (default: Source Code Security Assessment)")
    g.add_argument("--contact", help="Assessor email or phone")
    g.add_argument("--reviewer", help="Reviewed by")
    g.add_argument("--agent-author", default=DEFAULT_AGENT_AUTHOR, help="Credit line: who developed the agent (default: %(default)s)")
    g.add_argument("--classification", default="Confidential", help="Confidential, Internal, Restricted or Public")
    g.add_argument("--report-version", default="1.0")
    g.add_argument("--report-date", help="YYYY-MM-DD (default: today)")
    g.add_argument("--logo", metavar="FILE", help="PNG or JPEG logo for the cover page")
    p.add_argument("--fail-on", choices=list(SEVERITY_RANK), help="Exit 1 if an active finding has at least this severity")
    p.add_argument("--version", action="version", version=f"VulnAgent {__version__}")
    return p


def scan_main(argv) -> int:
    args = build_scan_parser().parse_args(argv)
    target = Path(args.project).expanduser().resolve()
    if not target.exists():
        print(f"[!] Not found: {target}", file=sys.stderr)
        return 2
    options = ScanOptions(use_llm=not args.no_llm, discover=args.discover, model=args.model, host=args.ollama_host,
                          num_ctx=args.num_ctx, max_files=args.max_files, max_triage=args.max_triage,
                          exclude=tuple(args.exclude), semgrep=args.semgrep, semgrep_config=args.semgrep_config, deps=args.deps,
                          a01=not args.no_a01, a01_public_paths=tuple(args.public_path))

    def progress(stage, done, total, message):
        print(f"[{stage}] {message} ({done}/{total})", flush=True)

    logo = None
    if args.logo:
        try:
            logo = process_logo(Path(args.logo).read_bytes())
        except (OSError, ValueError) as error:
            print(f"[!] Logo: {error}", file=sys.stderr)
            return 2
    engagement = from_mapping({"assessor": args.assessor, "company": args.company, "client": args.client,
                               "application": args.application, "title": args.title, "contact": args.contact,
                               "reviewer": args.reviewer, "agent_author": args.agent_author,
                               "classification": args.classification, "version": args.report_version,
                               "date": args.report_date}, logo)

    with tempfile.TemporaryDirectory(prefix="vulnagent-") as tmp:
        project, name = target, target.name
        if target.is_file():
            if target.suffix.lower() != ".zip":
                print("[!] Provide a directory or a .zip file.", file=sys.stderr)
                return 2
            try:
                safe_extract(target, tmp)
            except UnsafeArchive as error:
                print(f"[!] {error}", file=sys.stderr)
                return 2
            project, name = Path(tmp), target.stem
        report = run_scan(project, options, progress=progress, project_name=name, engagement=engagement)

    base = Path(args.output)
    base = base.with_suffix("") if base.suffix in (".md", ".json", ".sarif", ".pdf", ".docx") else base
    formats = {f.strip().lower() for f in args.format.split(",") if f.strip()}
    written = []
    if "md" in formats:
        written.append(write_markdown(report, base.with_suffix(".md")))
    if "json" in formats:
        written.append(write_json(report, base.with_suffix(".json")))
    if "sarif" in formats:
        written.append(write_sarif(report, base.with_suffix(".sarif")))
    if "pdf" in formats:
        from .pdf_report import build_pdf
        written.append(build_pdf(report, base.with_suffix(".pdf")))
    if "docx" in formats:
        from .docx_report import build_docx
        written.append(build_docx(report, base.with_suffix(".docx")))

    s = report.stats["severity"]
    print(f"\nFiles: {report.stats['files']}  Findings: {report.stats['total']} "
          f"(critical {s['critical']}, high {s['high']}, medium {s['medium']}, low {s['low']}, info {s['info']})"
          + (f"  Dismissed by AI: {report.stats['dismissed']}" if report.stats["dismissed"] else ""))
    for note in report.notes:
        print(f"[note] {note}")
    for path in written:
        print(f"[+] {path}")
    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]
        if any(f.rank >= threshold for f in report.active):
            return 1
    return 0


def serve_main(argv) -> int:
    p = argparse.ArgumentParser(prog="vulnagent serve", description="Start the local web app")
    p.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1 = this computer only)")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--model", default="qwen3:8b")
    p.add_argument("--ollama-host", default=DEFAULT_HOST)
    args = p.parse_args(argv)
    from .web.app import create_app
    app = create_app(model=args.model, ollama_host=args.ollama_host)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("[!] WARNING: binding to a non-local address. Anyone who can reach this port can upload code and "
              "download reports. There is no login.", file=sys.stderr)
    print(f"VulnAgent web app: http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "serve":
        return serve_main(argv[1:])
    return scan_main(argv)


if __name__ == "__main__":
    sys.exit(main())
