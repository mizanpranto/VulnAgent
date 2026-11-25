"""The end-to-end scan used by both the CLI and the web app."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import requests

from . import __version__
from .agent import discover, triage_all
from .engagement import Engagement
from .deps import collect as collect_deps, query_osv
from .models import CWE_CATALOG, SCHEMA_VERSION, SEVERITIES
from .ollama_client import OllamaClient, OllamaError
from .scanner import scan_project_ex
from .standards import OWASP_CATEGORIES, top25_rank, tags_for
from .semgrep_runner import run_semgrep
from .verify import dedupe_and_merge

LANGUAGE = {".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
            ".ts": "TypeScript", ".tsx": "TypeScript"}


@dataclass
class ScanOptions:
    use_llm: bool = True
    discover: bool = False
    model: str = "qwen3:8b"
    host: str = "http://127.0.0.1:11434"
    num_ctx: int = 8192
    max_files: int = 150
    max_triage: int = 40
    max_discovery_chunks: int = 40
    exclude: tuple = ()
    semgrep: bool = False
    semgrep_config: str = "auto"
    llm_timeout: int = 300
    deps: bool = False            # opt-in: sends package names+versions to api.osv.dev
    osv_session: object = None    # injectable HTTP session (tests)
    a01: bool = True              # OWASP A01 access-control analysis (entry-point / guard model)
    a01_public_paths: tuple = ()  # extra regexes for intentionally public routes (allow-list)
    a01_cache_dir: Optional[str] = None


@dataclass
class ScanReport:
    project: str
    findings: list
    stats: dict
    meta: dict
    notes: list = field(default_factory=list)
    engagement: Optional[Engagement] = None
    a01: Optional[dict] = None      # entry-point authorization matrix, coverage and limitations

    @property
    def active(self):
        return [f for f in self.findings if not f.dismissed]

    @property
    def dismissed(self):
        return [f for f in self.findings if f.dismissed]

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": "VulnAgent", "version": __version__},
            "project": self.project,
            "meta": self.meta,
            "stats": self.stats,
            "notes": self.notes,
            "engagement": self.engagement.to_dict() if self.engagement else None,
            "a01": self.a01,
            "findings": [f.to_dict() for f in self.findings],
        }


def _noop(*_args, **_kwargs):
    return None


def run_scan(project, options: Optional[ScanOptions] = None, client=None,
             progress: Callable = _noop, project_name: Optional[str] = None,
             engagement: Optional[Engagement] = None) -> ScanReport:
    options = options or ScanOptions()
    project = Path(project)
    started = time.time()
    notes: list = []
    meta = {
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": options.model if options.use_llm else None,
        "llm_stages": [], "llm_available": False,
        "rejected_llm_claims": [], "triage": {}, "semgrep": None,
    }

    progress("scan", 0, 1, "Reading source files")
    scan = scan_project_ex(project, max_files=options.max_files, exclude=options.exclude)
    files_by_path = {f["path"]: f["content"] for f in scan.files}
    findings = list(scan.findings)
    if scan.truncated:
        notes.append(f"Only the first {options.max_files} files were analyzed (file limit reached).")
    if scan.skipped_minified:
        notes.append(f"{scan.skipped_minified} minified or bundled file(s) were skipped (not readable source).")
    if scan.skipped_large:
        notes.append(f"{scan.skipped_large} file(s) larger than 180 KB were skipped.")

    if options.semgrep:
        progress("semgrep", 0, 1, "Running Semgrep")
        try:
            extra = run_semgrep(project, options.semgrep_config)
            findings.extend(extra)
            meta["semgrep"] = {"config": options.semgrep_config, "findings": len(extra)}
        except RuntimeError as error:
            notes.append(f"Semgrep stage skipped: {error}")

    a01_result, a01_report = None, None
    if options.a01:
        progress("a01", 0, 1, "Modelling entry points and guards (OWASP A01)")
        from .a01 import analyze as a01_analyze
        from .a01.merge import merge_a01
        a01_sources = dict(files_by_path)
        a01_sources.update({f["path"]: f["content"] for f in scan.extra_files})
        a01_result = a01_analyze(a01_sources, scan.all_paths, {"public_paths": list(options.a01_public_paths)})
        findings, superseded = merge_a01(findings, a01_result)
        a01_report = a01_result.report
        a01_report["superseded_legacy_findings"] = superseded
        meta["a01"] = {"entry_points": a01_report["entry_points"], "findings": len(a01_result.findings),
                       "superseded_legacy": superseded}

    findings = dedupe_and_merge(findings)
    dep_count, dep_findings = 0, []
    if options.deps:
        progress("deps", 0, 1, "Checking dependencies")
        try:
            dep_list = collect_deps(project)
            dep_count = len(dep_list)
            session = options.osv_session or requests.Session()
            dep_findings = query_osv(dep_list, session)
            meta["dependencies"] = {"checked": dep_count, "source": "osv.dev"}
        except RuntimeError as error:
            notes.append(f"Dependency check skipped: {error}")

    if options.use_llm and files_by_path:
        client = client or OllamaClient(options.host, options.model, timeout=options.llm_timeout,
                                        num_ctx=options.num_ctx)
        try:
            if hasattr(client, "check"):
                client.check()
            meta["llm_available"] = True
            if findings and options.max_triage > 0:
                meta["llm_stages"].append("triage")
                meta["triage"] = triage_all(client, findings, files_by_path, options.max_triage, progress)
            if options.discover:
                meta["llm_stages"].append("discovery")
                extra, rejected = discover(client, scan.files, findings, files_by_path,
                                           options.max_discovery_chunks, progress)
                meta["rejected_llm_claims"] = rejected
                findings = dedupe_and_merge(findings + extra)
                if rejected:
                    notes.append(f"{len(rejected)} AI claim(s) were rejected because they could not be verified "
                                 "against the source (see report metadata).")
            if a01_result is not None and a01_result.findings:
                from .a01.llm_review import review_a01
                meta["llm_stages"].append("a01-review")
                meta["a01_review"] = review_a01(client, a01_result, files_by_path, options.max_triage,
                                                cache_dir=options.a01_cache_dir, progress=progress)
        except OllamaError as error:
            notes.append(f"AI stages unavailable: {error} Deterministic results are still shown.")

    findings = sorted(findings + dep_findings, key=lambda f: (-f.rank, f.file, f.line)) if dep_findings else findings
    languages = Counter(LANGUAGE.get(Path(f["path"]).suffix.lower(), "Other") for f in scan.files)
    active = [f for f in findings if not f.dismissed]
    by_cwe = Counter(f.cwe for f in active if f.cwe)
    stats = {
        "files": len(scan.files),
        "lines": sum(len(f["content"].splitlines()) for f in scan.files),
        "languages": dict(languages),
        "severity": {s: sum(1 for f in active if f.severity == s) for s in SEVERITIES},
        "total": len(active),
        "dismissed": len(findings) - len(active),
        "by_cwe": [{"cwe": c, "name": CWE_CATALOG.get(c, ""), "count": n} for c, n in by_cwe.most_common()],
        "by_file": [{"file": p, "count": n} for p, n in Counter(f.file for f in active).most_common(10)],
        "owasp": [{"id": f"{c}:2025", "name": OWASP_CATEGORIES[c], "count": n}
                  for c, n in sorted(Counter(i for f in active for i in tags_for(f.cwe)["owasp_ids"]).items())],
        "top25": sum(1 for f in active if top25_rank(f.cwe)),
        "by_origin": dict(Counter(o for f in active for o in f.origins)),
    }
    meta["duration_seconds"] = round(time.time() - started, 1)
    progress("done", 1, 1, "Finished")
    if a01_report is not None:
        stats["a01"] = {"findings": sum(1 for f in active if f.rule_id.startswith("A01-")),
                        "entry_points": a01_report["entry_points"]}
    return ScanReport(project=project_name or project.name, findings=findings, stats=stats, meta=meta, notes=notes,
                      engagement=engagement, a01=a01_report)
