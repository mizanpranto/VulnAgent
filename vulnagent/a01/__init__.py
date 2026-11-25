"""A01:2025 Broken Access Control analysis (entry-point / guard model + declarative rules)."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

from . import patterns as P
from .engine import Engine
from .ir import Project
from .plausibility import classify_side
from .registry import RULES

LANGS = {".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".ts": "TypeScript",
         ".tsx": "TypeScript", ".py": "Python", ".java": "Java", ".kt": "Kotlin", ".cs": "C#", ".php": "PHP", ".go": "Go",
         ".rb": "Ruby", ".rs": "Rust", ".scala": "Scala", ".swift": "Swift", ".c": "C", ".cpp": "C++", ".m": "Objective-C",
         ".ex": "Elixir", ".exs": "Elixir", ".dart": "Dart", ".lua": "Lua", ".pl": "Perl", ".groovy": "Groovy", ".vue": "Vue",
         ".svelte": "Svelte", ".graphql": "GraphQL", ".gql": "GraphQL"}
FULL = {"JavaScript", "TypeScript", "Python"}
PARTIAL = {"Java", "C#"}
SKELETON = {"PHP", "Go", "Ruby"}
SOURCE_EXTS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".java", ".cs", ".php", ".go", ".rb")
GENERAL_LIMITATIONS = [
    "A01 analysis is static: authentication/authorization enforced outside the code (reverse proxy, API gateway, WAF, "
    "network policy) is not visible, so such routes may be reported as unguarded.",
    "Routes registered dynamically (computed paths, reflection, plugin loaders) and GraphQL/RPC/queue/scheduled-job entry points "
    "are not enumerated; only HTTP entry points are modelled.",
    "Absence-based findings (missing authentication/authorization, CSRF) are never 'confirmed': they need human review.",
    "Object-level checks performed in a helper or service layer that the extractor cannot resolve may produce IDOR false positives.",
]


@dataclass
class A01Result:
    findings: list
    project: Project
    report: dict = field(default_factory=dict)
    spans: list = field(default_factory=list)


def language_of(path: str):
    return LANGS.get(posixpath.splitext(path)[1].lower())


def analyze(files: dict, all_paths=(), config=None) -> A01Result:
    """files: relative path -> source text. all_paths: every project path (for exposure checks)."""
    config = config or {}
    project = Project()
    project.all_paths = list(all_paths) or list(files)
    for path, src in files.items():
        project.side_by_file[path] = classify_side(path, src)
    side_of = lambda p: project.side_by_file.get(p, "unknown")
    counts = {}
    for path in project.all_paths:
        lang = language_of(path)
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    src_files = {p: s for p, s in files.items() if p.lower().endswith(SOURCE_EXTS)}

    from .extractors import js, py, java, csharp, stubs
    js_files = {p: s for p, s in src_files.items() if p.lower().endswith(js.EXTS)}
    if js_files:
        if js.available():
            js.extract(js_files, project, side_of, config)
        else:
            project.warnings.append("tree-sitter is not installed: JavaScript/TypeScript were NOT analysed (pip install vulnagent[a01])")
            project.unsupported["JavaScript/TypeScript"] = len(js_files)
    py_files = {p: s for p, s in src_files.items() if p.endswith(".py")}
    if py_files:
        py.extract(py_files, project, side_of, config)
    java_files = {p: s for p, s in src_files.items() if p.endswith(".java")}
    if java_files:
        if java.available():
            java.extract(java_files, project, side_of, config)
        else:
            project.unsupported["Java"] = len(java_files)
    cs_files = {p: s for p, s in src_files.items() if p.endswith(".cs")}
    if cs_files:
        if csharp.available():
            csharp.extract(cs_files, project, side_of, config)
        else:
            project.unsupported["C#"] = len(cs_files)
    stubs.extract(src_files, project)
    for lang, n in counts.items():
        if lang not in FULL | PARTIAL | SKELETON and lang not in project.unsupported:
            project.unsupported[lang] = n
    if "Kotlin" in counts:
        project.unsupported["Kotlin"] = counts["Kotlin"]

    engine = Engine(project, files, config)
    findings = engine.run()
    spans = [(ep.file, ep.line, ep.end_line or ep.line) for ep in project.entry_points]
    report = build_report(project, engine, counts, findings)
    return A01Result(findings=findings, project=project, report=report, spans=spans)


# ---------------------------------------------------------------------------------------------
def _guard_names(guards, kind):
    names = []
    for g in guards:
        if g.kind == kind:
            tag = g.name + ("" if g.certainty == "code" else " (name only)") + (" [fails open]" if g.fails_open else "")
            if tag not in names:
                names.append(tag)
    return names


def matrix_rows(project: Project, engine: Engine) -> list:
    rows = []
    for ep in sorted(project.entry_points, key=lambda e: (e.path, e.method)):
        guards = engine.eff_guards(ep)
        authn = _guard_names(guards, "authentication")
        if "public_marker" in ep.notes:
            authn_txt = "public (marked)"
        elif authn:
            authn_txt = ", ".join(authn)
        elif ep.facts.authn_inline:
            authn_txt = "inline check"
        elif engine.is_public(ep):
            authn_txt = "none (public route)"
        else:
            authn_txt = "NONE"
        role = _guard_names(guards, "authorization") or (["inline check"] if ep.facts.role_check_inline else [])
        owner = _guard_names(guards, "ownership") or (["inline check"] if ep.facts.ownership_check_inline else [])
        csrf = _guard_names(guards, "csrf")
        if not csrf:
            if ep.method in ("GET", "HEAD", "OPTIONS"):
                csrf = ["n/a"]
            elif ep.framework in ("django", "spring", "rails", "laravel", "aspnet") and "csrf_exempt" not in ep.notes \
                    and not project.global_security.get("csrf_disabled"):
                csrf = ["framework default"]
            elif "csrf_exempt" in ep.notes or project.global_security.get("csrf_disabled"):
                csrf = ["DISABLED"]
            elif project.global_security.get("csrf_default", {}).get(ep.framework) or project.global_security.get("csrf_middleware"):
                csrf = ["global"]
            elif not project.cookie_auth:
                csrf = ["n/a (no cookie auth seen)"]
            else:
                csrf = ["none"]
        rows.append({"method": ep.method, "path": ep.path, "framework": ep.framework, "authentication": authn_txt,
                     "role_check": ", ".join(role) or "none", "ownership_check": ", ".join(owner) or "none",
                     "csrf": ", ".join(csrf), "handler": ep.handler, "location": f"{ep.file}:{ep.line}",
                     "notes": "; ".join(n.split(":")[0] for n in ep.notes)})
    return rows


def build_report(project: Project, engine: Engine, counts: dict, findings: list) -> dict:
    limitations = list(GENERAL_LIMITATIONS)
    not_analysed = {}
    for lang, note in project.partial.items():
        name = {"php": "PHP", "go": "Go", "ruby": "Ruby"}[lang]
        not_analysed[name] = note
        limitations.append(f"{name}: {note}.")
    for lang, n in project.unsupported.items():
        not_analysed[lang] = f"{n} file(s), no extractor"
        limitations.append(f"{lang}: {n} file(s) detected but no extractor exists; access control was not analysed for them.")
    for lang in ("Java", "C#"):
        if lang in counts and lang not in project.unsupported:
            limitations.append(f"{lang}: partial extractor (routes, annotations/attributes, global security configuration); "
                               "handler data-flow facts are limited, so IDOR/exposure rules have reduced recall.")
    if project.files_failed:
        limitations.append(f"{len(project.files_failed)} file(s) could not be parsed and were skipped.")
    gs = project.global_security
    return {
        "languages": counts,
        "frameworks": sorted(project.frameworks),
        "extractors_used": project.extractors_used,
        "entry_points": len(project.entry_points),
        "files_parsed": len(project.files_parsed),
        "files_failed": [{"file": f, "reason": r} for f, r in project.files_failed],
        "files_skipped": [{"file": f, "reason": r} for f, r in project.files_skipped],
        "global_security": {"found": gs["found"], "notes": gs["notes"], "default_authn": gs["default_authn"],
                            "csrf_disabled": [f"{f}:{l}" for f, l, _ in gs["csrf_disabled"]],
                            "default_allow_all": bool(gs["default_allow_all"])},
        "guards_found": len(project.guards),
        "models_found": len(project.models),
        "not_analysed": not_analysed,
        "warnings": project.warnings,
        "limitations": limitations,
        "matrix": matrix_rows(project, engine),
        "rules": {rid: {"title": r.title, "cwes": [f"CWE-{c}" for c in r.cwes]} for rid, r in RULES.items()},
    }
