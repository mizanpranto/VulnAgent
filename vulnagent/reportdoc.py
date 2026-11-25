"""Content of a pentest-style report, independent of the output format.

The PDF and DOCX writers both read these helpers, so the two documents always say
the same thing. Nothing here invents facts: every number and sentence is derived
from the scan result.
"""

from __future__ import annotations

from collections import OrderedDict

from .models import CWE_CATALOG, SEVERITIES
from .standards import OWASP_YEAR, TOP25_YEAR, label as standards_label, tags_for

SEVERITY_DEFINITIONS = OrderedDict([
    ("critical", "Likely to be exploitable with little effort and to lead to full compromise of the application or its "
                 "data (for example, untrusted input reaching a command or code-execution call). Fix immediately."),
    ("high", "A serious weakness that could allow data theft, account takeover or significant abuse if the right "
             "conditions exist. Fix as a priority."),
    ("medium", "A weakness that needs specific conditions or additional access to exploit, or that weakens defences. "
               "Plan a fix in the next release cycle."),
    ("low", "Limited impact or hard to exploit on its own; hardening and good-practice items."),
    ("info", "Observation with no direct security impact, included for awareness."),
])

TIMEFRAME = OrderedDict([("critical", "Immediate"), ("high", "Immediate"), ("medium", "Short term"),
                         ("low", "Long term"), ("info", "Long term")])


def finding_id(index: int) -> str:
    return f"VA-{index:03d}"


SEVERAL_HIGH = 3   # this many High findings together rate the application Critical


def overall_risk(stats: dict) -> tuple:
    """Risk follows the worst finding: any Critical -> Critical; several High -> Critical."""
    sev = stats["severity"]
    if sev.get("critical"):
        return "Critical", "Critical-severity issues were identified and should be remediated immediately."
    if sev.get("high", 0) >= SEVERAL_HIGH:
        return "Critical", (f"{sev['high']} High-severity issues were identified; together they put the application at Critical "
                            "risk and should be remediated immediately.")
    if sev.get("high"):
        return "High", "High-severity issues were identified and should be remediated as a priority."
    if sev.get("medium"):
        return "Medium", "Medium-severity issues were identified; schedule remediation in the next release cycle."
    if sev.get("low") or sev.get("info"):
        return "Low", "Only low-severity or informational issues were identified."
    return "None identified", ("The automated checks reported no issues. This does not prove the application is free "
                               "of vulnerabilities: see the limitations of this assessment.")


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def languages_text(stats: dict) -> str:
    return ", ".join(f"{k} ({v})" for k, v in stats["languages"].items()) or "none"


def executive_summary(report, application: str) -> list:
    """Paragraphs of plain text."""
    stats = report.stats
    sev = stats["severity"]
    parts = [f"{sev.get(s, 0)} {s}" for s in SEVERITIES if sev.get(s)]
    paragraphs = [
        f"VulnAgent performed an automated source code security assessment of {application}, covering "
        f"{_plural(stats['files'], 'file')} and {stats['lines']:,} lines of code ({languages_text(stats)})."]
    if stats["total"]:
        paragraphs.append(f"The assessment identified {_plural(stats['total'], 'finding')}: " + ", ".join(parts) + ".")
    else:
        paragraphs.append("The assessment did not identify any findings.")
    if stats["by_cwe"]:
        top = "; ".join(f"CWE-{r['cwe']} {r['name']} ({r['count']})" for r in stats["by_cwe"][:3])
        paragraphs.append(f"The most frequent weakness types were: {top}.")
    if stats.get("owasp"):
        top = "; ".join(f"{r['id'][:3]} {r['name']} ({r['count']})"
                        for r in sorted(stats["owasp"], key=lambda r: -r["count"])[:3])
        paragraphs.append(f"Mapped to the OWASP Top 10:{OWASP_YEAR}, the largest groups were {top}. "
                          f"{stats.get('top25', 0)} finding(s) fall within the CWE Top 25 ({TOP25_YEAR}).")
    return paragraphs


def top_priorities(report, limit: int = 5) -> list:
    """(id, finding) for the most severe active findings, in report order."""
    return [(finding_id(i), f) for i, f in enumerate(report.active, 1)][:limit]


def remediation_roadmap(report) -> list:
    """Rows: (timeframe, count, summary of what to fix)."""
    buckets = OrderedDict((t, []) for t in OrderedDict.fromkeys(TIMEFRAME.values()))
    for finding in report.active:
        buckets[TIMEFRAME.get(finding.severity, "Long term")].append(finding)
    rows = []
    for timeframe, findings in buckets.items():
        if not findings:
            continue
        titles = OrderedDict()
        for f in findings:
            titles[f.title.split(":")[0]] = titles.get(f.title.split(":")[0], 0) + 1
        shown = [f"{t} ({n})" if n > 1 else t for t, n in list(titles.items())[:4]]
        more = len(titles) - len(shown)
        rows.append((timeframe, len(findings), "; ".join(shown) + (f"; and {more} more type(s)" if more > 0 else "")))
    return rows


def scope_rows(report, application: str) -> list:
    stats, meta = report.stats, report.meta
    llm = meta.get("llm_stages") or []
    rows = [("Application", application),
            ("Files analysed", str(stats["files"])),
            ("Lines of code", f"{stats['lines']:,}"),
            ("Languages", languages_text(stats)),
            ("Assessment type", "Automated static source code analysis (white-box)"),
            ("Analysis stages", ", ".join(analysis_stages(report)))]
    a01 = getattr(report, "a01", None)
    if a01:
        rows.append(("Access-control model", f"{a01['entry_points']} entry point(s); frameworks: {', '.join(a01['frameworks']) or 'none detected'}"))
    if llm:
        rows.append(("AI model", f"{meta.get('model')} (local, via Ollama)"))
    return rows


def analysis_stages(report) -> list:
    meta = report.meta
    stages = ["taint analysis (Python)", "pattern rules (JavaScript/TypeScript and fallback)"]
    if getattr(report, "a01", None):
        stages.append("access-control model (OWASP A01: entry points, guards, declarative rules)")
    if meta.get("semgrep"):
        stages.append("Semgrep rules")
    if meta.get("dependencies"):
        stages.append("dependency check (OSV)")
    for stage in meta.get("llm_stages") or []:
        stages.append({"triage": "AI triage", "discovery": "AI discovery (verified)", "a01-review": "AI access-control review (structured)"}.get(stage, stage))
    return stages


def methodology_steps(report) -> list:
    meta = report.meta
    steps = [
        ("Source intake", "The submitted archive or folder was read without executing any code. Dependency "
                          "folders, build output and binary or minified files were skipped."),
        ("Static analysis", "Python files were parsed into syntax trees and untrusted input (sources) was followed "
                            "through assignments to dangerous operations (sinks) within each function, honouring "
                            "known sanitisers. JavaScript and TypeScript were checked with pattern rules."),
    ]
    if meta.get("semgrep"):
        steps.append(("Semgrep", f"Semgrep rules ({meta['semgrep'].get('config')}) were run and merged into the results."))
    if meta.get("dependencies"):
        steps.append(("Dependency check", f"{meta['dependencies'].get('checked', 0)} pinned package versions were "
                                          "compared with the OSV vulnerability database (only names and versions "
                                          "were sent)."))
    if "triage" in (meta.get("llm_stages") or []):
        steps.append(("AI triage", f"A local model ({meta.get('model')}) reviewed each finding using read-only code "
                                   "lookups and labelled it confirmed, uncertain or likely false positive. The model "
                                   "cannot delete findings: dismissed items are listed in an appendix, and critical "
                                   "findings are never auto-dismissed."))
    if "discovery" in (meta.get("llm_stages") or []):
        steps.append(("AI discovery", "The model proposed additional issues. Each claim was accepted only when its "
                                      "quoted code exists in the file; unverifiable claims were rejected."))
    steps.append(("Standards mapping", f"Each finding was tagged with its CWE, its OWASP Top 10:{OWASP_YEAR} "
                                       f"category and, where applicable, its CWE Top 25 ({TOP25_YEAR}) rank."))
    steps.append(("Reporting", "Findings were de-duplicated, ordered by severity and written to this report."))
    return steps


def limitations(report) -> list:
    base = _base_limitations(report)
    a01 = getattr(report, "a01", None)
    if a01:
        base = [l for l in base if not l.startswith(("JavaScript and TypeScript are checked", "Python analysis follows"))]
        base.append("Access control (OWASP A01) is evaluated on a model of entry points and guards. Python and JavaScript/TypeScript are parsed "
                    "with real parsers; other languages are partial or not analysed (see Appendix B).")
        base += [l for l in a01.get("limitations", [])]
    return base


def _base_limitations(report) -> list:
    return [
        "This is an automated assessment. No dynamic testing, exploitation or manual code review was performed "
        "unless stated by the assessor.",
        "Findings are leads to be validated by a person; severity is an estimate based on the type of weakness, not "
        "a scored CVSS rating.",
        "Python analysis follows data within a single function only. Cross-function and cross-file flows, framework "
        "and ORM behaviour, and guards such as allowlists are not fully understood.",
        "JavaScript and TypeScript are checked with pattern rules and have no data-flow analysis.",
        "Absence of a finding is not evidence of absence of a vulnerability.",
    ]


def validation_status(finding) -> str:
    verdict = (finding.triage or {}).get("verdict")
    if verdict == "confirmed":
        return "AI triage: confirmed; not manually validated"
    if verdict == "uncertain":
        return "AI triage: uncertain; manual validation required"
    if finding.dismissed:
        return "AI triage: likely false positive; manual review recommended"
    return "Automated result; not manually validated"


def references(finding) -> list:
    refs = []
    if finding.cwe:
        refs.append(f"CWE-{finding.cwe}: https://cwe.mitre.org/data/definitions/{finding.cwe}.html")
    return refs


def a01_standards_text(finding) -> str:
    """A01 scope plus the official OWASP category of each listed CWE (never invented: both come from the registry/standards)."""
    if not finding.owasp_scope:
        return ""
    official = {}
    for c in finding.cwes:
        for cat in tags_for(c)["owasp_ids"]:
            official.setdefault(cat, []).append(f"CWE-{c}")
    parts = [f"{cat}: {', '.join(cs)}" for cat, cs in sorted(official.items())]
    return f"{finding.owasp_scope}:2025 access-control scope (official mapping of the rule's CWEs: {'; '.join(parts)})"


def affected_text(finding, limit: int = 8) -> str:
    items = [f"{a.get('method', '')} {a.get('path', '')} ({a.get('file', '')}:{a.get('line', '')})".strip() for a in finding.affected]
    more = f"; +{len(items) - limit} more" if len(items) > limit else ""
    return "; ".join(items[:limit]) + more


def finding_fields(finding) -> list:
    """(label, value) pairs shown in the detail table for one finding."""
    rows = [("Severity", finding.severity.capitalize()), ("Confidence", finding.confidence.capitalize()),
            ("Location", f"{finding.file}:{finding.line}")]
    if finding.rule_id.startswith("A01-"):
        rows.insert(0, ("Rule", finding.rule_id))
        rows.insert(2, ("Status", finding.status or "n/a"))
        rows.append(("CWE(s)", ", ".join(f"CWE-{c}" for c in finding.cwes) or f"CWE-{finding.cwe}"))
        rows.append(("OWASP", a01_standards_text(finding)))
        if finding.impact:
            rows.append(("Impact", finding.impact))
        if finding.affected:
            rows.append((f"Affected ({len(finding.affected)})", affected_text(finding)))
        if finding.evidence:
            rows.append(("Evidence verified", "yes: quoted line exists in the file" if finding.evidence_verified else "no"))
        for sup in finding.supporting[:3]:
            rows.append(("Supporting", f"{sup.get('type')}: {sup.get('file')}:{sup.get('line')}  {sup.get('evidence', '')}"))
    if finding.cwe and not finding.rule_id.startswith("A01-"):
        rows.append(("Weakness", f"CWE-{finding.cwe} {CWE_CATALOG.get(finding.cwe, '')}".strip()))
    tag = standards_label(finding.cwe)
    if tag and not finding.rule_id.startswith("A01-"):
        rows.append(("Standards", tag))
    rows.append(("Validation", validation_status(finding)))
    if finding.triage and finding.triage.get("reason"):
        rows.append(("AI reasoning", finding.triage["reason"]))
    return rows


def confidentiality_text(eng, application: str) -> str:
    who = eng.client or "the named recipient"
    who += "" if who.endswith(".") else "."
    return (f"This document is classified {eng.classification.upper()}. It contains information about security "
            f"weaknesses in {application} and is intended only for {who} Do not copy or distribute it without "
            "permission.")


def tool_line(agent_author: str = "") -> str:
    return "VulnAgent" + (f", developed by {agent_author}" if agent_author else "")


def a01_coverage_rows(report) -> list:
    """(label, value) rows for the access-control coverage section."""
    a = getattr(report, "a01", None)
    if not a:
        return []
    gs = a["global_security"]
    langs = ", ".join(f"{k} ({v})" for k, v in sorted(a["languages"].items())) or "none"
    rows = [("Languages detected", langs),
            ("Frameworks detected", ", ".join(a["frameworks"]) or "none recognised"),
            ("Extractors used", "; ".join(a["extractors_used"]) or "none"),
            ("Entry points found", str(a["entry_points"])),
            ("Guards found", str(a["guards_found"])),
            ("Data models found", str(a["models_found"])),
            ("Files parsed / failed / skipped", f"{a['files_parsed']} / {len(a['files_failed'])} / {len(a['files_skipped'])}"),
            ("Global security configuration", ("found: " + "; ".join(gs["notes"])) if gs["found"] and gs["notes"] else
             "found" if gs["found"] else "NOT found (no deny-by-default or default-authentication setting was detected)")]
    if gs.get("csrf_disabled"):
        rows.append(("CSRF explicitly disabled at", ", ".join(gs["csrf_disabled"])))
    if gs.get("default_allow_all"):
        rows.append(("Default access policy", "allow-all (permit-all / AllowAny)"))
    if a["not_analysed"]:
        rows.append(("NOT analysed", "; ".join(f"{k}: {v}" for k, v in a["not_analysed"].items())))
    if a.get("superseded_legacy_findings"):
        rows.append(("Legacy findings superseded", f"{a['superseded_legacy_findings']} (replaced by the more precise A01 findings)"))
    for w in a["warnings"][:5]:
        rows.append(("Warning", w))
    return rows


MATRIX_HEADERS = ["Method", "Path", "Authentication", "Role check", "Ownership", "CSRF", "Handler", "Location"]


def a01_matrix(report, limit: int = 400) -> tuple:
    a = getattr(report, "a01", None)
    if not a:
        return MATRIX_HEADERS, [], 0
    rows = [[r["method"], r["path"], r["authentication"], r["role_check"], r["ownership_check"], r["csrf"], r["handler"], r["location"]]
            for r in a["matrix"]]
    return MATRIX_HEADERS, rows[:limit], max(0, len(rows) - limit)
