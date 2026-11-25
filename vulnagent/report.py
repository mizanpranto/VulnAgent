"""Report writers: Markdown, JSON and SARIF 2.1.0 (PDF lives in pdf_report.py).

Fields that have no value are omitted, never printed as "Not provided", and
absolute paths from the scanning machine are never written.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import __version__
from . import reportdoc
from .models import CWE_CATALOG, cwe_label
from .standards import OWASP_YEAR, TOP25_YEAR, label as standards_label, tags_for

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
ORIGIN_LABEL = {"taint": "taint analysis", "regex": "pattern rule", "semgrep": "Semgrep",
                "llm-discovery": "AI discovery (verified)", "dependency": "OSV advisory database",
                "a01": "access-control model (A01)"}


def sarif_tags(cwe) -> list:
    tags = tags_for(cwe)
    out = [f"external/owasp/{OWASP_YEAR}/{i}" for i in tags["owasp_ids"]]
    if tags["cwe_top25_rank"]:
        out.append(f"external/cwe/top25-{TOP25_YEAR}")
    return out


def _fence(text: str) -> str:
    return (text or "").replace("```", "'''")


def _origins(finding) -> str:
    return ", ".join(ORIGIN_LABEL.get(o, o) for o in finding.origins) or "n/a"


def _a01_finding_md(finding) -> list:
    lines = [f"- **Rule:** `{finding.rule_id}`  ·  **Status:** {finding.status or 'n/a'}",
             f"- **CWE(s):** {', '.join(f'CWE-{c}' for c in finding.cwes) or finding.cwe}",
             f"- **OWASP:** {reportdoc.a01_standards_text(finding)}"]
    if finding.impact:
        lines.append(f"- **Impact:** {finding.impact}")
    if finding.affected:
        lines.append(f"- **Affected entry points ({len(finding.affected)}):** {reportdoc.affected_text(finding)}")
    for sup in finding.supporting[:3]:
        lines.append(f"- **Supporting evidence:** {sup.get('type')} at `{sup.get('file')}:{sup.get('line')}`")
    return lines


def _finding_md(index: int, finding) -> list:
    lines = [f"### {index}. {finding.title}", "",
             f"- **Severity:** {finding.severity}  ·  **Confidence:** {finding.confidence}",
             f"- **Location:** `{finding.file}:{finding.line}`",
             f"- **Weakness:** {cwe_label(finding.cwe)}",
             f"- **Detected by:** {_origins(finding)}"]
    if finding.rule_id.startswith("A01-"):
        lines += _a01_finding_md(finding)
        lines = [l for l in lines if not l.startswith("- **Weakness:**")]
    elif standards_label(finding.cwe):
        lines.insert(5, f"- **Standards:** {standards_label(finding.cwe)}")
    if finding.triage:
        verdict = finding.triage.get("verdict", "").replace("_", " ")
        reason = finding.triage.get("reason", "")
        lines.append(f"- **AI triage:** {verdict}" + (f" — {reason}" if reason else ""))
        if finding.triage.get("note"):
            lines.append(f"- **Triage note:** {finding.triage['note']}")
    lines.append("")
    if finding.evidence:
        lines += ["```", _fence(finding.evidence), "```", ""]
    if finding.data_flow:
        lines.append("**Data flow**")
        lines += [f"{n}. {step}" for n, step in enumerate(finding.data_flow, 1)]
        lines.append("")
    if finding.explanation:
        lines += [f"**Why it matters:** {finding.explanation}", ""]
    if finding.fix:
        lines += [f"**Fix:** {finding.fix}", ""]
    if finding.safe_example:
        lines += ["```", _fence(finding.safe_example), "```", ""]
    return lines


def render_markdown(report) -> str:
    stats, meta = report.stats, report.meta
    eng = report.engagement
    lines = [f"# VulnAgent security report — {(eng.application if eng and eng.application else report.project)}", ""]
    if eng:
        cover = [("Prepared for", eng.client), ("Assessed by", ", ".join(x for x in (eng.assessor, eng.company) if x)),
                 ("Reviewed by", eng.reviewer), ("Date", eng.resolved_date()), ("Version", eng.version),
                 ("Classification", eng.classification)]
        lines += [f"**{k}:** {v}  " for k, v in cover if v] + [""]
    lines += [
             f"Generated {meta.get('started_at', '')} by VulnAgent "
             f"in {meta.get('duration_seconds', 0)} s. "
             "Automated analysis: validate findings manually before acting on them.", "",
             "## Summary", "",
             "| Severity | Findings |", "|---|---|"]
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {severity.capitalize()} | {stats['severity'].get(severity, 0)} |")
    lines += ["", f"**{stats['total']}** active finding(s) across **{stats['files']}** file(s) "
                  f"({stats['lines']} lines). "
                  + (f"{stats['dismissed']} finding(s) were dismissed by AI triage and are listed separately. "
                     if stats["dismissed"] else "")
                  + f"Languages: {', '.join(f'{k} ({v})' for k, v in stats['languages'].items()) or 'none'}.", ""]
    if stats.get("owasp"):
        lines += [f"**OWASP Top 10:{OWASP_YEAR} coverage**", "", "| Category | Findings |", "|---|---|"]
        lines += [f"| {r['id']} {r['name']} | {r['count']} |" for r in stats["owasp"]]
        lines += ["", f"{stats.get('top25', 0)} finding(s) are in the CWE Top 25 ({TOP25_YEAR}).", ""]
    for note in report.notes:
        lines.append(f"> {note}")
    if report.notes:
        lines.append("")
    llm = meta.get("llm_stages") or []
    lines += ["**How this was produced:** deterministic taint/pattern analysis"
              + (" + Semgrep" if meta.get("semgrep") else "")
              + (f" + AI {', '.join(llm)} with `{meta.get('model')}`" if llm else " (no AI stage ran)") + ".", ""]

    lines += ["## Findings", ""]
    if not report.active:
        lines += ["No findings were reported.", ""]
    for index, finding in enumerate(report.active, 1):
        lines += _finding_md(index, finding)
    if report.dismissed:
        lines += ["## Dismissed by AI triage", "",
                  "These were reported by the analyzer but judged false positives by the model. "
                  "They are kept here so a human can overrule the model.", ""]
        for index, finding in enumerate(report.dismissed, 1):
            lines += _finding_md(index, finding)
    if getattr(report, "a01", None):
        lines += ["## Access-control coverage (OWASP A01)", "", "| | |", "|---|---|"]
        lines += [f"| {k} | {str(v).replace('|', '/')} |" for k, v in reportdoc.a01_coverage_rows(report)]
        headers, rows, hidden = reportdoc.a01_matrix(report)
        lines += ["", "## Entry-point authorization matrix", "", "| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
        lines += ["| " + " | ".join(str(c).replace("|", "/") for c in r) + " |" for r in rows]
        if hidden:
            lines.append(f"\n{hidden} more entry point(s) are listed in the JSON report.")
        lines.append("")
    lines += ["## Scope and limitations", ""] + [f"- {l}" for l in reportdoc.limitations(report)] + [""]
    return "\n".join(lines)


def to_sarif(report) -> dict:
    rules, rule_index, results = [], {}, []
    for finding in report.findings:
        rule_id = f"CWE-{finding.cwe}" if finding.cwe else (finding.rule_id or "vulnagent")
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "name": CWE_CATALOG.get(finding.cwe, finding.title)[:80] if finding.cwe else finding.title[:80],
                "shortDescription": {"text": CWE_CATALOG.get(finding.cwe, finding.title)},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{finding.cwe}.html" if finding.cwe else None,
            })
            if rules[-1]["helpUri"] is None:
                del rules[-1]["helpUri"]
        result = {
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": SARIF_LEVEL.get(finding.severity, "warning"),
            "message": {"text": finding.title + (f" — {finding.explanation}" if finding.explanation else "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": finding.file},
                "region": {"startLine": max(1, finding.line),
                           "snippet": {"text": finding.evidence}}}}],
            "properties": {"severity": finding.severity, "confidence": finding.confidence,
                           "origins": finding.origins, "triage": finding.triage,
                           "tags": sarif_tags(finding.cwe)},
        }
        if finding.data_flow:
            result["codeFlows"] = [{"threadFlows": [{"locations": [
                {"message": {"text": step}} for step in finding.data_flow]}]}]
        if finding.dismissed:
            result["suppressions"] = [{"kind": "external", "status": "underReview",
                                       "justification": (finding.triage or {}).get("reason", "AI triage")}]
        results.append(result)
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "VulnAgent", "version": __version__,
                            "informationUri": "https://github.com/", "rules": rules}},
        "results": results}]}


def write_markdown(report, destination) -> Path:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(report), encoding="utf-8")
    return path


def write_json(report, destination) -> Path:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return path


def write_sarif(report, destination) -> Path:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_sarif(report), indent=2), encoding="utf-8")
    return path
