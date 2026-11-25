"""Deterministic verification of findings.

LLM output is treated as a *claim*. Before a claim becomes a finding it must be
grounded in the real source: the quoted evidence has to exist in the file, and
the reported line number is recomputed from that evidence instead of trusted.
(The first version let the model report line numbers directly; 8 of 9 were
wrong on the project's own test app.)
"""

from __future__ import annotations

import re
from typing import Optional

from .models import (Finding, SEVERITY_RANK, clamp_confidence, clamp_severity,
                     normalize_cwe)


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def _resolve_path(claimed: str, files_by_path: dict) -> Optional[str]:
    claimed = (claimed or "").strip().replace("\\", "/").lstrip("./")
    if claimed in files_by_path:
        return claimed
    matches = [p for p in files_by_path if p.endswith("/" + claimed) or p == claimed
               or p.rsplit("/", 1)[-1] == claimed.rsplit("/", 1)[-1]]
    return matches[0] if len(matches) == 1 else None


def ground_finding(finding: Finding, files_by_path: dict):
    """Return ``(finding | None, reason)``.

    ``files_by_path`` maps relative path -> file content (str).
    """
    path = _resolve_path(finding.file, files_by_path)
    if path is None:
        return None, f"file not found: {finding.file!r}"
    lines = files_by_path[path].splitlines()
    evidence_lines = [_norm(l) for l in (finding.evidence or "").splitlines() if len(_norm(l)) >= 6]
    if not evidence_lines:
        return None, "no usable evidence quoted"
    claimed = finding.line if isinstance(finding.line, int) else 0
    best = None
    for needle in evidence_lines:
        for index, line in enumerate(lines, 1):
            hay = _norm(line)
            if hay and (needle in hay or (len(hay) >= 12 and hay in needle)):
                distance = abs(index - claimed) if claimed else 0
                if best is None or distance < best[0]:
                    best = (distance, index)
        if best is not None:
            break
    if best is None:
        return None, "evidence not found in file (possible hallucination)"
    finding.file, finding.line = path, best[1]
    finding.evidence = lines[best[1] - 1].strip()[:300]
    return finding, "grounded"


def finding_from_llm(raw: dict, origin: str = "llm-discovery") -> Optional[Finding]:
    """Build a ``Finding`` from untrusted model JSON, with every field clamped."""
    if not isinstance(raw, dict):
        return None
    title = str(raw.get("title") or "").strip()[:160]
    if not title:
        return None
    try:
        line = int(raw.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    flow = raw.get("data_flow") or raw.get("attack_path") or []
    if isinstance(flow, str):
        flow = [flow]
    return Finding(
        title=title,
        severity=clamp_severity(raw.get("severity")),
        confidence=clamp_confidence(raw.get("confidence"), "low"),
        file=str(raw.get("file") or ""),
        line=line,
        cwe=normalize_cwe(raw.get("cwe"), title),
        evidence=str(raw.get("evidence") or "")[:600],
        explanation=str(raw.get("explanation") or "")[:1200],
        source=str(raw.get("source") or "")[:300],
        sink=str(raw.get("sink") or "")[:300],
        data_flow=[str(x)[:300] for x in flow][:8] if isinstance(flow, list) else [],
        fix=str(raw.get("fix") or "")[:800],
        safe_example=str(raw.get("safe_example") or "")[:1200],
        origins=[origin],
        rule_id="llm",
    )


def dedupe_and_merge(findings: list, line_window: int = 4) -> list:
    """Merge findings about the same weakness at (nearly) the same place."""
    ordered = sorted(findings, key=lambda f: (f.file, f.cwe or 0, f.title, f.line))
    merged: list = []
    for finding in ordered:
        target = None
        for existing in reversed(merged):
            if existing.file != finding.file:
                break
            same_kind = (existing.cwe == finding.cwe and finding.cwe is not None) or \
                        (finding.cwe is None and existing.title == finding.title)
            distance = abs(existing.line - finding.line)
            # Same line always merges. Nearby lines merge only when one side is an
            # AI-suggested finding (e.g. the model points at the f-string line while
            # the analyzer points at the execute() line). Two deterministic findings
            # on different lines are distinct issues (e.g. three hard-coded secrets
            # on consecutive lines).
            ai_involved = "llm-discovery" in existing.origins or "llm-discovery" in finding.origins
            if same_kind and (distance == 0 or (ai_involved and distance <= line_window)):
                target = existing
                break
        if target is None:
            merged.append(finding)
            continue
        _merge_into(target, finding)
    merged.sort(key=lambda f: (-f.rank, f.file, f.line))
    return merged


def _merge_into(target: Finding, other: Finding) -> None:
    if other.rank > target.rank:
        target.severity = other.severity
    for origin in other.origins:
        if origin not in target.origins:
            target.origins.append(origin)
    # Prefer the evidence-rich deterministic record, fill gaps from the other.
    for attribute in ("explanation", "fix", "safe_example", "source", "sink", "evidence"):
        if not getattr(target, attribute) and getattr(other, attribute):
            setattr(target, attribute, getattr(other, attribute))
    if len(other.data_flow) > len(target.data_flow):
        target.data_flow = other.data_flow
    if "taint" in other.origins and "taint" not in target.origins:
        target.title = other.title
    if len(target.origins) >= 2 or "taint" in target.origins:
        target.confidence = "high"
    if other.rule_id and other.rule_id not in (target.rule_id or ""):
        target.rule_id = f"{target.rule_id},{other.rule_id}".strip(",")


def summarize(findings: list) -> dict:
    counts = {name: 0 for name in SEVERITY_RANK}
    for finding in findings:
        if not finding.dismissed:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts
