"""Merge A01 findings into the legacy pipeline findings without double reporting."""

from __future__ import annotations

# legacy rule id -> A01 rule ids that supersede it (when A01 modelled the surrounding entry point)
SUPERSEDES = {
    "missing-authz": {"A01-AUTHN-MISSING", "A01-AUTHZ-MISSING"},
    "idor": {"A01-IDOR"},
    "client-authz": {"A01-IDENTITY-FROM-REQUEST", "A01-IDOR"},
    "ssrf": {"A01-SSRF"},
    "path-traversal": {"A01-PATH-TRAVERSAL"},
    "open-redirect": {"A01-OPEN-REDIRECT"},
    "chmod-world-writable": {"A01-INSECURE-DEFAULTS"},
}


def merge_a01(legacy: list, result) -> tuple:
    """Return (merged findings, number of superseded legacy findings).

    A legacy finding is dropped only when the A01 layer parsed the same handler (an entry point's line span contains
    it): the entry-point model is more precise (guards, allow-lists, ownership filters). Legacy findings outside any
    modelled handler stay, so recall never drops for code the A01 layer did not understand.
    """
    spans = {}
    for file, start, end in result.spans:
        spans.setdefault(file, []).append((start, end))
    a01_locations = {}
    for nf in result.findings:
        for loc in [(nf.file, nf.line)] + [(a.get("file"), a.get("line")) for a in nf.affected]:
            a01_locations.setdefault(loc, set()).add(nf.rule_id)
    kept, dropped = [], 0
    for f in legacy:
        if f.rule_id in SUPERSEDES and (any(a <= f.line <= b for a, b in spans.get(f.file, []))
                                         or a01_locations.get((f.file, f.line), set()) & SUPERSEDES[f.rule_id]):
            dropped += 1
            continue
        kept.append(f)
    return kept + list(result.findings), dropped
