"""Single source of truth for A01 rules: CWE, OWASP category, severity, text.

CWE ids, severities and categories come from ``rules.json`` and the official
mapping in ``vulnagent.standards``; neither the LLM nor the extractors choose them.
A rule may list CWEs that the official OWASP list files under another category
(for example CWE-942 under A02). The headline CWE of a rule is the first one the
official A01:2025 list contains, so the finding's standards tag is honest, and
``owasp_scope`` records that the rule belongs to this assessment's A01 scope.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..models import CWE_CATALOG, SEVERITY_RANK
from ..standards import owasp_categories

SIDES = {"server", "client", "config", "infra"}
EVIDENCE_KINDS = {"presence", "heuristic", "absence"}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    cwes: tuple
    severity: str
    side: str
    languages: tuple
    evidence_kind: str
    description: str
    impact: str
    remediation: str
    fix_example: str
    false_positive_guards: tuple
    owasp: str = "A01"

    @property
    def headline_cwe(self) -> int:
        for cwe in self.cwes:
            if "A01" in owasp_categories(cwe):
                return cwe
        return self.cwes[0]

    @property
    def official_owasp(self) -> dict:
        return {c: owasp_categories(c) for c in self.cwes}


def load_rules(path=None) -> dict:
    data = json.loads(Path(path or Path(__file__).with_name("rules.json")).read_text(encoding="utf-8"))
    rules = {}
    for raw in data:
        rule = Rule(rule_id=raw["rule_id"], title=raw["title"], cwes=tuple(raw["cwes"]), severity=raw["severity"],
                    side=raw["side"], languages=tuple(raw.get("languages", ["*"])), evidence_kind=raw["evidence_kind"],
                    description=raw["description"], impact=raw["impact"], remediation=raw["remediation"],
                    fix_example=raw["fix_example"], false_positive_guards=tuple(raw.get("false_positive_guards", [])))
        validate(rule)
        rules[rule.rule_id] = rule
    return rules


def validate(rule: Rule) -> None:
    unknown = [c for c in rule.cwes if c not in CWE_CATALOG]
    if unknown:
        raise ValueError(f"{rule.rule_id}: CWE(s) {unknown} are not in the CWE catalog")
    if rule.severity not in SEVERITY_RANK:
        raise ValueError(f"{rule.rule_id}: bad severity")
    if rule.side not in SIDES or rule.evidence_kind not in EVIDENCE_KINDS:
        raise ValueError(f"{rule.rule_id}: bad side/evidence_kind")
    if not rule.fix_example.strip():
        raise ValueError(f"{rule.rule_id}: fix_example is required")


RULES = load_rules()


def get(rule_id: str) -> Rule:
    return RULES[rule_id]
