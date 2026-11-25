"""Shared data model: findings, severities and a small CWE catalog.

Every stage of the pipeline (static analysis, Semgrep, LLM discovery, LLM
triage, reporting) reads and writes ``Finding`` objects, so a single schema
drives the prompt, the validator and the reports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Optional

SCHEMA_VERSION = "2.1"

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
CONFIDENCES = ["low", "medium", "high"]

# CWE ids VulnAgent knows about. LLM output that names any other id is
# discarded instead of being trusted (an earlier version let the model tag an
# IDOR as CWE-621, which is a different weakness).
CWE_CATALOG = {
    20: "Improper Input Validation",
    22: "Path Traversal",
    23: "Relative Path Traversal",
    36: "Absolute Path Traversal",
    78: "OS Command Injection",
    79: "Cross-site Scripting",
    89: "SQL Injection",
    94: "Code Injection",
    95: "Eval Injection",
    200: "Exposure of Sensitive Information",
    201: "Insertion of Sensitive Information Into Sent Data",
    209: "Error Message Containing Sensitive Information",
    266: "Incorrect Privilege Assignment",
    269: "Improper Privilege Management",
    276: "Incorrect Default Permissions",
    284: "Improper Access Control",
    285: "Improper Authorization",
    295: "Improper Certificate Validation",
    306: "Missing Authentication for Critical Function",
    327: "Use of a Broken or Risky Cryptographic Algorithm",
    347: "Improper Verification of Cryptographic Signature",
    330: "Use of Insufficiently Random Values",
    338: "Use of Cryptographically Weak PRNG",
    352: "Cross-Site Request Forgery",
    359: "Exposure of Private Personal Information to an Unauthorized Actor",
    377: "Insecure Temporary File",
    400: "Uncontrolled Resource Consumption",
    434: "Unrestricted Upload of File with Dangerous Type",
    489: "Active Debug Code",
    502: "Deserialization of Untrusted Data",
    521: "Weak Password Requirements",
    532: "Insertion of Sensitive Information into Log File",
    538: "Insertion of Sensitive Information into Externally-Accessible File or Directory",
    540: "Inclusion of Sensitive Information in Source Code",
    548: "Exposure of Information Through Directory Listing",
    552: "Files or Directories Accessible to External Parties",
    602: "Client-Side Enforcement of Server-Side Security",
    613: "Insufficient Session Expiration",
    636: "Not Failing Securely ('Failing Open')",
    601: "Open Redirect",
    611: "XML External Entity Reference",
    639: "Authorization Bypass Through User-Controlled Key",
    668: "Exposure of Resource to Wrong Sphere",
    732: "Incorrect Permission Assignment for Critical Resource",
    798: "Use of Hard-coded Credentials",
    862: "Missing Authorization",
    863: "Incorrect Authorization",
    915: "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    922: "Insecure Storage of Sensitive Information",
    942: "Permissive Cross-domain Policy with Untrusted Domains",
    916: "Password Hash With Insufficient Computational Effort",
    918: "Server-Side Request Forgery",
    1004: "Sensitive Cookie Without HttpOnly Flag",
    1333: "Inefficient Regular Expression Complexity",
    1336: "Improper Neutralization of Special Elements in a Template Engine",
    1395: "Dependency on Vulnerable Third-Party Component",
    1427: "Improper Neutralization of Input Used for LLM Prompting",
}

# Used to repair a missing/invalid CWE from an LLM-provided title.
TITLE_TO_CWE = [
    (r"sql", 89),
    (r"command|shell injection|os command", 78),
    (r"path traversal|directory traversal|file inclusion", 22),
    (r"template", 1336),
    (r"xss|cross.?site script", 79),
    (r"deserializ|pickle|unpickl", 502),
    (r"ssrf|server.?side request", 918),
    (r"open redirect|unvalidated redirect", 601),
    (r"idor|direct object|user-controlled key", 639),
    (r"missing auth|unauthenticated|missing access control|missing authorization", 862),
    (r"hard.?coded|embedded (secret|credential|password)", 798),
    (r"weak (password )?hash|unsalted|md5|sha-?1", 916),
    (r"random", 338),
    (r"jwt|signature", 347),
    (r"xxe|xml external", 611),
    (r"tls|ssl|certificate", 295),
    (r"debug", 489),
    (r"redos|regular expression|regex", 1333),
    (r"upload", 434),
    (r"temp(orary)? file", 377),
    (r"permission|chmod", 732),
    (r"log", 532),
    (r"eval|code execution|code injection", 95),
    (r"resource consumption|denial of service|dos\b", 400),
    (r"information (exposure|disclosure)|sensitive (data|information)|leak", 200),
    (r"error message|stack trace|exception detail", 209),
    (r"prompt injection", 1427),
]


def normalize_cwe(value, title: str = "") -> Optional[int]:
    """Return a catalog CWE id (int) or None.

    Accepts ``"CWE-89"``, ``"89"``, ``89``. Ids outside the catalog are
    replaced by a title-based guess, otherwise dropped.
    """
    number = None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        match = re.search(r"(\d{1,5})", value)
        if match:
            number = int(match.group(1))
    if number in CWE_CATALOG:
        return number
    lowered = (title or "").lower()
    for pattern, cwe in TITLE_TO_CWE:
        if re.search(pattern, lowered):
            return cwe
    return None


def cwe_label(cwe: Optional[int]) -> str:
    if cwe is None:
        return "n/a"
    return f"CWE-{cwe} ({CWE_CATALOG.get(cwe, 'unknown')})"


@dataclass
class Finding:
    title: str
    severity: str
    file: str
    line: int
    cwe: Optional[int] = None
    confidence: str = "medium"
    evidence: str = ""
    explanation: str = ""
    # Where untrusted data enters and where it is used (filled by taint analysis
    # or by the LLM, but only ever displayed, never trusted for location).
    source: str = ""
    sink: str = ""
    data_flow: list = field(default_factory=list)
    fix: str = ""
    safe_example: str = ""
    # Which engines reported it: "taint", "regex", "semgrep", "llm-discovery".
    origins: list = field(default_factory=list)
    rule_id: str = ""
    # AI triage result: {"verdict": confirmed|false_positive|uncertain,
    #                    "reason": str, "steps": int}
    triage: Optional[dict] = None
    # True when the AI triage dismissed it. Deterministic findings are never
    # deleted, only labelled, so a manipulated model cannot hide them.
    dismissed: bool = False
    # --- access-control (A01) layer; all optional so older stages are unaffected ---
    cwes: list = field(default_factory=list)       # every CWE the rule lists (cwe stays the headline one)
    owasp_scope: str = ""                          # e.g. "A01": the category this rule belongs to (from the registry)
    status: str = ""                               # confirmed | likely | needs-review
    side: str = ""                                 # server | client | config | infra
    impact: str = ""
    affected: list = field(default_factory=list)   # [{"method","path","file","line","handler"}]
    supporting: list = field(default_factory=list) # supporting evidence, e.g. client-side checks
    evidence_verified: bool = False

    def to_dict(self) -> dict:
        data = asdict(self)
        data["cwe_id"] = f"CWE-{self.cwe}" if self.cwe else None
        data["cwe_name"] = CWE_CATALOG.get(self.cwe) if self.cwe else None
        from .standards import tags_for
        tags = tags_for(self.cwe)
        data["owasp"] = tags["owasp"]
        data["cwe_top25_rank"] = tags["cwe_top25_rank"]
        data["fix_example"] = self.safe_example
        if self.cwes:
            data["cwe_ids"] = [f"CWE-{c}" for c in self.cwes]
            data["official_owasp_by_cwe"] = {f"CWE-{c}": tags_for(c)["owasp"] for c in self.cwes}
        return data

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)


def clamp_severity(value, default="medium") -> str:
    value = str(value or "").strip().lower()
    return value if value in SEVERITY_RANK else default


def clamp_confidence(value, default="medium") -> str:
    value = str(value or "").strip().lower()
    return value if value in CONFIDENCES else default
