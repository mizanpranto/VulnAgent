"""Language-neutral intermediate representation for access-control analysis.

Every extractor fills these structures; every rule reads only these structures,
so a rule is written once and works for every language/framework.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

GUARD_KINDS = ("authentication", "authorization", "ownership", "csrf", "rate_limit", "validation")
HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")


@dataclass
class ArgInfo:
    """What the extractor knows about one expression (argument, value, operand)."""
    text: str = ""
    taint: Optional[tuple] = None        # (kind, field, numeric) kind: body|query|params|headers|cookies|files|request
    identity: bool = False               # expression is the verified token/session identity
    literal: object = None
    has_literal: bool = False
    prefix: str = ""                     # leading string literal of a built string ("https://api.x/")
    keys: dict = field(default_factory=dict)   # object literal / keyword args: key -> ArgInfo
    origin: Optional[dict] = None        # {"model","op","projected","collection"} for DB results
    spread_taint: bool = False           # whole request body spread/bound into the value
    lead_known: bool = False             # True when lead_taint describes only the *first* part of a built string
    lead_taint: Optional[tuple] = None   # taint of the leading part (host position) of a built string
    line: int = 0


@dataclass
class CallRec:
    callee: str
    args: list
    line: int
    text: str = ""
    receiver_origin: Optional[dict] = None   # origin of the variable the method is called on
    single: bool = False                     # query chain ends in first()/one()/get(): a single-object lookup


@dataclass
class AssignRec:
    target: str
    value: ArgInfo
    line: int
    text: str = ""


@dataclass
class CompareRec:
    left: ArgInfo
    right: ArgInfo
    op: str
    line: int
    text: str = ""


@dataclass
class ResponseRec:
    kind: str            # json | send | redirect | render | return
    arg: ArgInfo
    status: Optional[int]
    line: int


@dataclass
class HandlerFacts:
    calls: list = field(default_factory=list)
    assigns: list = field(default_factory=list)
    compares: list = field(default_factory=list)
    responses: list = field(default_factory=list)
    reads: dict = field(default_factory=dict)          # kind -> sorted field names
    uses_identity: bool = False
    authn_inline: bool = False                         # handler itself rejects anonymous callers
    role_check_inline: bool = False
    ownership_check_inline: bool = False
    checked_texts: set = field(default_factory=set)    # operands seen in validation conditions
    contained_paths: bool = False                      # base-directory containment check present
    deny_statuses: set = field(default_factory=set)
    parsed: bool = True


@dataclass
class Guard:
    name: str
    kind: str
    scope: str = "route"                 # route | controller | router | global
    certainty: str = "name"              # code | name
    fails_open: bool = False
    fail_open_reason: str = ""
    fail_open_line: int = 0
    identity_source: str = "unknown"     # verified | request | unknown
    identity_evidence: str = ""
    methods: Optional[set] = None        # None = all methods
    file: str = ""
    line: int = 0
    evidence: str = ""
    source: str = ""                     # trimmed guard source (for the LLM review)


@dataclass
class EntryPoint:
    kind: str = "HTTP"                   # HTTP | GraphQL | RPC | queue | job | CLI
    method: str = "GET"
    path: str = ""
    framework: str = ""
    handler: str = ""
    file: str = ""
    line: int = 0
    end_line: int = 0
    guards: list = field(default_factory=list)
    facts: HandlerFacts = field(default_factory=HandlerFacts)
    source: str = ""
    group: str = ""                      # router / controller identity, used for de-duplication
    notes: list = field(default_factory=list)      # e.g. "csrf_exempt", "registered_before_guard:<name>"
    handler_resolved: bool = True

    @property
    def id(self) -> str:
        return f"{self.method} {self.path} @ {self.file}:{self.line}"


@dataclass
class DataModel:
    name: str
    file: str
    line: int
    fields: list = field(default_factory=list)
    sensitive: list = field(default_factory=list)
    privileged: list = field(default_factory=list)


@dataclass
class Signal:
    """A configuration/code-level fact that does not need an entry point (CORS, chmod, ...)."""
    rule_id: str
    file: str
    line: int
    evidence: str
    cwe: Optional[int] = None
    severity: Optional[str] = None
    detail: str = ""
    confidence: Optional[str] = None
    extra: dict = field(default_factory=dict)


@dataclass
class Project:
    entry_points: list = field(default_factory=list)
    guards: list = field(default_factory=list)          # guard definitions found
    models: list = field(default_factory=list)
    signals: list = field(default_factory=list)
    frameworks: set = field(default_factory=set)
    files_parsed: list = field(default_factory=list)
    files_failed: list = field(default_factory=list)    # (path, reason)
    files_skipped: list = field(default_factory=list)   # (path, reason)
    warnings: list = field(default_factory=list)
    unsupported: dict = field(default_factory=dict)     # language -> file count
    partial: dict = field(default_factory=dict)         # language -> note (extractor is a skeleton)
    extractors_used: list = field(default_factory=list)
    global_security: dict = field(default_factory=lambda: {
        "found": False, "notes": [], "default_authn": None, "default_allow_all": False,
        "csrf_default": {}, "csrf_disabled": []})
    cookie_auth: bool = False
    all_paths: list = field(default_factory=list)
    samesite_configured: bool = False
    client_checks: list = field(default_factory=list)   # (file, line, evidence, urls)
    side_by_file: dict = field(default_factory=dict)
    static_dirs: list = field(default_factory=list)
    global_guards: list = field(default_factory=list)   # extractor-supplied app-wide guards (per framework)
