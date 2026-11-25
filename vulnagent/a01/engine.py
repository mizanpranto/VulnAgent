"""Deterministic A01 rules over the language-neutral IR.

Rules never look at syntax; they read ``Project`` / ``EntryPoint`` / ``Guard`` records.
CWE, severity base, text and fix example come from the registry, not from this file.
"""

from __future__ import annotations

import re
from collections import OrderedDict

from ..models import SEVERITIES, SEVERITY_RANK, Finding
from . import patterns as P
from .ir import ArgInfo, CallRec, EntryPoint, Guard, Project
from .plausibility import rule_applies
from .registry import RULES

PUBLIC_CATALOGUE = re.compile(r"(^|/)(products?|catalog(ue)?|items?|categories|category|posts?|articles?|books?|movies?|menu|"
                              r"blogs?|news|faq|pages?|brands?|tags?|courses?|recipes?|events?|listings?|reviews?)(/|$|\.)", re.I)
PUBLIC_MODEL = re.compile(r"^(products?|catalog(ue)?|items?|categor(y|ies)|posts?|articles?|books?|movies?|menu|blogs?|"
                          r"news|faq|pages?|brands?|tags?|courses?|recipes?|events?|listings?)$", re.I)
USERISH_MODEL = re.compile(r"(user|account|member|customer|order|payment|invoice|profile|employee|admin|person|patient|"
                           r"card|wallet|address|message|ticket|booking|subscription|session|token|credential)", re.I)
PAYMENT = re.compile(r"(pay|charge|refund|transfer|withdraw|checkout|purchase|billing|wallet|balance|credit)", re.I)
CREDENTIAL = re.compile(r"(password|passwd|credential|reset|2fa|mfa|otp|api[-_]?key|token|email|role|permission|privilege|grant|promote)", re.I)
DESTRUCTIVE = re.compile(r"^(delete|destroy|remove|drop|deleteOne|deleteMany|findByIdAndDelete|findOneAndDelete|findByIdAndRemove|deleteById|deleteAll|Remove|RemoveAsync|"
                         r"unlink|unlinkSync|rm|rmSync|rmdir|truncate|Delete)$")
SQL_WRITE = re.compile(r"^\s*(insert|update|delete|replace|drop|alter|truncate)\b", re.I)
HIDE_FIELDS = re.compile(r"(delete\s+\w+\.(password|hash|token|secret)|\.(password|passwd|hash|token|secret)\w*\s*=\s*(undefined|null|None)|"
                         r"\.toJSON\b|toObject\(\{[^}]*(transform|hide)|select\(\s*['\"]-|\.pop\(['\"](password|hash)|"
                         r"del\s+\w+\[['\"](password|hash)|exclude\s*=|exclude\(|only\(|values\(|serializer|Serializer|"
                         r"attributes\s*:\s*\{?\s*exclude|projection|\bomit\b|\bpick\b)", re.I)
ID_KEY = re.compile(r"^(_?id|pk|uuid|guid|\w+_?id|\w+Id|\w+_pk|slug|filename|number|ref)$", re.I)
STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE", "ANY"}


def _sev_max(a, b):
    return a if SEVERITY_RANK[a] >= SEVERITY_RANK[b] else b


def _down(sev, steps=1):
    return SEVERITIES[max(1, SEVERITY_RANK[sev] - steps)]


def _up(sev, steps=1):
    return SEVERITIES[min(len(SEVERITIES) - 1, SEVERITY_RANK[sev] + steps)]


class Engine:
    def __init__(self, project: Project, files: dict, config=None):
        self.p, self.files, self.cfg = project, files, config or {}
        self.lines_cache = {}
        self.cands = OrderedDict()
        self.public_extra = list(self.cfg.get("public_paths", []))
        self.lookups_by_ep = {}

    # ------------------------------------------------------------------ utilities
    def line_text(self, file, line):
        lines = self.lines_cache.get(file)
        if lines is None:
            lines = self.files.get(file, "").splitlines()
            self.lines_cache[file] = lines
        return lines[line - 1].strip() if 1 <= line <= len(lines) else ""

    def side(self, file):
        return self.p.side_by_file.get(file, "unknown")

    def eff_guards(self, ep: EntryPoint):
        gs = list(ep.guards) + list(self.p.global_guards)
        gs = [g for g in gs if g.methods is None or ep.method in g.methods or ep.method == "ANY"]
        gsec = self.p.global_security
        if gsec.get("default_authn") is True:
            gs.append(Guard(name="<global default authentication>", kind="authentication", scope="global", certainty="code",
                            identity_source="verified"))
        return gs

    def kinds(self, ep, kind):
        return [g for g in self.eff_guards(ep) if g.kind == kind]

    def authenticated(self, ep):
        return bool(self.kinds(ep, "authentication")) or ep.facts.authn_inline

    def is_public(self, ep):
        if "public_marker" in ep.notes:
            return True
        if not P.is_public_path(ep.path, self.public_extra):
            return False
        # A reset/recovery *request* is public, but changing a credential for a request-supplied account without any
        # proof of ownership (token/code/signature) is not a public flow.
        if re.search(r"reset|forgot|recover|change[-_]?password", ep.path + " " + ep.handler, re.I) and ep.facts.parsed:
            fields = " ".join(sum(ep.facts.reads.values(), [])).lower()
            wrote = bool(self.writes(ep))
            proof = re.search(r"token|code|otp|signature|sig|key|hash|nonce|secret", fields)
            if wrote and re.search(r"pass", fields) and not proof and not ep.facts.uses_identity:
                return False
        return True

    def is_write_call(self, c: CallRec) -> bool:
        if c.callee.startswith("new "):
            return False
        parts = c.callee.split(".")
        last = parts[-1]
        if parts[0] in ("res", "req", "reply", "response", "request", "ctx", "console", "logger", "Math", "JSON"):
            return False
        if re.match(r"^(fs|fsp|fse|fs\.promises|promises)\.", c.callee) and re.search(r"(write|append|unlink|rm|rename|copy|mkdir|remove|move|output)", last, re.I):
            return True
        if P.FS_PY.match(c.callee) and re.search(r"(remove|unlink|rmdir|rename|replace|makedirs|mkdir|rmtree|move|copy)", c.callee):
            return True
        if last in ("execute", "run", "query", "exec", "executemany", "raw", "Exec"):
            first = c.args[0] if c.args else None
            return bool(first and ((first.has_literal and isinstance(first.literal, str) and SQL_WRITE.match(first.literal))
                                   or SQL_WRITE.match(first.prefix or "") or SQL_WRITE.match((first.text or "").strip("`'\""))))
        if not P.WRITE_NAMES.match(last) or last in ("run", "execute", "query", "set", "add") and c.receiver_origin is None and len(parts) < 2:
            return False
        if c.receiver_origin is not None:
            return True
        if len(parts) >= 2 and P.MODELISH.match(".".join(parts[:-1])) and not P.NON_DB_RECEIVER.match(parts[0]):
            return last not in ("set", "add", "run", "get") or parts[-2] in ("session", "objects")
        return False

    def writes(self, ep):
        return [c for c in ep.facts.calls if self.is_write_call(c)]

    def info(self, ep):
        """Impact facts about an entry point."""
        f = ep.facts
        writes = self.writes(ep)
        deletes = [c for c in writes if DESTRUCTIVE.match(c.callee.split(".")[-1])]
        upload = "files" in f.reads
        text = " ".join([ep.path, ep.handler] + [c.callee for c in writes])
        field_text = " ".join(sum(f.reads.values(), [])) if f.reads else ""
        responses = [r for r in f.responses if r.arg is not None]
        models = []
        for r in responses:
            for a in [r.arg] + list(r.arg.keys.values()):
                if a.origin:
                    models.append(a.origin["model"])
        sens_model = next((m for m in models if self.model_sensitive(m)), None)
        user_model = next((m for m in models if USERISH_MODEL.search(m) and not PUBLIC_MODEL.match(m)), None)
        lookups = [c for c in f.calls if c.receiver_origin is None and P.LOOKUP_NAMES.match(c.callee.split(".")[-1])
                   and len(c.callee.split(".")) >= 2 and P.MODELISH.match(".".join(c.callee.split(".")[:-1]))
                   and not P.NON_DB_RECEIVER.match(c.callee.split(".")[0])]
        state_change = bool(writes) or upload or ep.method in ("PUT", "PATCH", "DELETE") or \
            (ep.method in ("POST", "ANY") and (not ep.handler_resolved))
        path_sensitive = bool(P.SENSITIVE_PATH.search(ep.path)) and not PUBLIC_CATALOGUE.search(ep.path)
        sensitive_read = (ep.method in ("GET", "HEAD", "ANY")) and ((sens_model or user_model) or
                                                                     (path_sensitive and (lookups or responses or not ep.handler_resolved)))
        return {"writes": writes, "deletes": deletes, "upload": upload, "state_change": state_change,
                "payment": bool(PAYMENT.search(text)) and bool(writes), "cred": bool(CREDENTIAL.search(text + " " + field_text)) and bool(writes),
                "adminlike": bool(P.ADMINLIKE_PATH.search(ep.path)), "sens_model": sens_model, "user_model": user_model,
                "sensitive_read": bool(sensitive_read), "lookups": lookups, "unresolved": not ep.handler_resolved}

    def model_by_name(self, name):
        n = (name or "").lower().rstrip("s")
        for m in self.p.models:
            if m.name.lower().rstrip("s") == n or n.endswith(m.name.lower().rstrip("s")) and len(m.name) > 3:
                return m
        return None

    def model_sensitive(self, name):
        m = self.model_by_name(name)
        return bool(m and m.sensitive)

    def affected(self, ep):
        return {"method": ep.method, "path": ep.path, "file": ep.file, "line": ep.line, "handler": ep.handler}

    # ------------------------------------------------------------------ candidate handling
    def emit(self, rule_id, file, line, *, ep=None, severity=None, confidence="medium", explanation="", cwe=None,
             source="", sink="", key=None, affected=None, supporting=None):
        rule = RULES[rule_id]
        if not rule_applies(rule, self.side(file)):
            return
        sev = severity or rule.severity
        if rule.evidence_kind == "absence" and confidence == "high":
            confidence = "medium"
        group = key if key is not None else (ep.group if ep is not None else file)
        k = (rule_id, group, cwe)
        entry = {"rule": rule, "file": file, "line": line, "sev": sev, "conf": confidence, "expl": explanation, "cwe": cwe,
                 "source": source, "sink": sink, "affected": [], "supporting": supporting or []}
        aff = affected if affected is not None else ([self.affected(ep)] if ep is not None else [])
        cur = self.cands.get(k)
        if cur is None:
            entry["affected"] = list(aff)
            self.cands[k] = entry
        else:
            for a in aff:
                if a not in cur["affected"]:
                    cur["affected"].append(a)
            if SEVERITY_RANK[sev] > SEVERITY_RANK[cur["sev"]]:
                for f_ in ("file", "line", "sev", "conf", "expl", "source", "sink"):
                    cur[f_] = entry[f_]
            cur["supporting"] += entry["supporting"]

    def to_findings(self):
        out = []
        for entry in self.cands.values():
            rule = entry["rule"]
            conf = entry["conf"]
            if rule.evidence_kind == "absence":
                status = "likely" if conf == "medium" else "needs-review"
            else:
                status = {"high": "confirmed", "medium": "likely", "low": "needs-review"}[conf]
            evidence = self.line_text(entry["file"], entry["line"])
            cwe = entry["cwe"] if entry["cwe"] in rule.cwes else rule.headline_cwe
            n = len(entry["affected"])
            title = rule.title + (f" ({n} entry points)" if n > 1 else "")
            f = Finding(title=title, severity=entry["sev"], file=entry["file"], line=entry["line"], cwe=cwe, confidence=conf,
                        evidence=evidence, explanation=entry["expl"], source=entry["source"], sink=entry["sink"],
                        fix=rule.remediation, safe_example=rule.fix_example, origins=["a01"], rule_id=rule.rule_id,
                        cwes=list(rule.cwes), owasp_scope=rule.owasp, status=status, side=rule.side, impact=rule.impact,
                        affected=entry["affected"], supporting=entry["supporting"], evidence_verified=bool(evidence))
            out.append(f)
        return out

    # ------------------------------------------------------------------ driver
    def run(self):
        for ep in self.p.entry_points:
            if self.side(ep.file) == "client":
                continue
            self.r_authn(ep)
            self.r_authz(ep)
            self.r_identity(ep)
            self.r_idor(ep)
            self.r_priv(ep)
            self.r_sinks(ep)
            self.r_csrf(ep)
            self.r_exposure(ep)
        self.r_authz_siblings()
        self.r_fail_open()
        self.r_coverage()
        self.r_signals()
        self.r_static_files()
        self.r_token_guards()
        self.r_client_only()
        return self.to_findings()

    # ------------------------------------------------------------------ R1 authentication
    def r_authn(self, ep):
        if self.authenticated(ep) or self.is_public(ep):
            return
        i = self.info(ep)
        if not (i["state_change"] or i["sensitive_read"]):
            return
        sev, why = None, []
        if i["deletes"]:
            sev, why = "critical", ["deletes data"]
        elif i["payment"]:
            sev, why = "critical", ["performs a payment/balance operation"]
        elif i["cred"] and i["writes"]:
            sev, why = "critical", ["changes credentials, roles or tokens"]
        elif i["adminlike"] and (i["state_change"] or i["sensitive_read"]):
            sev, why = ("critical" if i["state_change"] else "high"), ["is an admin/management path"]
        elif i["state_change"]:
            sev, why = "high", ["changes data" if i["writes"] else "changes state"]
            if i["upload"]:
                why = ["accepts file uploads"]
        else:
            sev = "high" if (i["sens_model"] or i["user_model"]) else "medium"
            why = ["returns user/order/payment/admin data" if sev == "high" else "returns data from a sensitive path"]
        if ep.method == "ANY" and not i["writes"]:
            sev = _down(sev)
        conf = "medium" if (ep.handler_resolved and (i["writes"] or i["sens_model"] or i["user_model"] or i["upload"])) else "low"
        if conf == "low":
            sev = _down(sev)
        guards_seen = bool(self.p.guards) or bool(self.p.global_guards)
        expl = (f"{ep.method} {ep.path} {', '.join(why)} and no authentication guard applies "
                f"({'global security configuration was found but does not enforce authentication' if self.p.global_security.get('found') else 'no global security configuration was found'}).")
        if not guards_seen:
            expl += " The project defines no authentication guard at all."
        self.emit("A01-AUTHN-MISSING", ep.file, ep.line, ep=ep, severity=sev, confidence=conf, explanation=expl,
                  cwe=306 if False else None, source="request", sink=ep.handler)

    # ------------------------------------------------------------------ R2 authorization
    def has_role_or_owner(self, ep):
        return bool(self.kinds(ep, "authorization") or self.kinds(ep, "ownership") or ep.facts.role_check_inline
                    or ep.facts.ownership_check_inline)

    def r_authz(self, ep):
        if not self.authenticated(ep) or self.has_role_or_owner(ep):
            return
        i = self.info(ep)
        if i["adminlike"] and (i["state_change"] or i["sensitive_read"] or i["unresolved"]):
            conf = "medium" if ep.handler_resolved else "low"
            self.emit("A01-AUTHZ-MISSING", ep.file, ep.line, ep=ep, severity="high" if conf == "medium" else "medium",
                      confidence=conf, source="session", sink=ep.handler,
                      explanation=f"{ep.method} {ep.path} looks like an administrative action but is reachable by any authenticated user: "
                                  "no role, permission or ownership check was found in its guards or handler.")

    def r_authz_siblings(self):
        groups = {}
        for ep in self.p.entry_points:
            groups.setdefault(ep.group, []).append(ep)
        for group, eps in groups.items():
            guarded = [e for e in eps if self.kinds(e, "authorization") and not self.is_public(e)]
            if not guarded or len(guarded) == len(eps):
                continue
            ref = guarded[0]
            for ep in eps:
                if ep in guarded or self.has_role_or_owner(ep) or self.is_public(ep) or not self.authenticated(ep):
                    continue
                i = self.info(ep)
                if i["state_change"] and (i["deletes"] or i["cred"] or i["adminlike"]):
                    self.emit("A01-AUTHZ-MISSING", ep.file, ep.line, ep=ep, severity="medium", confidence="medium",
                              key=f"sibling:{group}", source="session", sink=ep.handler,
                              explanation=f"{ep.method} {ep.path} changes data without the role check that sibling route "
                                          f"{ref.method} {ref.path} enforces ({self.kinds(ref, 'authorization')[0].name}).")

    # ------------------------------------------------------------------ R3 identity from request
    def r_identity(self, ep):
        f = ep.facts
        for c in f.calls:
            last = c.callee.split(".")[-1]
            if not (self.is_write_call(c) or P.LOOKUP_NAMES.match(last)) or c.callee.startswith(("res.", "req.")):
                continue
            for a in c.args:
                for key, v in self._flat(a):
                    if v.taint and v.taint[0] in ("body", "query", "headers", "cookies") and not v.taint[2] and \
                            P.IDENT_FIELD.match(v.taint[1] or "") and (P.OWNER_KEY.search(key or "") or not key or P.ROLE_FIELD.match(v.taint[1])):
                        if P.ROLE_FIELD.match(v.taint[1]) and PRIV_WRITE_KEY(key):  # handled by privilege rule
                            continue
                        self.emit("A01-IDENTITY-FROM-REQUEST", ep.file, c.line, ep=ep, severity="high", confidence="high",
                                  explanation=f"The caller identity '{v.taint[1]}' is read from the request {v.taint[0]} and used in "
                                              f"{c.callee}() instead of the verified token/session identity.",
                                  source=f"request {v.taint[0]}.{v.taint[1]}", sink=c.callee, key=f"call:{ep.group}",
                                  cwe=285 if P.ROLE_FIELD.match(v.taint[1]) else 639)
        for cmp in f.compares:
            for a, b in ((cmp.left, cmp.right), (cmp.right, cmp.left)):
                if a.taint and a.taint[0] in ("body", "query", "headers", "cookies") and P.IDENT_FIELD.match(a.taint[1] or "") \
                        and (P.ROLE_FIELD.match(a.taint[1]) or (b.has_literal or b.identity)):
                    if P.ROLE_FIELD.match(a.taint[1]) or b.identity or re.search(r"owner|user|id", b.text, re.I):
                        sev = "critical" if P.ROLE_FIELD.match(a.taint[1]) else "high"
                        self.emit("A01-IDENTITY-FROM-REQUEST", ep.file, cmp.line, ep=ep, severity=sev, confidence="high",
                                  explanation=f"An authorization decision compares request-supplied '{a.taint[1]}' "
                                              f"({a.taint[0]}) instead of the verified identity.",
                                  source=f"request {a.taint[0]}.{a.taint[1]}", sink="authorization decision", key=f"cmp:{ep.group}",
                                  cwe=285 if P.ROLE_FIELD.match(a.taint[1]) else 639)

    def _flat(self, a: ArgInfo, depth=0):
        yield ("", a)
        if depth < 3:
            for k, v in a.keys.items():
                for kk, vv in self._flat(v, depth + 1):
                    yield (kk or k, vv)

    # ------------------------------------------------------------------ R4 IDOR
    def r_idor(self, ep):
        if self.is_public(ep) and not self.authenticated(ep):
            return
        if self.kinds(ep, "ownership") or ep.facts.ownership_check_inline or self.kinds(ep, "authorization") or ep.facts.role_check_inline:
            return
        self.r_idor_sql(ep)
        i = self.info(ep)
        calls = [c for c in ep.facts.calls if c.callee.split(".")[-1] and not c.callee.startswith(("res.", "req."))]
        for c in calls:
            last = c.callee.split(".")[-1]
            parts = c.callee.split(".")
            is_model_call = (len(parts) >= 2 and P.MODELISH.match(".".join(parts[:-1])) and not P.NON_DB_RECEIVER.match(parts[0])) or c.receiver_origin
            if not is_model_call or not (P.SINGLE_LOOKUP.match(last) or c.single or self.is_write_call(c)):
                continue
            if last in ("get", "delete", "update") and not (P.MODELISH.match(".".join(parts[:-1])) and parts[-2][:1].isupper() or
                                                            parts[-2] in ("objects", "query", "session") or c.receiver_origin):
                continue
            idarg, scoped = None, False
            for a in c.args:
                for key, v in self._flat(a):
                    if v.identity:
                        scoped = True
                    if v.taint and v.taint[0] in ("params", "query", "body") and not P.ROLE_FIELD.match(v.taint[1] or "") \
                            and not (key == "" and a.keys) and (key == "" and a is v or ID_KEY.match(key or "") or P.OWNER_KEY.search(key or "")):
                        if P.IDENT_FIELD.match(v.taint[1] or "") and v.taint[0] != "params":
                            continue  # reported as identity-from-request
                        idarg = idarg or (key, v)
            if idarg is None or scoped:
                continue
            model = parts[-2] if len(parts) >= 2 else ""
            if c.receiver_origin:
                model = c.receiver_origin["model"]
            readonly = not self.is_write_call(c)
            if readonly and (PUBLIC_MODEL.match(model) or PUBLIC_CATALOGUE.search(ep.path)) and not self.model_sensitive(model):
                continue
            if HIDE_OWNER_FILTER(c):
                continue
            sev = "high"
            if readonly and not (self.model_sensitive(model) or USERISH_MODEL.search(model + ep.path)):
                sev = "medium"
            if not self.authenticated(ep) and not readonly:
                sev = "critical"
            conf = "medium"
            self.emit("A01-IDOR", ep.file, c.line, ep=ep, severity=sev, confidence=conf,
                      explanation=f"{c.callee}() selects an object by '{idarg[1].taint[1]}' from the request {idarg[1].taint[0]} with no "
                                  "owner/tenant filter and no ownership check, so any caller can pass another user's id.",
                      source=f"request {idarg[1].taint[0]}.{idarg[1].taint[1]}", sink=c.callee)
            break

    def r_idor_sql(self, ep):
        """Raw SQL selecting/changing a row by a request-supplied id with no owner column bound to the verified identity."""
        i = self.info(ep)
        for c in ep.facts.calls:
            if c.callee.split(".")[-1] not in ("execute", "query", "run", "all", "get", "exec", "executemany", "raw", "fetchone"):
                continue
            if c.callee.startswith(("res.", "req.", "request.")) or not c.args:
                continue
            first = c.args[0]
            sql = first.literal if first.has_literal and isinstance(first.literal, str) else first.text
            if not re.match(r"^\s*[\"'`f]*\s*(select|update|delete)\b", sql, re.I) or not re.search(r"\bwhere\b", sql, re.I):
                continue
            if not re.search(r"\bwhere\b[^;]*?\b(\w*_?id|pk|uuid|guid)\b\s*=", sql, re.I):
                continue
            rest = c.args[1:] + ([first] if first.taint else [])
            tainted = next((a for a in rest if a.taint and a.taint[0] in ("params", "query", "body") and not P.ROLE_FIELD.match(a.taint[1] or "")), None)
            if tainted is None or any(a.identity for a in rest):
                continue
            if re.search(r"\b(user|owner|account|tenant|customer|author|created_?by)_?id\b\s*=", sql, re.I):
                continue
            write = bool(re.match(r"^\s*[\"'`f]*\s*(update|delete)\b", sql, re.I))
            sev = "critical" if (write and not self.authenticated(ep)) else "high" if (write or USERISH_MODEL.search(sql + ep.path)) else "medium"
            self.emit("A01-IDOR", ep.file, c.line, ep=ep, severity=sev, confidence="medium", source=f"request {tainted.taint[0]}.{tainted.taint[1]}",
                      sink=c.callee, explanation=f"The SQL statement selects/changes a row by '{tainted.taint[1]}' from the request {tainted.taint[0]} "
                                                 "with no owner/tenant condition bound to the verified identity.")
            return

    # ------------------------------------------------------------------ R5 privilege assignment
    def r_priv(self, ep):
        f = ep.facts
        registration = ep.method in ("POST", "ANY", "PUT") and (bool(P.REGISTRATION_PATH.search(ep.path)) or
                                                                  bool(re.search(r"regist|signup|sign_up|createUser|create_user|addUser", ep.handler, re.I)))
        anon = not self.authenticated(ep)
        admin_only = bool(self.kinds(ep, "authorization")) or f.role_check_inline
        records = []
        for c in f.calls:
            for a in c.args:
                for key, v in self._flat(a):
                    if key and P.PRIV_KEYS.match(key):
                        records.append((key, v, c.line, c.callee))
        for a in f.assigns:
            key = re.split(r"[.\[]", a.target)[-1].strip("'\"]")
            if P.PRIV_KEYS.match(key):
                records.append((key, a.value, a.line, a.target))
        for key, v, line, where in records:
            literal_priv = v.has_literal and ((isinstance(v.literal, str) and v.literal.lower() in P.PRIV_LITERALS) or
                                              (v.literal is True and re.match(r"(is_?admin|admin|is_?superuser|is_?staff|is_?root)", key, re.I)))
            numeric_priv = v.has_literal and isinstance(v.literal, int) and not isinstance(v.literal, bool) and registration and \
                re.match(r"^(role|user_?type|account_?type|access_?level)$", key, re.I) and v.literal in (0, 1)
            tainted = v.taint and v.taint[0] in ("body", "query", "cookies", "headers")
            if literal_priv and registration:
                self.emit("A01-PRIV-ASSIGN", ep.file, line, ep=ep, severity="critical", confidence="high", source="registration",
                          sink=where, key=f"reg:{ep.group}",
                          explanation=f"The registration/create-user path assigns the privileged value '{v.literal}' to '{key}', "
                                      "so every new account is an administrator.")
            elif numeric_priv:
                self.emit("A01-PRIV-ASSIGN", ep.file, line, ep=ep, severity="high", confidence="medium", source="registration",
                          sink=where, key=f"regnum:{ep.group}",
                          explanation=f"The registration path assigns the numeric value {v.literal} to '{key}'; verify it is not an admin role.")
            elif tainted and not admin_only:
                sev = "critical" if (registration and anon) else "high"
                self.emit("A01-PRIV-ASSIGN", ep.file, line, ep=ep, severity=sev, confidence="high",
                          source=f"request {v.taint[0]}.{v.taint[1]}", sink=where, key=f"req:{ep.group}",
                          explanation=f"'{key}' is assigned from request data ({v.taint[0]}.{v.taint[1]}); a caller can grant themselves "
                                      "any role or permission.")
        if admin_only:
            return
        for c in f.calls:
            last = c.callee.split(".")[-1]
            if c.callee.startswith(("res.", "req.")):
                continue
            is_bind = c.callee.startswith("new ") or self.is_write_call(c) or last in ("assign", "update", "create", "merge", "extend", "setattr", "populate_obj", "from_dict", "update_from_dict")
            if not is_bind:
                continue
            for a in c.args:
                whole = a.spread_taint or (a.taint and a.taint[0] in ("body", "request") and a.taint[1] == "*" and not a.keys)
                if not whole:
                    continue
                model = c.callee[4:] if c.callee.startswith("new ") else (c.args[0].origin or {}).get("model") if (last == "setattr" and c.args and c.args[0].origin) else (c.receiver_origin or {}).get("model") or \
                    (c.callee.split(".")[-2] if "." in c.callee else "")
                m = self.model_by_name(model)
                priv = m.privileged if m else []
                if m and not priv:
                    continue
                if last == "assign" and not c.args[0].origin and not c.args[0].text.strip():
                    continue
                if last == "assign" and not (len(c.args) > 1 and (c.args[0].origin or m)) and c.callee == "Object.assign" and not c.args[0].origin:
                    continue
                sev = ("critical" if registration and anon else "high") if priv else "medium"
                conf = "high" if priv else "medium"
                self.emit("A01-PRIV-ASSIGN", ep.file, c.line, ep=ep, severity=sev, confidence=conf,
                          source="request body", sink=c.callee, key=f"mass:{ep.group}", cwe=915,
                          explanation=f"The whole request body is bound to {model or 'a model'} in {c.callee}()"
                                      + (f"; the model has privileged field(s) {priv} the caller can set." if priv else
                                         "; if the model has role/permission fields the caller can set them (model definition not found)."))
                break

    # ------------------------------------------------------------------ R8/R9/R10 sinks
    def r_sinks(self, ep):
        f = ep.facts
        unauth = not self.authenticated(ep)
        for c in f.calls:
            callee = c.callee
            if callee.startswith(("res.status", "console.")):
                continue
            # --- path traversal / zip-slip
            fs_hit = P.FS_JS.match(callee) or P.FS_SEND.match(callee) or P.FS_PY.match(callee) or P.FS_PY_METHOD.search(callee)
            if fs_hit and not f.contained_paths:
                if callee.endswith("send_from_directory"):
                    cand = c.args[:1]
                else:
                    cand = [a for a in c.args if a.taint and not a.taint[2] and a.taint[0] != "headers"]
                if P.FS_SEND.match(callee) and len(c.args) > 1 and "root" in c.args[1].keys:
                    cand = []
                cand = [a for a in cand if a.taint and a.text not in f.checked_texts]
                if cand:
                    a = cand[0]
                    write = bool(re.search(r"(write|append|unlink|rm|rename|copy|mkdir|remove|replace|makedirs)", callee, re.I))
                    sev = "critical" if (write and unauth) else "high"
                    self.emit("A01-PATH-TRAVERSAL", ep.file, c.line, ep=ep, severity=sev, confidence="high",
                              source=f"request {a.taint[0]}.{a.taint[1]}", sink=callee,
                              explanation=f"{a.taint[0]}.{a.taint[1]} reaches {callee}() without normalisation and a base-directory check, "
                                          "so '../' sequences can escape the intended directory.")
            if P.ARCHIVE.search(callee) and not f.contained_paths and not any(k == "filter" for a in c.args for k in a.keys):
                if "files" in f.reads or any(a.taint for a in c.args):
                    self.emit("A01-PATH-TRAVERSAL", ep.file, c.line, ep=ep, severity="high", confidence="medium", cwe=22,
                              source="uploaded archive", sink=callee, key=f"zip:{ep.group}",
                              explanation=f"{callee}() extracts an archive from the request without checking that every entry stays inside "
                                          "the destination directory (zip-slip).")
            # --- SSRF
            if (P.HTTP_JS.match(callee) or P.HTTP_PY.match(callee)) and not callee.startswith("res."):
                tv = self._url_taint(c)
                if tv and tv.text not in f.checked_texts and not any(tv.text.startswith(x) for x in f.checked_texts if x and len(x) > 6):
                    sev = "critical" if unauth else "high"
                    self.emit("A01-SSRF", ep.file, c.line, ep=ep, severity=sev, confidence="high",
                              source=f"request {tv.taint[0]}.{tv.taint[1]}", sink=callee,
                              explanation=f"{tv.taint[0]}.{tv.taint[1]} chooses the URL/host of {callee}() with no scheme/host allow-list "
                                          "or private-range blocking.")
            # --- open redirect
            if P.REDIRECT_JS.match(callee) or P.REDIRECT_PY.match(callee):
                tv = next((a for a in c.args if a.taint and a.taint[0] != "params" or (a.taint and a.taint[0] == "params" and not a.taint[2])), None)
                if tv and tv.taint and not tv.taint[2] and tv.text not in f.checked_texts:
                    pre = tv.prefix or ""
                    if pre.startswith("/") and not pre.startswith("//") and len(pre) > 1:
                        continue
                    if pre.startswith("http"):
                        continue
                    ref = tv.taint[1].lower() in ("referer", "referrer", "origin")
                    self.emit("A01-OPEN-REDIRECT", ep.file, c.line, ep=ep, severity="medium" if not ref else "low",
                              confidence="high" if not ref else "medium", source=f"request {tv.taint[0]}.{tv.taint[1]}", sink=callee,
                              explanation=f"{tv.taint[0]}.{tv.taint[1]} is used as the redirect location without an allow-list.")

    def _url_taint(self, c: CallRec):
        for a in c.args[:2]:
            for key, v in self._flat(a):
                if not v.taint or v.taint[2]:
                    continue
                if key and not P.URL_KEYS.match(key):
                    continue
                if v.lead_known and v.lead_taint is None:
                    continue  # host fixed by a literal/trusted prefix
                if re.match(r"^https?://[^/\s$]+", v.prefix or ""):
                    continue
                if a is c.args[0] or key:
                    return v
        return None

    # ------------------------------------------------------------------ R11 CSRF
    def r_csrf(self, ep):
        if ep.method not in STATE_METHODS or not self.authenticated(ep) and "csrf_exempt" not in ep.notes:
            return
        i = self.info(ep)
        if not (i["writes"] or i["upload"] or ep.method in ("PUT", "PATCH", "DELETE")):
            return
        explicit = "csrf_exempt" in ep.notes
        if explicit:
            self.emit("A01-CSRF", ep.file, ep.line, ep=ep, severity="medium", confidence="high",
                      explanation=f"CSRF protection is explicitly disabled for {ep.method} {ep.path}, which changes state for "
                                  "session-authenticated users.", key=f"csrf-exempt:{ep.group}")
            return
        gsec = self.p.global_security
        if ep.framework in ("django", "spring", "rails", "laravel", "aspnet", "symfony"):
            return  # framework default protects unless explicitly disabled (see global signals)
        if self.kinds(ep, "csrf") or gsec.get("csrf_default", {}).get(ep.framework) or gsec.get("csrf_middleware") \
                or self.p.samesite_configured or not self.p.cookie_auth:
            return
        self.emit("A01-CSRF", ep.file, ep.line, ep=ep, severity="medium", confidence="medium", key=f"csrf:{ep.group}",
                  explanation=f"{ep.method} {ep.path} changes state for cookie/session-authenticated users and the project has no CSRF "
                              "token, SameSite cookie setting or Origin check.")

    # ------------------------------------------------------------------ R13 data exposure
    def r_exposure(self, ep):
        f = ep.facts
        if HIDE_FIELDS.search(ep.source or ""):
            return
        unauth = not self.authenticated(ep)
        restricted = self.has_role_or_owner(ep)
        for r in f.responses:
            vals = [r.arg] + list(r.arg.keys.values())
            for v in vals:
                o = v.origin
                if not o or o.get("op") == "new" or o.get("projected"):
                    continue
                model = o["model"]
                m = self.model_by_name(model)
                sens = bool(m and m.sensitive)
                if PUBLIC_MODEL.match(model) and not sens:
                    continue
                coll = o.get("collection")
                if sens:
                    sev = "critical" if (coll and unauth) else "high"
                    self.emit("A01-DATA-EXPOSURE", ep.file, r.line, ep=ep, severity=sev, confidence="high", cwe=200,
                              source=f"{model} model", sink="response", key=f"sens:{ep.group}",
                              explanation=f"The response returns whole {model} {'collection' if coll else 'object'}(s) without projection; the model has "
                                          f"sensitive field(s) {m.sensitive[:4]}.")
                elif coll and USERISH_MODEL.search(model) and not restricted:
                    self.emit("A01-DATA-EXPOSURE", ep.file, r.line, ep=ep, severity="high" if unauth else "medium", confidence="medium",
                              cwe=200, source=f"{model} model", sink="response", key=f"coll:{ep.group}",
                              explanation=f"The endpoint returns the whole {model} collection with no role or ownership restriction.")
                break

    # ------------------------------------------------------------------ R6 fail-open
    def r_fail_open(self):
        used = {}
        for ep in self.p.entry_points:
            for g in self.eff_guards(ep):
                used.setdefault((g.file, g.line, g.name), []).append(ep)
        seen = set()
        for g in self.p.guards:
            if not g.fails_open:
                continue
            key = (g.file, g.fail_open_line or g.line)
            if key in seen:
                continue
            seen.add(key)
            eps = used.get((g.file, g.line, g.name), [])
            line = g.fail_open_line or g.line
            sev = "critical" if eps else "high"
            self.emit("A01-GUARD-FAIL-OPEN", g.file, line, severity=sev, confidence="high", key=f"guard:{g.file}:{g.line}",
                      affected=[self.affected(e) for e in eps], source="guard", sink=g.name,
                      explanation=f"Guard '{g.name}' ({g.kind}) {'swallows an exception and ' if g.fail_open_reason == 'error-swallowed' else 'writes a deny response but '}"
                                  f"still reaches the protected code (line {line}); {len(eps)} entry point(s) rely on it.")

    # ------------------------------------------------------------------ R7 coverage
    def r_coverage(self):
        by_handler = {}
        for ep in self.p.entry_points:
            for n in ep.notes:
                if n.startswith("registered_before_guard:"):
                    _, name, line = n.split(":", 2)
                    self.emit("A01-GUARD-COVERAGE", ep.file, ep.line, ep=ep, severity="high", confidence="medium",
                              key=f"order:{ep.group}:{name}", source="guard order", sink=name,
                              explanation=f"{ep.method} {ep.path} is registered before guard '{name}' (line {line}) in the same router, "
                                          "so the guard never runs for it.")
                elif n.startswith("guard_above_route:"):
                    name = n.split(":", 1)[1]
                    self.emit("A01-GUARD-COVERAGE", ep.file, ep.line, ep=ep, severity="high", confidence="high",
                              key=f"above:{ep.group}:{name}", source="decorator order", sink=name,
                              explanation=f"Decorator '{name}' is placed above the route decorator on {ep.method} {ep.path}; the framework registers "
                                          "the undecorated function, so the guard never runs.")
                elif n.startswith("method_limited_guard:"):
                    _, name, methods = n.split(":", 2)
                    self.emit("A01-GUARD-COVERAGE", ep.file, ep.line, ep=ep, severity="high", confidence="medium",
                              key=f"method:{ep.group}:{name}", source="guard scope", sink=name,
                              explanation=f"Guard '{name}' is registered only for {methods}, so {ep.method} {ep.path} is not protected by it.")
            if ep.handler_resolved and not ep.handler.startswith("<"):
                by_handler.setdefault((ep.facts and ep.file, ep.handler), []).append(ep)
        for (_, h), eps in by_handler.items():
            if len(eps) < 2:
                continue
            guarded = [e for e in eps if self.authenticated(e)]
            open_ = [e for e in eps if not self.authenticated(e) and not self.is_public(e)]
            if guarded and open_:
                for e in open_:
                    self.emit("A01-GUARD-COVERAGE", e.file, e.line, ep=e, severity="high", confidence="medium", key=f"alt:{h}",
                              source="alternative route", sink=h,
                              explanation=f"Handler {h} is reachable through {guarded[0].method} {guarded[0].path} (authenticated) and "
                                          f"through {e.method} {e.path} (no authentication guard).")

    # ------------------------------------------------------------------ signals
    def r_signals(self):
        authish = bool(self.p.cookie_auth or any(g.kind == "authentication" for g in self.p.guards) or self.p.global_security.get("default_authn"))
        for s in self.p.signals:
            rule = RULES.get(s.rule_id)
            if rule is None:
                continue
            sev, conf, expl = s.severity or rule.severity, s.confidence or "medium", s.detail
            if s.rule_id == "A01-CORS":
                kind, cred = s.extra.get("origin"), s.extra.get("credentials")
                if kind == "reflected":
                    sev = "high" if cred else "medium"
                elif kind == "wildcard":
                    sev = "medium" if cred else ("low" if not authish else "medium")
                elif kind == "default":
                    sev = "medium" if authish else "low"
                elif kind == "regex":
                    sev = "medium"
                if cred and kind in ("reflected", "regex"):
                    expl += " and credentials are allowed"
            self.emit(s.rule_id, s.file, s.line, severity=sev, confidence=conf, explanation=expl, cwe=s.cwe,
                      key=f"sig:{s.rule_id}:{s.file}:{s.cwe}:{s.extra.get('kind', '')}", sink=s.evidence[:80],
                      affected=[{"method": "-", "path": "-", "file": s.file, "line": s.line, "handler": s.rule_id}])
        gsec = self.p.global_security
        for item in gsec.get("csrf_disabled", []):
            file, line, text = item
            self.emit("A01-CSRF", file, line, severity="medium", confidence="high", key=f"csrf-off:{file}",
                      explanation="CSRF protection is explicitly disabled in the framework security configuration.",
                      affected=[{"method": "*", "path": "*", "file": file, "line": line, "handler": "security config"}])
        if gsec.get("default_allow_all"):
            file, line = gsec["default_allow_all"] if isinstance(gsec["default_allow_all"], tuple) else ("", 0)
            self.emit("A01-AUTHN-MISSING", file, line, severity="high", confidence="high", key="allow-all",
                      explanation="The global security configuration permits every request without authentication (permit-all / AllowAny default).",
                      affected=[{"method": "*", "path": "*", "file": file, "line": line, "handler": "security config"}])

    def r_static_files(self):
        served = set(P.CONVENTIONAL_PUBLIC_DIRS) | {d.split("/")[-1] for d in self.p.static_dirs if d}
        hits, rootsens = [], []
        for path in self.p.all_paths:
            parts = path.split("/")
            if not any(x in served for x in parts[:-1]):
                if len(parts) == 1 and P.SENSITIVE_FILE_NAMES.search(parts[0]):
                    rootsens.append(path)
                continue
            base = parts[-1]
            if ".git" in parts or P.SENSITIVE_FILE_NAMES.search(base):
                hits.append(path)
        for path in hits[:25]:
            base = path.split("/")[-1]
            cwe = 552 if ".git" in path.split("/") else 538 if re.search(r"env|key|pem|sql|sqlite|db|htpasswd|secret|credential|config|git", base, re.I) else 548
            sev = "high" if re.search(r"\.env|\.pem|\.key|\.sql|sqlite|\.db$|htpasswd|id_rsa|\.git|secret|credential", path, re.I) else "medium"
            self.emit("A01-INSECURE-DEFAULTS", path, 1, severity=sev, confidence="high", cwe=cwe, key="static-sensitive",
                      explanation=f"'{path}' is a sensitive/backup/config file inside a web-served directory and can be downloaded by anyone.",
                      affected=[{"method": "GET", "path": "/" + "/".join(path.split("/")[1:]), "file": path, "line": 1, "handler": "static files"}])
        if rootsens:
            for s in self.p.signals:
                if s.extra.get("kind") == "root-static":
                    for path in rootsens[:10]:
                        self.emit("A01-INSECURE-DEFAULTS", s.file, s.line, severity="high", confidence="high", cwe=538, key="root-static-sensitive",
                                  explanation=f"The project root is served statically and contains '{path}'.",
                                  affected=[{"method": "GET", "path": "/" + path, "file": path, "line": 1, "handler": "static files"}])

    def r_token_guards(self):
        for g in self.p.guards:
            if g.identity_source == "request" and g.identity_evidence.startswith("token decoded"):
                self.emit("A01-TOKEN-SESSION", g.file, g.line, severity="high", confidence="high", cwe=285, key=f"decode:{g.file}:{g.line}",
                          explanation=f"Guard '{g.name}' decodes a token without verifying its signature and trusts the result as identity.",
                          affected=[{"method": "*", "path": "*", "file": g.file, "line": g.line, "handler": g.name}])
            elif g.identity_source == "request" and g.kind in ("authentication", "authorization", "ownership"):
                self.emit("A01-IDENTITY-FROM-REQUEST", g.file, g.line, severity="critical", confidence="high", key=f"guard:{g.file}:{g.line}",
                          source="request data", sink=g.name,
                          explanation=f"Guard '{g.name}' decides using request-supplied identity ({g.identity_evidence}); any caller can set it.",
                          affected=[{"method": "*", "path": "*", "file": g.file, "line": g.line, "handler": g.name}])
            elif g.identity_source == "static-key":
                self.emit("A01-TOKEN-SESSION", g.file, g.line, severity="medium", confidence="medium", cwe=922, key=f"static-key:{g.file}",
                          explanation=f"Guard '{g.name}' compares a header with a hard-coded API key: one long-lived, unscoped credential is the only access control.",
                          affected=[{"method": "*", "path": "*", "file": g.file, "line": g.line, "handler": g.name}])

    # ------------------------------------------------------------------ R15 client only
    def r_client_only(self):
        for file, line, text, urls in self.p.client_checks:
            matches = []
            for ep in self.p.entry_points:
                if self.kinds(ep, "authorization") or ep.facts.role_check_inline or ep.facts.ownership_check_inline:
                    continue
                rx = re.compile("^" + re.sub(r":\w+\*?|\{\w+\}", "[^/]+", re.escape(ep.path).replace("\\:", ":").replace("\\{", "{").replace("\\}", "}")) + "$")
                if any(rx.match(u.split("?")[0].rstrip("/") or "/") or u.split("?")[0].rstrip("/").startswith(ep.path.rstrip("/") + "/") for u in urls):
                    if self.info(ep)["state_change"] or self.info(ep)["sensitive_read"] or P.ADMINLIKE_PATH.search(ep.path):
                        matches.append(ep)
            if matches:
                self.emit("A01-CLIENT-ONLY", file, line, severity="low", confidence="medium", key=f"client:{file}",
                          source="front-end", sink="server endpoint",
                          explanation="The front-end hides or shows features by role, but the server endpoint(s) it calls have no matching role check.",
                          affected=[self.affected(e) for e in matches[:10]])
                for ep in matches[:10]:
                    for k, entry in self.cands.items():
                        if k[0] in ("A01-AUTHZ-MISSING", "A01-AUTHN-MISSING") and self.affected(ep) in entry["affected"]:
                            entry["supporting"].append({"type": "client-side check", "file": file, "line": line, "evidence": text[:160]})


def PRIV_WRITE_KEY(key):
    return bool(key and P.PRIV_KEYS.match(key))


def HIDE_OWNER_FILTER(c: CallRec) -> bool:
    """True when the lookup text itself shows an owner scope in a form the extractor could not flatten."""
    return bool(re.search(r"\b(owner|user_?id|userId|created_?by|tenant)\b\s*[:=]\s*(req|request)\.(user|auth|session)", c.text))


def run_rules(project: Project, files: dict, config=None) -> list:
    return Engine(project, files, config).run()
