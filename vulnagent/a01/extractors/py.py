"""Python extractor (stdlib ``ast``): Flask, FastAPI, Django / Django REST Framework."""

from __future__ import annotations

import ast
import posixpath
import re

from .. import patterns as P
from ..ir import (ArgInfo, AssignRec, CallRec, CompareRec, DataModel, EntryPoint, Guard, HandlerFacts, Project,
                  ResponseRec, Signal)
from .base import join_path, path_matches_scope, trim_source

ROUTE_VERBS = {"get", "post", "put", "patch", "delete", "head", "options"}
RESPONSE_NAMES = {"jsonify", "JsonResponse", "Response", "render", "render_template", "HttpResponse", "make_response",
                  "JSONResponse", "ORJSONResponse", "HTMLResponse", "PlainTextResponse", "StreamingResponse"}
KNOWN_NON_MODELS = RESPONSE_NAMES | {"HTTPException", "Depends", "Query", "Body", "Path", "Form", "File", "UUID", "Decimal",
                                     "Request", "Exception", "ValueError", "Q", "F", "Path", "Security", "Header", "Cookie",
                                     "HttpResponseRedirect", "HttpResponseForbidden", "PermissionDenied", "Http404", "Blueprint",
                                     "Flask", "FastAPI", "APIRouter", "Counter", "OrderedDict", "Fernet", "Session", "URL"}
CHAIN_FILTER = {"filter", "filter_by", "where", "exclude", "order_by", "limit", "offset", "distinct", "join", "options",
                "select_related", "prefetch_related", "annotate", "paginate"}
CHAIN_END = {"first", "all", "one", "one_or_none", "scalar", "scalars", "get", "last", "first_or_404", "get_or_404", "count",
             "fetchall", "fetchone", "iterator", "latest", "earliest"}
CHAIN_PROJ = {"only", "values", "values_list", "with_entities", "load_only", "defer", "exclude"}
PASSTHROUGH_FUNCS = {"strip", "lower", "upper", "replace", "split", "join", "format", "decode", "encode", "items", "values",
                     "keys", "copy", "dict", "model_dump", "get_json", "loads", "str", "unquote", "unquote_plus", "normpath",
                     "lstrip", "rstrip", "title", "dict_", "to_dict"}
DRF_PERM_NAMES = {"IsAuthenticated": "authentication", "IsAdminUser": "authorization", "DjangoModelPermissions": "authorization",
                  "DjangoModelPermissionsOrAnonReadOnly": "authorization", "DjangoObjectPermissions": "ownership",
                  "IsAuthenticatedOrReadOnly": "partial", "AllowAny": "allow"}
LIB_DECORATORS = {
    "login_required": "authentication", "jwt_required": "authentication", "fresh_jwt_required": "authentication",
    "verify_jwt_in_request": "authentication", "auth_required": "authentication", "token_required": "authentication",
    "roles_required": "authorization", "roles_accepted": "authorization", "permission_required": "authorization",
    "user_passes_test": "authorization", "staff_member_required": "authorization", "superuser_required": "authorization",
    "permissions_required": "authorization", "has_permission": "authorization", "admin_required": "authorization",
    "csrf_protect": "csrf", "limiter": "rate_limit", "limit": "rate_limit", "ratelimit": "rate_limit",
}
LIB_MODULES = ("flask_login", "flask_jwt_extended", "flask_httpauth", "flask_security", "flask_principal", "flask_praetorian",
               "django.contrib.auth", "rest_framework", "flask_limiter", "flask_wtf", "fastapi", "guardian", "flask_jwt", "flask_user")


def available():
    return True


def unparse(node) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover
        return ""


def lineno(node):
    return getattr(node, "lineno", 0)


def const_str(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def callee_parts(func) -> list:
    parts = []
    node = func
    while True:
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.Name):
            parts.append(node.id)
            break
        elif isinstance(node, ast.Subscript):
            node = node.value
        else:
            parts.append(unparse(node)[:30])
            break
    parts.reverse()
    return parts


def callee_text(func) -> str:
    return ".".join(callee_parts(func))


def dotted_to_path(paths, dotted, from_path=None, level=0):
    parts = [p for p in (dotted or "").split(".") if p]
    cands = []
    if level and from_path:
        base = posixpath.dirname(from_path)
        for _ in range(level - 1):
            base = posixpath.dirname(base)
        rel = posixpath.join(base, *parts) if parts else base
        cands = [rel + ".py", posixpath.join(rel, "__init__.py")]
        return next((c for c in cands if c in paths), None)
    tail = "/".join(parts)
    hits = [p for p in paths if p == tail + ".py" or p.endswith("/" + tail + ".py") or p == tail + "/__init__.py"
            or p.endswith("/" + tail + "/__init__.py")]
    return min(hits, key=len) if hits else None


class PyModule:
    def __init__(self, path, source, paths):
        self.path, self.source, self.paths = path, source, paths
        self.tree = ast.parse(source)
        self.lines = source.splitlines()
        self.funcs, self.classes, self.imports, self.assigns = {}, {}, {}, {}
        for node in self.tree.body:
            self._index(node)

    def _index(self, node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.funcs[node.name] = node
        elif isinstance(node, ast.ClassDef):
            self.classes[node.name] = node
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.funcs[f"{node.name}.{item.name}"] = item
        elif isinstance(node, ast.Import):
            for a in node.names:
                self.imports[a.asname or a.name.split(".")[0]] = (dotted_to_path(self.paths, a.name), None, a.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            base = dotted_to_path(self.paths, mod, self.path, node.level)
            for a in node.names:
                sub = dotted_to_path(self.paths, (mod + "." if mod else "") + a.name, self.path, node.level)
                self.imports[a.asname or a.name] = (sub or base, None if sub else a.name, mod)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name) and node.value is not None:
                    self.assigns[t.id] = node.value
        elif isinstance(node, (ast.If, ast.Try)):
            for sub in list(node.body) + list(getattr(node, "orelse", [])):
                self._index(sub)


# ---------------------------------------------------------------------------------------------
# handler analysis
# ---------------------------------------------------------------------------------------------
class PyAnalyzer:
    def __init__(self, fn, framework="flask", param_env=None, models=None, req_names=("request",)):
        self.fn, self.framework, self.models = fn, framework, models or {}
        self.facts = HandlerFacts()
        self.env = dict(param_env or {})
        self.seen = set()
        self.req_names = set(req_names) | {"request"}
        args = [a.arg for a in fn.args.args]
        if args and args[0] in ("self", "cls"):
            args = args[1:]
        if args and framework in ("django", "drf") and args[0] in ("request", "req"):
            self.req_names.add(args[0])
        elif args and framework == "flask" and args and args[0] == "request":
            pass

    # --- text helpers
    def norm(self, text):
        text = re.sub(r"\bself\.request\b", "request", text)
        for n in self.req_names:
            if n != "request" and re.match(rf"^{re.escape(n)}\b", text):
                text = "request" + text[len(n):]
        return text

    def source_taint(self, text):
        t = self.norm(text)
        m = P.REQUEST_SOURCE.match(t)
        if not m:
            if re.match(r"^request\.(view_args|path_params)", t) or re.match(r"^self\.kwargs", t):
                seg = re.findall(r"\[['\"](\w+)['\"]\]|\.get\(['\"](\w+)['\"]", t)
                return ("params", (seg[-1][0] or seg[-1][1]) if seg else "*", False)
            return None
        kind = {"args": "query", "form": "body", "values": "body", "json": "body", "data": "body", "GET": "query", "POST": "body",
                "query_params": "query", "path_params": "params", "COOKIES": "cookies", "FILES": "files", "files": "files",
                "META": "headers", "body": "body"}.get(m.group(1), m.group(1))
        rest = t[len("request." + m.group(1)):]
        segs = re.findall(r"\[['\"]([\w\-]+)['\"]\]|\.get\(['\"]([\w\-]+)['\"]|\.getlist\(['\"]([\w\-]+)['\"]|\.(\w+)", rest)
        field = "*"
        if segs:
            last = segs[0]
            field = last[0] or last[1] or last[2] or (last[3] if last[3] not in ("get", "getlist", "items", "keys", "values", "copy") else "*") or "*"
        return (kind, field, False)

    # --- expression info
    def info(self, node) -> ArgInfo:
        if node is None:
            return ArgInfo()
        text = unparse(node)
        line = lineno(node)
        if isinstance(node, ast.Constant):
            return ArgInfo(text=text, literal=node.value, has_literal=True, line=line, prefix=node.value if isinstance(node.value, str) else "")
        if isinstance(node, ast.Name):
            known = self.env.get(node.id)
            if known is not None:
                return known
            if node.id in self.req_names:
                return ArgInfo(text=text, taint=("request", "*", False), line=line)
            return ArgInfo(text=text, line=line, identity=bool(P.IDENTITY_EXPR.match(text)))
        if isinstance(node, ast.JoinedStr):
            first = node.values[0] if node.values else None
            prefix = first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else ""
            merged, lead = None, None
            for idx, v in enumerate(node.values):
                if isinstance(v, ast.FormattedValue):
                    inf = self.info(v.value)
                    merged = merged or inf.taint
                    if lead is None and not prefix and idx == 0:
                        lead = inf.taint
            return ArgInfo(text=text, taint=merged, prefix=prefix, line=line, lead_known=True, lead_taint=lead)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            base = self.info(node.value)
            direct = self.source_taint(text)
            if isinstance(node, ast.Attribute):
                key = node.attr
            else:
                sl = node.slice
                key = const_str(sl) or (str(sl.value) if isinstance(sl, ast.Constant) else "*")
            ident = bool(P.IDENTITY_EXPR.match(self.norm(text)) or P.IDENTITY_EXPR.match(text)) or base.identity
            taint = direct
            if taint is None and base.taint:
                taint = (base.taint[0], key, base.taint[2]) if base.taint[0] != "request" else self.source_taint(f"request.{key}")
            origin = base.origin if (base.origin and key in ("data", "__dict__", "dict")) else None
            return ArgInfo(text=text, taint=taint, identity=ident and not taint, origin=origin, line=line)
        if isinstance(node, ast.Call):
            return self.call_info(node)
        if isinstance(node, ast.BinOp):
            l, r = self.info(node.left), self.info(node.right)
            pre = l.prefix if isinstance(node.op, (ast.Add, ast.Mod)) else ""
            return ArgInfo(text=text, taint=l.taint or r.taint, prefix=pre, line=line, lead_known=True,
                           lead_taint=None if pre else (l.lead_taint if l.lead_known else l.taint))
        if isinstance(node, ast.Dict):
            keys, spread, taint = {}, False, None
            for k, v in zip(node.keys, node.values):
                if k is None:
                    inner = self.info(v)
                    if inner.taint and inner.taint[1] == "*":
                        spread, taint = True, inner.taint
                    continue
                ks = const_str(k) or unparse(k)
                keys[ks] = self.info(v)
            return ArgInfo(text=text[:300], keys=keys, spread_taint=spread, taint=taint if spread else None, line=line)
        if isinstance(node, ast.Compare):
            left = self.info(node.left)
            outs = ArgInfo(text=text, line=line)
            for op, comp in zip(node.ops, node.comparators):
                right = self.info(comp)
                if isinstance(op, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)):
                    self.facts.compares.append(CompareRec(left, right, "==" if isinstance(op, (ast.Eq, ast.Is)) else "!=", line, text[:200]))
                    if isinstance(node.left, ast.Attribute) and isinstance(op, ast.Eq):
                        outs.keys[node.left.attr] = right
                    elif isinstance(comp, ast.Attribute) and isinstance(op, ast.Eq):
                        outs.keys[comp.attr] = left
                elif isinstance(op, (ast.In, ast.NotIn)):
                    self.facts.checked_texts.add(left.text)
                    self.facts.checked_texts.add(right.text)
            return outs
        if isinstance(node, (ast.IfExp,)):
            a, b = self.info(node.body), self.info(node.orelse)
            self.info(node.test)
            return ArgInfo(text=text, taint=a.taint or b.taint, line=line)
        if isinstance(node, (ast.BoolOp,)):
            infos = [self.info(v) for v in node.values]
            return ArgInfo(text=text, taint=next((i.taint for i in infos if i.taint), None),
                           identity=any(i.identity for i in infos), line=line)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            infos = [self.info(v) for v in node.elts]
            return ArgInfo(text=text[:200], taint=next((i.taint for i in infos if i.taint), None),
                           identity=any(i.identity for i in infos), line=line)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            gen = node.generators[0]
            it = self.info(gen.iter)
            return ArgInfo(text=text[:200], taint=it.taint, origin=None, line=line)
        if isinstance(node, ast.Await):
            return self.info(node.value)
        if isinstance(node, ast.Starred):
            return self.info(node.value)
        if isinstance(node, ast.UnaryOp):
            return self.info(node.operand)
        return ArgInfo(text=text[:200], line=line)

    def call_info(self, call: ast.Call) -> ArgInfo:
        func = call.func
        parts = callee_parts(func)
        callee = ".".join(parts)
        line = lineno(call)
        last = parts[-1] if parts else ""
        args = [self.info(a) for a in call.args]
        kw = ArgInfo(text="kwargs", line=line)
        spread_whole = None
        for k in call.keywords:
            inf = self.info(k.value)
            if k.arg is None:
                if inf.taint and inf.taint[1] == "*":
                    kw.spread_taint, kw.taint, spread_whole = True, inf.taint, inf
                elif inf.keys:
                    kw.keys.update(inf.keys)
            else:
                kw.keys[k.arg] = inf
        if kw.keys or kw.spread_taint:
            args = args + [kw]
        # chain: base call info for method chains
        base = None
        if isinstance(func, ast.Attribute) and isinstance(func.value, (ast.Call,)):
            base = self.info(func.value)
        owner_origin = None
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                owner_origin = (self.env.get(func.value.id) or ArgInfo()).origin
            elif base is not None:
                owner_origin = base.origin
        key = (line, getattr(call, "col_offset", 0), callee)
        rec = None
        if key not in self.seen:
            self.seen.add(key)
            is_new = bool(parts) and len(parts) == 1 and parts[0][:1].isupper() and parts[0] not in KNOWN_NON_MODELS \
                and (call.keywords or call.args)
            rec = CallRec(callee=("new " + parts[0]) if is_new else callee, args=args, line=line, text=unparse(call)[:240],
                          receiver_origin=owner_origin)
            self.facts.calls.append(rec)
            self._flags(call, callee, last, args)
        if rec is not None and base is not None and base.origin is not None and base.origin.get("rec") is not None \
                and last in ("delete", "update", "save", "remove"):
            rec.args = list(rec.args) + list(base.origin["rec"].args)       # write terminal inherits the chain's filters
        # --- chain continuation keeps origin and merges filters
        if base is not None and base.origin is not None and last in (CHAIN_FILTER | CHAIN_END | CHAIN_PROJ):
            origin = dict(base.origin)
            if last in CHAIN_PROJ and last != "exclude":
                origin["projected"] = True
            if last in ("all", "fetchall", "iterator"):
                origin["collection"] = True
            if last in ("first", "one", "one_or_none", "get", "last", "first_or_404", "get_or_404", "scalar"):
                origin["collection"] = False
            if last in CHAIN_FILTER and (kw.keys or args) and origin.get("rec") is not None:
                origin["rec"].args.extend([a for a in args if a.keys or a.taint or a.identity])
            if last in ("first", "one", "one_or_none", "get", "last", "first_or_404", "get_or_404", "scalar") and origin.get("rec") is not None:
                origin["rec"].single = True
            return ArgInfo(text=unparse(call)[:200], origin=origin, line=line)
        if base is not None and base.taint and last in PASSTHROUGH_FUNCS:
            return ArgInfo(text=unparse(call)[:200], taint=base.taint, line=line)
        # --- request sources by call syntax
        t = self.norm(unparse(call))
        if re.match(r"^request\.(get_json|json|get_data|body)\(", t) or t.startswith("json.loads(request.") \
                or (last in ("get_json",) and "request" in callee):
            return ArgInfo(text=t[:200], taint=("body", "*", False), line=line)
        m = re.match(r"^request\.(args|form|values|headers|cookies|GET|POST|query_params|data|COOKIES|META|json)\.(get|getlist)$", self.norm(callee))
        if m and args and args[0].has_literal:
            st = self.source_taint(f"request.{m.group(1)}.get('{args[0].literal}')")
            return ArgInfo(text=t[:200], taint=st, line=line)
        if last == "get" and isinstance(func, ast.Attribute):
            b = self.info(func.value)
            if b.taint and args and args[0].has_literal:
                return ArgInfo(text=t[:200], taint=(b.taint[0], str(args[0].literal), b.taint[2]), line=line)
            if b.identity:
                return ArgInfo(text=t[:200], identity=True, line=line)
        if P.PICK_FUNCS.search(callee) or P.SANITIZE_PATH.search(callee):
            return ArgInfo(text=t[:200], line=line)
        tainted = next((a for a in args if a.taint), None)
        if callee in ("int", "float", "bool", "len", "UUID", "uuid.UUID", "Decimal") or callee.endswith("UUID"):
            return ArgInfo(text=t[:200], taint=(tainted.taint[0], tainted.taint[1], True) if tainted else None, line=line)
        if re.search(r"(^|\.)(get_jwt_identity|get_jwt|current_user|get_current_user)$", callee):
            return ArgInfo(text=t[:200], identity=True, line=line)
        # --- Serializer(obj).data keeps no origin (projection handled by the serializer)
        if last.endswith("Serializer") and parts[0] == last:
            return ArgInfo(text=t[:200], origin=None, taint=None, line=line)
        # --- DB lookups
        if last in ("get_object_or_404", "get_list_or_404", "get_object") and args:
            first = args[0]
            model = first.text if first.text[:1].isupper() else (self.models.get("queryset") or "")
            rec2 = rec
            if rec2 is not None and first.text[:1].isupper():
                rec2.callee = f"{first.text}.objects.get"
                rec2.args = args[1:]
            return ArgInfo(text=t[:200], origin={"model": model or "?", "op": "get", "projected": False,
                                                 "collection": last == "get_list_or_404", "rec": rec2, "line": line}, line=line)
        if len(parts) >= 2 and P.LOOKUP_NAMES.match(last) and P.MODELISH.match(".".join(parts[:-1])) and not P.NON_DB_RECEIVER.match(parts[0]):
            model = next((p for p in parts[:-1] if p[:1].isupper()), parts[-2])
            if parts[0] in ("db", "session", "self", "cls") and len(parts) > 2:
                model = args[0].text if args and args[0].text[:1].isupper() and last == "query" else model
            collection = last in ("all", "filter", "find", "query", "where", "filter_by") and last != "get"
            origin = {"model": model, "op": last, "projected": False, "collection": collection, "rec": rec, "line": line}
            return ArgInfo(text=t[:200], origin=origin, line=line)
        if len(parts) == 1 and parts[0][:1].isupper() and parts[0] not in KNOWN_NON_MODELS and (call.keywords or call.args):
            return ArgInfo(text=t[:200], origin={"model": parts[0], "op": "new", "projected": False, "collection": False, "line": line}, line=line)
        if last in ("join", "Path", "PurePath", "normpath", "abspath", "realpath", "urljoin", "quote", "unquote", "expanduser") or callee in ("os.path.join", "str"):
            return ArgInfo(text=t[:200], taint=tainted.taint if tainted else None, prefix=args[0].prefix if args else "",
                           lead_known=True, lead_taint=args[0].taint if args else None, line=line)
        if last in ("loads", "decode", "strip", "lower", "format") and tainted:
            return ArgInfo(text=t[:200], taint=tainted.taint, line=line)
        return ArgInfo(text=t[:200], line=line)

    def _flags(self, call, callee, last, args):
        f = self.facts
        lit = [a.literal for a in args if a.has_literal]
        if last == "abort" and lit and lit[0] in (401, 403):
            f.deny_statuses.add(lit[0])
        if re.search(r"(HTTPException|PermissionDenied|Forbidden|NotAuthenticated|AuthenticationFailed|Unauthorized)", callee):
            for kwd in call.keywords:
                if kwd.arg == "status_code" and isinstance(kwd.value, ast.Constant) and kwd.value.value in (401, 403):
                    f.deny_statuses.add(kwd.value.value)
            if "PermissionDenied" in callee or "Forbidden" in callee or "NotAuthenticated" in callee or "Unauthorized" in callee:
                f.deny_statuses.add(403)
        for kwd in call.keywords:
            if kwd.arg in ("status", "status_code") and isinstance(kwd.value, ast.Constant) and kwd.value.value in (401, 403):
                f.deny_statuses.add(kwd.value.value)
        if P.VALIDATION_CALL.search(last):
            for a in args:
                f.checked_texts.add(a.text)
            if isinstance(call.func, ast.Attribute):
                f.checked_texts.add(unparse(call.func.value))
        if last in ("startswith", "is_relative_to", "commonpath", "relative_to", "samefile", "safe_join", "isSubPath") or callee.endswith("path.commonpath"):
            f.contained_paths = True
        if P.OWNERSHIP_CALL.search(last) and any(a.identity for a in args):
            f.ownership_check_inline = True

    # --- statements
    def run(self):
        for stmt in self.fn.body:
            self.stmt(stmt, top=True)
        self._finish()
        return self.facts

    def bind(self, target, value: ArgInfo):
        if isinstance(target, ast.Name):
            self.env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for t in target.elts:
                self.bind(t, ArgInfo(text=unparse(t), taint=value.taint, identity=value.identity, origin=None))
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            self.facts.assigns.append(AssignRec(target=unparse(target), value=value, line=lineno(target), text=""))

    def condition(self, test):
        text = unparse(test)
        self.info(test)
        if P.VALIDATION_CALL.search(text) or re.search(r"\b(in|startswith|endswith)\b", text):
            for n in ast.walk(test):
                if isinstance(n, (ast.Name, ast.Attribute, ast.Subscript)):
                    self.facts.checked_texts.add(unparse(n))
        has_identity = any(self.info(n).identity for n in ast.walk(test) if isinstance(n, (ast.Name, ast.Attribute, ast.Subscript)))
        if has_identity and re.search(r"\b(role|roles|is_admin|isAdmin|admin|is_staff|is_superuser|permissions?|has_perm|scope|can)\b", text, re.I):
            self.facts.role_check_inline = True

    def stmt(self, s, top=False):
        f = self.facts
        if isinstance(s, (ast.Assign, ast.AnnAssign)):
            value = s.value
            targets = s.targets if isinstance(s, ast.Assign) else [s.target]
            if value is not None:
                v = self.info(value)
                for t in targets:
                    self.bind(t, v)
        elif isinstance(s, ast.AugAssign):
            self.info(s.value)
        elif isinstance(s, ast.Expr):
            self.info(s.value)
            if isinstance(s.value, ast.Tuple):  # bare "jsonify(...), 401" (no return): still a deny attempt
                for e in s.value.elts:
                    if isinstance(e, ast.Constant) and e.value in (401, 403):
                        self.facts.deny_statuses.add(e.value)
        elif isinstance(s, ast.Return):
            if s.value is not None and top:
                self.ret(s.value, lineno(s))
            elif s.value is not None:
                self.info(s.value)
        elif isinstance(s, ast.If):
            self.condition(s.test)
            for x in s.body + s.orelse:
                self.stmt(x, top=False)
        elif isinstance(s, (ast.For, ast.AsyncFor)):
            it = self.info(s.iter)
            self.bind(s.target, ArgInfo(text=unparse(s.target), taint=it.taint if it.taint else None, origin=None))
            for x in s.body + s.orelse:
                self.stmt(x, top=False)
        elif isinstance(s, ast.While):
            self.condition(s.test)
            for x in s.body:
                self.stmt(x, top=False)
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                v = self.info(item.context_expr)
                if item.optional_vars is not None:
                    self.bind(item.optional_vars, v)
            for x in s.body:
                self.stmt(x, top=top)
        elif isinstance(s, ast.Try):
            for x in s.body + s.orelse + s.finalbody:
                self.stmt(x, top=top)
            for h in s.handlers:
                for x in h.body:
                    self.stmt(x, top=False)
        elif isinstance(s, ast.Raise) and s.exc is not None:
            self.info(s.exc)
        elif isinstance(s, ast.Assert):
            self.condition(s.test)

    def ret(self, value, line):
        status = None
        node = value
        if isinstance(node, ast.Tuple) and node.elts:
            for e in node.elts[1:]:
                if isinstance(e, ast.Constant) and isinstance(e.value, int):
                    status = e.value
            node = node.elts[0]
        v = self.info(node)
        if isinstance(node, ast.Call):
            callee = callee_text(node.func)
            for kwd in node.keywords:
                if kwd.arg in ("status", "status_code") and isinstance(kwd.value, ast.Constant) and isinstance(kwd.value.value, int):
                    status = kwd.value.value
            if callee.split(".")[-1] in RESPONSE_NAMES or callee.endswith("Response"):
                first = self.info(node.args[0]) if node.args else ArgInfo()
                v = first if node.args else ArgInfo(text=unparse(node))
                if callee.split(".")[-1] in ("render", "render_template"):
                    v = ArgInfo(text=unparse(node))
        if status in (401, 403):
            self.facts.deny_statuses.add(status)
        self.facts.responses.append(ResponseRec("return", v, status, line))

    def _finish(self):
        f = self.facts
        for c in f.compares:
            sides = (c.left, c.right)
            if any(s.identity for s in sides):
                other = c.right if c.left.identity else c.left
                if not other.has_literal and not other.taint:
                    f.ownership_check_inline = True
                    if re.search(r"role|admin|permission|staff", c.text, re.I):
                        f.role_check_inline = True
                elif other.has_literal and re.search(r"role|admin|permission|staff", c.text, re.I):
                    f.role_check_inline = True
        idtexts = [c.text for c in f.calls] + [a.text for a in f.assigns] + [c.text for c in f.compares] + [v.text for v in self.env.values()]
        f.uses_identity = any(P.IDENTITY_EXPR.match(self.norm(t)) or P.IDENTITY_EXPR.match(t) for t in re.findall(r"[\w$.\[\]'\"()]+", " ".join(idtexts))) \
            or any(v.identity for v in self.env.values()) or any(a.identity for c in f.calls for a in c.args)
        f.authn_inline = f.uses_identity and bool(f.deny_statuses)
        reads = {}

        def collect(a):
            if a.taint:
                reads.setdefault(a.taint[0], set()).add(a.taint[1])
            for k in a.keys.values():
                collect(k)
        for c in f.calls:
            for a in c.args:
                collect(a)
        for a in f.assigns:
            collect(a.value)
        for v in self.env.values():
            if v.taint:
                reads.setdefault(v.taint[0], set()).add(v.taint[1])
        f.reads = {k: sorted(x) for k, x in reads.items()}


# ---------------------------------------------------------------------------------------------
# fail-open analysis
# ---------------------------------------------------------------------------------------------
class PyFailOpen:
    """Abstract interpretation: deny without return/raise, or swallowed exception, then proceed."""

    def __init__(self, fn, proceed_names=(), fallthrough_proceeds=False, proceed_on_return=False):
        self.fn, self.proceed = fn, set(proceed_names)
        self.fall = fallthrough_proceeds
        self.on_return = proceed_on_return
        self.events = []

    def run(self):
        end_states = self._block(self.fn.body, frozenset())
        if self.fall:
            for st in end_states:
                if st:
                    self.events.append({"line": getattr(self.fn.body[-1], "end_lineno", lineno(self.fn)), "reason": self._reason(st),
                                        "text": "function ends without denying"})
        return self.events

    @staticmethod
    def _reason(st):
        return "error-swallowed" if "swallowed" in st and "denied" not in st else "denied"

    def _is_proceed_call(self, node):
        for n in ast.walk(node):
            if isinstance(n, ast.Call):
                name = callee_text(n.func)
                if name in self.proceed or name.split(".")[-1] in self.proceed:
                    return n
        return None

    def _is_deny_expr(self, e):
        """Expression statement that builds an error response but is not returned."""
        if isinstance(e, ast.Tuple):
            return any(isinstance(x, ast.Constant) and x.value in (401, 403) for x in e.elts)
        if isinstance(e, ast.Call):
            name = callee_text(e.func).split(".")[-1]
            if name in ("abort",):
                return False
            if name in RESPONSE_NAMES or name in ("redirect", "HttpResponseForbidden", "HttpResponseRedirect", "HTTPException", "PermissionDenied"):
                for kwd in e.keywords:
                    if kwd.arg in ("status", "status_code") and isinstance(kwd.value, ast.Constant) and kwd.value.value in (401, 403):
                        return True
                return name in ("redirect", "HttpResponseForbidden", "HTTPException", "PermissionDenied") or \
                    any(isinstance(a, ast.Constant) and a.value in (401, 403) for a in e.args)
        return False

    def _block(self, stmts, st):
        states = [st]
        for s in stmts:
            nxt = []
            for cur in states:
                nxt.extend(self._stmt(s, cur))
            states = nxt
            if not states:
                break
        return states

    def _stmt(self, s, st):
        if isinstance(s, ast.Return):
            if s.value is not None and self._is_proceed_call(s.value) and st:
                self.events.append({"line": lineno(s), "reason": self._reason(st), "text": unparse(s)[:120]})
            elif self.on_return and st and s.value is not None:
                self.events.append({"line": lineno(s), "reason": self._reason(st), "text": unparse(s)[:120]})
            elif s.value is None and self.fall and st:
                self.events.append({"line": lineno(s), "reason": self._reason(st), "text": "return"})
            elif self.fall and st and isinstance(s.value, ast.Constant) and s.value.value is None:
                self.events.append({"line": lineno(s), "reason": self._reason(st), "text": "return None"})
            return []
        if isinstance(s, ast.Raise):
            return []
        if isinstance(s, ast.If):
            then = self._block(s.body, st)
            other = self._block(s.orelse, st) if s.orelse else [st]
            return then + other
        if isinstance(s, ast.Try):
            body = self._block(s.body, st)
            caught = []
            for h in s.handlers:
                caught += self._block(h.body, st | {"swallowed"})
            out = body + caught
            if s.finalbody:
                out = [x for o in out for x in self._block(s.finalbody, o)]
            return out
        if isinstance(s, (ast.For, ast.While, ast.AsyncFor)):
            self._block(s.body, st)
            return [st]
        if isinstance(s, (ast.With, ast.AsyncWith)):
            return self._block(s.body, st)
        if isinstance(s, ast.Expr):
            p = self._is_proceed_call(s.value)
            if p is not None and st:
                self.events.append({"line": lineno(s), "reason": self._reason(st), "text": unparse(s)[:120]})
            if self._is_deny_expr(s.value):
                return [st | {"denied"}]
            return [st]
        if isinstance(s, (ast.Assign, ast.AnnAssign)):
            v = s.value
            if v is not None and self._is_proceed_call(v) and st:
                self.events.append({"line": lineno(s), "reason": self._reason(st), "text": unparse(s)[:120]})
            return [st]
        return [st]


# ---------------------------------------------------------------------------------------------
# project assembly
# ---------------------------------------------------------------------------------------------
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
VIEWSET_ACTIONS = {"list": ("GET", ""), "create": ("POST", ""), "retrieve": ("GET", "/:pk"), "update": ("PUT", "/:pk"),
                   "partial_update": ("PATCH", "/:pk"), "destroy": ("DELETE", "/:pk")}
VIEWSET_BASES = {"ModelViewSet": set(VIEWSET_ACTIONS), "ReadOnlyModelViewSet": {"list", "retrieve"},
                 "GenericViewSet": set(), "ViewSet": set(), "ListAPIView": {"list"}, "CreateAPIView": {"create"},
                 "RetrieveAPIView": {"retrieve"}, "UpdateAPIView": {"update", "partial_update"}, "DestroyAPIView": {"destroy"},
                 "ListCreateAPIView": {"list", "create"}, "RetrieveUpdateAPIView": {"retrieve", "update", "partial_update"},
                 "RetrieveDestroyAPIView": {"retrieve", "destroy"}, "RetrieveUpdateDestroyAPIView": {"retrieve", "update", "partial_update", "destroy"}}
HTTP_METHOD_FUNCS = {"get", "post", "put", "patch", "delete", "head", "options"}


def _route_path(node):
    value = const_str(node)
    if value is None:
        return None
    value = re.sub(r"<(?:\w+:)?(\w+)>", r":\1", value)          # flask / django
    value = re.sub(r"\(\?P<(\w+)>[^)]*\)", r":\1", value)        # django re_path
    value = value.lstrip("^").rstrip("$")
    value = re.sub(r"\{(\w+)(?::[^}]*)?\}", r":\1", value)       # fastapi
    return value


class PyExtractor:
    def __init__(self, files, project: Project, side_of, config=None):
        self.project, self.side_of = project, side_of
        self.paths = set(files)
        self.mods = {}
        self.cache = {}
        self.seen = set()
        for path, src in files.items():
            if not path.endswith(".py"):
                continue
            try:
                self.mods[path] = PyModule(path, src, self.paths)
                project.files_parsed.append(path)
            except SyntaxError as exc:
                project.files_failed.append((path, f"SyntaxError: {exc.msg} (line {exc.lineno})"))
        self.model_map = {}
        for mod in self.mods.values():
            self._models(mod)

    # ------------------------------------------------------------------ symbol resolution
    def resolve(self, mod, node):
        """Name/Attribute/Call -> (module, def, name, library_module) or None."""
        if isinstance(node, ast.Call):
            node = node.func
        if isinstance(node, ast.Name):
            n = node.id
            if n in mod.funcs:
                return (mod, mod.funcs[n], n, None)
            if n in mod.classes:
                return (mod, mod.classes[n], n, None)
            if n in mod.imports:
                target, name, lib = mod.imports[n]
                tm = self.mods.get(target) if target else None
                if tm is not None:
                    nm = name or n
                    if nm in tm.funcs:
                        return (tm, tm.funcs[nm], nm, lib)
                    if nm in tm.classes:
                        return (tm, tm.classes[nm], nm, lib)
                    if nm in getattr(tm, "objs", {}):
                        return (tm, None, nm, lib)
                    if nm in tm.imports and nm != n:  # re-export one hop
                        return self.resolve(tm, ast.Name(id=nm))
                return (None, None, n, lib)
            return None
        if isinstance(node, ast.Attribute):
            base = node.value
            if isinstance(base, ast.Name) and base.id in mod.imports:
                target, name, lib = mod.imports[base.id]
                tm = self.mods.get(target) if target else None
                if tm is not None:
                    if node.attr in tm.funcs:
                        return (tm, tm.funcs[node.attr], node.attr, lib)
                    if node.attr in tm.classes:
                        return (tm, tm.classes[node.attr], node.attr, lib)
                return (None, None, f"{base.id}.{node.attr}", lib or name)
            if isinstance(base, ast.Name) and base.id in mod.classes and f"{base.id}.{node.attr}" in mod.funcs:
                return (mod, mod.funcs[f"{base.id}.{node.attr}"], f"{base.id}.{node.attr}", None)
            return (None, None, unparse(node), None)
        return None

    def is_lib(self, lib):
        return bool(lib) and lib.startswith(LIB_MODULES)

    # ------------------------------------------------------------------ models
    def _models(self, mod):
        for name, cls in mod.classes.items():
            bases = " ".join(unparse(b) for b in cls.bases)
            if re.search(r"(Model|AbstractUser|AbstractBaseUser|Base|SQLModel|Document|Entity)\b", bases) and "Serializer" not in bases \
                    and "Form" not in bases and "View" not in bases and "Permission" not in bases:
                fields = []
                for item in cls.body:
                    if isinstance(item, ast.Assign) and isinstance(item.value, ast.Call):
                        ctext = callee_text(item.value.func)
                        if re.search(r"(Column|Field|models\.|db\.|relationship|Mapped|mapped_column|Key|Boolean|String|Integer)", ctext + unparse(item.value)[:40]):
                            fields += [t.id for t in item.targets if isinstance(t, ast.Name)]
                    elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                        fields.append(item.target.id)
                if "AbstractUser" in bases or "AbstractBaseUser" in bases:
                    fields += ["password", "is_staff", "is_superuser"]
                sens = [f for f in fields if P.SENSITIVE_FIELD.search(f) and not P.SENSITIVE_FIELD_EXCLUDE.search(f)]
                priv = [f for f in fields if P.PRIV_KEYS.match(f)]
                dm = DataModel(name=name, file=mod.path, line=lineno(cls), fields=fields, sensitive=sens, privileged=priv)
                self.project.models.append(dm)
                self.model_map[name] = dm
            if "Serializer" in bases:
                self._serializer(mod, cls)

    def _serializer(self, mod, cls):
        for item in cls.body:
            if isinstance(item, ast.ClassDef) and item.name == "Meta":
                model, fields_all, line = None, False, lineno(item)
                for st in item.body:
                    if isinstance(st, ast.Assign) and isinstance(st.targets[0], ast.Name):
                        if st.targets[0].id == "model":
                            model = unparse(st.value)
                        if st.targets[0].id == "fields" and const_str(st.value) == "__all__":
                            fields_all, line = True, lineno(st)
                if model and fields_all:
                    dm = self.model_map.get(model)
                    if dm and dm.sensitive:
                        self.project.signals.append(Signal("A01-DATA-EXPOSURE", mod.path, line, mod.lines[line - 1].strip() if line <= len(mod.lines) else "",
                                                           cwe=200, confidence="high",
                                                           detail=f"serializer {cls.name} exposes every field of {model} (including {dm.sensitive[:3]}) via fields='__all__'",
                                                           severity="high"))
                    self.project.frameworks.add("drf")

    # ------------------------------------------------------------------ guards
    def _descend_wrapper(self, fn):
        names, cur = [], fn
        while True:
            a = [x.arg for x in cur.args.args if x.arg not in ("self", "cls")]
            if a:
                names.append(a[0])
            nested = [n for n in cur.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            if not nested:
                return cur, names
            cur = nested[-1] if len(nested) > 1 and nested[-1].name != "wrapper" and any(n.name == "wrapper" for n in nested) is False else \
                next((n for n in nested if n.name in ("wrapper", "wrapped", "decorated", "inner", "decorated_function")), nested[-1])

    def analyze(self, mod, fn, framework, env=None):
        key = (mod.path, lineno(fn), framework)
        if key not in self.cache:
            self.cache[key] = PyAnalyzer(fn, framework, param_env=env, models=self.model_map).run()
        return self.cache[key]

    def _code_kinds(self, facts):
        kinds = set()
        calls = [c.callee for c in facts.calls]
        if any(P.TOKEN_VERIFY.search(c) for c in calls) or any(re.search(r"is_authenticated|login_user|verify_jwt|check_password|authenticate$", c) for c in calls):
            kinds.add("authentication")
        elif facts.uses_identity and facts.deny_statuses and not facts.role_check_inline:
            kinds.add("authentication")
        if any(re.search(r"authorization", c.text, re.I) for c in facts.calls if c.callee.endswith((".get", ".headers.get"))) and facts.deny_statuses:
            kinds.add("authentication")
        if facts.role_check_inline:
            kinds.add("authorization")
        if facts.ownership_check_inline and not facts.role_check_inline:
            kinds.add("ownership")
        return kinds

    def _identity_source(self, facts):
        for c in facts.compares:
            for a, b in ((c.left, c.right), (c.right, c.left)):
                if a.taint and a.taint[0] in ("body", "query", "headers", "cookies") and P.IDENT_FIELD.match(a.taint[1] or ""):
                    return "request", c.text
                if a.taint and a.taint[0] == "headers" and re.search(r"api[-_]?key|x[-_]?token|secret", a.taint[1] or "", re.I) \
                        and b.has_literal and isinstance(b.literal, str):
                    return "static-key", c.text
        for c in facts.calls:
            if re.search(r"(^|\.)decode$", c.callee) and re.search(r"jwt", c.callee, re.I):
                unverified = any(("verify" in a.keys and a.keys["verify"].literal is False) or
                                 ("options" in a.keys and "verify_signature" in a.keys["options"].keys and a.keys["options"].keys["verify_signature"].literal is False)
                                 for a in c.args)
                if unverified:
                    return "request", "token decoded without signature verification"
        if any(P.TOKEN_VERIFY.search(c.callee) for c in facts.calls) or facts.uses_identity:
            return "verified", ""
        return "unknown", ""

    def guard_from(self, mod, node, scope, methods=None, dependency=False) -> list:
        """One decorator / Depends(...) / permission class expression -> guards."""
        target = node
        if isinstance(node, ast.Call):
            if callee_text(node.func).endswith("Depends") or callee_text(node.func).endswith("Security"):
                if node.args:
                    return self.guard_from(mod, node.args[0], scope, methods, dependency=True)
                return []
            target = node.func
        name = callee_text(target) if isinstance(target, (ast.Name, ast.Attribute, ast.Call)) else unparse(target)
        short = name.split(".")[-1]
        res = self.resolve(mod, target)
        lib = res[3] if res else None
        kinds = {k: "name" for k in P.classify_guard_name(name)}
        if short in LIB_DECORATORS and (self.is_lib(lib) or res is None or res[1] is None):
            kinds[LIB_DECORATORS[short]] = "code" if self.is_lib(lib) else kinds.get(LIB_DECORATORS[short], "name")
        if short in DRF_PERM_NAMES:
            kind = DRF_PERM_NAMES[short]
            if kind == "allow":
                return []
            if kind == "partial":
                g = Guard(name=short, kind="authentication", scope=scope, certainty="code", file=mod.path, line=lineno(node),
                          evidence=unparse(node)[:100], methods=UNSAFE_METHODS, identity_source="verified")
                self.project.guards.append(g)
                return [g]
            kinds = {kind: "code"}
        if short in ("OAuth2PasswordBearer", "HTTPBearer", "HTTPBasic", "APIKeyHeader", "APIKeyCookie", "OAuth2PasswordRequestForm", "oauth2_scheme"):
            kinds["authentication"] = "code" if short != "OAuth2PasswordRequestForm" else "name"
        facts, fo, src, fnode, fmod = None, [], "", None, mod
        if res and isinstance(res[1], (ast.FunctionDef, ast.AsyncFunctionDef)):
            fmod, fn = res[0], res[1]
            proceed = set()
            if dependency:
                fnode = fn
                proceed = set()
                facts = self.analyze(fmod, fnode, "fastapi")
                fo = PyFailOpen(fnode, proceed, proceed_on_return=True).run()
            else:
                fnode, names = self._descend_wrapper(fn)
                proceed = set(names) | {"get_response", "view_func", "func", "f", "fn", "view", "function"}
                facts = self.analyze(fmod, fnode, "flask")
                fo = PyFailOpen(fnode, proceed).run()
            for k in self._code_kinds(facts):
                kinds[k] = "code"
            src = trim_source("\n".join(fmod.lines[lineno(fn) - 1: getattr(fn, "end_lineno", lineno(fn))]), 45)
            if not kinds:
                return []
        elif res and isinstance(res[1], ast.ClassDef):
            fmod = res[0]
            cls = res[1]
            for mname in ("has_permission", "has_object_permission"):
                fn = fmod.funcs.get(f"{cls.name}.{mname}")
                if fn is not None:
                    f2 = self.analyze(fmod, fn, "drf")
                    for k in self._code_kinds(f2):
                        kinds[k] = "code"
                    if mname == "has_object_permission" and (f2.compares or f2.ownership_check_inline):
                        kinds["ownership"] = "code"
                    src = trim_source("\n".join(fmod.lines[lineno(fn) - 1: getattr(fn, "end_lineno", lineno(fn))]), 40)
            if not kinds:
                return []
        elif not kinds:
            return []
        out = []
        for kind, cert in kinds.items():
            g = Guard(name=name, kind=kind, scope=scope, certainty=cert, methods=methods, file=fmod.path if fmod else mod.path,
                      line=lineno(fnode) if fnode is not None else lineno(node), evidence=unparse(node)[:140], source=src)
            if facts is not None:
                g.identity_source, g.identity_evidence = self._identity_source(facts)
                if fo and kind in ("authentication", "authorization", "ownership"):
                    g.fails_open, g.fail_open_reason, g.fail_open_line = True, fo[0]["reason"], fo[0]["line"]
            elif kind == "authentication" and cert == "code":
                g.identity_source = "verified"
            out.append(g)
            self.project.guards.append(g)
        return out

    # ------------------------------------------------------------------ param env
    def param_env(self, fn, route_path, framework, skip_first=0):
        env = {}
        names = {m for m in re.findall(r":(\w+)", route_path or "")}
        args = [a for a in fn.args.args + fn.args.kwonlyargs]
        defaults = ([None] * (len(fn.args.args) - len(fn.args.defaults)) + list(fn.args.defaults) + list(fn.args.kw_defaults))
        if args and args[0].arg in ("self", "cls"):
            args, defaults = args[1:], defaults[1:]
        if framework in ("django", "drf") and args and args[0].arg in ("request", "req"):
            args, defaults = args[1:], defaults[1:]
        for a, d in zip(args, defaults):
            n = a.arg
            if framework == "fastapi":
                dtext = unparse(d) if d is not None else ""
                ann = unparse(a.annotation) if a.annotation is not None else ""
                if dtext.startswith(("Depends", "Security")):
                    kinds = self.guard_from(self.cur_mod, d, "route", dependency=True) if self.cur_mod else []
                    if any(k.kind == "authentication" for k in kinds) or re.search(r"user|current|auth|principal", n + dtext, re.I):
                        env[n] = ArgInfo(text=n, identity=True)
                    continue
                if n in names:
                    env[n] = ArgInfo(text=n, taint=("params", n, False))
                elif dtext.startswith(("Body", "Form")) or (ann in self.model_classes_pydantic):
                    env[n] = ArgInfo(text=n, taint=("body", "*", False))
                elif dtext.startswith(("File",)) or ann.startswith("UploadFile"):
                    env[n] = ArgInfo(text=n, taint=("files", n, False))
                elif ann == "Request":
                    pass
                elif dtext.startswith("Header"):
                    env[n] = ArgInfo(text=n, taint=("headers", n, False))
                else:
                    env[n] = ArgInfo(text=n, taint=("query", n, False))
            else:
                if n not in ("request", "req"):
                    env[n] = ArgInfo(text=n, taint=("params", n, False))
        return env

    @property
    def model_classes_pydantic(self):
        if not hasattr(self, "_pyd"):
            self._pyd = {n for m in self.mods.values() for n, c in m.classes.items()
                         if re.search(r"BaseModel|SQLModel", " ".join(unparse(b) for b in c.bases))}
        return self._pyd

    # ------------------------------------------------------------------ entries
    def make_entry(self, mod, fn, method, path, framework, guards, group, name=None, env=None, line=None, extra_notes=(), response_model=False):
        ep = EntryPoint(method=method, path=path or "/", framework=framework, file=mod.path, line=line or lineno(fn), group=group,
                        handler=name or fn.name)
        facts = self.analyze(mod, fn, framework, env=env if env is not None else {})
        ep.facts = facts
        if response_model:
            for r in facts.responses:
                for a in [r.arg] + list(r.arg.keys.values()):
                    if a.origin:
                        a.origin["projected"] = True
        ep.end_line = getattr(fn, "end_lineno", lineno(fn))
        ep.source = trim_source("\n".join(mod.lines[lineno(fn) - 1: ep.end_line]), 60)
        ep.guards = self._dedupe(guards)
        ep.notes += list(extra_notes)
        self.project.frameworks.add(framework)
        key = (ep.method, ep.path, ep.file, ep.line, ep.group)
        if key not in self.seen:
            self.seen.add(key)
            self.project.entry_points.append(ep)
        return ep

    @staticmethod
    def _dedupe(gs):
        seen, out = set(), []
        for g in gs:
            k = (g.name, g.kind, g.file, g.line)
            if k not in seen:
                seen.add(k)
                out.append(g)
        return out

    # ------------------------------------------------------------------ Flask / FastAPI
    def run(self):
        self.cur_mod = None
        self.collect_settings()
        for mod in self.mods.values():
            self.collect_objects(mod)
        self.build_flask_fastapi()
        self.build_django()
        for mod in self.mods.values():
            self.signals(mod)
        if self.mods:
            self.project.extractors_used.append("python (ast: Flask, FastAPI, Django/DRF)")

    def collect_objects(self, mod):
        mod.objs = {}          # name -> {"kind": app|bp|router, "prefix":..., "deps": [...], "framework":...}
        mod.mounts = []        # (parent_name, child_node, prefix, deps_nodes, line)
        mod.hooks = {}         # obj name -> [fn]
        mod.routes = []        # (obj, fn, methods, path, decorator_index, decorators, kwargs)
        mod.resources = []     # (obj, class_node, path)
        mod.url_rules = []
        for node in ast.walk(mod.tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                ctext = callee_text(node.value.func)
                short = ctext.split(".")[-1]
                kw = {k.arg: k.value for k in node.value.keywords if k.arg}
                name = node.targets[0].id
                if short == "Flask":
                    mod.objs[name] = {"kind": "app", "framework": "flask", "prefix": "", "deps": []}
                    sf = const_str(kw.get("static_folder")) if "static_folder" in kw else None
                    if sf in (".", "./", "/", ""):
                        self.project.signals.append(Signal("A01-INSECURE-DEFAULTS", mod.path, lineno(node), mod.lines[lineno(node) - 1].strip(),
                                                           cwe=538, confidence="high", detail="Flask static_folder points at the project root",
                                                           extra={"kind": "root-static"}))
                    elif sf:
                        self.project.static_dirs.append(sf.strip("./"))
                elif short == "Blueprint":
                    mod.objs[name] = {"kind": "bp", "framework": "flask", "prefix": _route_path(kw.get("url_prefix")) or "", "deps": []}
                elif short == "FastAPI":
                    mod.objs[name] = {"kind": "app", "framework": "fastapi", "prefix": "", "deps": self._deps(kw)}
                elif short == "APIRouter":
                    mod.objs[name] = {"kind": "router", "framework": "fastapi", "prefix": _route_path(kw.get("prefix")) or "", "deps": self._deps(kw)}
                elif short in ("Api", "Resource_Api") and node.value.args:
                    mod.objs[name] = {"kind": "api", "framework": "flask", "prefix": "", "deps": []}
                elif short in ("DefaultRouter", "SimpleRouter"):
                    mod.objs[name] = {"kind": "drf-router", "framework": "drf", "prefix": "", "deps": []}
        for node in ast.walk(mod.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for idx, d in enumerate(node.decorator_list):
                    if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and isinstance(d.func.value, ast.Name)):
                        if isinstance(d, ast.Attribute) and isinstance(d.value, ast.Name) and d.attr in ("before_request", "before_app_request"):
                            mod.hooks.setdefault(d.value.id, []).append(node)
                        continue
                    obj = d.func.value.id
                    attr = d.func.attr
                    if obj not in mod.objs:
                        continue
                    kw = {k.arg: k.value for k in d.keywords if k.arg}
                    if attr in ROUTE_VERBS or attr in ("route", "api_route", "websocket"):
                        path = _route_path(d.args[0]) if d.args else _route_path(kw.get("path"))
                        if path is None:
                            continue
                        if attr in ROUTE_VERBS:
                            methods = [attr.upper()]
                        else:
                            m = kw.get("methods")
                            methods = [const_str(e).upper() for e in m.elts if const_str(e)] if isinstance(m, (ast.List, ast.Tuple)) else ["GET"]
                        mod.routes.append((obj, node, methods, path, idx, node.decorator_list, kw))
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                obj, attr = node.func.value.id, node.func.attr
                kw = {k.arg: k.value for k in node.keywords if k.arg}
                if attr == "register_blueprint" and node.args:
                    mod.mounts.append((obj, node.args[0], _route_path(kw.get("url_prefix")), [], lineno(node)))
                elif attr == "include_router" and node.args:
                    mod.mounts.append((obj, node.args[0], _route_path(kw.get("prefix")) or "", self._deps(kw), lineno(node)))
                elif attr == "add_url_rule" and node.args:
                    path = _route_path(node.args[0])
                    view = kw.get("view_func") or (node.args[2] if len(node.args) > 2 else None)
                    m = kw.get("methods")
                    methods = [const_str(e).upper() for e in m.elts if const_str(e)] if isinstance(m, (ast.List, ast.Tuple)) else ["GET"]
                    if path and view is not None:
                        mod.url_rules.append((obj, view, methods, path, lineno(node)))
                elif attr == "add_resource" and len(node.args) >= 2:
                    mod.resources.append((obj, node.args[0], [_route_path(a) for a in node.args[1:] if _route_path(a)], lineno(node)))
                elif attr == "mount" and node.args and len(node.args) >= 2 and "StaticFiles" in unparse(node.args[1]):
                    for k in node.args[1].keywords:
                        if k.arg == "directory" and const_str(k.value):
                            d = const_str(k.value)
                            if d in (".", "./", "/", ""):
                                self.project.signals.append(Signal("A01-INSECURE-DEFAULTS", mod.path, lineno(node), mod.lines[lineno(node) - 1].strip(),
                                                                   cwe=538, confidence="high", detail="StaticFiles serves the project root",
                                                                   extra={"kind": "root-static"}))
                            else:
                                self.project.static_dirs.append(d.strip("./"))
                elif attr == "add_middleware" and node.args:
                    self._fastapi_middleware(mod, node)

    def _deps(self, kw):
        d = kw.get("dependencies")
        return list(d.elts) if isinstance(d, (ast.List, ast.Tuple)) else []

    def build_flask_fastapi(self):
        mounted = {}
        for path, mod in self.mods.items():
            for parent, child, prefix, deps, line in mod.mounts:
                res = self.resolve(mod, child)
                if res is None:
                    continue
                cmod = res[0] or mod
                cname = res[2]
                if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name) and child.value.id in mod.imports:
                    t = mod.imports[child.value.id][0]
                    cmod, cname = self.mods.get(t, mod), child.attr
                if isinstance(child, ast.Name) and child.id in mod.objs:
                    cmod, cname = mod, child.id
                if cname in getattr(cmod, "objs", {}):
                    mounted.setdefault((cmod.path, cname), []).append((mod, parent, prefix, deps))
        roots = [(m.path, n) for m in self.mods.values() for n, o in m.objs.items()
                 if o["framework"] in ("flask", "fastapi") and o["kind"] in ("app", "bp", "router") and (m.path, n) not in mounted]
        if not roots and not any(m.objs for m in self.mods.values()):
            return
        for key in roots:
            self.walk_obj(key, "", [], set(), 0)
        # flask-restful resources
        for mod in self.mods.values():
            for obj, cls_node, paths, line in mod.resources:
                self.restful(mod, obj, cls_node, paths, line)

    def walk_obj(self, key, prefix, inherited, seen, depth):
        if key in seen or depth > 6:
            return
        seen = seen | {key}
        mod = self.mods[key[0]]
        obj = mod.objs[key[1]]
        fw = obj["framework"]
        own = prefix if depth else join_path(prefix, obj["prefix"])
        guards_here = list(inherited)
        for dep in obj["deps"]:
            guards_here += self.guard_from(mod, dep, "router" if depth else "global", dependency=True)
        for fn in mod.hooks.get(key[1], []):
            fo = PyFailOpen(fn, (), fallthrough_proceeds=True).run()
            facts = self.analyze(mod, fn, "flask")
            kinds = self._code_kinds(facts) or {k for k in P.classify_guard_name(fn.name)}
            for k in kinds:
                g = Guard(name=f"before_request:{fn.name}", kind=k, scope="global" if obj["kind"] == "app" else "router", certainty="code",
                          file=mod.path, line=lineno(fn), evidence=f"@{key[1]}.before_request", source=trim_source("\n".join(mod.lines[lineno(fn) - 1: fn.end_lineno]), 40))
                g.identity_source, g.identity_evidence = self._identity_source(facts)
                if fo and k in ("authentication", "authorization"):
                    g.fails_open, g.fail_open_reason, g.fail_open_line = True, fo[0]["reason"], fo[0]["line"]
                guards_here.append(g)
                self.project.guards.append(g)
        self.cur_mod = mod
        for (o, fn, methods, path, idx, decos, kw) in mod.routes:
            if o != key[1]:
                continue
            full = join_path(own, path)
            gs = list(guards_here)
            notes = []
            for dep in self._deps(kw):
                gs += self.guard_from(mod, dep, "route", dependency=True)
            for i, d in enumerate(decos):
                if i == idx:
                    continue
                if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ROUTE_VERBS | {"route"}:
                    continue
                found = self.guard_from(mod, d, "route")
                if fw == "flask" and i < idx and found:
                    for g in found:
                        if g.kind in ("authentication", "authorization"):
                            notes.append(f"guard_above_route:{g.name}")
                    found = []   # decorators above @route never wrap the registered view
                gs += found
            env = self.param_env(fn, full, fw)
            for m in methods:
                self.make_entry(mod, fn, m, full, fw, gs, f"{key[0]}:{key[1]}", env=env, extra_notes=notes,
                                response_model="response_model" in kw)
        for (o, view, methods, path, line) in mod.url_rules:
            if o != key[1]:
                continue
            res = self.resolve(mod, view)
            if res and isinstance(res[1], (ast.FunctionDef, ast.AsyncFunctionDef)):
                full = join_path(own, path)
                gs = list(guards_here)
                for d in res[1].decorator_list:
                    gs += self.guard_from(res[0], d, "route")
                for m in methods:
                    self.make_entry(res[0], res[1], m, full, "flask", gs, f"{key[0]}:{key[1]}", env=self.param_env(res[1], full, "flask"), line=lineno(res[1]))
        # children
        for parent, child, pfx, deps, line in mod.mounts:
            if parent != key[1]:
                continue
            res = self.resolve(mod, child)
            cmod, cname = (res[0] or mod, res[2]) if res else (mod, None)
            if isinstance(child, ast.Name) and child.id in mod.objs:
                cmod, cname = mod, child.id
            elif isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name) and child.value.id in mod.imports:
                cmod = self.mods.get(mod.imports[child.value.id][0], mod)
                cname = child.attr
            if cname and cname in getattr(cmod, "objs", {}):
                cobj = cmod.objs[cname]
                child_prefix = join_path(own, pfx if pfx is not None else cobj["prefix"]) if fw == "flask" else join_path(own, (pfx or "") + cobj["prefix"])
                mg = []
                for dep in deps:
                    mg += self.guard_from(mod, dep, "router", dependency=True)
                self.walk_obj((cmod.path, cname), child_prefix, guards_here + mg, seen, depth + 1)

    def restful(self, mod, obj, cls_node, paths, line):
        res = self.resolve(mod, cls_node)
        if not res or not isinstance(res[1], ast.ClassDef):
            return
        cmod, cls = res[0], res[1]
        gs = []
        for item in cls.body:
            if isinstance(item, ast.Assign) and isinstance(item.targets[0], ast.Name) and item.targets[0].id == "method_decorators":
                for d in getattr(item.value, "elts", []):
                    gs += self.guard_from(cmod, d, "controller")
        for path in paths:
            for mname in HTTP_METHOD_FUNCS:
                fn = cmod.funcs.get(f"{cls.name}.{mname}")
                if fn is not None:
                    full = join_path("", path)
                    self.make_entry(cmod, fn, mname.upper(), full, "flask", gs + [g for d in fn.decorator_list for g in self.guard_from(cmod, d, "route")],
                                    f"{cmod.path}:{cls.name}", name=f"{cls.name}.{mname}", env=self.param_env(fn, full, "flask"))

    def _fastapi_middleware(self, mod, call):
        if not call.args or "CORSMiddleware" not in unparse(call.args[0]):
            return
        kw = {k.arg: k.value for k in call.keywords if k.arg}
        origins = kw.get("allow_origins")
        cred = isinstance(kw.get("allow_credentials"), ast.Constant) and kw["allow_credentials"].value is True
        has_star = isinstance(origins, (ast.List, ast.Tuple)) and any(const_str(e) == "*" for e in origins.elts)
        rx = const_str(kw.get("allow_origin_regex")) if "allow_origin_regex" in kw else None
        line = lineno(call)
        text = mod.lines[line - 1].strip()
        if rx is not None and (rx in (".*", ".+") or not rx.endswith("$")):
            self.project.signals.append(Signal("A01-CORS", mod.path, line, text, detail="CORS allow_origin_regex is broad/unanchored",
                                               confidence="high", extra={"origin": "regex", "credentials": cred}))
        elif has_star:
            self.project.signals.append(Signal("A01-CORS", mod.path, line, text, detail="CORS allow_origins=['*']", confidence="high",
                                               extra={"origin": "wildcard", "credentials": cred}))

    # ------------------------------------------------------------------ settings / signals
    def collect_settings(self):
        gs = self.project.global_security
        for mod in self.mods.values():
            for name, value in mod.assigns.items():
                line = next((lineno(n) for n in ast.walk(mod.tree) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)), 1)
                if name == "REST_FRAMEWORK" and isinstance(value, ast.Dict):
                    gs["found"] = True
                    keys = {const_str(k): v for k, v in zip(value.keys, value.values) if const_str(k)}
                    perms = keys.get("DEFAULT_PERMISSION_CLASSES")
                    names = [unparse(e).split(".")[-1] for e in getattr(perms, "elts", [])]
                    if perms is None or "AllowAny" in names:
                        gs["notes"].append(f"DRF DEFAULT_PERMISSION_CLASSES is {'AllowAny' if perms is not None else 'unset (defaults to AllowAny)'} ({mod.path})")
                        if perms is not None:
                            gs["default_allow_all"] = (mod.path, line)
                    elif any(n in ("IsAuthenticated", "IsAdminUser", "DjangoModelPermissions") for n in names):
                        gs["default_authn"] = True
                        gs["notes"].append(f"DRF default permission classes require authentication ({mod.path})")
                    self.project.frameworks.add("drf")
                elif name == "MIDDLEWARE" and isinstance(value, (ast.List, ast.Tuple)):
                    gs["found"] = True
                    items = [const_str(e) or "" for e in value.elts]
                    if any(i.endswith("CsrfViewMiddleware") for i in items):
                        gs["csrf_default"]["django"] = True
                    else:
                        gs["csrf_disabled"].append((mod.path, line, "MIDDLEWARE lacks CsrfViewMiddleware"))
                    if any(i.endswith("LoginRequiredMiddleware") for i in items):
                        gs["default_authn"] = True
                    if any(i.endswith("SessionMiddleware") for i in items):
                        self.project.cookie_auth = True
                    self.project.frameworks.add("django")
                elif name in ("CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL") and isinstance(value, ast.Constant) and value.value is True:
                    cred = "CORS_ALLOW_CREDENTIALS" in mod.assigns and unparse(mod.assigns["CORS_ALLOW_CREDENTIALS"]) == "True"
                    self.project.signals.append(Signal("A01-CORS", mod.path, line, mod.lines[line - 1].strip(), detail=f"{name} = True reflects every origin",
                                                       confidence="high", extra={"origin": "reflected", "credentials": cred}))
                elif name in ("SESSION_COOKIE_SAMESITE", "CSRF_COOKIE_SAMESITE") and const_str(value) in ("Lax", "Strict"):
                    self.project.samesite_configured = True
                elif name == "WTF_CSRF_ENABLED" and isinstance(value, ast.Constant) and value.value is False:
                    gs["csrf_disabled"].append((mod.path, line, "WTF_CSRF_ENABLED = False"))
        for mod in self.mods.values():
            for node in ast.walk(mod.tree):
                if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Subscript) and "config" in unparse(node.targets[0]):
                    key = const_str(node.targets[0].slice)
                    if key == "WTF_CSRF_ENABLED" and isinstance(node.value, ast.Constant) and node.value.value is False:
                        gs["csrf_disabled"].append((mod.path, lineno(node), "WTF_CSRF_ENABLED = False"))
                    if key and key.endswith("SAMESITE") and const_str(node.value) in ("Lax", "Strict"):
                        self.project.samesite_configured = True
                if isinstance(node, ast.Call):
                    ct = callee_text(node.func)
                    if ct.endswith("config.update"):
                        for kwd in node.keywords:
                            if kwd.arg and kwd.arg.endswith("SAMESITE") and const_str(kwd.value) in ("Lax", "Strict"):
                                self.project.samesite_configured = True
                            if kwd.arg == "WTF_CSRF_ENABLED" and isinstance(kwd.value, ast.Constant) and kwd.value.value is False:
                                gs["csrf_disabled"].append((mod.path, lineno(node), "WTF_CSRF_ENABLED = False"))
                    if ct.endswith("CSRFProtect") or ct.endswith("CSRFProtect.init_app") or ct.endswith("CsrfProtect"):
                        gs["csrf_default"]["flask"] = True
                        gs["csrf_default"]["fastapi"] = True
                    if ct.endswith("LoginManager") or ct.endswith("login_user") or ct.endswith("SessionMiddleware") or ct.endswith("flask_session.Session"):
                        self.project.cookie_auth = True
                if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == "session":
                    self.project.cookie_auth = True

    def signals(self, mod):
        for node in ast.walk(mod.tree):
            if not isinstance(node, ast.Call):
                continue
            callee = callee_text(node.func)
            short = callee.split(".")[-1]
            line = lineno(node)
            text = mod.lines[line - 1].strip() if line <= len(mod.lines) else ""
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            if short == "CORS" and callee in ("CORS", "flask_cors.CORS") or (short == "CORS" and "flask_cors" in unparse(mod.tree)[:3000]):
                origins = kw.get("origins") or kw.get("resources")
                cred = isinstance(kw.get("supports_credentials"), ast.Constant) and kw["supports_credentials"].value is True
                star = origins is None or const_str(origins) == "*" or (isinstance(origins, (ast.List, ast.Tuple)) and any(const_str(e) == "*" for e in origins.elts)) \
                    or (isinstance(origins, ast.Dict) and "*" in unparse(origins))
                if star:
                    self.project.signals.append(Signal("A01-CORS", mod.path, line, text, confidence="high" if origins is not None else "medium",
                                                       detail="Flask-CORS allows every origin" + ("" if origins is not None else " (default)"),
                                                       extra={"origin": "wildcard" if origins is not None else "default", "credentials": cred}))
            elif callee in ("os.chmod", "os.fchmod") and len(node.args) >= 2:
                mode = node.args[1].value if isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, int) else None
                if mode is not None and mode & 0o002:
                    self.project.signals.append(Signal("A01-INSECURE-DEFAULTS", mod.path, line, text, cwe=732, confidence="high",
                                                       detail=f"world-writable permissions (mode {oct(mode)})"))
            elif callee in ("os.makedirs", "os.mkdir") and "mode" in kw and isinstance(kw["mode"], ast.Constant) and isinstance(kw["mode"].value, int) and kw["mode"].value & 0o002:
                self.project.signals.append(Signal("A01-INSECURE-DEFAULTS", mod.path, line, text, cwe=732, confidence="high",
                                                   detail=f"world-writable directory (mode {oct(kw['mode'].value)})"))
            elif callee == "os.umask" and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == 0:
                self.project.signals.append(Signal("A01-INSECURE-DEFAULTS", mod.path, line, text, cwe=276, confidence="medium",
                                                   detail="umask(0) makes new files world-writable"))
            elif callee == "send_from_directory" and node.args and (const_str(node.args[0]) in (".", "./", "/") or "getcwd" in unparse(node.args[0])):
                self.project.signals.append(Signal("A01-INSECURE-DEFAULTS", mod.path, line, text, cwe=538, confidence="high",
                                                   detail="send_from_directory serves the project root", extra={"kind": "root-static"}))
            elif callee in ("jwt.encode", "pyjwt.encode") and node.args and isinstance(node.args[0], ast.Dict):
                keys = {const_str(k) for k in node.args[0].keys if k is not None}
                if "exp" not in keys:
                    self.project.signals.append(Signal("A01-TOKEN-SESSION", mod.path, line, text, cwe=613, confidence="high",
                                                       detail="JWT issued without an exp claim"))

    # ------------------------------------------------------------------ Django / DRF
    def build_django(self):
        url_mods = {p: m for p, m in self.mods.items() if "urlpatterns" in m.assigns}
        if not url_mods:
            return
        included = set()
        for p, m in url_mods.items():
            for call in ast.walk(m.assigns["urlpatterns"]):
                if isinstance(call, ast.Call) and callee_text(call.func).split(".")[-1] == "include" and call.args:
                    target = const_str(call.args[0])
                    if target:
                        t = dotted_to_path(self.paths, target)
                        if t:
                            included.add(t)
        for p, m in url_mods.items():
            if p not in included:
                self.walk_urls(m, "", [], set(), 0)

    def walk_urls(self, mod, prefix, inherited, seen, depth):
        if mod.path in seen or depth > 6:
            return
        seen = seen | {mod.path}
        up = mod.assigns.get("urlpatterns")
        if up is None:
            return
        self.cur_mod = mod
        elts = list(getattr(up, "elts", []))
        # urlpatterns += [...] / router.urls
        for node in mod.tree.body:
            if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id == "urlpatterns":
                elts += list(getattr(node.value, "elts", []))
        for e in elts:
            if not (isinstance(e, ast.Call) and callee_text(e.func).split(".")[-1] in ("path", "re_path", "url")) or not e.args:
                continue
            route = _route_path(e.args[0]) or ""
            full = join_path(prefix, route)
            view = e.args[1] if len(e.args) > 1 else None
            if view is None:
                continue
            if isinstance(view, ast.Call) and callee_text(view.func).split(".")[-1] == "include" and view.args:
                inc = view.args[0]
                t = const_str(inc)
                if t:
                    path = dotted_to_path(self.paths, t)
                    if path in self.mods:
                        self.walk_urls(self.mods[path], full, inherited, seen, depth + 1)
                elif isinstance(inc, ast.Attribute) and inc.attr == "urls":
                    self.drf_router(mod, inc.value, full, inherited)
                continue
            self.django_view(mod, view, full, inherited)
        for name, obj in getattr(mod, "objs", {}).items():
            pass

    def drf_router(self, mod, router_node, prefix, inherited):
        name = router_node.id if isinstance(router_node, ast.Name) else None
        for node in ast.walk(mod.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "register" \
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == name and len(node.args) >= 2:
                route = _route_path(node.args[0]) or ""
                res = self.resolve(mod, node.args[1])
                if res and isinstance(res[1], ast.ClassDef):
                    self.drf_class(res[0], res[1], join_path(prefix, route), inherited, viewset=True)

    def django_view(self, mod, view, path, inherited):
        node = view
        mapping = None
        if isinstance(view, ast.Call) and callee_text(view.func).endswith("as_view"):
            if view.args and isinstance(view.args[0], ast.Dict):
                mapping = {const_str(k): const_str(v) for k, v in zip(view.args[0].keys, view.args[0].values) if const_str(k)}
            node = view.func.value if isinstance(view.func, ast.Attribute) else view
        res = self.resolve(mod, node)
        if not res or res[1] is None:
            return
        vmod, vdef = res[0], res[1]
        if isinstance(vdef, ast.ClassDef):
            self.drf_class(vmod, vdef, path, inherited, viewset=False, mapping=mapping)
            return
        gs = list(inherited)
        methods, notes = None, []
        for d in vdef.decorator_list:
            dtxt = unparse(d)
            if dtxt.startswith("csrf_exempt") or dtxt.endswith(".csrf_exempt"):
                notes.append("csrf_exempt")
                continue
            if isinstance(d, ast.Call) and callee_text(d.func).split(".")[-1] == "api_view":
                ms = [const_str(e).upper() for e in getattr(d.args[0], "elts", []) if const_str(e)] if d.args else ["GET"]
                methods = ms or ["GET"]
                continue
            if isinstance(d, ast.Call) and callee_text(d.func).split(".")[-1] in ("require_http_methods", "require_methods"):
                methods = [const_str(e).upper() for e in getattr(d.args[0], "elts", []) if const_str(e)]
                continue
            if dtxt in ("require_POST",):
                methods = ["POST"]
                continue
            if dtxt in ("require_GET",):
                methods = ["GET"]
                continue
            if isinstance(d, ast.Call) and callee_text(d.func).split(".")[-1] == "permission_classes":
                for e in getattr(d.args[0], "elts", []) if d.args else []:
                    gs += self.guard_from(vmod, e, "route")
                continue
            gs += self.guard_from(vmod, d, "route")
        framework = "drf" if any("api_view" in unparse(d) for d in vdef.decorator_list) else "django"
        env = self.param_env(vdef, path, framework)
        for m in (methods or ["ANY"]):
            self.make_entry(vmod, vdef, m, path, framework, gs, f"{vmod.path}:urls", env=env, extra_notes=notes)

    def drf_class(self, mod, cls, path, inherited, viewset=False, mapping=None):
        bases = [unparse(b).split(".")[-1] for b in cls.bases]
        attrs = {}
        for item in cls.body:
            if isinstance(item, ast.Assign) and isinstance(item.targets[0], ast.Name):
                attrs[item.targets[0].id] = item.value
        gs = list(inherited)
        notes = []
        if "LoginRequiredMixin" in bases or "AccessMixin" in bases:
            gs.append(Guard(name="LoginRequiredMixin", kind="authentication", scope="controller", certainty="code", file=mod.path,
                            line=lineno(cls), evidence="LoginRequiredMixin", identity_source="verified"))
        if "PermissionRequiredMixin" in bases or "UserPassesTestMixin" in bases:
            gs.append(Guard(name=[b for b in bases if "Mixin" in b][0], kind="authorization", scope="controller", certainty="code",
                            file=mod.path, line=lineno(cls), evidence="mixin"))
        for d in cls.decorator_list:
            gs += self.guard_from(mod, d, "controller")
        perms = attrs.get("permission_classes")
        if perms is not None:
            for e in getattr(perms, "elts", []):
                gs += self.guard_from(mod, e, "controller")
        for mname, mnode in (("authentication_classes", attrs.get("authentication_classes")),):
            pass
        for d in [b for b in cls.bases]:
            pass
        is_drf = any(b in VIEWSET_BASES or b in ("APIView", "GenericAPIView") or b.endswith(("ViewSet", "APIView")) for b in bases)
        fw = "drf" if is_drf else "django"
        model = None
        qs = attrs.get("queryset")
        if qs is not None:
            m = re.match(r"([A-Z]\w*)\.", unparse(qs))
            model = m.group(1) if m else None
        scoped = False
        gq = mod.funcs.get(f"{cls.name}.get_queryset")
        if gq is not None:
            f2 = self.analyze(mod, gq, fw)
            scoped = f2.uses_identity or any(a.identity for c in f2.calls for a in c.args) or \
                any(v.identity for c in f2.calls for a in c.args for v in a.keys.values())
            m2 = next((c.callee.split(".")[0] for c in f2.calls if ".objects" in c.callee or c.callee.split(".")[-1] in ("filter", "all")), None)
            model = model or m2
        serializer = attrs.get("serializer_class")
        implied = set()
        for b in bases:
            implied |= VIEWSET_BASES.get(b, set())
        defined = {n.name for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        actions = {}
        if mapping:
            for http, action in mapping.items():
                actions[http.upper()] = action
        elif viewset:
            for a in VIEWSET_ACTIONS:
                if a in defined or a in implied:
                    http, sub = VIEWSET_ACTIONS[a]
                    actions[(http, sub)] = a
        else:
            for h in HTTP_METHOD_FUNCS:
                if h in defined:
                    actions[h.upper()] = h
            for a in implied:
                http, sub = VIEWSET_ACTIONS.get(a, (None, ""))
                if http and http not in actions:
                    actions[http] = a
        for http_key, action in actions.items():
            if isinstance(http_key, tuple):
                http, sub = http_key
            else:
                http, sub = http_key, ("/:pk" if action in ("retrieve", "update", "partial_update", "destroy") and "pk" not in path else "")
            full = join_path(path, sub)
            fn = mod.funcs.get(f"{cls.name}.{action}")
            method_guards = list(gs)
            if fn is not None:
                for d in fn.decorator_list:
                    method_guards += self.guard_from(mod, d, "route")
                env = self.param_env(fn, full, fw)
                ep = self.make_entry(mod, fn, http, full, fw, method_guards, f"{mod.path}:{cls.name}", name=f"{cls.name}.{action}", env=env,
                                     extra_notes=notes)
                if scoped:
                    ep.facts.ownership_check_inline = True
            else:
                ep = self.synth_entry(mod, cls, http, full, fw, method_guards, action, model, scoped, serializer)
            if fw == "django":
                pass

    def synth_entry(self, mod, cls, http, path, fw, guards, action, model, scoped, serializer):
        """Generic DRF action (no source of its own): facts are derived from queryset/serializer metadata."""
        facts = HandlerFacts()
        pk = ArgInfo(text="pk", taint=("params", "pk", False))
        mname = model or "?"
        if action in ("retrieve", "update", "partial_update", "destroy"):
            facts.calls.append(CallRec(callee=f"{mname}.objects.get", args=[ArgInfo(keys={"pk": pk})], line=lineno(cls), text=f"{mname}.objects.get(pk=...)"))
        if action in ("update", "partial_update", "create", "destroy"):
            op = "delete" if action == "destroy" else "save"
            facts.calls.append(CallRec(callee=f"{mname}.objects.{op}", args=[], line=lineno(cls), text=f"{mname}.{op}()"))
        if action in ("create", "update", "partial_update") and serializer is not None:
            sname = unparse(serializer)
            sres = self.resolve(mod, ast.Name(id=sname))
            dm = self.model_map.get(mname)
            priv = [f for f in (dm.privileged if dm else [])]
            if priv and sres and sres[1] is not None and self._serializer_writes_all(sres[1]):
                facts.calls.append(CallRec(callee=f"new {mname}", args=[ArgInfo(text="request.data", taint=("body", "*", False), spread_taint=True)],
                                           line=lineno(cls), text=f"{sname}(data=request.data).save()"))
        if action in ("list", "retrieve"):
            facts.responses.append(ResponseRec("return", ArgInfo(text=f"{mname}.objects.all()", origin={"model": mname, "op": "all", "projected": True,
                                                                                                      "collection": action == "list", "line": lineno(cls)}), None, lineno(cls)))
        facts.ownership_check_inline = scoped
        facts.reads = {"params": ["pk"]} if "pk" in path else {}
        facts.uses_identity = scoped
        ep = EntryPoint(method=http, path=path, framework=fw, file=mod.path, line=lineno(cls), group=f"{mod.path}:{cls.name}",
                        handler=f"{cls.name}.{action}", facts=facts, end_line=getattr(cls, "end_lineno", lineno(cls)),
                        source=trim_source("\n".join(mod.lines[lineno(cls) - 1: getattr(cls, "end_lineno", lineno(cls))]), 40), guards=self._dedupe(guards))
        self.project.frameworks.add(fw)
        key = (ep.method, ep.path, ep.file, ep.line, ep.group)
        if key not in self.seen:
            self.seen.add(key)
            self.project.entry_points.append(ep)
        return ep

    def _serializer_writes_all(self, cls):
        for item in cls.body:
            if isinstance(item, ast.ClassDef) and item.name == "Meta":
                f = None
                ro = False
                for st in item.body:
                    if isinstance(st, ast.Assign) and isinstance(st.targets[0], ast.Name):
                        if st.targets[0].id == "fields":
                            f = st.value
                        if st.targets[0].id == "read_only_fields":
                            ro = True
                return const_str(f) == "__all__" and not ro
        return False


def extract(files: dict, project: Project, side_of, config=None):
    ex = PyExtractor(files, project, side_of, config)
    ex.run()
    return ex
