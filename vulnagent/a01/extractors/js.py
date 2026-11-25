"""JavaScript / TypeScript extractor (tree-sitter).

Frameworks: Express, Fastify, Koa (koa-router), NestJS, Next.js API routes.
Structure (routes, mounts, guards, handlers) is discovered only from parsed
nodes; regular expressions only classify text inside an already-parsed node.
"""

from __future__ import annotations

import posixpath
import re

from .. import patterns as P
from ..ir import (ArgInfo, AssignRec, CallRec, CompareRec, DataModel, EntryPoint, Guard, HandlerFacts, Project,
                  ResponseRec, Signal)
from .base import guards_from_name, join_path, path_matches_scope, trim_source

try:  # optional dependency (pip install vulnagent[a01])
    import tree_sitter_javascript as _tsj
    import tree_sitter_typescript as _tst
    from tree_sitter import Language, Parser
    AVAILABLE = True
except Exception:  # pragma: no cover - exercised when the extra is not installed
    AVAILABLE = False

EXTS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "all"}
FUNC_TYPES = {"function_declaration", "function_expression", "function", "arrow_function", "method_definition",
              "generator_function", "generator_function_declaration"}
PASSTHROUGH = {"toString", "trim", "toLowerCase", "toUpperCase", "replace", "slice", "substring", "substr", "concat",
               "split", "join", "normalize", "decodeURIComponent", "decodeURI", "encodeURI", "String", "at", "toLocaleLowerCase"}
CHAIN_PASS = {"select", "lean", "populate", "sort", "limit", "skip", "exec", "then", "orFail", "toArray", "cursor",
              "catch", "finally", "where", "eager", "withGraphFetched", "first", "clone"}
RES_CHAIN_NOISE = {"status", "code", "header", "set", "type", "setHeader", "contentType", "cookie", "links", "append",
                   "vary", "attachment", "location", "setStatus", "clearCookie"}
HTTP_STATUS_CALLS = {"status", "code", "setStatus", "sendStatus"}
NEST_ROUTE = {"Get": "GET", "Post": "POST", "Put": "PUT", "Patch": "PATCH", "Delete": "DELETE", "All": "ANY",
              "Head": "HEAD", "Options": "OPTIONS"}
NEST_IDENTITY = {"CurrentUser", "User", "GetUser", "AuthUser", "ActiveUser", "Identity", "AuthenticatedUser", "UserId"}
NEST_PUBLIC = {"Public", "SkipAuth", "AllowAnonymous", "NoAuth", "IsPublic"}
DENY_RE = re.compile(r"(Unauthorized|Forbidden)(Exception|Error)|\b40[13]\b")


def available() -> bool:
    return AVAILABLE


def _make_parsers():
    js = Parser(Language(_tsj.language()))
    return {".js": js, ".jsx": js, ".mjs": js, ".cjs": js,
            ".ts": Parser(Language(_tst.language_typescript())), ".tsx": Parser(Language(_tst.language_tsx()))}


# ---------------------------------------------------------------------------------------------
# node helpers
# ---------------------------------------------------------------------------------------------
def T(node) -> str:
    return node.text.decode("utf8", "replace") if node is not None else ""


def L(node) -> int:
    return node.start_point[0] + 1


def walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def nk(node):
    return (node.start_byte, node.end_byte, node.type)


def named(node):
    return [c for c in node.children if c.is_named and c.type != "comment"]


def string_value(node):
    """Literal value of a string / template without substitutions / regex, else None."""
    if node is None:
        return None
    if node.type == "string":
        return "".join(T(c) for c in node.children if c.type in ("string_fragment", "escape_sequence"))
    if node.type == "template_string":
        if any(c.type == "template_substitution" for c in node.children):
            return None
        return T(node)[1:-1]
    return None


def template_prefix(node) -> str:
    if node.type == "template_string":
        out = ""
        for c in node.children[1:-1]:
            if c.type == "template_substitution":
                break
            out += T(c)
        return out
    if node.type == "string":
        return string_value(node) or ""
    if node.type == "binary_expression" and T(node.child_by_field_name("operator")) == "+":
        return template_prefix(node.child_by_field_name("left"))
    return ""


def fn_params(fn):
    params = fn.child_by_field_name("parameters")
    if params is not None:
        return named(params)
    single = fn.child_by_field_name("parameter")
    return [single] if single is not None else []


def param_name(p):
    if p is None:
        return None
    if p.type == "identifier":
        return T(p)
    if p.type in ("required_parameter", "optional_parameter"):
        return param_name(p.child_by_field_name("pattern"))
    if p.type == "assignment_pattern":
        return param_name(p.child_by_field_name("left"))
    return None


def fn_body(fn):
    return fn.child_by_field_name("body")


def callee_text(fn_node) -> str:
    """Dotted callee with intermediate call segments removed ('res.status(401).json' -> 'res.json')."""
    parts = []
    node = fn_node
    while node is not None:
        if node.type == "member_expression":
            parts.append(T(node.child_by_field_name("property")))
            node = node.child_by_field_name("object")
        elif node.type == "call_expression":
            node = node.child_by_field_name("function")
        elif node.type == "parenthesized_expression" or node.type == "await_expression" or node.type == "non_null_expression":
            kids = named(node)
            node = kids[0] if kids else None
        elif node.type in ("identifier", "this", "super", "property_identifier"):
            parts.append(T(node))
            node = None
        else:
            parts.append(T(node)[:30])
            node = None
    parts.reverse()
    if parts and parts[0] in ("res", "reply", "response") and len(parts) > 2:
        parts = [parts[0]] + [p for p in parts[1:-1] if p not in RES_CHAIN_NOISE] + [parts[-1]]
    return ".".join(parts)


def chain_status(fn_node):
    node = fn_node
    while node is not None and node.type == "member_expression":
        obj = node.child_by_field_name("object")
        if obj is not None and obj.type == "call_expression":
            inner = obj.child_by_field_name("function")
            if inner is not None and inner.type == "member_expression" and T(inner.child_by_field_name("property")) in HTTP_STATUS_CALLS:
                args = named(obj.child_by_field_name("arguments"))
                if args and args[0].type == "number":
                    try:
                        return int(T(args[0]))
                    except ValueError:
                        return None
            node = inner
        else:
            node = obj
    return None


def parse_int_literal(text: str):
    t = text.strip().replace("_", "")
    try:
        if t.lower().startswith("0o"):
            return int(t[2:], 8)
        if len(t) > 1 and t.startswith("0") and t.isdigit():
            return int(t, 8)
        return int(t, 0)
    except ValueError:
        return None


def resolve_module(from_path: str, spec: str, paths: set):
    if not spec or not spec.startswith("."):
        return None
    base = posixpath.normpath(posixpath.join(posixpath.dirname(from_path), spec))
    candidates = [base] + [base + e for e in EXTS] + [posixpath.join(base, "index" + e) for e in EXTS]
    stem = re.sub(r"\.(js|jsx|mjs|cjs)$", "", base)
    candidates += [stem + e for e in (".ts", ".tsx")]
    for c in candidates:
        if c in paths:
            return c
    return None


# ---------------------------------------------------------------------------------------------
# per-file index
# ---------------------------------------------------------------------------------------------
class JsFile:
    def __init__(self, path, source, parsers, paths):
        self.path, self.source, self.paths = path, source, paths
        ext = posixpath.splitext(path)[1].lower()
        self.tree = parsers[ext].parse(source.encode("utf8", "replace"))
        self.root = self.tree.root_node
        self.has_error = self.root.has_error
        self.funcs, self.imports, self.routers = {}, {}, {}
        self.exports = {"default": None, "names": {}}
        self.ops, self.classes = [], []
        self.models = []
        self._index()

    # -- indexing ------------------------------------------------------------------------------
    def _bind_require(self, name_node, call):
        fn = call.child_by_field_name("function")
        if fn is None or T(fn) != "require":
            return False
        args = named(call.child_by_field_name("arguments"))
        spec = string_value(args[0]) if args else None
        target = resolve_module(self.path, spec or "", self.paths)
        if name_node.type == "identifier":
            self.imports[T(name_node)] = (target, "default", spec)
        elif name_node.type == "object_pattern":
            for c in named(name_node):
                if c.type == "shorthand_property_identifier_pattern":
                    self.imports[T(c)] = (target, T(c), spec)
                elif c.type == "pair_pattern":
                    key, val = c.child_by_field_name("key"), c.child_by_field_name("value")
                    self.imports[T(val)] = (target, T(key), spec)
        return True

    def _router_kind(self, value):
        if value is None:
            return None
        node = value
        if node.type == "new_expression":
            ctor = T(node.child_by_field_name("constructor"))
            return "router" if ctor in ("Router", "KoaRouter", "Koa", "Hono") else None
        if node.type == "call_expression":
            fn = T(node.child_by_field_name("function"))
            if fn in ("express", "fastify", "Fastify", "restify.createServer", "polka", "connect", "Router", "express.Router",
                      "express.application", "KoaRouter", "createRouter", "new Router", "require('koa-router')",
                      "require('express').Router", "require('express')", "require(\"express\").Router", "require(\"express\")"):
                return "router"
            if fn.startswith("require(") and ("router" in fn.lower() or "express" in fn.lower()):
                return "router"
        return None

    def _index(self):
        for node in walk(self.root):
            t = node.type
            if t == "variable_declarator":
                name, value = node.child_by_field_name("name"), node.child_by_field_name("value")
                if name is None or value is None:
                    continue
                inner = value
                while inner.type in ("await_expression", "parenthesized_expression", "as_expression", "non_null_expression"):
                    kids = named(inner)
                    inner = kids[0] if kids else inner
                    if inner is value:
                        break
                if inner.type in ("arrow_function", "function_expression", "function"):
                    if name.type == "identifier":
                        self.funcs[T(name)] = inner
                elif inner.type == "call_expression":
                    if not self._bind_require(name, inner) and name.type == "identifier":
                        if self._router_kind(inner):
                            self.routers[T(name)] = "router"
                elif inner.type == "member_expression":
                    obj = inner.child_by_field_name("object")
                    if obj is not None and obj.type == "call_expression" and T(obj.child_by_field_name("function")) == "require":
                        args = named(obj.child_by_field_name("arguments"))
                        spec = string_value(args[0]) if args else None
                        if name.type == "identifier":
                            self.imports[T(name)] = (resolve_module(self.path, spec or "", self.paths),
                                                     T(inner.child_by_field_name("property")), spec)
                elif inner.type == "new_expression" and name.type == "identifier":
                    if self._router_kind(inner):
                        self.routers[T(name)] = "router"
                    ctor = T(inner.child_by_field_name("constructor"))
                    if ctor in ("Schema", "mongoose.Schema"):
                        self._model_from_schema(T(name), inner)
            elif t == "function_declaration":
                nm = node.child_by_field_name("name")
                if nm is not None:
                    self.funcs[T(nm)] = node
            elif t == "import_statement":
                self._import(node)
            elif t == "assignment_expression":
                self._assignment(node)
            elif t == "export_statement":
                self._export(node)
            elif t == "class_declaration":
                self._class(node)
            elif t == "call_expression":
                self._call_op(node)
                self._model_call(node)
            elif t == "public_field_definition":
                pass
        self.ops.sort(key=lambda o: o["line"])

    def _import(self, node):
        src = node.child_by_field_name("source")
        spec = string_value(src)
        target = resolve_module(self.path, spec or "", self.paths)
        for c in node.children:
            if c.type != "import_clause":
                continue
            for part in c.children:
                if part.type == "identifier":
                    self.imports[T(part)] = (target, "default", spec)
                elif part.type == "named_imports":
                    for spec_node in named(part):
                        nm = spec_node.child_by_field_name("name")
                        alias = spec_node.child_by_field_name("alias")
                        self.imports[T(alias or nm)] = (target, T(nm), spec)
                elif part.type == "namespace_import":
                    ids = [k for k in named(part) if k.type == "identifier"]
                    if ids:
                        self.imports[T(ids[0])] = (target, "*", spec)

    def _assignment(self, node):
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if left is None or right is None:
            return
        lt = T(left)
        if lt in ("module.exports", "exports.default"):
            if right.type == "identifier":
                self.exports["default"] = T(right)
            elif right.type == "object":
                for c in named(right):
                    if c.type == "shorthand_property_identifier":
                        self.exports["names"][T(c)] = T(c)
                    elif c.type == "pair":
                        k, v = c.child_by_field_name("key"), c.child_by_field_name("value")
                        self.exports["names"][T(k)] = T(v) if v.type == "identifier" else None
                        if v.type in ("arrow_function", "function_expression"):
                            self.funcs[f"<export>.{T(k)}"] = v
                            self.exports["names"][T(k)] = f"<export>.{T(k)}"
            elif right.type in ("arrow_function", "function_expression", "function"):
                self.funcs["<default>"] = right
                self.exports["default"] = "<default>"
            elif right.type == "call_expression":
                if self._router_kind(right):
                    self.routers["<module>"] = "router"
                    self.exports["default"] = "<module>"
        elif lt.startswith("module.exports.") or (lt.startswith("exports.") and lt != "exports.default"):
            name = lt.split(".")[-1]
            if right.type == "identifier":
                self.exports["names"][name] = T(right)
            elif right.type in ("arrow_function", "function_expression", "function"):
                self.funcs[f"<export>.{name}"] = right
                self.exports["names"][name] = f"<export>.{name}"
        elif left.type == "identifier" and right.type == "call_expression" and self._router_kind(right):
            self.routers[lt] = "router"

    def _export(self, node):
        decl = node.child_by_field_name("declaration")
        is_default = any(c.type == "default" for c in node.children)
        value = node.child_by_field_name("value")
        if decl is not None:
            if decl.type == "function_declaration":
                nm = T(decl.child_by_field_name("name"))
                self.exports["names"][nm] = nm
                if is_default:
                    self.exports["default"] = nm
            elif decl.type == "lexical_declaration":
                for d in named(decl):
                    if d.type == "variable_declarator":
                        nm = T(d.child_by_field_name("name"))
                        self.exports["names"][nm] = nm
            elif decl.type == "class_declaration":
                nm = T(decl.child_by_field_name("name"))
                self.exports["names"][nm] = nm
        elif value is not None and is_default:
            if value.type == "identifier":
                self.exports["default"] = T(value)
            elif value.type in ("arrow_function", "function_expression", "function"):
                self.funcs["<default>"] = value
                self.exports["default"] = "<default>"
        else:
            for c in node.children:
                if c.type == "export_clause":
                    for s in named(c):
                        nm = s.child_by_field_name("name")
                        alias = s.child_by_field_name("alias")
                        self.exports["names"][T(alias or nm)] = T(nm)
                        if T(alias or nm) == "default":
                            self.exports["default"] = T(nm)

    def _class(self, node):
        name = node.child_by_field_name("name")
        body = node.child_by_field_name("body")
        if name is None or body is None:
            return
        cname = T(name)
        decorators = [c for c in node.children if c.type == "decorator"]
        if node.parent is not None and node.parent.type == "export_statement":
            decorators = [c for c in node.parent.children if c.type == "decorator"] + decorators
        members, pending = [], []
        for c in body.children:
            if c.type == "decorator":
                pending.append(c)
            elif c.type == "method_definition":
                members.append((c, pending))
                nm = c.child_by_field_name("name")
                if nm is not None:
                    self.funcs[f"{cname}.{T(nm)}"] = c
                pending = []
            elif c.is_named and c.type != "comment":
                pending = []
        self.classes.append({"name": cname, "node": node, "decorators": decorators, "members": members})
        if any(re.search(r"@Entity|@Table|@Schema|@modelname", T(d)) for d in decorators):
            self._model_from_class(cname, node, body)

    # -- models --------------------------------------------------------------------------------
    def _add_model(self, name, line, fields):
        fields = [f for f in fields if f]
        sens = [f for f in fields if P.SENSITIVE_FIELD.search(f) and not P.SENSITIVE_FIELD_EXCLUDE.search(f)]
        priv = [f for f in fields if P.PRIV_KEYS.match(f)]
        self.models.append(DataModel(name=name, file=self.path, line=line, fields=fields, sensitive=sens, privileged=priv))

    def _model_from_schema(self, var, new_node):
        args = named(new_node.child_by_field_name("arguments"))
        if args and args[0].type == "object":
            fields = [T(c.child_by_field_name("key")).strip("'\"") for c in named(args[0]) if c.type == "pair"
                      and not re.search(r"select\s*:\s*false", T(c.child_by_field_name("value")))]
            fields += [T(c) for c in named(args[0]) if c.type == "shorthand_property_identifier"]
            self._schemas = getattr(self, "_schemas", {})
            self._schemas[var] = (L(new_node), fields)

    def _model_call(self, call):
        fn = T(call.child_by_field_name("function"))
        args = named(call.child_by_field_name("arguments"))
        if fn in ("mongoose.model", "model") and len(args) >= 2:
            nm = string_value(args[0])
            schema = T(args[1])
            data = getattr(self, "_schemas", {}).get(schema)
            if nm and data:
                self._add_model(nm, data[0], data[1])
        elif fn.endswith(".define") and len(args) >= 2 and args[1].type == "object":
            nm = string_value(args[0])
            fields = [T(c.child_by_field_name("key")).strip("'\"") for c in named(args[1]) if c.type == "pair"]
            if nm:
                self._add_model(nm, L(call), fields)

    def _model_from_class(self, cname, node, body):
        fields = []
        for c in body.children:
            if c.type == "public_field_definition":
                nm = c.child_by_field_name("name")
                if nm is not None:
                    fields.append(T(nm))
        self._add_model(cname, L(node), fields)

    # -- route / use operations ----------------------------------------------------------------
    def _route_base(self, obj):
        """For router.route('/x').get(a).post(b): return (router_node, path, [(method, args)...])."""
        chain = []
        node = obj
        while node is not None and node.type == "call_expression":
            fn = node.child_by_field_name("function")
            if fn is None or fn.type != "member_expression":
                return None
            prop = T(fn.child_by_field_name("property"))
            if prop == "route":
                args = named(node.child_by_field_name("arguments"))
                path = string_value(args[0]) if args else None
                return fn.child_by_field_name("object"), path, chain
            if prop in METHODS:
                chain.append((prop, named(node.child_by_field_name("arguments"))))
                node = fn.child_by_field_name("object")
            else:
                return None
        return None

    def _call_op(self, call):
        fn = call.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            return
        prop = T(fn.child_by_field_name("property"))
        obj = fn.child_by_field_name("object")
        args = named(call.child_by_field_name("arguments"))
        line = L(call)
        if prop in METHODS and obj is not None and obj.type == "call_expression":
            base = self._route_base(obj)
            if base is not None:
                router, path, chain = base
                if router is not None:
                    for m, a in [(prop, args)] + chain:
                        self.ops.append({"op": "route", "router": T(router), "method": m.upper(), "path": path or "",
                                         "args": a, "line": line, "node": call})
                return
        if obj is None or obj.type not in ("identifier", "member_expression", "this"):
            return
        router = T(obj)
        if prop in METHODS and args:
            path = string_value(args[0]) if args[0].type in ("string", "template_string") else None
            is_regex = args[0].type == "regex"
            is_arr = args[0].type == "array"
            if (path is not None and (path.startswith("/") or path.startswith("*"))) or is_regex or is_arr:
                if path is None:
                    arr = [string_value(x) for x in named(args[0])] if is_arr else []
                    path = next((a for a in arr if a), "/") if is_arr else T(args[0])
                rest = args[1:]
                # fastify style: second argument is an options object holding hooks
                self.ops.append({"op": "route", "router": router, "method": prop.upper(), "path": path or "",
                                 "args": rest, "line": line, "node": call})
            return
        if prop == "use" and args:
            path, rest = "", args
            first = string_value(args[0]) if args[0].type in ("string", "template_string") else None
            if first is not None:
                path, rest = first, args[1:]
            elif args[0].type == "regex":
                path, rest = T(args[0]), args[1:]
            elif args[0].type == "array" and all(string_value(x) is not None for x in named(args[0])):
                path, rest = string_value(named(args[0])[0]) or "", args[1:]
            self.ops.append({"op": "use", "router": router, "path": path, "args": rest, "line": line, "node": call})
        elif prop == "register" and args:
            prefix = ""
            if len(args) > 1 and args[1].type == "object":
                for c in named(args[1]):
                    if c.type == "pair" and T(c.child_by_field_name("key")) == "prefix":
                        prefix = string_value(c.child_by_field_name("value")) or ""
            self.ops.append({"op": "use", "router": router, "path": prefix, "args": [args[0]], "line": line, "node": call})
        elif prop == "addHook" and len(args) >= 2 and string_value(args[0]) in ("onRequest", "preHandler", "preValidation", "preParsing"):
            self.ops.append({"op": "use", "router": router, "path": "", "args": [args[1]], "line": line, "node": call})
        elif prop == "route" and args and args[0].type == "object":
            self._fastify_route(router, args[0], line, call)

    def _fastify_route(self, router, obj, line, call):
        keys = {T(c.child_by_field_name("key")): c.child_by_field_name("value") for c in named(obj) if c.type == "pair"}
        methods = keys.get("method")
        url = string_value(keys.get("url")) if keys.get("url") is not None else None
        handler = keys.get("handler")
        if url is None or handler is None:
            return
        mws = []
        for k in ("onRequest", "preHandler", "preValidation"):
            if k in keys:
                mws += named(keys[k]) if keys[k].type == "array" else [keys[k]]
        mlist = [string_value(x) or "GET" for x in named(methods)] if methods is not None and methods.type == "array" \
            else [string_value(methods) or "GET"] if methods is not None else ["GET"]
        for m in mlist:
            self.ops.append({"op": "route", "router": router, "method": m.upper(), "path": url,
                             "args": mws + [handler], "line": line, "node": call})


# ---------------------------------------------------------------------------------------------
# handler / guard function analysis
# ---------------------------------------------------------------------------------------------
class FuncAnalyzer:
    """Collects HandlerFacts for one function with a light taint environment."""

    def __init__(self, jsfile: JsFile, fn, framework="express", extra_env=None, req_name=None):
        self.f, self.fn, self.framework = jsfile, fn, framework
        self.facts = HandlerFacts()
        self.visited = set()
        params = fn_params(fn)
        names = [param_name(p) for p in params]
        self.req = req_name or (names[0] if names and names[0] else "req")
        self.res = names[1] if len(names) > 1 and names[1] else "res"
        self.env = dict(extra_env or {})
        self.reads = {}
        for p in params:
            self._bind_param(p)

    # -- parameters (Nest decorators, Next.js destructuring) ------------------------------------
    def _bind_param(self, p):
        if p.type not in ("required_parameter", "optional_parameter"):
            if p.type == "object_pattern":
                for c in named(p):
                    if c.type == "shorthand_property_identifier_pattern" and T(c) == "params":
                        self.env["params"] = ArgInfo(text="params", taint=("params", "*", False))
            return
        pattern = p.child_by_field_name("pattern")
        name = param_name(p)
        for d in [c for c in p.children if c.type == "decorator"]:
            call = next((c for c in d.children if c.type == "call_expression"), None)
            dname = T(call.child_by_field_name("function")) if call is not None else T(d).lstrip("@")
            dargs = named(call.child_by_field_name("arguments")) if call is not None else []
            field = string_value(dargs[0]) if dargs and dargs[0].type == "string" else "*"
            kind = {"Body": "body", "Param": "params", "Query": "query", "Headers": "headers", "Header": "headers",
                    "Cookies": "cookies", "UploadedFile": "files", "UploadedFiles": "files"}.get(dname)
            if name and kind:
                self.env[name] = ArgInfo(text=name, taint=(kind, field, False))
            elif name and dname in NEST_IDENTITY:
                self.env[name] = ArgInfo(text=name, identity=True)
            elif name and dname in ("Req", "Request"):
                self.req = name
        if pattern is not None and pattern.type == "object_pattern" and name is None:
            for c in named(pattern):
                if c.type == "shorthand_property_identifier_pattern" and T(c) == "params":
                    self.env["params"] = ArgInfo(text="params", taint=("params", "*", False))

    # -- expression analysis -----------------------------------------------------------------
    def norm(self, text: str) -> str:
        text = text.replace("?.", ".").replace("!.", ".")
        for alias in {self.req, "request"} - {"ctx"}:
            if text == alias or text.startswith(alias + ".") or text.startswith(alias + "["):
                return "req" + text[len(alias):]
        return text

    def source_taint(self, text):
        m = P.REQUEST_SOURCE.match(self.norm(text))
        if not m:
            return None
        kind = m.group(1)
        kind = {"args": "query", "form": "body", "values": "body", "json": "body", "data": "body", "GET": "query",
                "POST": "body", "query_params": "query", "path_params": "params", "COOKIES": "cookies", "FILES": "files",
                "META": "headers"}.get(kind, kind)
        rest = self.norm(text)[m.end(1) + 4:] if False else self.norm(text)[len("req." + m.group(1)):]
        segs = re.findall(r"\.(\w+)|\[['\"]([\w\-]+)['\"]\]", rest)
        field = (segs[-1][0] or segs[-1][1]) if segs else "*"
        return (kind, field, False)

    def info(self, node) -> ArgInfo:
        if node is None:
            return ArgInfo()
        t = node.type
        text = T(node)
        line = L(node)
        if t in ("parenthesized_expression", "await_expression", "non_null_expression", "as_expression", "satisfies_expression"):
            kids = named(node)
            return self.info(kids[0]) if kids else ArgInfo(text=text, line=line)
        if t == "identifier":
            known = self.env.get(text)
            if known is not None:
                return known
            if self.norm(text) == "req":
                return ArgInfo(text=text, taint=("request", "*", False), line=line)
            return ArgInfo(text=text, line=line)
        if t in ("string", "number", "true", "false", "null", "undefined", "regex"):
            val = string_value(node) if t == "string" else (parse_int_literal(text) if t == "number" else
                                                           True if t == "true" else False if t == "false" else None)
            return ArgInfo(text=text, literal=val, has_literal=True, line=line, prefix=val if isinstance(val, str) else "")
        if t == "template_string":
            subs = [c for c in node.children if c.type == "template_substitution"]
            if not subs:
                return ArgInfo(text=text, literal=string_value(node), has_literal=True, line=line, prefix=string_value(node) or "")
            merged, first = None, None
            for idx, s in enumerate(subs):
                sub = self.info(named(s)[0]) if named(s) else ArgInfo()
                merged = merged or sub.taint
                if idx == 0:
                    first = sub.taint
            pre = template_prefix(node)
            return ArgInfo(text=text, taint=merged, prefix=pre, line=line, lead_known=True,
                           lead_taint=None if pre else first)
        if t in ("member_expression", "subscript_expression"):
            obj = node.child_by_field_name("object")
            base = self.info(obj)
            direct = self.source_taint(text)
            prop = node.child_by_field_name("property") or node.child_by_field_name("index")
            pname = (string_value(prop) if prop is not None and prop.type == "string" else T(prop)) if prop is not None else ""
            ident = bool(P.IDENTITY_EXPR.match(self.norm(text)) or P.IDENTITY_EXPR.match(text)) or base.identity
            taint = direct or (base.taint and (base.taint[0], pname or "*", base.taint[2]) if base.taint else None)
            if base.taint and base.taint[0] == "request" and not direct:
                taint = self.source_taint(self.req + "." + pname) if pname else None
            return ArgInfo(text=text, taint=taint, identity=ident and not taint, line=line,
                           origin=None)
        if t == "binary_expression":
            op = T(node.child_by_field_name("operator"))
            left, right = self.info(node.child_by_field_name("left")), self.info(node.child_by_field_name("right"))
            if op in ("===", "!==", "==", "!="):
                self.facts.compares.append(CompareRec(left, right, op, line, text[:200]))
                return ArgInfo(text=text, line=line)
            pre = template_prefix(node)
            return ArgInfo(text=text, taint=left.taint or right.taint, prefix=pre, line=line, identity=False,
                           lead_known=op == "+", lead_taint=None if pre else (left.lead_taint if left.lead_known else left.taint))
        if t == "ternary_expression":
            a, b = self.info(node.child_by_field_name("consequence")), self.info(node.child_by_field_name("alternative"))
            self.info(node.child_by_field_name("condition"))
            return ArgInfo(text=text, taint=a.taint or b.taint, identity=a.identity and b.identity, line=line)
        if t == "object":
            keys, spread = {}, False
            taint = None
            for c in named(node):
                if c.type == "pair":
                    k = c.child_by_field_name("key")
                    key = string_value(k) if k.type == "string" else T(k)
                    keys[key] = self.info(c.child_by_field_name("value"))
                elif c.type == "shorthand_property_identifier":
                    keys[T(c)] = self.info(c) if c.type == "identifier" else self.env.get(T(c)) or ArgInfo(text=T(c), line=line)
                elif c.type == "spread_element":
                    inner = self.info(named(c)[0]) if named(c) else ArgInfo()
                    if inner.taint and inner.taint[0] in ("body", "request") and inner.taint[1] == "*":
                        spread, taint = True, inner.taint
                elif c.type == "method_definition":
                    pass
            return ArgInfo(text=text[:300], keys=keys, spread_taint=spread, taint=taint if spread else None, line=line)
        if t == "array":
            infos = [self.info(c) for c in named(node)]
            tn = next((i.taint for i in infos if i.taint), None)
            return ArgInfo(text=text[:200], taint=tn, identity=any(i.identity for i in infos), line=line)
        if t == "spread_element":
            return self.info(named(node)[0]) if named(node) else ArgInfo()
        if t == "call_expression":
            return self.call_info(node)
        if t == "new_expression":
            return self.new_info(node)
        if t == "assignment_expression":
            right = self.info(node.child_by_field_name("right"))
            self.assign(node.child_by_field_name("left"), right, node)
            return right
        if t in ("arrow_function", "function_expression", "function"):
            return ArgInfo(text="<function>", line=line)
        return ArgInfo(text=text[:200], line=line)

    def args_info(self, call):
        args = call.child_by_field_name("arguments")
        return [self.info(a) for a in named(args)] if args is not None else []

    def call_info(self, call) -> ArgInfo:
        fn = call.child_by_field_name("function")
        line = L(call)
        callee = callee_text(fn)
        norm = self.norm(callee)
        args = self.args_info(call)
        rec_args = args
        owner_origin = None
        if fn is not None and fn.type == "member_expression":
            obj = fn.child_by_field_name("object")
            if obj is not None:
                if obj.type == "identifier":
                    owner_origin = (self.env.get(T(obj)) or ArgInfo()).origin
                elif obj.type in ("call_expression", "await_expression"):
                    owner_origin = self.info(obj).origin
        first_seen = nk(call) not in self.visited
        self.visited.add(nk(call))
        if first_seen:
            self.facts.calls.append(CallRec(callee=norm, args=rec_args, line=line, text=T(call)[:240], receiver_origin=owner_origin))
            self._response_and_flags(call, fn, norm, rec_args)
        last = norm.split(".")[-1]
        # --- body sources through call syntax: request.json(), req.formData()
        if re.match(r"^(req|request)\.(json|formData|text|body)$", norm):
            return ArgInfo(text=T(call)[:200], taint=("body", "*", False), line=line)
        if re.match(r"^(req|request)\.(get|header|param|query)$", norm) and rec_args and rec_args[0].has_literal:
            kind = "headers" if last in ("get", "header") else "params" if last == "param" else "query"
            return ArgInfo(text=T(call)[:200], taint=(kind, str(rec_args[0].literal), False), line=line)
        if P.PICK_FUNCS.search(norm):
            return ArgInfo(text=T(call)[:200], line=line)
        if P.SANITIZE_PATH.search(norm):
            return ArgInfo(text=T(call)[:200], line=line)
        tainted = next((a for a in rec_args if a.taint), None)
        if last in P.CAST_FUNCS or norm in P.CAST_FUNCS:
            return ArgInfo(text=T(call)[:200], taint=(tainted.taint[0], tainted.taint[1], True) if tainted else None,
                           identity=bool(rec_args and rec_args[0].identity), line=line)
        # --- chained query builders keep the origin of the lookup
        if fn is not None and fn.type == "member_expression" and last in CHAIN_PASS:
            base = self.info(fn.child_by_field_name("object"))
            if base.origin is not None:
                origin = dict(base.origin)
                if last in ("select",) and rec_args and rec_args[0].has_literal:
                    origin["projected"] = True
                elif last == "select":
                    origin["projected"] = True
                return ArgInfo(text=T(call)[:200], origin=origin, line=line)
            if base.taint:
                return ArgInfo(text=T(call)[:200], taint=base.taint, line=line)
        # --- database lookups
        parts = norm.split(".")
        if len(parts) >= 2 and P.LOOKUP_NAMES.match(last) and P.MODELISH.match(".".join(parts[:-1])) \
                and not P.NON_DB_RECEIVER.match(parts[0]):
            model = parts[-2] if parts[-2] not in ("objects", "query", "manager", "repository") else parts[-3] if len(parts) > 2 else parts[-2]
            projected = any(k in P.PROJECTION_KEYS for a in rec_args for k in a.keys) or \
                any(a.has_literal and isinstance(a.literal, str) and len(rec_args) > 1 and a is rec_args[1] for a in rec_args)
            collection = last in ("find", "findAll", "findMany", "all", "filter", "where", "query", "findAndCountAll", "find_all") \
                and not (last == "find" and False)
            if last == "find" and rec_args and rec_args[0].taint and not rec_args[0].keys:
                collection = False
            return ArgInfo(text=T(call)[:200], origin={"model": model, "op": last, "projected": projected,
                                                      "collection": collection, "line": line}, line=line)
        # --- string helpers keep taint of the receiver / args
        if fn is not None and fn.type == "member_expression" and last in PASSTHROUGH:
            base = self.info(fn.child_by_field_name("object"))
            if base.taint:
                return ArgInfo(text=T(call)[:200], taint=base.taint, prefix=base.prefix, line=line)
            if tainted and last in ("replace", "concat", "join", "slice"):
                return ArgInfo(text=T(call)[:200], taint=tainted.taint, line=line)
        if last in ("join", "resolve", "normalize", "format", "pathToFileURL", "URL", "relative") or norm in ("String", "path.join", "path.resolve"):
            return ArgInfo(text=T(call)[:200], taint=tainted.taint if tainted else None,
                           prefix=rec_args[0].prefix if rec_args else "", line=line)
        if last in ("parse", "stringify") and norm.startswith("JSON") and tainted:
            return ArgInfo(text=T(call)[:200], taint=tainted.taint, line=line)
        if last in P.TOKEN_VERIFY.pattern or P.TOKEN_VERIFY.search(norm):
            return ArgInfo(text=T(call)[:200], identity=True, line=line)
        return ArgInfo(text=T(call)[:200], line=line)

    def new_info(self, node):
        ctor = node.child_by_field_name("constructor")
        args_node = node.child_by_field_name("arguments")
        args = [self.info(a) for a in named(args_node)] if args_node is not None else []
        name = T(ctor)
        if nk(node) not in self.visited:
            self.visited.add(nk(node))
            self.facts.calls.append(CallRec(callee="new " + name, args=args, line=L(node), text=T(node)[:240]))
        if name in ("URL", "URLSearchParams") and args:
            return ArgInfo(text=T(node)[:200], taint=args[0].taint, line=L(node))
        origin = {"model": name, "op": "new", "projected": False, "collection": False, "line": L(node)}
        return ArgInfo(text=T(node)[:200], origin=origin, line=L(node))

    def _response_and_flags(self, call, fn, norm, args):
        line = L(call)
        parts = norm.split(".")
        root = parts[0]
        last = parts[-1]
        if root in (self.res, "res", "reply", "response", "ctx") and len(parts) >= 2:
            status = chain_status(fn)
            text = T(call)
            if last == "sendStatus" and args and args[0].has_literal and isinstance(args[0].literal, int):
                status = args[0].literal
            if last in ("json", "send", "end", "render", "jsonp", "sendStatus", "redirect", "sendFile", "download", "status"):
                kind = "redirect" if last == "redirect" else "json" if last in ("json", "jsonp") else "send"
                if last != "status":
                    self.facts.responses.append(ResponseRec(kind, args[0] if args else ArgInfo(), status, line))
            if status in (401, 403) or (last == "sendStatus" and status in (401, 403)):
                self.facts.deny_statuses.add(status)
        if any(a.keys.get("status") is not None and a.keys["status"].literal in (401, 403) for a in args):
            self.facts.deny_statuses.add(401)
        if norm == "redirect" and args and args[0].has_literal and "login" in str(args[0].literal):
            self.facts.deny_statuses.add(401)
        if DENY_RE.search(norm) or (norm.endswith(".throw") and args and args[0].has_literal and args[0].literal in (401, 403)):
            self.facts.deny_statuses.add(401)
        # validation-looking calls: remember operands for allow-list suppression
        if P.VALIDATION_CALL.search(last):
            for a in args:
                self.facts.checked_texts.add(a.text)
            if fn is not None and fn.type == "member_expression":
                self.facts.checked_texts.add(T(fn.child_by_field_name("object")))
        if last in ("startsWith", "relative", "isSubPath", "isInside", "is_relative_to") or norm.endswith("path.relative"):
            self.facts.contained_paths = True
        if P.OWNERSHIP_CALL.search(last) and any(a.identity for a in args):
            self.facts.ownership_check_inline = True

    def assign(self, left, value: ArgInfo, node):
        if left is None:
            return
        lt = T(left)
        if left.type == "identifier":
            self.env[lt] = value
        elif left.type in ("member_expression", "subscript_expression"):
            self.facts.assigns.append(AssignRec(target=lt, value=value, line=L(node), text=T(node)[:200]))
        elif left.type == "object_pattern":
            self.destructure(left, value)

    def destructure(self, pattern, value: ArgInfo):
        for c in named(pattern):
            if c.type == "shorthand_property_identifier_pattern":
                nm = T(c)
                self.env[nm] = self._project(value, nm)
            elif c.type == "pair_pattern":
                k, v = c.child_by_field_name("key"), c.child_by_field_name("value")
                if v is not None and v.type == "identifier":
                    self.env[T(v)] = self._project(value, T(k))
            elif c.type == "rest_pattern":
                for ident in named(c):
                    if ident.type == "identifier":
                        self.env[T(ident)] = value

    def _project(self, value: ArgInfo, name: str) -> ArgInfo:
        if value.taint:
            return ArgInfo(text=name, taint=(value.taint[0], name, value.taint[2]))
        if value.identity or name in ("user", "auth") and value.text in (self.req, "req", "request"):
            return ArgInfo(text=name, identity=True)
        if value.text in (self.req, "req", "request") and name in ("body", "params", "query", "headers", "cookies"):
            return ArgInfo(text=name, taint=(name, "*", False))
        return ArgInfo(text=name)

    # -- traversal ---------------------------------------------------------------------------
    def run(self):
        body = fn_body(self.fn)
        if body is None:
            return self.facts
        if body.type != "statement_block":  # expression-bodied arrow
            self.info(body)
        self._visit(body, nested=False)
        self._finish()
        return self.facts

    def _visit(self, node, nested):
        t = node.type
        if t == "variable_declarator":
            name, value = node.child_by_field_name("name"), node.child_by_field_name("value")
            if value is not None:
                v = self.info(value)
                if name is not None and name.type == "identifier":
                    self.env[T(name)] = v
                elif name is not None and name.type == "object_pattern":
                    self.destructure(name, v)
        elif t == "assignment_expression":
            self.info(node)
        elif t in ("call_expression", "new_expression"):
            self.info(node)
        elif t == "binary_expression":
            self.info(node)
        elif t == "if_statement" or t == "ternary_expression" or t == "while_statement":
            cond = node.child_by_field_name("condition")
            if cond is not None:
                self._condition(cond)
        elif t == "return_statement" and not nested:
            kids = named(node)
            if kids:
                v = self.info(kids[0])
                self.facts.responses.append(ResponseRec("return", v, None, L(node)))
        for c in node.children:
            if c.is_named:
                self._visit(c, nested or (c.type in FUNC_TYPES))

    def _condition(self, cond):
        text = T(cond)
        for n in walk(cond):
            if n.type in ("identifier", "member_expression") and (n.parent is None or n.parent.type != "member_expression"):
                if P.VALIDATION_CALL.search(text):
                    self.facts.checked_texts.add(T(n))
        low = text
        has_identity = any(self.info(n).identity for n in walk(cond) if n.type in ("member_expression", "identifier"))
        if has_identity and re.search(r"\b(role|roles|isAdmin|is_admin|admin|permissions?|scope|isSuperuser|can)\b", low, re.I):
            self.facts.role_check_inline = True

    def _finish(self):
        facts = self.facts
        for c in facts.compares:
            sides = (c.left, c.right)
            if any(s.identity for s in sides):
                other = c.right if c.left.identity else c.left
                if not other.has_literal and not other.taint:
                    facts.ownership_check_inline = True
                    if re.search(r"role|admin|permission", other.text + " " + (c.left.text if c.left.identity else c.right.text), re.I):
                        facts.role_check_inline = True
                elif other.has_literal and re.search(r"role|admin|permission", c.text, re.I):
                    facts.role_check_inline = True
        texts = " ".join(i.text for c in facts.calls for i in c.args)
        facts.uses_identity = any(
            (P.IDENTITY_EXPR.match(self.norm(t)) or P.IDENTITY_EXPR.match(t)) for t in set(re.findall(r"[\w$.\[\]'\"]+", " ".join(
                [c.text for c in facts.calls] + [a.text for a in facts.assigns] + [c.text for c in facts.compares])))) \
            or any(a.identity for c in facts.calls for a in c.args) \
            or any(v.identity for v in self.env.values())
        facts.authn_inline = facts.uses_identity and bool(facts.deny_statuses)
        reads = {}
        for c in facts.calls:
            for a in c.args:
                self._collect_reads(a, reads)
        for a in facts.assigns:
            self._collect_reads(a.value, reads)
        for v in self.env.values():
            if v.taint:
                reads.setdefault(v.taint[0], set()).add(v.taint[1])
        facts.reads = {k: sorted(v) for k, v in reads.items()}

    def _collect_reads(self, a, reads):
        if a.taint:
            reads.setdefault(a.taint[0], set()).add(a.taint[1])
        for k in a.keys.values():
            self._collect_reads(k, reads)


# ---------------------------------------------------------------------------------------------
# fail-open analysis (small abstract interpreter over statements)
# ---------------------------------------------------------------------------------------------
class FailOpen:
    """Finds paths where a deny response (or swallowed exception) is followed by proceeding."""

    def __init__(self, fn, nest=False):
        params = [param_name(p) for p in fn_params(fn)]
        self.fn = fn
        self.nest = nest
        self.next_names = {params[2]} if len(params) > 2 and params[2] else set()
        if len(params) == 2 and params[1] in ("next", "done"):
            self.next_names = {params[1]}
        self.next_names |= {"next", "done"}
        self.events = []

    def run(self):
        body = fn_body(self.fn)
        if body is not None and body.type == "statement_block":
            self._block(named(body), frozenset())
        return self.events

    # -- predicates ----------------------------------------------------------------------------
    def _calls(self, stmt):
        """Calls in this statement, not descending into nested functions."""
        out, stack = [], [stmt]
        while stack:
            n = stack.pop()
            if n.type in FUNC_TYPES and n is not stmt:
                continue
            if n.type == "call_expression":
                out.append(n)
            stack.extend(n.children)
        return out

    def _is_proceed(self, call):
        fn = call.child_by_field_name("function")
        if fn is None:
            return False
        name = T(fn)
        if name in self.next_names:
            args = named(call.child_by_field_name("arguments"))
            return not args
        return False

    def _is_deny(self, call):
        fn = call.child_by_field_name("function")
        norm = callee_text(fn)
        parts = norm.split(".")
        if parts[0] in ("res", "reply", "response") and parts[-1] in ("json", "send", "end", "sendStatus", "redirect", "render"):
            status = chain_status(fn)
            args = named(call.child_by_field_name("arguments"))
            if parts[-1] == "sendStatus" and args and args[0].type == "number":
                status = parse_int_literal(T(args[0]))
            if parts[-1] == "redirect":
                return True
            return status is not None and 400 <= status < 500
        if T(fn) in self.next_names:
            return bool(named(call.child_by_field_name("arguments")))  # next(err)
        return False

    def _callbacks(self, stmt):
        out, stack = [], [stmt]
        while stack:
            n = stack.pop()
            if n.type == "call_expression":
                for a in named(n.child_by_field_name("arguments")):
                    if a.type in ("arrow_function", "function_expression", "function"):
                        out.append(a)
            if n.type in FUNC_TYPES and n is not stmt:
                continue
            stack.extend(n.children)
        return out

    # -- interpreter ---------------------------------------------------------------------------
    def _block(self, stmts, state):
        states = [state]
        for s in stmts:
            nxt = []
            for st in states:
                nxt.extend(self._stmt(s, st))
            states = nxt
            if not states:
                break
        return states

    def _body(self, node, state):
        if node is None:
            return [state]
        if node.type == "statement_block":
            return self._block(named(node), state)
        if node.type == "else_clause":
            kids = named(node)
            return self._body(kids[0], state) if kids else [state]
        return self._stmt(node, state)

    def _proceed_event(self, stmt, state):
        if state:
            reason = "error-swallowed" if "swallowed" in state and "denied" not in state else "denied"
            self.events.append({"line": L(stmt), "reason": reason, "text": T(stmt)[:160]})

    def _stmt(self, s, st):
        t = s.type
        if t == "return_statement":
            for c in self._calls(s):
                if self._is_proceed(c):
                    self._proceed_event(s, st)
            for cb in self._callbacks(s):
                self._callback(cb)
            return []
        if t == "throw_statement":
            return []
        if t == "if_statement":
            then = self._body(s.child_by_field_name("consequence"), st)
            alt = s.child_by_field_name("alternative")
            other = self._body(alt, st) if alt is not None else [st]
            return then + other
        if t == "statement_block":
            return self._block(named(s), st)
        if t == "try_statement":
            body = self._body(s.child_by_field_name("body"), st)
            handler = s.child_by_field_name("handler")
            caught = []
            if handler is not None:
                caught = self._body(handler.child_by_field_name("body"), st | {"swallowed"})
            fin = s.child_by_field_name("finalizer")
            out = body + caught
            if fin is not None:
                out = [x for o in out for x in self._body(fin.child_by_field_name("body") or fin, o)]
            return out
        if t in ("for_statement", "for_in_statement", "while_statement", "do_statement"):
            self._body(s.child_by_field_name("body"), st)
            return [st]
        if t == "switch_statement":
            body = s.child_by_field_name("body")
            for c in named(body) if body is not None else []:
                self._block([k for k in named(c) if k.type not in ("string", "identifier", "number")], st)
            return [st]
        # simple statements
        calls = self._calls(s)
        for c in calls:
            if self._is_proceed(c):
                self._proceed_event(s, st)
        for cb in self._callbacks(s):
            self._callback(cb)
        if any(self._is_deny(c) for c in calls):
            return [st | {"denied"}]
        if t == "expression_statement":
            kids = named(s)
            if kids and kids[0].type == "assignment_expression" and re.match(r"ctx\.status\s*=\s*4\d\d", T(kids[0])):
                return [st | {"denied"}]
        return [st]

    def _callback(self, cb):
        body = fn_body(cb)
        if body is not None and body.type == "statement_block":
            self._block(named(body), frozenset())


def nest_fail_open(fn):
    """canActivate that returns true on an error path."""
    events = []
    for n in walk(fn):
        if n.type == "catch_clause":
            for r in walk(n):
                if r.type == "return_statement" and re.fullmatch(r"return\s+true;?", T(r).strip()):
                    events.append({"line": L(r), "reason": "error-swallowed", "text": T(r)})
    return events


# ---------------------------------------------------------------------------------------------
# project-level assembly
# ---------------------------------------------------------------------------------------------
LIB_GUARDS = {  # import specifier -> guard kind (behaviour is documented library semantics)
    "express-jwt": "authentication", "passport": "authentication", "passport-jwt": "authentication",
    "@fastify/jwt": "authentication", "fastify-jwt": "authentication", "@fastify/auth": "authentication",
    "koa-jwt": "authentication", "express-oauth2-jwt-bearer": "authentication", "express-openid-connect": "authentication",
    "csurf": "csrf", "csrf-csrf": "csrf", "lusca": "csrf", "@fastify/csrf-protection": "csrf", "koa-csrf": "csrf",
    "express-rate-limit": "rate_limit", "@fastify/rate-limit": "rate_limit", "koa-ratelimit": "rate_limit",
    "express-validator": "validation", "celebrate": "validation", "express-joi-validation": "validation",
    "connect-ensure-login": "authentication", "express-jwt-authz": "authorization", "accesscontrol": "authorization",
    "casbin": "authorization", "express-acl": "authorization",
}
ADMINISH = re.compile(r"admin|superuser|root|staff|owner|manager", re.I)


class JsExtractor:
    def __init__(self, files: dict, project: Project, side_of, config=None):
        self.project, self.side_of, self.config = project, side_of, config or {}
        self.paths = set(files.keys())
        self.files = {}
        self.cache = {}
        self.parsers = _make_parsers()
        self.seen_entries = set()
        for path, source in files.items():
            if not path.lower().endswith(EXTS):
                continue
            try:
                self.files[path] = JsFile(path, source, self.parsers, self.paths)
                if self.files[path].has_error:
                    project.warnings.append(f"{path}: syntax errors in parse tree (partial analysis)")
                project.files_parsed.append(path)
            except Exception as exc:  # pragma: no cover
                project.files_failed.append((path, f"{type(exc).__name__}: {exc}"))
        self.router_ops = {}
        for path, jf in self.files.items():
            for op in jf.ops:
                self.router_ops.setdefault((path, op["router"]), []).append(op)
            project.models.extend(jf.models)

    # -- function resolution -------------------------------------------------------------------
    def _file_func(self, jf, var):
        if var is None:
            return None
        fn = jf.funcs.get(var)
        return (jf, fn, var) if fn is not None else None

    def resolve_func(self, jf, node):
        """-> (file, fn_node, name, import_spec) or None"""
        if node is None:
            return None
        t = node.type
        if t in ("arrow_function", "function_expression", "function"):
            return (jf, node, "<inline>", None)
        if t == "parenthesized_expression" or t == "await_expression":
            kids = named(node)
            return self.resolve_func(jf, kids[0]) if kids else None
        if t == "identifier":
            name = T(node)
            if name in jf.funcs:
                return (jf, jf.funcs[name], name, None)
            if name in jf.imports:
                target, export, spec = jf.imports[name]
                tj = self.files.get(target) if target else None
                if tj is not None:
                    var = tj.exports["default"] if export == "default" else tj.exports["names"].get(export, export)
                    hit = self._file_func(tj, var) or self._file_func(tj, export)
                    if hit:
                        return (hit[0], hit[1], name, spec)
                return (None, None, name, spec)
            return None
        if t == "member_expression":
            obj, prop = node.child_by_field_name("object"), T(node.child_by_field_name("property"))
            if obj is not None and obj.type == "identifier":
                oname = T(obj)
                if f"{oname}.{prop}" in jf.funcs:
                    return (jf, jf.funcs[f"{oname}.{prop}"], f"{oname}.{prop}", None)
                if oname in jf.imports:
                    target, export, spec = jf.imports[oname]
                    tj = self.files.get(target) if target else None
                    if tj is not None:
                        var = tj.exports["names"].get(prop)
                        hit = self._file_func(tj, var) or self._file_func(tj, prop) or self._file_func(tj, f"{export}.{prop}")
                        if hit is None and export not in ("default", "*"):
                            hit = self._file_func(tj, f"{export}.{prop}")
                        if hit is None and tj.exports["default"]:
                            hit = self._file_func(tj, f"{tj.exports['default']}.{prop}")
                        if hit:
                            return (hit[0], hit[1], f"{oname}.{prop}", spec)
                    return (None, None, f"{oname}.{prop}", spec)
            return None
        return None

    def _returned_fn(self, fn):
        body = fn_body(fn)
        if body is None:
            return None
        if body.type != "statement_block":
            return body if body.type in ("arrow_function", "function_expression") else None
        for n in walk(body):
            if n.type == "return_statement":
                kids = named(n)
                if kids and kids[0].type in ("arrow_function", "function_expression"):
                    return kids[0]
        return None

    def analyze(self, jf, fn, framework="express"):
        key = (jf.path, fn.start_byte, framework)
        if key not in self.cache:
            try:
                self.cache[key] = FuncAnalyzer(jf, fn, framework).run()
            except RecursionError:  # pragma: no cover
                self.cache[key] = HandlerFacts(parsed=False)
        return self.cache[key]

    # -- guards --------------------------------------------------------------------------------
    def guard_from_node(self, jf, node, scope, methods=None):
        """Classify one middleware argument; returns list[Guard] (possibly empty)."""
        if node.type == "array":
            out = []
            for k in named(node):
                out += self.guard_from_node(jf, k, scope, methods)
            return out
        factory_args = []
        target = node
        if node.type == "call_expression":
            fn_node = node.child_by_field_name("function")
            if fn_node is not None and fn_node.type == "member_expression" and T(fn_node.child_by_field_name("property")) == "unless":
                inner = self.guard_from_node(jf, fn_node.child_by_field_name("object"), scope, methods)
                self._unless_signal(jf, node)
                return inner
            target = fn_node
            factory_args = named(node.child_by_field_name("arguments"))
        name = callee_text(target) if target is not None and target.type in ("member_expression", "call_expression") else T(target)
        short = name.split(".")[-1]
        resolved = self.resolve_func(jf, target)
        spec = resolved[3] if resolved else None
        if spec is None and target is not None and target.type == "member_expression":
            root = target
            while root.type == "member_expression":
                root = root.child_by_field_name("object")
            if root is not None and root.type == "identifier" and T(root) in jf.imports:
                spec = jf.imports[T(root)][2]
        if spec is None and target is not None and target.type == "identifier" and T(target) in jf.imports:
            spec = jf.imports[T(target)][2]
        kinds = {k: "name" for k in P.classify_guard_name(name)}
        if spec in LIB_GUARDS:
            kinds[LIB_GUARDS[spec]] = "code"
            if LIB_GUARDS[spec] == "authentication" and "authorization" in kinds and short.lower() in ("authorize",):
                kinds.pop("authentication", None)
        elif spec and spec.startswith(("express-session", "cookie-session", "helmet", "cors", "morgan")):
            return []
        facts, fo, source = None, [], ""
        fnode, ffile = None, jf
        if resolved and resolved[1] is not None:
            ffile, fnode = resolved[0], resolved[1]
            inner = self._returned_fn(fnode) if node.type == "call_expression" else None
            if inner is not None:
                fnode = inner
            facts = self.analyze(ffile, fnode)
            source = trim_source(T(fnode), 45)
            code = self._code_kinds(facts, fnode)
            for k in code:
                kinds[k] = "code"
            if not kinds:
                return []
            if "authentication" in kinds or "authorization" in kinds or "ownership" in kinds:
                fo = FailOpen(fnode).run()
        elif not kinds:
            return []
        if "authorization" in kinds and not any(k in kinds for k in ("authentication",)) and factory_args:
            pass
        guards = []
        for kind, cert in kinds.items():
            g = Guard(name=name, kind=kind, scope=scope, certainty=cert, methods=methods, file=ffile.path if ffile else jf.path,
                      line=L(fnode) if fnode is not None else L(node), evidence=T(node)[:160], source=source)
            if fnode is not None and facts is not None:
                src, ev = self._identity_source(facts, fnode)
                g.identity_source, g.identity_evidence = src, ev
                if fo and kind in ("authentication", "authorization", "ownership"):
                    g.fails_open = True
                    g.fail_open_reason = fo[0]["reason"]
                    g.fail_open_line = fo[0]["line"]
            elif spec in LIB_GUARDS and kind == "authentication":
                g.identity_source = "verified"
            guards.append(g)
        for g in guards:
            self.project.guards.append(g)
        return guards

    def _code_kinds(self, facts, fnode):
        kinds = set()
        calls = [c.callee for c in facts.calls]
        if any(P.TOKEN_VERIFY.search(c) for c in calls) or any(re.search(r"isAuthenticated|passport\.authenticate", c) for c in calls):
            kinds.add("authentication")
        elif facts.uses_identity and facts.deny_statuses and not facts.role_check_inline:
            kinds.add("authentication")
        elif any(re.search(r"authorization", c.text, re.I) and True for c in facts.calls if c.callee.endswith((".get", ".header"))) and facts.deny_statuses:
            kinds.add("authentication")
        if facts.role_check_inline:
            kinds.add("authorization")
        if facts.ownership_check_inline and not facts.role_check_inline:
            kinds.add("ownership")
        text = T(fnode)
        if re.search(r"req(uest)?\.(headers?|get)\W+['\"]?authorization", text, re.I) and facts.deny_statuses:
            kinds.add("authentication")
        return kinds

    def _identity_source(self, facts, fnode):
        for c in facts.compares:
            for s in (c.left, c.right):
                if s.taint and s.taint[0] in ("body", "query", "headers", "cookies") and P.IDENT_FIELD.match(s.taint[1] or ""):
                    return "request", c.text
        for c in facts.compares:
            for a, b in ((c.left, c.right), (c.right, c.left)):
                if a.taint and a.taint[0] == "headers" and re.search(r"api[-_]?key|x[-_]?token|secret", a.taint[1] or "", re.I) \
                        and b.has_literal and isinstance(b.literal, str):
                    return "static-key", c.text
        calls = [c.callee for c in facts.calls]
        if any(TOKEN_DECODE_RE.search(c) for c in calls) and not any(P.TOKEN_VERIFY.search(c) for c in calls):
            return "request", "token decoded without signature verification"
        if any(P.TOKEN_VERIFY.search(c) for c in calls) or facts.uses_identity:
            return "verified", ""
        return "unknown", ""

    def _unless_signal(self, jf, call):
        text = T(call)
        if re.search(r"/\.\*|\.\*|\*\*|/admin|/api\b", text):
            self.project.signals.append(Signal("A01-GUARD-COVERAGE", jf.path, L(call), text[:200],
                                               detail="guard is excluded from broad path patterns via unless()",
                                               confidence="medium", extra={"kind": "broad-exclusion"}))

    # -- routers ---------------------------------------------------------------------------------
    def resolve_router(self, jf, node):
        if node is None:
            return None
        t = node.type
        if t == "call_expression":
            fn = node.child_by_field_name("function")
            if fn is not None and fn.type == "member_expression" and T(fn.child_by_field_name("property")) in ("routes", "allowedMethods", "middleware"):
                return self.resolve_router(jf, fn.child_by_field_name("object"))
            if fn is not None and T(fn) == "require":
                args = named(node.child_by_field_name("arguments"))
                spec = string_value(args[0]) if args else None
                tj = self.files.get(resolve_module(jf.path, spec or "", self.paths) or "")
                return self._default_router(tj)
            return None
        if t == "identifier":
            name = T(node)
            if name in jf.routers or (jf.path, name) in self.router_ops:
                return (jf.path, name)
            if name in jf.imports:
                target, export, _ = jf.imports[name]
                tj = self.files.get(target) if target else None
                if tj is None:
                    return None
                var = tj.exports["default"] if export == "default" else tj.exports["names"].get(export, export)
                if var and ((tj.path, var) in self.router_ops or var in tj.routers):
                    return (tj.path, var)
                return self._default_router(tj)
            return None
        if t == "member_expression":
            obj, prop = node.child_by_field_name("object"), T(node.child_by_field_name("property"))
            if obj is not None and obj.type == "identifier" and T(obj) in jf.imports:
                target, _, _ = jf.imports[T(obj)]
                tj = self.files.get(target) if target else None
                if tj is not None:
                    var = tj.exports["names"].get(prop)
                    if var and ((tj.path, var) in self.router_ops or var in tj.routers):
                        return (tj.path, var)
            return None
        return None

    def _default_router(self, tj):
        if tj is None:
            return None
        var = tj.exports["default"]
        if var and (tj.path, var) in self.router_ops:
            return (tj.path, var)
        vars_ = {k[1] for k in self.router_ops if k[0] == tj.path}
        if len(vars_) == 1:
            return (tj.path, next(iter(vars_)))
        return None

    def _split_args(self, jf, args, scope):
        """-> (guards, handler_arg or None). Flattens arrays, folds fastify option objects."""
        flat = []
        for a in args:
            if a.type == "array":
                flat += named(a)
            else:
                flat.append(a)
        guards, handler_nodes = [], []
        for a in flat:
            if a.type == "object":  # fastify route options
                for c in named(a):
                    if c.type == "pair" and T(c.child_by_field_name("key")) in ("preHandler", "onRequest", "preValidation", "preParsing", "beforeHandler"):
                        v = c.child_by_field_name("value")
                        for g in (named(v) if v.type == "array" else [v]):
                            guards += self.guard_from_node(jf, g, "route")
                continue
            handler_nodes.append(a)
        handler = handler_nodes[-1] if handler_nodes else None
        for a in handler_nodes[:-1]:
            guards += self.guard_from_node(jf, a, scope)
        return guards, handler, handler_nodes

    # -- traversal ---------------------------------------------------------------------------------
    def run(self):
        mounted = set()
        for (path, var), ops in self.router_ops.items():
            jf = self.files[path]
            for op in ops:
                if op["op"] == "use":
                    for a in op["args"]:
                        r = self.resolve_router(jf, a)
                        if r and r != (path, var):
                            mounted.add(r)
        roots = [k for k in self.router_ops if k not in mounted]
        for root in sorted(roots):
            self.walk_router(root, "", [], 0, set())
        self.nest()
        self.next_js()
        self.apply_global()
        for jf in self.files.values():
            self.scan_signals(jf)

    def walk_router(self, key, prefix, inherited, depth, stack_seen):
        if depth > 8 or key in stack_seen:
            return
        stack_seen = stack_seen | {key}
        jf = self.files[key[0]]
        stack, made = [], []
        root_scope = "global" if depth == 0 else "router"
        for op in self.router_ops.get(key, []):
            if op["op"] == "use":
                routers, guards = [], []
                for a in op["args"]:
                    r = self.resolve_router(jf, a)
                    if r and r != key:
                        routers.append(r)
                    else:
                        guards += self.guard_from_node(jf, a, root_scope)
                if routers:
                    child_prefix = join_path(prefix, op["path"])
                    applicable = [g for sc in stack for g in sc["guards"] if path_matches_scope(op["path"], sc["path"])]
                    for r in routers:
                        for g in guards:
                            g.scope = "router"
                        self.walk_router(r, child_prefix, inherited + applicable + guards, depth + 1, stack_seen)
                elif guards:
                    stack.append({"path": op["path"], "guards": guards, "line": op["line"], "methods": None})
            elif op["op"] == "route":
                guards, handler, hnodes = self._split_args(jf, op["args"], "route")
                resolved = self.resolve_func(jf, handler) if handler is not None else None
                if self._is_guard_only(jf, handler, resolved, op):
                    gs = self.guard_from_node(jf, handler, "router", methods={op["method"]}) if handler is not None else []
                    stack.append({"path": op["path"], "guards": guards + gs, "line": op["line"],
                                  "methods": {op["method"]} if op["method"] != "ALL" else None})
                    for g in guards + gs:
                        g.methods = {op["method"]} if op["method"] != "ALL" else None
                    continue
                path = join_path(prefix, op["path"])
                applicable = [g for sc in stack for g in sc["guards"] if path_matches_scope(op["path"], sc["path"])]
                ep = self._entry(jf, op, path, resolved, key, jf.path)
                ep.guards = [g for g in inherited + applicable + guards if g.methods is None or ep.method in g.methods or ep.method == "ANY"]
                ep.guards = self._dedupe_guards(ep.guards)
                ep.notes += [f"method_limited_guard:{g.name}:{','.join(sorted(g.methods))}" for g in inherited + applicable
                             if g.methods and ep.method not in g.methods and g.kind in ("authentication", "authorization")]
                made.append((ep, op["path"], len(stack)))
                self._add(ep)
        # coverage: routes registered before a router-level guard
        for sc in stack:
            for g in sc["guards"]:
                if g.kind not in ("authentication", "authorization") or g.methods:
                    continue
                for ep, rel, depth_at in made:
                    if path_matches_scope(rel, sc["path"]) and not any(x.kind == g.kind for x in ep.guards):
                        ep.notes.append(f"registered_before_guard:{g.name}:{sc['line']}")

    def _is_guard_only(self, jf, handler, resolved, op):
        if handler is None:
            return True
        if resolved and resolved[1] is not None:
            facts = self.analyze(resolved[0], resolved[1])
            has_output = bool(facts.responses) or any(re.search(r"\.(render|json|send|sendFile|redirect|end)$", c.callee) for c in facts.calls)
            return (not has_output) and bool(P.classify_guard_name(resolved[2])) and (op["path"].endswith("*") or op["path"] in ("", "/"))
        if resolved and resolved[1] is None and handler.type in ("identifier", "member_expression"):
            return bool(P.classify_guard_name(resolved[2])) and op["path"].endswith("*")
        return False

    @staticmethod
    def _dedupe_guards(gs):
        seen, out = set(), []
        for g in gs:
            k = (g.name, g.kind, g.line, g.file)
            if k not in seen:
                seen.add(k)
                out.append(g)
        return out

    def _entry(self, jf, op, path, resolved, key, group_file, framework="express"):
        ep = EntryPoint(method=op["method"] if op["method"] != "ALL" else "ANY", path=path, framework=framework,
                        file=jf.path, line=op["line"], group=f"{key[0]}:{key[1]}")
        self._fill_handler(ep, jf, op, resolved, framework)
        self.project.frameworks.add(framework)
        return ep

    def _fill_handler(self, ep, jf, op, resolved, framework):
        if resolved is None or resolved[1] is None:
            ep.handler = resolved[2] if resolved else "<unresolved>"
            ep.handler_resolved = False
            ep.facts = HandlerFacts(parsed=False)
            ep.end_line = ep.line
            return
        hfile, fn, name, _ = resolved
        framework_for = "koa" if self._is_koa(fn) else framework
        ep.facts = self.analyze(hfile, fn, framework_for)
        ep.handler = name if name != "<inline>" else f"<inline@{L(fn)}>"
        if name != "<inline>":
            ep.file, ep.line = hfile.path, L(fn)
        ep.end_line = fn.end_point[0] + 1
        ep.source = trim_source(T(fn), 60)

    @staticmethod
    def _is_koa(fn):
        names = [param_name(p) for p in fn_params(fn)]
        return bool(names) and names[0] == "ctx"

    def _add(self, ep):
        key = (ep.method, ep.path, ep.file, ep.line, ep.group)
        if key in self.seen_entries:
            return
        self.seen_entries.add(key)
        self.project.entry_points.append(ep)

    # -- NestJS ------------------------------------------------------------------------------------
    def _deco(self, d):
        call = next((c for c in d.children if c.type == "call_expression"), None)
        if call is not None:
            return T(call.child_by_field_name("function")), named(call.child_by_field_name("arguments"))
        return T(d).lstrip("@").split("(")[0], []

    def nest(self):
        for jf in self.files.values():
            for cls in jf.classes:
                decos = [self._deco(d) for d in cls["decorators"]]
                ctl = next(((n, a) for n, a in decos if n == "Controller"), None)
                if ctl is None:
                    continue
                self.project.frameworks.add("nestjs")
                prefix = ""
                if ctl[1]:
                    a0 = ctl[1][0]
                    prefix = string_value(a0) or ""
                    if a0.type == "object":
                        for c in named(a0):
                            if c.type == "pair" and T(c.child_by_field_name("key")) == "path":
                                prefix = string_value(c.child_by_field_name("value")) or ""
                class_guards = self._nest_guards(jf, cls["decorators"], "controller")
                class_public = any(n in NEST_PUBLIC for n, _ in decos)
                for method, mdecos in cls["members"]:
                    md = [self._deco(d) for d in mdecos]
                    routes = [(NEST_ROUTE[n], a) for n, a in md if n in NEST_ROUTE]
                    if not routes:
                        continue
                    mguards = self._nest_guards(jf, mdecos, "route")
                    public = class_public or any(n in NEST_PUBLIC for n, _ in md)
                    for verb, a in routes:
                        sub = (string_value(a[0]) if a and a[0].type == "string" else "") or ""
                        ep = EntryPoint(method=verb, path=join_path(join_path("", prefix), sub), framework="nestjs", file=jf.path,
                                        line=L(method), group=f"{jf.path}:{cls['name']}", handler=f"{cls['name']}.{T(method.child_by_field_name('name'))}")
                        ep.facts = self.analyze(jf, method, "nestjs")
                        ep.end_line = method.end_point[0] + 1
                        ep.source = trim_source(T(method), 60)
                        ep.guards = self._dedupe_guards(class_guards + mguards)
                        if public:
                            ep.notes.append("public_marker")
                        self._add(ep)

    def _nest_guards(self, jf, decorators, scope):
        out = []
        for d in decorators:
            name, args = self._deco(d)
            if name == "UseGuards":
                for a in args:
                    out += self._nest_guard_class(jf, a, scope)
            elif name in ("Roles", "RequirePermissions", "Permissions", "Scopes", "RequireRole", "Role"):
                out.append(Guard(name=f"@{name}", kind="authorization", scope=scope, certainty="name", file=jf.path,
                                 line=L(d), evidence=T(d)[:120]))
            elif name in ("Authorized", "Auth", "ApiBearerAuth_", "JwtAuth", "Authenticated"):
                out.append(Guard(name=f"@{name}", kind="authentication", scope=scope, certainty="name", file=jf.path,
                                 line=L(d), evidence=T(d)[:120], identity_source="verified"))
        return out

    def _nest_guard_class(self, jf, node, scope):
        if node.type == "call_expression":  # AuthGuard('jwt')
            nm = T(node.child_by_field_name("function"))
            g = Guard(name=T(node)[:60], kind="authentication", scope=scope, certainty="code", file=jf.path, line=L(node),
                      evidence=T(node)[:120], identity_source="verified") if nm == "AuthGuard" else None
            return [g] if g else []
        name = T(node)
        cls = next((c for c in self._all_classes() if c["name"] == name), None)
        kinds = {k: "name" for k in P.classify_guard_name(name)}
        file_, fo, src_text, line, ident = jf.path, [], "", L(node), "unknown"
        if cls is not None:
            cjf = cls["file"]
            file_, line = cjf.path, L(cls["node"])
            heritage = T(cls["node"])[:200]
            if re.search(r"extends\s+AuthGuard\(", heritage):
                kinds["authentication"] = "code"
                ident = "verified"
            fn = cjf.funcs.get(f"{name}.canActivate")
            if fn is not None:
                facts = self.analyze(cjf, fn, "nestjs")
                code = self._code_kinds(facts, fn)
                ftext = T(fn)
                if re.search(r"getAllAndOverride|reflector|getRequiredRoles|\.roles|role", ftext, re.I) and re.search(r"includes|some\(|===", ftext):
                    code.add("authorization")
                for k in code:
                    kinds[k] = "code"
                fo = nest_fail_open(fn) + FailOpen(fn).run()
                src_text = trim_source(ftext, 45)
                ident = self._identity_source(facts, fn)[0]
        out = []
        for k, cert in kinds.items():
            g = Guard(name=name, kind=k, scope=scope, certainty=cert, file=file_, line=line, evidence=name, source=src_text,
                      identity_source=ident)
            if fo and k in ("authentication", "authorization"):
                g.fails_open, g.fail_open_reason, g.fail_open_line = True, fo[0]["reason"], fo[0]["line"]
            out.append(g)
            self.project.guards.append(g)
        return out

    def _all_classes(self):
        for jf in self.files.values():
            for c in jf.classes:
                yield {**c, "file": jf}

    # -- Next.js ---------------------------------------------------------------------------------
    def next_js(self):
        mw = next((jf for p, jf in self.files.items() if re.search(r"(^|/)middleware\.(t|j)s$", p)), None)
        mw_scopes = None
        if mw is not None and re.search(r"getToken|jwtVerify|verify|auth\(|withAuth|next-auth/middleware|cookies\.get", mw.source):
            m = re.findall(r"['\"](/[\w\-/:*()]*)['\"]", mw.source[mw.source.find("matcher"):] if "matcher" in mw.source else "")
            mw_scopes = [re.sub(r"[/:*()\w]*:path\*$|\(\.\*\)$|\*$", "", x).rstrip("/") for x in m] or [""]
            self.project.global_security["found"] = True
            self.project.global_security["notes"].append(f"Next.js middleware ({mw.path}) performs an auth check for {mw_scopes}")
        for path, jf in self.files.items():
            m = re.search(r"(?:^|/)pages/(api/.*)\.(?:t|j)sx?$", path)
            m2 = re.search(r"(?:^|/)app/(.*)/?route\.(?:t|j)sx?$", path)
            if not (m or m2):
                continue
            self.project.frameworks.add("nextjs")
            raw = (m.group(1) if m else m2.group(1)).rstrip("/")
            raw = re.sub(r"/index$", "", raw)
            raw = re.sub(r"\([^)]*\)/?", "", raw)
            route = "/" + re.sub(r"\[\.\.\.(\w+)\]", r":\1*", re.sub(r"\[(\w+)\]", r":\1", raw))
            handlers = []
            if m:
                var = jf.exports["default"]
                hit = self._file_func(jf, var)
                if hit:
                    handlers.append(("ANY", hit[1], var))
            else:
                for name, var in jf.exports["names"].items():
                    if name in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                        hit = self._file_func(jf, var) or self._file_func(jf, name)
                        if hit:
                            handlers.append((name, hit[1], name))
            for method, fn, name in handlers:
                ep = EntryPoint(method=method, path=route, framework="nextjs", file=jf.path, line=L(fn), handler=name,
                                group=jf.path)
                ep.facts = FuncAnalyzer(jf, fn, "nextjs").run()
                ep.end_line = fn.end_point[0] + 1
                ep.source = trim_source(T(fn), 60)
                if method == "ANY":
                    ms = {str(c.right.literal).upper() for c in ep.facts.compares if c.right.has_literal and isinstance(c.right.literal, str)
                          and "method" in c.left.text.lower() and str(c.right.literal).upper() in ("GET", "POST", "PUT", "PATCH", "DELETE")}
                    if len(ms) == 1:
                        ep.method = next(iter(ms))
                if mw_scopes is not None and any(path_matches_scope(route, s) or s == "" for s in mw_scopes):
                    ep.guards.append(Guard(name="middleware.ts", kind="authentication", scope="global", certainty="name",
                                           file=mw.path, line=1, evidence="Next.js middleware", identity_source="verified"))
                self._add(ep)

    def apply_global(self):
        for gg in self.project.global_guards:
            pass

    # -- signals (CORS, defaults, tokens, cookies) -------------------------------------------------
    def scan_signals(self, jf):
        proj = self.project
        sess_import = any(spec and re.search(r"express-session|cookie-session|iron-session|next-auth|passport|koa-session|@fastify/(session|cookie)|fastify-session|cookie-parser", spec)
                          for _, _, spec in jf.imports.values())
        if sess_import:
            proj.cookie_auth = True
        if re.search(r"\breq\.(session|cookies)\b", jf.source) or re.search(r"\bsession\s*\(\s*\{", jf.source):
            proj.cookie_auth = True
        cred_header = bool(re.search(r"Access-Control-Allow-Credentials", jf.source, re.I))
        for n in walk(jf.root):
            if n.type == "pair":
                k = T(n.child_by_field_name("key")).strip("'\"")
                v = n.child_by_field_name("value")
                if k.lower() == "samesite" and v is not None and T(v).strip("'\"").lower() in ("lax", "strict", "true"):
                    proj.samesite_configured = True
            if n.type != "call_expression":
                continue
            fn = n.child_by_field_name("function")
            name = callee_text(fn)
            args = named(n.child_by_field_name("arguments"))
            short = name.split(".")[-1]
            line = L(n)
            if short in ("cors", "enableCors") or (name in jf.imports and jf.imports[name][2] == "cors"):
                self._cors(jf, n, args, line)
            elif re.match(r"^(res|reply|response|ctx)\.(header|set|setHeader|append)$", name) and args:
                if string_value(args[0]) and string_value(args[0]).lower() == "access-control-allow-origin" and len(args) > 1:
                    val = T(args[1])
                    if re.search(r"origin|referer", val, re.I) and not args[1].type == "string":
                        proj.signals.append(Signal("A01-CORS", jf.path, line, T(n)[:200], detail="Access-Control-Allow-Origin reflects the request Origin",
                                                   confidence="high", extra={"origin": "reflected", "credentials": cred_header}))
                    elif string_value(args[1]) == "*":
                        proj.signals.append(Signal("A01-CORS", jf.path, line, T(n)[:200], detail="Access-Control-Allow-Origin: *",
                                                   confidence="high", extra={"origin": "wildcard", "credentials": cred_header}))
            elif name.endswith("express.static") or short in ("serveStatic",):
                self._static(jf, n, args, line)
            elif short == "serveIndex":
                proj.signals.append(Signal("A01-INSECURE-DEFAULTS", jf.path, line, T(n)[:160], cwe=548,
                                           detail="directory listing enabled with serve-index", confidence="high"))
            elif re.match(r"^(fs|fsp|fse|fs\.promises|promises)\.(chmod|chmodSync|mkdir|mkdirSync|writeFile|writeFileSync|copyFile|open|openSync)$", name):
                self._mode(jf, n, args, line, short)
            elif name == "process.umask" and args and T(args[0]) in ("0", "0o0", "000"):
                proj.signals.append(Signal("A01-INSECURE-DEFAULTS", jf.path, line, T(n)[:160], cwe=276,
                                           detail="umask(0) makes new files world-writable", confidence="medium"))
            elif P.TOKEN_SIGN.match(name) and name.startswith(("jwt.", "jsonwebtoken.")) or name in ("jwt.sign", "jsonwebtoken.sign"):
                self._jwt_sign(jf, n, args, line)
        if self.side_of(jf.path) == "client":
            self._client(jf)

    def _cors(self, jf, n, args, line):
        proj = self.project
        text = T(n)[:200]
        if not args:
            proj.signals.append(Signal("A01-CORS", jf.path, line, text, detail="cors() with defaults allows every origin",
                                       confidence="medium", extra={"origin": "default", "credentials": False}))
            return
        opts = args[0] if args[0].type == "object" else None
        if opts is None:
            return
        keys = {T(c.child_by_field_name("key")).strip("'\""): c.child_by_field_name("value") for c in named(opts) if c.type == "pair"}
        cred = "credentials" in keys and T(keys["credentials"]) == "true"
        origin = keys.get("origin")
        if origin is None:
            proj.signals.append(Signal("A01-CORS", jf.path, line, text, detail="cors() without an origin allow-list",
                                       confidence="medium", extra={"origin": "default", "credentials": cred}))
            return
        ot = T(origin)
        if ot == "true" or (origin.type in ("arrow_function", "function_expression") and re.search(r"cb\(\s*null\s*,\s*true|callback\(\s*null\s*,\s*true|=>\s*true", ot)):
            kind, detail = "reflected", "CORS origin callback/true reflects every request Origin"
        elif string_value(origin) == "*":
            kind, detail = "wildcard", "CORS origin '*'"
        elif origin.type == "regex" and not re.search(r"\$/?[gimsuy]*$", ot):
            kind, detail = "regex", "CORS origin regular expression is not anchored"
        elif origin.type == "regex" and re.search(r"\.\*", ot):
            kind, detail = "regex", "CORS origin regular expression is overly broad"
        else:
            return
        proj.signals.append(Signal("A01-CORS", jf.path, line, text, detail=detail, confidence="high",
                                   extra={"origin": kind, "credentials": cred}))

    def _static(self, jf, n, args, line):
        if not args:
            return
        a = args[0]
        txt = T(a)
        lit = string_value(a)
        directory = lit
        if directory is None and a.type == "call_expression":
            lits = [string_value(x) for x in named(a.child_by_field_name("arguments")) if string_value(x) is not None]
            directory = lits[-1] if lits else ""
            if not lits and re.search(r"__dirname|process\.cwd\(\)", txt):
                directory = "."
        if directory is None and re.fullmatch(r"__dirname|process\.cwd\(\)", txt):
            directory = "."
        if directory in (".", "./", "", "/", "..") or (directory is not None and directory.strip("./") == ""):
            self.project.signals.append(Signal("A01-INSECURE-DEFAULTS", jf.path, line, T(n)[:160], cwe=538,
                                               detail="the project/application root is served as static files",
                                               confidence="high", extra={"kind": "root-static"}))
        elif directory:
            self.project.static_dirs.append(directory.strip("./"))

    def _mode(self, jf, n, args, line, short):
        mode = None
        if short.startswith("chmod") and len(args) >= 2:
            mode = parse_int_literal(T(args[1])) if args[1].type == "number" else (int(string_value(args[1]), 8) if (string_value(args[1]) or "").isdigit() else None)
        else:
            for a in args:
                if a.type == "object":
                    for c in named(a):
                        if c.type == "pair" and T(c.child_by_field_name("key")) == "mode":
                            v = c.child_by_field_name("value")
                            mode = parse_int_literal(T(v)) if v.type == "number" else None
        if mode is not None and mode & 0o002:
            self.project.signals.append(Signal("A01-INSECURE-DEFAULTS", jf.path, line, T(n)[:160], cwe=732,
                                               detail=f"world-writable permissions (mode {oct(mode)})", confidence="high"))

    def _jwt_sign(self, jf, n, args, line):
        if len(args) < 2:
            return
        opts = args[2] if len(args) > 2 else None
        has_exp = False
        if opts is not None and opts.type == "object":
            has_exp = any(T(c.child_by_field_name("key")).strip("'\"") in ("expiresIn", "exp", "notBefore") for c in named(opts) if c.type == "pair")
        elif opts is not None:
            return  # options come from a variable: unknown
        payload = args[0]
        if payload.type == "object" and any(T(c.child_by_field_name("key")).strip("'\"") == "exp" for c in named(payload) if c.type == "pair"):
            has_exp = True
        if not has_exp:
            self.project.signals.append(Signal("A01-TOKEN-SESSION", jf.path, line, T(n)[:160], cwe=613,
                                               detail="JWT signed without expiry (expiresIn/exp)", confidence="high"))

    def _client(self, jf):
        urls = sorted({v for n in walk(jf.root) if n.type in ("string", "template_string")
                       for v in [string_value(n) if n.type == "string" else template_prefix(n)]
                       if v and v.startswith("/") and len(v) > 2 and not re.search(r"\.(png|jpg|svg|css|js|ico|gif)$", v)})
        for n in walk(jf.root):
            if n.type == "binary_expression":
                op = T(n.child_by_field_name("operator"))
                l, r = T(n.child_by_field_name("left")), T(n.child_by_field_name("right"))
                if op in ("===", "==", "!==", "!=") and (re.search(r"role|isAdmin|userType|permission", l + r, re.I)) and \
                        (ADMINISH.search(l) or ADMINISH.search(r)):
                    self.project.client_checks.append((jf.path, L(n), T(n)[:160], urls))
            elif n.type == "member_expression" and re.search(r"\.(isAdmin|is_admin|isSuperuser)$", T(n)) and n.parent is not None \
                    and n.parent.type in ("binary_expression", "if_statement", "parenthesized_expression", "jsx_expression", "ternary_expression"):
                self.project.client_checks.append((jf.path, L(n), T(n.parent)[:160], urls))


TOKEN_DECODE_RE = re.compile(r"^(jwt|jsonwebtoken|jose|JWT)\.decode$|^jwtDecode$|^jwt_decode$|^decodeJwt$")


def extract(files: dict, project: Project, side_of, config=None):
    """Fill ``project`` from every JS/TS file in ``files`` (path -> source)."""
    ex = JsExtractor(files, project, side_of, config)
    ex.run()
    if ex.files:
        project.extractors_used.append("javascript/typescript (tree-sitter)")
    return ex
