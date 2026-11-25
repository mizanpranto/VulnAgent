"""C# extractor (tree-sitter-c-sharp): ASP.NET Core attributes and authorization setup (partial)."""

from __future__ import annotations

import re

from ..ir import ArgInfo, CallRec, EntryPoint, Guard, HandlerFacts, Project, ResponseRec
from .base import join_path, trim_source

try:
    import tree_sitter_c_sharp as _tscs
    from tree_sitter import Language, Parser
    AVAILABLE = True
except Exception:  # pragma: no cover
    AVAILABLE = False

VERBS = {"HttpGet": "GET", "HttpPost": "POST", "HttpPut": "PUT", "HttpPatch": "PATCH", "HttpDelete": "DELETE", "Route": "ANY"}


def available():
    return AVAILABLE


def T(n):
    return n.text.decode("utf8", "replace") if n is not None else ""


def L(n):
    return n.start_point[0] + 1


def walk(n):
    stack = [n]
    while stack:
        c = stack.pop()
        yield c
        stack.extend(reversed(c.children))


def attrs(node):
    out = []
    for al in (c for c in node.children if c.type == "attribute_list"):
        for a in (c for c in al.children if c.type == "attribute"):
            name = T(a.child_by_field_name("name")) if a.child_by_field_name("name") is not None else T(a.children[0])
            args = next((c for c in a.children if c.type == "attribute_argument_list"), None)
            out.append((name.split(".")[-1], T(args) if args is not None else "", a))
    return out


class CSharpExtractor:
    def __init__(self, files, project: Project, side_of, config=None):
        self.project = project
        self.parser = Parser(Language(_tscs.language()))
        self.sources = {p: s for p, s in files.items() if p.endswith(".cs")}

    def run(self):
        gs = self.project.global_security
        for path, src in self.sources.items():
            try:
                tree = self.parser.parse(src.encode("utf8", "replace"))
            except Exception as exc:  # pragma: no cover
                self.project.files_failed.append((path, str(exc)))
                continue
            self.project.files_parsed.append(path)
            if re.search(r"FallbackPolicy|RequireAuthorization\(\)|AddAuthorization", src):
                gs["found"] = True
                if re.search(r"FallbackPolicy\s*=[^;]*RequireAuthenticatedUser|MapControllers\(\)\s*\.RequireAuthorization\(\)", src, re.S):
                    gs["default_authn"] = True
                    gs["notes"].append(f"fallback authorization policy requires authenticated users ({path})")
            for cls in (n for n in walk(tree.root_node) if n.type == "class_declaration"):
                self.controller(path, cls)
        if self.sources:
            self.project.extractors_used.append("c# (tree-sitter: ASP.NET Core attributes) - partial")

    def controller(self, path, cls):
        name = T(cls.child_by_field_name("name"))
        cattrs = attrs(cls)
        cnames = {a[0] for a in cattrs}
        if not (name.endswith("Controller") or "ApiController" in cnames):
            return
        self.project.frameworks.add("aspnet")
        base = ""
        for n, a, _ in cattrs:
            if n == "Route":
                m = re.search(r'"([^"]*)"', a)
                base = (m.group(1) if m else "").replace("[controller]", re.sub(r"Controller$", "", name).lower())
        cguards = self.guards(path, cattrs, "controller")
        csrf_ignore = "IgnoreAntiforgeryToken" in cnames
        body = cls.child_by_field_name("body")
        for m in (body.children if body is not None else []):
            if m.type != "method_declaration":
                continue
            mattrs = attrs(m)
            verbs = [(VERBS[n], a) for n, a, _ in mattrs if n in VERBS and n != "Route"]
            if not verbs:
                continue
            sub = ""
            for n, a, _ in mattrs:
                if n in VERBS:
                    mm = re.search(r'"([^"]*)"', a)
                    sub = mm.group(1) if mm else sub
            mguards = self.guards(path, mattrs, "route")
            anon = any(n == "AllowAnonymous" for n, _, _ in mattrs) or "AllowAnonymous" in cnames
            for verb, _ in verbs:
                full = join_path(re.sub(r"\{(\w+)(?::[^}]*)?\}", r":\1", base), re.sub(r"\{(\w+)(?::[^}]*)?\}", r":\1", sub))
                ep = EntryPoint(method=verb, path=full, framework="aspnet", file=path, line=L(m), group=f"{path}:{name}",
                                handler=f"{name}.{T(m.child_by_field_name('name'))}")
                ep.facts = self.facts(m)
                ep.end_line = m.end_point[0] + 1
                ep.source = trim_source(T(m), 60)
                gl = [g for g in (cguards + mguards)]
                if anon:
                    gl = [g for g in gl if g.kind not in ("authentication", "authorization")]
                    ep.notes.append("public_marker")
                ep.guards = gl
                if csrf_ignore or any(n == "IgnoreAntiforgeryToken" for n, _, _ in mattrs):
                    ep.notes.append("csrf_exempt")
                self.project.entry_points.append(ep)

    def guards(self, path, anns, scope):
        out = []
        for n, a, node in anns:
            if n == "Authorize":
                kind = "authorization" if re.search(r"Roles|Policy", a) else "authentication"
                out.append(Guard(name=f"Authorize{a}", kind=kind, scope=scope, certainty="code", file=path, line=L(node), evidence=f"[Authorize{a}]",
                                 identity_source="verified"))
                if kind == "authorization":
                    out.append(Guard(name="Authorize", kind="authentication", scope=scope, certainty="code", file=path, line=L(node),
                                     evidence=f"[Authorize{a}]", identity_source="verified"))
            elif n in ("ValidateAntiForgeryToken", "AutoValidateAntiforgeryToken"):
                out.append(Guard(name=n, kind="csrf", scope=scope, certainty="code", file=path, line=L(node), evidence=n))
        for g in out:
            self.project.guards.append(g)
        return out

    def facts(self, method):
        f = HandlerFacts()
        env = {}
        params = method.child_by_field_name("parameters") or method.child_by_field_name("parameter_list")
        for p in (params.children if params is not None else []):
            if p.type != "parameter":
                continue
            name = T(p.child_by_field_name("name"))
            panns = {a[0] for a in attrs(p)}
            if "FromBody" in panns:
                env[name] = ArgInfo(text=name, taint=("body", "*", False))
            elif "FromQuery" in panns:
                env[name] = ArgInfo(text=name, taint=("query", name, False))
            elif "FromHeader" in panns:
                env[name] = ArgInfo(text=name, taint=("headers", name, False))
            elif not panns:
                env[name] = ArgInfo(text=name, taint=("params", name, False))
        body = method.child_by_field_name("body")
        reads = {}
        for n in walk(body) if body is not None else []:
            if n.type == "invocation_expression":
                fn = n.child_by_field_name("function")
                args_node = n.child_by_field_name("arguments")
                args = []
                for a in (args_node.children if args_node is not None else []):
                    if a.type == "argument":
                        t = T(a)
                        args.append(env.get(t) or ArgInfo(text=t, identity=bool(re.search(r"User\.(FindFirst|Identity)|GetUserId", t))))
                f.calls.append(CallRec(callee=re.sub(r"\s+", "", T(fn)), args=args, line=L(n), text=T(n)[:240]))
            elif n.type == "return_statement":
                kids = [c for c in n.children if c.is_named]
                if kids:
                    f.responses.append(ResponseRec("return", ArgInfo(text=T(kids[0])), None, L(n)))
        for v in env.values():
            if v.taint:
                reads.setdefault(v.taint[0], set()).add(v.taint[1])
        f.reads = {k: sorted(x) for k, x in reads.items()}
        f.uses_identity = any("User." in c.text for c in f.calls)
        return f


def extract(files, project, side_of, config=None):
    CSharpExtractor(files, project, side_of, config).run()
