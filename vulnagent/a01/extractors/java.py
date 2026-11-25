"""Java / Kotlin-style (Java grammar) extractor: Spring MVC / Spring Security / JAX-RS annotations.

Implemented: controller routes with class+method mappings, @PreAuthorize/@Secured/@RolesAllowed/@PermitAll guards,
request-bound parameters, repository calls for the shared rules, SecurityFilterChain (csrf disabled, permitAll /
authenticated defaults, path rules). Kotlin sources are listed as not analysed.
"""

from __future__ import annotations

import re

from ..ir import ArgInfo, CallRec, EntryPoint, Guard, HandlerFacts, Project, ResponseRec
from .base import join_path, path_matches_scope, trim_source
from .. import patterns as P

try:
    import tree_sitter_java as _tsj
    from tree_sitter import Language, Parser
    AVAILABLE = True
except Exception:  # pragma: no cover
    AVAILABLE = False

MAPPINGS = {"GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT", "PatchMapping": "PATCH", "DeleteMapping": "DELETE",
            "RequestMapping": "ANY", "GET": "GET", "POST": "POST", "PUT": "PUT", "DELETE": "DELETE", "PATCH": "PATCH"}


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


def annotations(node):
    mods = next((c for c in node.children if c.type == "modifiers"), None)
    out = []
    for a in (mods.children if mods is not None else []):
        if a.type in ("annotation", "marker_annotation"):
            name = T(a.child_by_field_name("name"))
            args = a.child_by_field_name("arguments")
            out.append((name.split(".")[-1], T(args) if args is not None else "", a))
    return out


def strings(text):
    return re.findall(r'"([^"]*)"', text)


def mapping_path(args_text):
    s = strings(args_text)
    return s[0] if s else ""


def method_from_request_mapping(args_text):
    m = re.search(r"RequestMethod\.(GET|POST|PUT|DELETE|PATCH)", args_text)
    return m.group(1) if m else "ANY"


def guard_from_expr(expr: str, name: str, file: str, line: int, scope: str):
    kinds = []
    e = expr
    if re.search(r"permitAll|anonymous", e):
        return None
    if re.search(r"hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|hasPermission|@\w+\.", e):
        kinds.append("authorization")
    if re.search(r"isAuthenticated|authenticated\(\)|fullyAuthenticated", e) and not kinds:
        kinds.append("authentication")
    if re.search(r"#\w+\s*==\s*authentication|principal|#id\s*==|\.owner|\.userId", e):
        kinds.append("ownership")
    if not kinds:
        kinds.append("authorization")
    return [Guard(name=name, kind=k, scope=scope, certainty="code", file=file, line=line, evidence=f"@{name}({e})"[:140],
                  identity_source="verified") for k in kinds]


class JavaExtractor:
    def __init__(self, files, project: Project, side_of, config=None):
        self.project = project
        self.parser = Parser(Language(_tsj.language()))
        self.sources = {p: s for p, s in files.items() if p.endswith(".java")}

    def run(self):
        for path, src in self.sources.items():
            try:
                tree = self.parser.parse(src.encode("utf8", "replace"))
            except Exception as exc:  # pragma: no cover
                self.project.files_failed.append((path, str(exc)))
                continue
            self.project.files_parsed.append(path)
            self.security_config(path, tree.root_node, src)
            for cls in (n for n in walk(tree.root_node) if n.type == "class_declaration"):
                self.controller(path, cls, src)
        self.apply_path_rules()
        if self.sources:
            self.project.extractors_used.append("java (tree-sitter: Spring MVC / Security, JAX-RS) - partial")

    # --------------------------------------------------------------- security configuration
    def security_config(self, path, root, src):
        gs = self.project.global_security
        text = src
        if not re.search(r"SecurityFilterChain|EnableWebSecurity|WebSecurityConfigurerAdapter|HttpSecurity", text):
            return
        gs["found"] = True
        self.project.frameworks.add("spring")
        gs["csrf_default"]["spring"] = True
        for n in walk(root):
            if n.type != "method_invocation":
                continue
            name = T(n.child_by_field_name("name"))
            full = T(n)
            line = L(n)
            if name == "disable" and re.search(r"csrf\s*\(", full.split(".disable")[0][-60:]) or (name == "csrf" and re.search(r"disable|ignoringRequestMatchers|AbstractHttpConfigurer::disable", full[:200]) and "csrf" in full[:30]):
                if not any(x[1] == line for x in gs["csrf_disabled"]):
                    gs["csrf_disabled"].append((path, line, "CSRF protection disabled in Spring Security"))
                gs["csrf_default"]["spring"] = False
            if name in ("permitAll", "authenticated", "hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority", "denyAll"):
                obj = n.child_by_field_name("object")
                oname = T(obj.child_by_field_name("name")) if obj is not None and obj.type == "method_invocation" else ""
                args = obj.child_by_field_name("arguments") if obj is not None and obj.type == "method_invocation" else None
                if oname == "anyRequest":
                    if name == "permitAll":
                        gs["default_allow_all"] = (path, line)
                    elif name in ("authenticated", "hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority"):
                        gs["default_authn"] = True
                        gs["notes"].append(f"anyRequest() requires {name} ({path}:{line})")
                elif oname in ("requestMatchers", "antMatchers", "mvcMatchers", "securityMatcher"):
                    kind = "public" if name == "permitAll" else "authentication" if name == "authenticated" else "authorization"
                    for pat in strings(T(args)):
                        gs.setdefault("path_rules", []).append((pat, kind, path, line, name))

    def apply_path_rules(self):
        rules = self.project.global_security.get("path_rules", [])
        for ep in self.project.entry_points:
            if ep.framework != "spring":
                continue
            for pat, kind, file, line, name in rules:
                base = re.sub(r"/?\*+$", "", pat)
                if path_matches_scope(ep.path, base) or ep.path == pat:
                    if kind == "public":
                        ep.notes.append("public_marker")
                    else:
                        ep.guards.append(Guard(name=name, kind=kind, scope="global", certainty="code", file=file, line=line,
                                               evidence=f"{pat} -> {name}", identity_source="verified"))

    # --------------------------------------------------------------- controllers
    def controller(self, path, cls, src):
        anns = annotations(cls)
        names = {a[0] for a in anns}
        if not names & {"RestController", "Controller", "Path"}:
            return
        self.project.frameworks.add("spring" if names & {"RestController", "Controller"} else "jaxrs")
        fw = "spring" if names & {"RestController", "Controller"} else "jaxrs"
        base = ""
        for n, a, _ in anns:
            if n in ("RequestMapping", "Path"):
                base = mapping_path(a)
        cguards = self.guards(path, anns, "controller")
        cname = T(cls.child_by_field_name("name"))
        body = cls.child_by_field_name("body")
        fields = {}
        for f in (body.children if body is not None else []):
            if f.type == "field_declaration":
                decl = next((c for c in f.children if c.type == "variable_declarator"), None)
                typ = f.child_by_field_name("type")
                if decl is not None and typ is not None:
                    fields[T(decl.child_by_field_name("name"))] = T(typ)
        for m in (body.children if body is not None else []):
            if m.type != "method_declaration":
                continue
            manns = annotations(m)
            verbs = [(MAPPINGS[n], a) for n, a, _ in manns if n in MAPPINGS]
            if not verbs:
                continue
            sub = ""
            for n, a, _ in manns:
                if n in MAPPINGS or n == "Path":
                    sub = mapping_path(a) or sub
            public = any(n in ("PermitAll",) for n, _, _ in manns)
            mguards = self.guards(path, manns, "route")
            for verb, a in verbs:
                if verb == "ANY":
                    verb = method_from_request_mapping(a)
                ep = EntryPoint(method=verb, path=join_path(base, sub), framework=fw, file=path, line=L(m), group=f"{path}:{cname}",
                                handler=f"{cname}.{T(m.child_by_field_name('name'))}")
                ep.facts = self.facts(m, fields)
                ep.end_line = m.end_point[0] + 1
                ep.source = trim_source(T(m), 60)
                ep.guards = cguards + mguards
                if public:
                    ep.notes.append("public_marker")
                self.project.entry_points.append(ep)

    def guards(self, path, anns, scope):
        out = []
        for n, a, node in anns:
            if n in ("PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed"):
                g = guard_from_expr(a if n in ("PreAuthorize", "PostAuthorize") else f"hasRole{a}", n, path, L(node), scope)
                if g:
                    out += g
        for g in out:
            self.project.guards.append(g)
        return out

    def facts(self, method, fields):
        f = HandlerFacts()
        env = {}
        params = method.child_by_field_name("parameters")
        for p in (params.children if params is not None else []):
            if p.type != "formal_parameter":
                continue
            name = T(p.child_by_field_name("name"))
            panns = annotations(p)
            pn = {a[0] for a in panns}
            ptype = T(p.child_by_field_name("type"))
            if "RequestBody" in pn or ("Valid" in pn and not pn & {"PathVariable", "RequestParam"}) or "BeanParam" in pn:
                env[name] = ArgInfo(text=name, taint=("body", "*", False), origin={"model": ptype, "op": "new", "projected": False, "collection": False})
            elif "PathVariable" in pn or "PathParam" in pn:
                env[name] = ArgInfo(text=name, taint=("params", name, False))
            elif pn & {"RequestParam", "QueryParam"}:
                env[name] = ArgInfo(text=name, taint=("query", name, False))
            elif pn & {"RequestHeader", "HeaderParam"}:
                env[name] = ArgInfo(text=name, taint=("headers", name, False))
            elif pn & {"AuthenticationPrincipal", "CurrentUser"} or ptype in ("Principal", "Authentication", "UserDetails"):
                env[name] = ArgInfo(text=name, identity=True)
        body = method.child_by_field_name("body")
        reads = {}
        for n in walk(body) if body is not None else []:
            if n.type == "method_invocation":
                obj = n.child_by_field_name("object")
                name = T(n.child_by_field_name("name"))
                callee = (T(obj) + "." if obj is not None else "") + name
                args_node = n.child_by_field_name("arguments")
                args = []
                for a in (args_node.children if args_node is not None else []):
                    if not a.is_named:
                        continue
                    t = T(a)
                    info = env.get(t)
                    if info is None:
                        m = re.match(r"(\w+)\.(get\w+)\(\)", t)
                        if m and m.group(1) in env and env[m.group(1)].taint:
                            fld = re.sub(r"^get", "", m.group(2))
                            fld = fld[:1].lower() + fld[1:]
                            info = ArgInfo(text=t, taint=(env[m.group(1)].taint[0], fld, False))
                        elif re.search(r"principal|authentication|getUsername|getName\(\)", t, re.I) and not env.get(t):
                            info = ArgInfo(text=t, identity=bool(re.match(r"(principal|authentication|auth)\b", t)))
                        else:
                            info = ArgInfo(text=t)
                    args.append(info)
                recv_origin = None
                if re.match(r"^(\w+)$", T(obj)) and T(obj) in env:
                    recv_origin = env[T(obj)].origin
                f.calls.append(CallRec(callee=callee, args=args, line=L(n), text=T(n)[:240], receiver_origin=recv_origin))
            elif n.type == "return_statement":
                kids = [c for c in n.children if c.is_named]
                if kids:
                    t = T(kids[0])
                    info = ArgInfo(text=t)
                    m = re.search(r"(\w+Repository|\w+Repo|\w+Service)\.(\w+)\(", t)
                    if m:
                        info.origin = {"model": re.sub(r"(Repository|Repo|Service)$", "", m.group(1)), "op": m.group(2), "projected": False,
                                       "collection": bool(re.match(r"(findAll|list|getAll|all)", m.group(2)))}
                    f.responses.append(ResponseRec("return", info, None, L(n)))
        for v in env.values():
            if v.taint:
                reads.setdefault(v.taint[0], set()).add(v.taint[1])
        f.reads = {k: sorted(x) for k, x in reads.items()}
        f.uses_identity = any(v.identity for v in env.values())
        return f


def extract(files, project, side_of, config=None):
    ex = JavaExtractor(files, project, side_of, config)
    ex.run()
    return ex
