"""Lightweight intra-procedural taint analysis for Python.

This is deliberately simple and explainable rather than complete:

* sources: ``request.args/form/json/...``, ``input()``, ``sys.argv`` and the
  parameters of route-decorated functions;
* propagation: assignments, f-strings, ``+``/``%``/``.format``, subscripts,
  attributes and ordinary calls (conservatively);
* sanitizers: ``int()``/``float()`` (becomes a "numeric" taint that cannot
  inject), ``shlex.quote``, ``secure_filename``, ``escape`` and friends;
* sinks: SQL execution, shell commands, file access, outbound requests,
  deserialization, ``eval``/``exec``, template rendering, redirects, ...

Limits (stated in the README as well): flows are tracked inside one function
only, there is no inter-procedural or cross-file analysis, and guards such as
``if host in ALLOWED`` are not understood. The LLM triage stage exists to
reason about exactly those cases.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Optional

from .models import Finding

SOURCE_ATTRS = {
    "args", "form", "values", "json", "data", "files", "cookies", "headers",
    "get_json", "get_data", "view_args", "query_string", "stream",
    # Django
    "GET", "POST", "body", "FILES", "COOKIES", "META",
    # request metadata an attacker also controls
    "url", "full_path", "path", "host", "host_url", "base_url", "url_root", "referrer", "user_agent",
}

SANITIZERS = {
    "escape", "quote", "quote_plus", "secure_filename", "basename", "clean",
    "sanitize", "slugify", "escape_string", "min", "len", "bool", "isinstance",
    "hash_password", "check_password_hash", "generate_password_hash",
}
NUMERIC_CASTS = {"int", "float"}

SECURITY_NAME = re.compile(
    r"token|secret|otp|passw|session|nonce|reset|csrf|api_?key|salt|auth", re.I
)
SENSITIVE_NAME = re.compile(
    r"passw|passwd|pwd|secret|token|api_?key|private_?key|credit|ssn", re.I
)
CRED_NAME = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|apikey|token|private[_-]?key|"
    r"auth[_-]?key|access[_-]?key)", re.I
)
PLACEHOLDER = re.compile(
    r"^(your|<|\$\{|\{\{|changeme|change_me|xxx|example|placeholder|todo|env:|none$|null$)",
    re.I,
)
AUTH_REF = re.compile(
    r"session|current_user|login_required|jwt|authoriz|authenticat|permission|"
    r"has_role|g\.user|require_|csrf_token|abort\(40[13]",
    re.I,
)
NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*[+*{]")
HTTP_VERBS = {"get", "post", "put", "delete", "patch", "head", "request", "options"}
ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "api_route"}


@dataclass
class Taint:
    label: str  # "str" can inject, "num" cannot (but can exhaust resources)
    trace: list = field(default_factory=list)

    def extend(self, step: str) -> "Taint":
        return Taint(self.label, (self.trace + [step])[-6:])


def dotted(node) -> Optional[str]:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Call):
        inner = dotted(node.func)
        if inner is not None:
            parts.append(inner + "()")
            return ".".join(reversed(parts))
    return None


def call_names(call: ast.Call):
    """Return (dotted name, last component) of the callee."""
    func = call.func
    full = dotted(func) or ""
    if isinstance(func, ast.Attribute):
        return full, func.attr
    if isinstance(func, ast.Name):
        return full or func.id, func.id
    return full, ""


def source_of(node) -> Optional[str]:
    cand = node
    if isinstance(cand, ast.Subscript):
        cand = cand.value
    if isinstance(cand, ast.Call):
        cand = cand.func
    if not isinstance(cand, (ast.Attribute, ast.Name)):
        return None
    name = dotted(cand)
    if not name:
        return None
    if name.startswith("flask."):
        name = name[len("flask."):]
    parts = name.split(".")
    if parts[0] == "request" and len(parts) >= 2 and parts[1] in SOURCE_ATTRS:
        return name
    if name in ("input", "raw_input", "sys.argv"):
        return name
    return None


def _merge(items):
    items = [t for t in items if t]
    if not items:
        return None
    for item in items:
        if item.label == "str":
            return item
    return items[0]


def taint_of(node, env) -> Optional[Taint]:
    if node is None or isinstance(node, ast.Constant):
        return None
    src = source_of(node)
    if src:
        return Taint("str", [f"{src} (line {node.lineno})"])
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.JoinedStr):
        return _merge([taint_of(v, env) for v in node.values])
    if isinstance(node, ast.FormattedValue):
        return taint_of(node.value, env)
    if isinstance(node, ast.BinOp):
        left, right = taint_of(node.left, env), taint_of(node.right, env)
        merged = _merge([left, right])
        if merged and merged.label == "num" and isinstance(node.op, ast.Mult):
            return None
        return merged
    if isinstance(node, (ast.Subscript, ast.Attribute, ast.Starred, ast.Await)):
        return taint_of(node.value, env)
    if isinstance(node, ast.IfExp):
        return _merge([taint_of(node.body, env), taint_of(node.orelse, env)])
    if isinstance(node, ast.BoolOp):
        return _merge([taint_of(v, env) for v in node.values])
    if isinstance(node, ast.UnaryOp):
        return taint_of(node.operand, env)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return _merge([taint_of(e, env) for e in node.elts])
    if isinstance(node, ast.Dict):
        return _merge([taint_of(v, env) for v in node.values if v is not None])
    if isinstance(node, ast.Call):
        full, base = call_names(node)
        args = list(node.args) + [k.value for k in node.keywords]
        inner = _merge([taint_of(a, env) for a in args])
        if base in NUMERIC_CASTS and full in NUMERIC_CASTS:
            return Taint("num", inner.trace) if inner else None
        if base in SANITIZERS:
            return None
        owner = None
        if isinstance(node.func, ast.Attribute):
            owner = taint_of(node.func.value, env)
        return _merge([inner, owner])
    return None


def _leading_text(node, strs) -> str:
    """Best-effort leading literal of a string-building expression."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and node.values:
        return _leading_text(node.values[0], strs)
    if isinstance(node, ast.BinOp):
        return _leading_text(node.left, strs)
    if isinstance(node, ast.Name):
        return strs.get(node.id, "")
    return ""


def _has_html_literal(node) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and "<" in sub.value:
            return True
    return False


def _route_info(func):
    """Return (is_route, {param: label}) for a function definition."""
    for dec in func.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute) and target.attr in ROUTE_DECORATORS:
            converters = {}
            if isinstance(dec, ast.Call) and dec.args:
                first = dec.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    for conv, name in re.findall(r"<(?:(\w+):)?(\w+)>", first.value):
                        converters[name] = "num" if conv in ("int", "float") else (
                            None if conv == "uuid" else "str"
                        )
            return True, converters
    return False, {}


class _Analyzer:
    def __init__(self, path: str, source: str):
        self.path = path
        self.lines = source.splitlines()
        self.findings: list = []

    # ---- helpers -------------------------------------------------------
    def line_text(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()[:300]
        return ""

    def add(self, node, title, severity, cwe, why, fix, rule,
            confidence="high", flow=None, source="", sink=""):
        line = getattr(node, "lineno", 1)
        self.findings.append(Finding(
            title=title, severity=severity, file=self.path, line=line, cwe=cwe,
            confidence=confidence, evidence=self.line_text(line),
            explanation=why, fix=fix, source=source, sink=sink,
            data_flow=flow or [], origins=["taint"], rule_id=rule,
        ))

    def tainted_sink(self, node, taint: Taint, sink_name, **kw):
        flow = taint.trace + [f"reaches {sink_name}() (line {node.lineno})"]
        self.add(node, flow=flow, source=taint.trace[0] if taint.trace else "",
                 sink=f"{sink_name}() (line {node.lineno})", **kw)

    # ---- module / function drivers -------------------------------------
    def run(self, tree):
        self.walk_body(tree.body, {}, {}, _Ctx("<module>", False, {}))
        for func in ast.walk(tree):
            if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.analyze_function(func)

    def analyze_function(self, func):
        is_route, converters = _route_info(func)
        env, strs = {}, {}
        if is_route:
            all_args = (func.args.posonlyargs + func.args.args + func.args.kwonlyargs)
            for arg in all_args:
                if arg.arg in ("self", "cls"):
                    continue
                label = converters.get(arg.arg, "str")
                if isinstance(arg.annotation, ast.Name) and arg.annotation.id in ("int", "float", "bool"):
                    label = "num"
                if label:
                    env[arg.arg] = Taint(label, [f"route parameter `{arg.arg}` (line {func.lineno})"])
        ctx = _Ctx(func.name, is_route, {a.arg for a in func.args.args})
        ctx.func = func
        ctx.func_text = ast.unparse(func).lower() if is_route else ""
        ctx.authenticated = bool(AUTH_REF.search(ctx.func_text)) or any(
            AUTH_REF.search(ast.unparse(d)) for d in func.decorator_list
        )
        self.walk_body(func.body, env, strs, ctx)

    def walk_body(self, body, env, strs, ctx):
        for stmt in body:
            self.walk_stmt(stmt, env, strs, ctx)

    def walk_stmt(self, stmt, env, strs, ctx):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        # 1. inspect expressions of this statement before updating state
        for expr in self.header_exprs(stmt):
            self.check_expr(expr, env, strs, ctx)
        # 2. state updates
        if isinstance(stmt, ast.Assign):
            taint = taint_of(stmt.value, env)
            lead = _leading_text(stmt.value, strs)
            for target in stmt.targets:
                self.assign(target, taint, lead, env, strs, stmt)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            self.assign(stmt.target, taint_of(stmt.value, env),
                        _leading_text(stmt.value, strs), env, strs, stmt)
        elif isinstance(stmt, ast.AugAssign):
            taint = _merge([taint_of(stmt.value, env), taint_of(stmt.target, env)])
            self.assign(stmt.target, taint, "", env, strs, stmt)
        elif isinstance(stmt, ast.For):
            taint = taint_of(stmt.iter, env)
            self.assign(stmt.target, taint, "", env, strs, stmt)
        elif isinstance(stmt, ast.Return) and stmt.value is not None:
            self.check_return(stmt, env, ctx)
        # 3. nested blocks
        for name in ("body", "orelse", "finalbody"):
            block = getattr(stmt, name, None)
            if isinstance(block, list) and not isinstance(stmt, (ast.FunctionDef, ast.ClassDef)):
                self.walk_body(block, env, strs, ctx)
        for handler in getattr(stmt, "handlers", []) or []:
            self.check_handler(handler)
            self.walk_body(handler.body, env, strs, ctx)

    def assign(self, target, taint, lead, env, strs, stmt):
        if isinstance(target, ast.Name):
            if taint:
                env[target.id] = taint.extend(f"assigned to `{target.id}` (line {stmt.lineno})")
            else:
                env.pop(target.id, None)
            if lead:
                strs[target.id] = lead.upper()
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.assign(element, taint, "", env, strs, stmt)

    @staticmethod
    def header_exprs(stmt):
        simple = (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Expr, ast.Return,
                  ast.Delete, ast.Assert, ast.Raise, ast.Import, ast.ImportFrom)
        if isinstance(stmt, simple):
            return [stmt]
        exprs = []
        if isinstance(stmt, (ast.If, ast.While)):
            exprs.append(stmt.test)
        elif isinstance(stmt, ast.For):
            exprs += [stmt.iter, stmt.target]
        elif isinstance(stmt, ast.With):
            exprs += [item.context_expr for item in stmt.items]
        return exprs

    # ---- checks ----------------------------------------------------------
    def check_expr(self, root, env, strs, ctx):
        for node in ast.walk(root):
            if isinstance(node, ast.Call):
                self.check_call(node, env, strs, ctx)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
                self.check_repeat(node, env)
            elif isinstance(node, ast.Compare):
                self.check_compare(node, env)
            elif isinstance(node, ast.Dict):
                self.check_dict_secrets(node)
            elif isinstance(node, ast.Attribute) and node.attr == "CERT_NONE":
                self.add(node, "TLS certificate verification disabled", "high", 295,
                         "ssl.CERT_NONE turns off certificate validation, enabling man-in-the-middle attacks.",
                         "Use ssl.create_default_context() and keep CERT_REQUIRED.", "tls-cert-none")
        if isinstance(root, (ast.Assign, ast.AnnAssign)):
            self.check_secret_assign(root)

    def check_call(self, call, env, strs, ctx):
        full, base = call_names(call)
        args = call.args
        first = taint_of(args[0], env) if args else None
        kw = {k.arg: k.value for k in call.keywords if k.arg}

        def str_taint(t):
            return t is not None and t.label == "str"

        # --- SQL injection
        if base in {"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query"} and args:
            if str_taint(first):
                self.tainted_sink(call, first, base, title="SQL injection", severity="high", cwe=89,
                                  why="Untrusted input is concatenated or interpolated into an SQL statement.",
                                  fix="Use parameterized queries: cursor.execute('... WHERE x = ?', (value,)).",
                                  rule="sqli")
            lead = _leading_text(args[0], strs).lstrip().upper()
            self.check_authz_on_write(call, lead, ctx)
            self.check_idor(call, args, ctx)
        # --- command injection
        if full in {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"} and args:
            if str_taint(first):
                self.tainted_sink(call, first, full, title="OS command injection", severity="critical", cwe=78,
                                  why="Untrusted input is placed into a shell command line.",
                                  fix="Pass an argument list with shell=False and validate the value against an allowlist.",
                                  rule="cmdi")
        elif full in {"subprocess.run", "subprocess.call", "subprocess.Popen",
                      "subprocess.check_output", "subprocess.check_call"} and args:
            shell_true = isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True
            is_list = isinstance(args[0], (ast.List, ast.Tuple))
            if str_taint(first) and (shell_true or not is_list):
                self.tainted_sink(call, first, full, title="OS command injection", severity="critical", cwe=78,
                                  why="Untrusted input reaches a subprocess command string.",
                                  fix="Use an argument list with shell=False and validate input.", rule="cmdi")
        # --- path traversal
        if full in {"open", "io.open", "send_file", "os.remove", "os.unlink", "os.listdir", "os.rename",
                    "shutil.copy", "shutil.rmtree"} and args and str_taint(first):
            self.tainted_sink(call, first, full, title="Path traversal", severity="high", cwe=22,
                              why="A user-controlled value forms a file path without normalisation or containment.",
                              fix="Resolve the path, then check it stays inside the base directory "
                                  "(Path.resolve().is_relative_to(base)) or use secure_filename().",
                              rule="path-traversal")
        if base == "save" and isinstance(call.func, ast.Attribute) and args and str_taint(first):
            self.tainted_sink(call, first, "save", title="Unrestricted file upload (user-controlled filename)",
                              severity="high", cwe=434,
                              why="The uploaded file is stored under a name taken from the client without sanitising "
                                  "or restricting type and size.",
                              fix="Use werkzeug.utils.secure_filename, an extension allowlist, size limits and a "
                                  "non-executable upload directory.", rule="upload")
        # --- SSRF
        is_http = (base == "urlopen" or
                   (full.split(".")[0] in {"requests", "httpx", "aiohttp"} and base in HTTP_VERBS))
        if is_http and args and str_taint(first):
            self.tainted_sink(call, first, full or base, title="Server-side request forgery (SSRF)", severity="high",
                              cwe=918, why="The server fetches a URL chosen by the client, so it can be pointed at "
                                           "internal services or cloud metadata endpoints.",
                              fix="Allowlist schemes and hosts, resolve and block private/link-local addresses, "
                                  "and do not follow redirects blindly.", rule="ssrf")
        # --- deserialization
        if full in {"pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads", "dill.loads",
                    "jsonpickle.decode"} or full in {"yaml.unsafe_load"} or (
                full == "yaml.load" and not self._safe_loader(call)):
            t = first if str_taint(first) else None
            if t:
                self.tainted_sink(call, t, full, title="Insecure deserialization", severity="critical", cwe=502,
                                  why="Untrusted bytes are deserialized with a format that can execute code.",
                                  fix="Use JSON (or yaml.safe_load) and validate the schema; never unpickle untrusted data.",
                                  rule="deserialization")
            else:
                self.add(call, "Unsafe deserialization API in use", "medium", 502,
                         "pickle/marshal/yaml.load can execute code if the data is attacker-influenced. "
                         "No attacker-controlled input was proven here.",
                         "Prefer JSON or yaml.safe_load.", "deserialization-api", confidence="low")
        # --- eval/exec
        if full in {"eval", "exec"}:
            if str_taint(first):
                self.tainted_sink(call, first, full, title="Code injection via eval/exec", severity="critical",
                                  cwe=95, why="Untrusted input is executed as Python code.",
                                  fix="Remove eval/exec; use ast.literal_eval or explicit parsing.", rule="eval")
            else:
                self.add(call, "Dynamic code execution", "medium", 95,
                         "eval/exec is dangerous; no attacker-controlled input was proven here.",
                         "Avoid dynamic execution; use ast.literal_eval or a parser.", "eval-api", confidence="low")
        # --- template injection / XSS
        if base == "render_template_string" and args and str_taint(first):
            self.tainted_sink(call, first, base, title="Server-side template injection / reflected XSS",
                              severity="critical", cwe=1336,
                              why="User input is placed into a template string before rendering, allowing template "
                                  "expressions (often leading to code execution) and HTML injection.",
                              fix="Pass the value as a template variable: render_template_string('{{ q }}', q=value).",
                              rule="ssti")
        if base in {"Markup", "mark_safe"} and args and str_taint(first):
            self.tainted_sink(call, first, base, title="Cross-site scripting (unescaped output)", severity="high",
                              cwe=79, why="User input is marked as safe HTML.",
                              fix="Escape the value or sanitise HTML with an allowlist (bleach).", rule="xss-markup")
        # --- open redirect
        if base == "redirect" and args and str_taint(first):
            self.tainted_sink(call, first, base, title="Open redirect", severity="medium", cwe=601,
                              why="The redirect destination is controlled by the client.",
                              fix="Redirect only to relative paths or an allowlist of hosts.", rule="open-redirect")
        # --- resource consumption
        if base == "range" and full == "range" and args and first is not None:
            self.tainted_sink(call, first, "range", title="Uncontrolled resource consumption", severity="medium",
                              cwe=400, why="A client-controlled number sizes a loop or allocation with no upper bound.",
                              fix="Clamp the value (e.g. min(count, 1000)) and enforce request limits.",
                              rule="resource-exhaustion", confidence="medium")
        # --- weak randomness
        if full.startswith("random.") and base in {"randint", "random", "randrange", "choice", "choices",
                                                    "getrandbits", "sample"}:
            if SECURITY_NAME.search(ctx.func_name or ""):
                self.add(call, "Predictable random value used for a security token", "medium", 338,
                         "The `random` module is not cryptographically secure; tokens can be predicted.",
                         "Use the `secrets` module (secrets.token_urlsafe).", "weak-random")
        # --- hashing
        if full in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}:
            self.add(call, "Weak hash algorithm (MD5/SHA-1)", "medium", 327,
                     "MD5 and SHA-1 are broken for security purposes.",
                     "Use SHA-256+ for integrity or a password KDF (argon2, bcrypt, scrypt) for passwords.",
                     "weak-hash")
        elif full in {"hashlib.sha224", "hashlib.sha256", "hashlib.sha384", "hashlib.sha512"}:
            if "pass" in ast.unparse(call).lower() or "pass" in (ctx.func_name or "").lower():
                self.add(call, "Password hashed with a fast, unsalted hash", "medium", 916,
                         "A single SHA-2 round is cheap to brute-force and has no per-user salt.",
                         "Use argon2, bcrypt or scrypt with a per-user salt.", "weak-password-hash")
        # --- TLS
        if full.endswith("_create_unverified_context"):
            self.add(call, "TLS certificate verification disabled", "high", 295,
                     "An unverified SSL context accepts any certificate.",
                     "Use ssl.create_default_context().", "tls-unverified-context")
        verify_off = "verify" in kw and isinstance(kw["verify"], ast.Constant) and kw["verify"].value is False
        if verify_off and full.split(".")[0] in {"jwt", "pyjwt", "jose"}:
            self.add(call, "JWT signature verification disabled", "high", 347,
                     "Tokens are accepted without checking their signature, so anyone can forge one.",
                     "Always verify signatures with a secret/public key and a fixed algorithm list.",
                     "jwt-no-verify")
        elif verify_off:
            self.add(call, "TLS certificate verification disabled", "high", 295,
                     "verify=False disables certificate checks.", "Remove verify=False.", "tls-verify-false")
        options = kw.get("options")
        if full.split(".")[0] == "jwt" and isinstance(options, ast.Dict) and any(
                isinstance(k, ast.Constant) and k.value == "verify_signature"
                and isinstance(v, ast.Constant) and v.value is False
                for k, v in zip(options.keys, options.values)):
            self.add(call, "JWT signature verification disabled", "high", 347,
                     "verify_signature is set to False.", "Always verify signatures.", "jwt-no-verify")
        # --- file permissions / temp files
        if full in {"os.chmod", "chmod"} and len(args) >= 2 and isinstance(args[1], ast.Constant) \
                and isinstance(args[1].value, int) and args[1].value & 0o002:
            self.add(call, "World-writable file permissions", "medium", 732,
                     f"Mode {oct(args[1].value)} lets any local user modify the file.",
                     "Use 0o600 (or 0o640) for sensitive files.", "chmod-world-writable")
        literal_path = ""
        if args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
            literal_path = args[0].value
        elif args and isinstance(args[0], ast.Name):
            literal_path = strs.get(args[0].id, "").lower()
        if full in {"open", "io.open"} and literal_path.startswith("/tmp/"):
            self.add(call, "Predictable temporary file path", "low", 377,
                     "A fixed path under /tmp enables symlink and race attacks.",
                     "Use tempfile.NamedTemporaryFile or tempfile.mkstemp.", "tmp-file", confidence="medium")
        if full == "tempfile.mktemp":
            self.add(call, "Insecure tempfile.mktemp()", "medium", 377,
                     "mktemp() is racy.", "Use tempfile.mkstemp().", "mktemp")
        # --- debug server
        if base == "run" and "debug" in kw and isinstance(kw["debug"], ast.Constant) and kw["debug"].value is True:
            self.add(call, "Flask debug mode enabled", "medium", 489,
                     "The interactive debugger permits remote code execution if reachable.",
                     "Never enable debug in production; read it from configuration.", "debug-mode")
        if base == "run" and isinstance(kw.get("host"), ast.Constant) and kw["host"].value == "0.0.0.0" \
                and "debug" in kw:
            self.add(call, "Development server bound to all interfaces", "low", 668,
                     "Binding 0.0.0.0 exposes the dev server on every network interface.",
                     "Bind to 127.0.0.1 or run behind a production WSGI server.", "bind-all", confidence="medium")
        # --- regex DoS
        if full.startswith("re.") and base in {"compile", "match", "search", "fullmatch", "sub", "findall"} \
                and args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str) \
                and NESTED_QUANTIFIER.search(args[0].value):
            self.add(call, "Regular expression denial of service (ReDoS)", "medium", 1333,
                     "Nested quantifiers cause catastrophic backtracking on crafted input.",
                     "Rewrite the pattern without nested quantifiers or use a linear-time engine (re2).", "redos")
        # --- sensitive data in logs
        if self._is_log_call(call, full, base):
            blob = " ".join(ast.unparse(a) for a in args)
            names = {n.id for a in args for n in ast.walk(a) if isinstance(n, ast.Name)}
            names |= {n.attr for a in args for n in ast.walk(a) if isinstance(n, ast.Attribute)}
            if any(SENSITIVE_NAME.search(n) for n in names) and blob:
                self.add(call, "Sensitive data written to logs", "medium", 532,
                         "Credentials or tokens appear in log output.",
                         "Never log secrets; log an identifier or a masked value.", "log-secret")
        # --- sensitive data in HTTP responses
        if base == "jsonify" or full == "json.dumps":
            self.check_exposure(call)
        # --- hardcoded credentials passed as keyword arguments
        for keyword in call.keywords:
            if keyword.arg and CRED_NAME.search(keyword.arg) and self._is_literal_secret(keyword.value):
                self.add(keyword.value, "Hard-coded credential", "high", 798,
                         f"`{keyword.arg}` is set to a string literal in source code.",
                         "Load secrets from environment variables or a secret manager.", "hardcoded-secret")

    @staticmethod
    def _safe_loader(call):
        for keyword in call.keywords:
            if keyword.arg == "Loader":
                text = ast.unparse(keyword.value)
                return "Safe" in text
        return False

    @staticmethod
    def _is_log_call(call, full, base):
        if full == "print" or base in {"info", "debug", "warning", "error", "critical", "exception"}:
            return True
        if base == "write" and isinstance(call.func, ast.Attribute):
            owner = dotted(call.func.value) or ""
            return "log" in owner.lower()
        return False

    @staticmethod
    def _is_literal_secret(node):
        return (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and len(node.value) >= 4 and not PLACEHOLDER.search(node.value))

    def check_exposure(self, call):
        for arg in call.args:
            for node in ast.walk(arg):
                if dotted(node) == "os.environ" and isinstance(node, ast.Attribute):
                    self.add(call, "Environment variables exposed in HTTP response", "high", 200,
                             "The response includes the process environment, which usually contains secrets.",
                             "Remove the endpoint or return an explicit, non-sensitive subset.", "exposure-environ")
                    return
            if isinstance(arg, ast.Dict):
                for key, value in zip(arg.keys, arg.values):
                    if isinstance(key, ast.Constant) and isinstance(key.value, str) and \
                            SENSITIVE_NAME.search(key.value):
                        self.add(call, "Sensitive values returned in HTTP response", "high", 200,
                                 f"The `{key.value}` field is returned to the client.",
                                 "Do not expose credentials or keys through the API.", "exposure-secret")
                        return

    def check_secret_assign(self, stmt):
        targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
        value = stmt.value
        if value is None or not self._is_literal_secret(value):
            return
        for target in targets:
            name = target.id if isinstance(target, ast.Name) else (
                target.attr if isinstance(target, ast.Attribute) else None)
            if name is None and isinstance(target, ast.Subscript):  # app.config["SECRET_KEY"] = "..."
                key = target.slice
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    name = key.value
            if name and CRED_NAME.search(name):
                self.add(stmt, "Hard-coded credential", "high", 798,
                         f"`{name}` is assigned a string literal in source code.",
                         "Load secrets from environment variables or a secret manager.", "hardcoded-secret")

    def check_dict_secrets(self, node):
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str) and \
                    CRED_NAME.search(key.value) and self._is_literal_secret(value):
                self.add(key, "Hard-coded credential", "high", 798,
                         f"The `{key.value}` entry holds a string literal credential.",
                         "Load secrets from environment variables or a secret manager.", "hardcoded-secret")

    def check_repeat(self, node, env):
        for a, b in ((node.left, node.right), (node.right, node.left)):
            literal = isinstance(a, ast.Constant) and isinstance(a.value, (str, bytes))
            taint = taint_of(b, env)
            if (literal or isinstance(a, ast.List)) and taint:
                self.tainted_sink(node, taint, "repeat", title="Uncontrolled resource consumption",
                                  severity="medium", cwe=400,
                                  why="A client-controlled number sizes an allocation.",
                                  fix="Clamp the value and enforce request limits.", rule="resource-exhaustion",
                                  confidence="medium")

    def check_compare(self, node, env):
        # client-controlled authorization: `if role == "admin"` with role from the request
        sides = [node.left] + list(node.comparators)
        for expr in sides:
            taint = taint_of(expr, env)
            if taint and taint.label == "str" and any(isinstance(s, ast.Constant) and isinstance(s.value, str)
                                                        for s in sides):
                text = ast.unparse(expr)
                if re.search(r"role|admin|priv|perm|access|level", text, re.I) or any(
                        isinstance(s, ast.Constant) and isinstance(s.value, str)
                        and s.value.lower() in {"admin", "root", "superuser"} for s in sides):
                    self.tainted_sink(node, taint, "comparison", title="Authorization decided by client-supplied value",
                                      severity="high", cwe=285,
                                      why="Access is granted based on a value the client controls.",
                                      fix="Derive the role from the server-side session or a signed token.",
                                      rule="client-authz")
                    return
        # weak password policy: len(password) >= 4
        if len(sides) == 2 and isinstance(sides[0], ast.Call) and call_names(sides[0])[0] == "len":
            inner = ast.unparse(sides[0]).lower()
            comp = sides[1]
            if "pass" in inner and isinstance(comp, ast.Constant) and isinstance(comp.value, int) and comp.value < 8:
                self.add(node, "Weak password policy", "low", 521,
                         f"Passwords are accepted with a minimum length of {comp.value}.",
                         "Require at least 8-12 characters and check against breached-password lists.",
                         "weak-password-policy")

    def check_authz_on_write(self, call, lead, ctx):
        if ctx.is_route and not ctx.authenticated and lead.startswith(("DELETE", "UPDATE")):
            self.add(call, "Missing authentication/authorization on a state-changing endpoint", "high", 862,
                     f"The `{ctx.func_name}` route modifies data but performs no authentication or authorization check.",
                     "Require an authenticated session and verify the caller may modify this resource "
                     "(and, for password reset, verify identity via a token).", "missing-authz")

    def check_idor(self, call, args, ctx):
        if not ctx.is_route or ctx.authenticated:
            return
        id_params = {p for p in ctx.params if re.search(r"(^id$|_id$|^uid$)", p)}
        used = set()
        for arg in args[1:]:
            used |= {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)}
        hit = used & id_params
        if hit:
            self.add(call, "Insecure direct object reference (no ownership check)", "medium", 639,
                     f"The record selected by `{sorted(hit)[0]}` is not checked against the current user.",
                     "Verify the object belongs to (or is visible to) the authenticated user before returning or "
                     "modifying it.", "idor", confidence="medium")

    def check_return(self, stmt, env, ctx):
        value = stmt.value
        taint = taint_of(value, env)
        if taint and taint.label == "str" and _has_html_literal(value) and \
                isinstance(value, (ast.BinOp, ast.JoinedStr, ast.Call)):
            self.tainted_sink(stmt, taint, "response", title="Reflected cross-site scripting", severity="high",
                              cwe=79, why="User input is embedded in an HTML response without escaping.",
                              fix="Escape output (markupsafe.escape) or use an auto-escaping template.",
                              rule="xss-return")

    def check_handler(self, handler):
        if not handler.name:
            return
        for node in ast.walk(handler):
            if isinstance(node, ast.Return) and node.value is not None:
                names = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
                text = ast.unparse(node.value)
                if handler.name in names or "format_exc" in text:
                    self.add(node, "Exception details returned to the client", "medium", 209,
                             "Internal error text can reveal paths, queries or library versions.",
                             "Log the exception server-side and return a generic error message.", "error-exposure")
                    return


@dataclass
class _Ctx:
    func_name: str
    is_route: bool
    params: set
    func: object = None
    func_text: str = ""
    authenticated: bool = False


def analyze_python(path: str, source: str) -> list:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    analyzer = _Analyzer(path, source)
    analyzer.run(tree)
    return analyzer.findings
