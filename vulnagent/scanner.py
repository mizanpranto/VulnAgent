"""Source collection and deterministic (non-LLM) detection.

Python files go through the AST/taint engine in ``taint.py``. JavaScript and
TypeScript files (and Python files that fail to parse) use regex rules.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding
from .taint import analyze_python

EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx"}
# Read only by the A01 access-control layer (legacy stages never see these files).
A01_EXTRA_EXTENSIONS = {".java", ".kt", ".cs", ".php", ".go", ".rb"}
MAX_EXTRA_FILES = 400
MAX_LISTED_PATHS = 20000
SKIP_DIRS = {
    ".git", ".venv", "venv", "env", "node_modules", "__pycache__", "dist",
    "build", ".next", "coverage", "vendor", ".tox", ".mypy_cache", "site-packages",
}
MAX_FILE_BYTES = 180_000

_SQL_WORDS = re.compile(r"\b(select|insert|update|delete|where|from)\b", re.I)
_CRED = (r"(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|token|private[_-]?key)\w*"
         r"\s*[:=]\s*[\"'](?![^\"']*(?:\$\{|\{\{|<|your|changeme|example|xxx))([^\"'\s]{6,})[\"']")

# (rule id, title, severity, cwe, regex, why, fix)
REGEX_RULES = [
    ("js-eval", "Dynamic code execution", "medium", 95,
     re.compile(r"\b(eval|new\s+Function)\s*\("),
     "eval/new Function executes strings as code.", "Remove dynamic execution; parse data explicitly."),
    ("js-cmd", "OS command execution with dynamic input", "high", 78,
     re.compile(r"\b(exec|execSync|spawn)\s*\(\s*(`[^`]*\$\{|[^)]*\+)"),
     "A shell command is built from concatenated or interpolated strings.",
     "Use execFile/spawn with an argument array and validate input."),
    ("js-sql", "Possible SQL injection (string-built query)", "high", 89,
     re.compile(r"\b(query|execute|raw)\s*\(\s*(`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)", re.I),
     "An SQL statement is assembled by interpolation or concatenation.",
     "Use parameterized queries / prepared statements."),
    ("js-xss", "DOM XSS sink (innerHTML / document.write)", "high", 79,
     re.compile(r"\.innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML"),
     "HTML is written from a string; unsanitised input leads to XSS.",
     "Use textContent or sanitise with DOMPurify."),
    ("js-tls", "TLS certificate verification disabled", "high", 295,
     re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0|verify\s*=\s*False"),
     "Certificate validation is turned off.", "Remove the override."),
    ("js-weak-hash", "Weak hash algorithm (MD5/SHA-1)", "medium", 327,
     re.compile(r"createHash\(\s*[\"'](md5|sha1)[\"']"),
     "MD5/SHA-1 are broken for security purposes.", "Use SHA-256+ or a password KDF."),
    ("js-redirect", "Open redirect", "medium", 601,
     re.compile(r"res\.redirect\(\s*req\.(query|body|params)"),
     "Redirect target comes straight from the request.", "Allowlist destinations."),
    ("js-path", "Path traversal", "high", 22,
     re.compile(r"(readFile|readFileSync|createReadStream|sendFile)\s*\([^)]*req\.(query|body|params)"),
     "A request value is used as a file path.", "Resolve and verify the path stays inside a base directory."),
    ("js-random", "Predictable random value", "low", 338,
     re.compile(r"(token|secret|otp|password|session|nonce)\w*\s*[:=].*Math\.random\s*\(", re.I),
     "Math.random() is not cryptographically secure.", "Use crypto.randomBytes."),
    ("cred", "Hard-coded credential", "high", 798, re.compile(_CRED),
     "A credential-like value is written into source code.",
     "Load secrets from environment variables or a secret manager."),
    ("debug", "Debug mode enabled", "medium", 489,
     re.compile(r"(?i)\bdebug\s*[:=]\s*true\b"),
     "Debug mode can expose internals.", "Disable debug outside development."),
    ("py-eval", "Dynamic code execution", "medium", 95,
     re.compile(r"\b(eval|exec)\s*\("), "Dynamic execution of strings.", "Avoid eval/exec."),
    ("py-pickle", "Unsafe deserialization API in use", "medium", 502,
     re.compile(r"\b(pickle\.loads?|yaml\.load)\s*\("), "Can execute code on untrusted data.",
     "Use JSON or yaml.safe_load."),
]
# Regex rules for Python used only if the file cannot be parsed.
_PY_FALLBACK = {"py-eval", "py-pickle", "cred", "debug"}
_JS_RULES = {r[0] for r in REGEX_RULES if r[0].startswith("js-")} | {"cred", "debug"}

# Text aimed at AI code reviewers (prompt injection planted in source).
INJECTION_RE = re.compile(
    r"(?i)((ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+"
    r"(instructions|rules|prompts?)"
    r"|(do\s+not|don't|never)\s+(report|mention|flag|list)\s+(any\s+)?(vulnerabilit|issue|finding|security)"
    r"|you\s+are\s+now\s+(a|an|the)\b"
    r"|report\s+(no|zero)\s+(vulnerabilit|issues|findings)"
    r"|this\s+(file|code)\s+(is|has)\s+(been\s+)?(audited|reviewed)\s+and\s+(safe|secure))"
)


@dataclass
class ScanResult:
    files: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    skipped_large: int = 0
    skipped_unreadable: int = 0
    skipped_minified: int = 0
    truncated: bool = False
    extra_files: list = field(default_factory=list)   # A01-only sources (java, c#, php, go, ruby, kotlin)
    all_paths: list = field(default_factory=list)     # every project path (names only) for exposure checks


def looks_minified(name: str, source: str) -> bool:
    """Minified or bundled code produces noise and is not the author's source."""
    if ".min." in name.lower() or name.lower().endswith((".bundle.js", ".chunk.js")):
        return True
    lines = source.splitlines() or [""]
    longest = max(len(line) for line in lines)
    return longest > 1500 or (len(source) > 20_000 and len(source) / len(lines) > 250)


def _excluded(relative: str, patterns) -> bool:
    return any(fnmatch.fnmatch(relative, p) or fnmatch.fnmatch(relative, p.rstrip("/") + "/*")
               for p in patterns)


def _finding(rule, path, lineno, line):
    rule_id, title, severity, cwe, _rx, why, fix = rule
    return Finding(title=title, severity=severity, file=path, line=lineno, cwe=cwe,
                   confidence="medium", evidence=line.strip()[:300], explanation=why,
                   fix=fix, origins=["regex"], rule_id=rule_id)


def regex_scan(path: str, source: str, allowed=None) -> list:
    findings = []
    for lineno, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        if INJECTION_RE.search(line):
            findings.append(Finding(
                title="Possible prompt-injection text aimed at AI code reviewers", severity="medium",
                file=path, line=lineno, cwe=1427, confidence="medium", evidence=stripped[:300],
                explanation="This text tries to instruct an AI reviewer. Findings from deterministic "
                            "analysis are unaffected, but AI triage of this file should be treated as untrusted.",
                fix="Remove the text; treat the file's origin with suspicion.",
                origins=["regex"], rule_id="prompt-injection-signal"))
        for rule in REGEX_RULES:
            if allowed is not None and rule[0] not in allowed:
                continue
            if not rule[4].search(line):
                continue
            if rule[0] == "cred" and _SQL_WORDS.search(line):
                continue  # SQL text, not a credential assignment
            findings.append(_finding(rule, path, lineno, line))
    return findings


def scan_project_ex(project, max_files: int = 150, exclude=()) -> ScanResult:
    project = Path(project)
    if not project.exists():
        raise FileNotFoundError(f"Project directory not found: {project}")
    if not project.is_dir():
        raise NotADirectoryError(f"Not a directory: {project}")

    result = ScanResult()
    for root, dirnames, filenames in os.walk(project, followlinks=False):
        if ".git" in dirnames and len(result.all_paths) < MAX_LISTED_PATHS:
            rel_root = Path(root).relative_to(project).as_posix()
            result.all_paths.append(f"{rel_root}/.git/HEAD".lstrip("./") if rel_root != "." else ".git/HEAD")
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS
                             and not os.path.islink(os.path.join(root, d)))
        for name in sorted(filenames):
            path = Path(root) / name
            if path.is_symlink():
                continue
            relative = path.relative_to(project).as_posix()
            if not _excluded(relative, exclude) and len(result.all_paths) < MAX_LISTED_PATHS:
                result.all_paths.append(relative)
            suffix = path.suffix.lower()
            if suffix in A01_EXTRA_EXTENSIONS and not _excluded(relative, exclude):
                if len(result.extra_files) < MAX_EXTRA_FILES:
                    try:
                        if path.stat().st_size <= MAX_FILE_BYTES:
                            result.extra_files.append({"path": relative, "content": path.read_text(encoding="utf-8", errors="replace")})
                    except OSError:
                        pass
                continue
            if suffix not in EXTENSIONS:
                continue
            if _excluded(relative, exclude):
                continue
            if len(result.files) >= max_files:
                result.truncated = True
                break
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    result.skipped_large += 1
                    continue
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                result.skipped_unreadable += 1
                continue
            if path.suffix.lower() != ".py" and looks_minified(path.name, source):
                result.skipped_minified += 1
                continue
            result.files.append({"path": relative, "content": source})
            if path.suffix.lower() == ".py":
                found = analyze_python(relative, source)
                parsed = bool(found) or _parses(source)
                result.findings.extend(found)
                # signals and (if unparsable) fallback rules via regex
                allowed = _PY_FALLBACK if not parsed else set()
                result.findings.extend(regex_scan(relative, source, allowed=allowed))
            else:
                result.findings.extend(regex_scan(relative, source, allowed=_JS_RULES))
        if result.truncated:
            break
    return result


def _parses(source: str) -> bool:
    import ast
    try:
        ast.parse(source)
        return True
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False


def scan_project(project, max_files: int = 150, exclude=()):
    """Backwards compatible wrapper returning ``(files, findings)``."""
    result = scan_project_ex(project, max_files=max_files, exclude=exclude)
    return result.files, result.findings
