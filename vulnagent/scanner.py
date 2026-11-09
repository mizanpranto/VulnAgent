
import ast
import re
from pathlib import Path

EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx"}

SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules",
    "__pycache__", "dist", "build", ".next",
    "coverage", "vendor"
}

MAX_FILE_BYTES = 180_000

PATTERNS = [
    (
        "Possible SQL Injection",
        "high",
        re.compile(
            r"""(?i)(execute|executemany|query)\s*\(.*?(f["']|["'][^"']*%s|["'][^"']*["']\s*\+)"""
        ),
        "Possible SQL query construction using interpolation or concatenation."
    ),
    (
        "Dynamic Code Execution",
        "high",
        re.compile(r"\b(eval|exec)\s*\("),
        "Dynamic execution may execute attacker-controlled input."
    ),
    (
        "Command Injection Risk",
        "high",
        re.compile(
            r"\b(subprocess\.(?:run|Popen|call)|os\.system)\s*\("
        ),
        "Check whether untrusted input reaches command execution."
    ),
    (
        "Unsafe Deserialization",
        "high",
        re.compile(
            r"\b(pickle\.loads?|yaml\.load)\s*\("
        ),
        "Unsafe deserialization may execute code or create unsafe objects."
    ),
    (
        "Weak Cryptographic Hash",
        "medium",
        re.compile(
            r"\b(hashlib\.)?(md5|sha1)\s*\("
        ),
        "MD5 and SHA1 are unsuitable for security-sensitive hashing."
    ),
    (
        "TLS Verification Disabled",
        "high",
        re.compile(
            r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false"
        ),
        "TLS certificate verification appears disabled."
    ),
    (
        "Potential Hardcoded Credential",
        "high",
        re.compile(
            r"""(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*["'][^"']{6,}["']"""
        ),
        "A credential-like value may be hardcoded."
    ),
    (
        "Debug Mode Enabled",
        "medium",
        re.compile(
            r"(?i)\b(DEBUG|debug)\s*[:=]\s*(True|true)"
        ),
        "Debug mode may expose sensitive application information."
    )
]


def python_ast_checks(path, source):
    findings = []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):

        if not isinstance(node, ast.Call):
            continue

        if isinstance(node.func, ast.Name):
            name = node.func.id

        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr

        else:
            name = ""

        if name in {"eval", "exec"}:
            findings.append({
                "title": "Python Dynamic Execution",
                "severity": "high",
                "file": str(path),
                "line": node.lineno,
                "evidence": ast.get_source_segment(source, node),
                "detail": "Dynamic execution requires investigation.",
                "source": "heuristic"
            })

    return findings


def scan_project(project: Path, max_files=150):

    project = Path(project)

    if not project.exists():
        raise FileNotFoundError(
            f"Project directory not found: {project}"
        )

    if not project.is_dir():
        raise NotADirectoryError(
            f"Not a directory: {project}"
        )

    files = []
    findings = []

    for path in project.rglob("*"):

        if not path.is_file():
            continue

        if path.suffix.lower() not in EXTENSIONS:
            continue

        if any(part in SKIP_DIRS for part in path.parts):
            continue

        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue

            source = path.read_text(
                encoding="utf-8",
                errors="replace"
            )

        except OSError:
            continue

        relative_path = str(path.relative_to(project))

        files.append({
            "path": relative_path,
            "content": source
        })

        if path.suffix.lower() == ".py":
            findings.extend(
                python_ast_checks(relative_path, source)
            )

        for line_number, line in enumerate(
            source.splitlines(), 1
        ):

            for title, severity, pattern, detail in PATTERNS:

                if pattern.search(line):

                    findings.append({
                        "title": title,
                        "severity": severity,
                        "file": relative_path,
                        "line": line_number,
                        "evidence": line.strip()[:300],
                        "detail": detail,
                        "source": "heuristic"
                    })

        if len(files) >= max_files:
            break

    return files, findings
