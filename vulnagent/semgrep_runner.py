"""Optional Semgrep integration (`--semgrep`). Semgrep is not a dependency.

If the `semgrep` binary is missing the stage is skipped with a clear note.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from .models import Finding, normalize_cwe

_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def available() -> bool:
    return shutil.which("semgrep") is not None


def parse_semgrep_json(data: dict, project: Path = None) -> list:
    findings = []
    for item in data.get("results", []):
        extra = item.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        cwe_raw = meta.get("cwe")
        if isinstance(cwe_raw, list):
            cwe_raw = cwe_raw[0] if cwe_raw else None
        path = str(item.get("path", ""))
        if project is not None:
            try:
                path = Path(path).resolve().relative_to(Path(project).resolve()).as_posix()
            except (ValueError, OSError):
                pass
        rule = str(item.get("check_id", "semgrep"))
        title = (meta.get("shortDescription") or rule.rsplit(".", 1)[-1].replace("-", " ").replace("_", " ")).strip()
        line = int(item.get("start", {}).get("line", 1))
        findings.append(Finding(
            title=title[:160].capitalize(),
            severity=_SEVERITY.get(str(extra.get("severity", "")).upper(), "medium"),
            file=path, line=line,
            cwe=normalize_cwe(cwe_raw, title),
            confidence={"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(
                str(meta.get("confidence", "")).upper(), "medium"),
            evidence=re.sub(r"\s+", " ", str(extra.get("lines", "")))[:300].strip(),
            explanation=str(extra.get("message", ""))[:600],
            origins=["semgrep"], rule_id=rule[-120:],
        ))
    return findings


def run_semgrep(project: Path, config: str = "auto", timeout: int = 300) -> list:
    if not available():
        raise RuntimeError("semgrep is not installed (pip install semgrep)")
    command = ["semgrep", "--config", config, "--json", "--quiet", "--metrics=off",
               "--timeout", "30", str(project)]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"semgrep timed out after {timeout}s") from error
    if not completed.stdout.strip():
        raise RuntimeError(f"semgrep produced no output: {completed.stderr.strip()[:200]}")
    return parse_semgrep_json(json.loads(completed.stdout), project)
