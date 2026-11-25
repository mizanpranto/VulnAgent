"""Dependency scanning: known-vulnerable packages via the OSV database (opt-in).

Reads exact versions from ``requirements*.txt`` (``name==version`` lines) and
``package-lock.json``. Only package names and versions are sent to
api.osv.dev; no source code is ever uploaded. The stage is off by default
because it is the only part of VulnAgent that uses the network.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .models import Finding
from .scanner import SKIP_DIRS

OSV = "https://api.osv.dev/v1"
REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+!-]+)")
SEVERITY_MAP = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


@dataclass(frozen=True)
class Dep:
    ecosystem: str   # "PyPI" | "npm"
    name: str
    version: str
    file: str
    line: int


def is_manifest(filename: str) -> bool:
    n = filename.lower()
    return (n.startswith("requirements") and n.endswith(".txt")) or n == "package-lock.json"


def find_manifests(project) -> list:
    """(relative path, text) for each manifest under project; no symlinks, size-capped."""
    project, found = Path(project), []
    for root, dirnames, filenames in os.walk(project, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not os.path.islink(os.path.join(root, d)))
        for name in sorted(filenames):
            path = Path(root) / name
            if is_manifest(name) and not path.is_symlink() and path.stat().st_size <= 5 * 1024 * 1024:
                found.append((path.relative_to(project).as_posix(), path.read_text(encoding="utf-8", errors="replace")))
    return found


def parse_requirements(path: str, text: str) -> list:
    deps = []
    for number, raw in enumerate(text.splitlines(), 1):
        match = REQ_LINE.match(raw.split("#", 1)[0])
        if match:
            deps.append(Dep("PyPI", match.group(1), match.group(2), path, number))
    return deps


def parse_package_lock(path: str, text: str) -> list:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    entries = {}
    for key, info in (data.get("packages") or {}).items():        # lockfile v2/v3
        if key.startswith("node_modules/") and isinstance(info, dict) and info.get("version"):
            entries[key.rsplit("node_modules/", 1)[1]] = info["version"]

    def walk(deps):                                                  # lockfile v1
        for name, info in (deps or {}).items():
            if isinstance(info, dict) and info.get("version"):
                entries.setdefault(name, info["version"])
                walk(info.get("dependencies"))
    walk(data.get("dependencies"))
    lines = text.splitlines()
    result = []
    for name, version in sorted(entries.items()):
        marker = f'"node_modules/{name}"'
        line = next((i for i, l in enumerate(lines, 1) if marker in l), None) \
            or next((i for i, l in enumerate(lines, 1) if f'"{name}":' in l), 1)
        result.append(Dep("npm", name, version, path, line))
    return result


def collect(project) -> list:
    deps = []
    for path, text in find_manifests(project):
        name = Path(path).name.lower()
        deps.extend(parse_package_lock(path, text) if name == "package-lock.json" else parse_requirements(path, text))
    return deps


def _severity(vuln: dict) -> str:
    label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    return SEVERITY_MAP.get(label, "medium")


def _fixed_versions(vuln: dict, dep: Dep) -> list:
    fixed = []
    for affected in vuln.get("affected", []):
        package = affected.get("package") or {}
        if package.get("name", "").lower() != dep.name.lower():
            continue
        for rng in affected.get("ranges", []):
            fixed += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return fixed


def query_osv(deps: list, session, max_deps: int = 500, timeout: int = 20) -> list:
    """Return Findings for vulnerable deps. Raises RuntimeError if OSV is unreachable."""
    deps = deps[:max_deps]
    if not deps:
        return []
    hits = {}  # dep index -> [vuln ids]
    try:
        for start in range(0, len(deps), 100):
            chunk = deps[start:start + 100]
            body = {"queries": [{"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
                                for d in chunk]}
            reply = session.post(f"{OSV}/querybatch", json=body, timeout=timeout)
            reply.raise_for_status()
            for offset, result in enumerate(reply.json().get("results", [])):
                ids = [v["id"] for v in result.get("vulns", []) if "id" in v]
                if ids:
                    hits[start + offset] = ids[:10]
        details = {}
        for vuln_id in sorted({i for ids in hits.values() for i in ids})[:150]:
            reply = session.get(f"{OSV}/vulns/{vuln_id}", timeout=timeout)
            if reply.status_code == 200:
                details[vuln_id] = reply.json()
    except Exception as error:  # network, TLS, HTTP, bad JSON: all mean "could not check"
        raise RuntimeError(f"OSV lookup failed ({type(error).__name__}).") from error

    findings = []
    for index, ids in sorted(hits.items()):
        dep = deps[index]
        for vuln_id in ids:
            vuln = details.get(vuln_id, {"id": vuln_id})
            fixed = _fixed_versions(vuln, dep)
            alias = next((a for a in vuln.get("aliases", []) if a.startswith("CVE-")), "")
            findings.append(Finding(
                title=f"Vulnerable dependency: {dep.name} {dep.version} ({alias or vuln_id})",
                severity=_severity(vuln), file=dep.file, line=dep.line, cwe=1395, confidence="high",
                evidence=f"{dep.name}=={dep.version}" if dep.ecosystem == "PyPI" else f'"{dep.name}": "{dep.version}"',
                explanation=(vuln.get("summary") or "Known vulnerability in this package version.")[:400]
                            + f" Advisory: https://osv.dev/{vuln_id}",
                fix=f"Upgrade {dep.name} to {fixed[0]} or later." if fixed else f"Upgrade {dep.name} (no fixed version listed).",
                origins=["dependency"], rule_id="vulnerable-dependency"))
    return findings
