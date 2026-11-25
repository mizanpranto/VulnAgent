"""Helpers shared by extractors."""

from __future__ import annotations

import re

from ..ir import Guard
from .. import patterns as P


def join_path(prefix: str, path: str) -> str:
    prefix, path = (prefix or "").rstrip("/"), (path or "")
    if path and not path.startswith("/"):
        path = "/" + path
    full = (prefix + path) or "/"
    return re.sub(r"/{2,}", "/", full)


def trim_source(text: str, max_lines: int = 60, max_chars: int = 3500) -> str:
    lines = text.splitlines()[:max_lines]
    return "\n".join(lines)[:max_chars]


def guards_from_name(name: str, scope: str, file: str, line: int, evidence: str = "") -> list:
    return [Guard(name=name, kind=k, scope=scope, certainty="name", file=file, line=line, evidence=evidence[:200])
            for k in P.classify_guard_name(name)]


def path_matches_scope(route_path: str, scope: str) -> bool:
    if not scope or scope in ("/", "*", "/*"):
        return True
    scope = re.sub(r"[/*]+$", "", scope)
    return route_path == scope or route_path.startswith(scope + "/") or route_path.startswith(scope + ".")
