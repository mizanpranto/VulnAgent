"""Plausibility gate: a rule only runs on the side of the system it applies to.

Server-side flaws (IDOR, missing authorization, upload validation) must never be
reported against client-only UI files. Side is derived from what a file imports
and uses, never from its folder name.
"""

from __future__ import annotations

import re

SERVER_IMPORT = re.compile(
    r"""(?:require\(|from\s+|import\s+)['"]?(express|fastify|koa|koa-router|@koa/router|@nestjs/[\w-]+|next/server|"""
    r"""next-auth|hono|restify|hapi|@hapi/hapi|mongoose|sequelize|typeorm|@prisma/client|knex|pg|mysql2?|"""
    r"""flask|django|fastapi|starlette|sqlalchemy|rest_framework|http\.server|aiohttp|tornado|bottle)\b""")
CLIENT_SIGNAL = re.compile(
    r"\b(document\.(getElementById|querySelector|createElement|cookie)|window\.(location|localStorage)|"
    r"localStorage\.|sessionStorage\.|ReactDOM|createRoot\(|from\s+['\"]react['\"]|from\s+['\"]vue['\"]|"
    r"@angular/core|useState\(|useEffect\()")
NEXT_SERVER_PATH = re.compile(r"(^|/)(pages/api/|app/.*/route\.(t|j)sx?$|middleware\.(t|j)s$)")


def classify_side(path: str, source: str) -> str:
    """'server' | 'client' | 'unknown' for a source file."""
    if NEXT_SERVER_PATH.search(path):
        return "server"
    if SERVER_IMPORT.search(source):
        return "server"
    if CLIENT_SIGNAL.search(source) or path.lower().endswith((".jsx", ".tsx")):
        return "client"
    return "unknown"


def rule_applies(rule, side: str) -> bool:
    """Server rules never fire on client files; client rules only on client files."""
    if rule.side == "server":
        return side != "client"
    if rule.side == "client":
        return side == "client"
    return True
