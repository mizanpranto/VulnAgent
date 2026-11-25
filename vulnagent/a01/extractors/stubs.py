"""Extractor skeletons for PHP (Laravel/Symfony), Go (net/http, Gin, Echo, Chi) and Ruby (Rails).

They detect the framework from real parse-free evidence (manifest / import names only), register the language as
"detected, not analysed" and add it to the report's limitations. They never emit "no findings" silently.
"""

from __future__ import annotations

import re

FRAMEWORK_HINTS = {
    "php": [("laravel", r"Illuminate\\|Route::(get|post|put|delete|group)"), ("symfony", r"Symfony\\Component|#\[Route\(")],
    "go": [("gin", r"gin-gonic/gin"), ("echo", r"labstack/echo"), ("chi", r"go-chi/chi"), ("net/http", r'"net/http"')],
    "ruby": [("rails", r"ActionController|Rails\.application\.routes|before_action")],
}
EXT_LANG = {".php": "php", ".go": "go", ".rb": "ruby"}


def extract(files, project):
    counts = {}
    for path, src in files.items():
        for ext, lang in EXT_LANG.items():
            if path.endswith(ext):
                counts.setdefault(lang, []).append((path, src))
    for lang, items in counts.items():
        found = set()
        for path, src in items:
            for fw, rx in FRAMEWORK_HINTS[lang]:
                if re.search(rx, src):
                    found.add(fw)
        project.partial[lang] = (f"{len(items)} file(s); framework(s): {', '.join(sorted(found)) or 'none recognised'}; "
                                 "extractor skeleton only - entry points, guards and rules were NOT evaluated")
        for path, _ in items:
            project.files_skipped.append((path, f"{lang}: extractor skeleton (not analysed)"))
