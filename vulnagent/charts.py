"""Server-side SVG diagrams for the web report.

All colors are CSS custom properties (defined in the page stylesheet, with a
dark-mode variant), so the same markup works on both themes. Escaping: every
piece of text that originates in scanned code goes through ``html.escape``.
"""

from __future__ import annotations

from html import escape

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}


def _t(text, limit=None):
    text = str(text)
    if limit and len(text) > limit:
        text = text[: limit - 1] + "…"
    return escape(text, quote=True)


def _bar(x, y, w, h, r, cls, title):
    """Bar anchored on its baseline at x with a rounded data end (right side)."""
    if w <= 0:
        return ""
    r = min(r, w, h / 2)
    path = (f"M{x},{y} h{w - r} a{r},{r} 0 0 1 {r},{r} v{h - 2 * r} a{r},{r} 0 0 1 -{r},{r} h-{w - r} z")
    return f'<path class="{cls}" d="{path}"><title>{_t(title)}</title></path>'


def severity_bars(counts: dict) -> str:
    rows = [(s, int(counts.get(s, 0))) for s in SEVERITY_ORDER]
    top = max([n for _, n in rows] + [1])
    width, label_w, bar_x, bar_max = 520, 76, 84, 380
    parts = [f'<svg class="chart" viewBox="0 0 {width} {len(rows) * 34 + 6}" role="img" '
             f'aria-label="Findings by severity">']
    for i, (sev, n) in enumerate(rows):
        y = i * 34 + 4
        w = round(bar_max * n / top)
        parts.append(f'<text class="lbl" x="0" y="{y + 14}">{SEVERITY_LABEL[sev]}</text>')
        parts.append(f'<line class="grid" x1="{bar_x}" y1="{y - 2}" x2="{bar_x}" y2="{y + 22}"/>')
        parts.append(_bar(bar_x, y, w, 20, 4, f"sev-{sev}", f"{SEVERITY_LABEL[sev]}: {n} finding(s)"))
        parts.append(f'<text class="val" x="{bar_x + w + 8}" y="{y + 15}">{n}</text>')
    parts.append("</svg>")
    return "".join(parts)


def category_bars(by_cwe: list, limit: int = 8) -> str:
    rows = by_cwe[:limit]
    if not rows:
        return '<p class="empty">No categorized findings.</p>'
    top = max(r["count"] for r in rows)
    width, bar_x, bar_max = 560, 236, 280
    parts = [f'<svg class="chart" viewBox="0 0 {width} {len(rows) * 30 + 6}" role="img" '
             f'aria-label="Findings by weakness type">']
    for i, row in enumerate(rows):
        y = i * 30 + 4
        w = round(bar_max * row["count"] / top)
        label = f'CWE-{row["cwe"]}  {row["name"]}'
        parts.append(f'<text class="lbl" x="0" y="{y + 13}">{_t(label, 36)}<title>{_t(label)}</title></text>')
        parts.append(f'<line class="grid" x1="{bar_x}" y1="{y - 2}" x2="{bar_x}" y2="{y + 20}"/>')
        parts.append(_bar(bar_x, y, w, 18, 4, "series-1", f"{label}: {row['count']}"))
        parts.append(f'<text class="val" x="{bar_x + w + 8}" y="{y + 14}">{row["count"]}</text>')
    parts.append("</svg>")
    return "".join(parts)


def file_risk(findings: list, limit: int = 8) -> str:
    """Stacked horizontal bars: one per file, segments by severity."""
    per_file: dict = {}
    for f in findings:
        if f.dismissed:
            continue
        per_file.setdefault(f.file, {s: 0 for s in SEVERITY_ORDER})[f.severity] += 1
    weight = {"critical": 16, "high": 8, "medium": 4, "low": 2, "info": 1}
    ranked = sorted(per_file.items(), key=lambda kv: -sum(weight[s] * n for s, n in kv[1].items()))[:limit]
    if not ranked:
        return '<p class="empty">No findings to chart.</p>'
    top = max(sum(c.values()) for _, c in ranked)
    width, bar_x, bar_max = 560, 200, 300
    parts = [f'<svg class="chart" viewBox="0 0 {width} {len(ranked) * 30 + 6}" role="img" '
             f'aria-label="Findings per file by severity">']
    for i, (path, counts) in enumerate(ranked):
        y = i * 30 + 4
        label = path if len(path) <= 30 else "…" + path[-29:]
        parts.append(f'<text class="lbl" x="0" y="{y + 13}">{_t(label)}<title>{_t(path)}</title></text>')
        parts.append(f'<line class="grid" x1="{bar_x}" y1="{y - 2}" x2="{bar_x}" y2="{y + 20}"/>')
        x, total = bar_x, sum(counts.values())
        unit = bar_max / top
        for sev in SEVERITY_ORDER:
            n = counts[sev]
            if not n:
                continue
            w = n * unit
            gap = 2 if x + w < bar_x + total * unit - 0.5 else 0
            parts.append(f'<rect class="sev-{sev}" x="{x:.1f}" y="{y}" width="{max(w - gap, 1):.1f}" height="18" rx="3">'
                         f'<title>{_t(path)} — {SEVERITY_LABEL[sev]}: {n}</title></rect>')
            if w >= 18:
                parts.append(f'<text class="seg" x="{x + (w - gap) / 2:.1f}" y="{y + 13}" text-anchor="middle">{n}</text>')
            x += w
        parts.append(f'<text class="val" x="{x + 8:.1f}" y="{y + 14}">{total}</text>')
    parts.append("</svg>")
    return "".join(parts)


def severity_legend() -> str:
    items = "".join(f'<li><span class="swatch sev-{s}"></span>{SEVERITY_LABEL[s]}</li>' for s in SEVERITY_ORDER)
    return f'<ul class="legend" aria-label="Severity legend">{items}</ul>'


def _wrap(text: str, width: int = 54, max_lines: int = 3):
    words, lines, current = str(text).split(), [], ""
    for word in words:
        while len(word) > width:  # break very long tokens
            lines.append(word[:width]); word = word[width:]
        if len(current) + len(word) + (1 if current else 0) > width:
            lines.append(current); current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = lines[-1][: width - 1] + "…"
    return lines or [""]


def flow_diagram(finding) -> str:
    """Vertical source -> propagation -> sink diagram for one finding."""
    steps = [s for s in (finding.data_flow or []) if s]
    if len(steps) >= 2:
        nodes = [("source", "Untrusted input", steps[0])]
        nodes += [("step", "", s) for s in steps[1:-1]]
        nodes.append(("sink", "Dangerous operation", steps[-1]))
    else:
        nodes = []
        if finding.source:
            nodes.append(("source", "Untrusted input", finding.source))
        nodes.append(("step", "Code", f"{finding.file}:{finding.line}  {finding.evidence}"))
        if finding.sink:
            nodes.append(("sink", "Dangerous operation", finding.sink))
        else:
            nodes.append(("sink", "Risk", finding.title))
    width, x0, box_w = 560, 8, 544
    y, parts, boxes = 6, [], []
    for kind, tag, text in nodes:
        lines = _wrap(text)
        height = 18 + 16 * len(lines) + (14 if tag else 0)
        boxes.append((kind, tag, lines, y, height))
        y += height + 26
    total_h = y - 20
    parts.append(f'<svg class="chart flow" viewBox="0 0 {width} {total_h}" role="img" '
                 f'aria-label="Data flow for {_t(finding.title)}"><defs><marker id="arr" viewBox="0 0 10 10" '
                 f'refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
                 f'<path d="M0,0 L10,5 L0,10 z" class="arrow"/></marker></defs>')
    for index, (kind, tag, lines, top, height) in enumerate(boxes):
        parts.append(f'<rect class="node node-{kind}" x="{x0}" y="{top}" width="{box_w}" height="{height}" rx="6"/>')
        text_y = top + 18
        if tag:
            parts.append(f'<text class="tag tag-{kind}" x="{x0 + 12}" y="{text_y - 2}">{_t(tag)}</text>')
            text_y += 14
        for line in lines:
            parts.append(f'<text class="code" x="{x0 + 12}" y="{text_y}">{_t(line)}</text>')
            text_y += 16
        if index < len(boxes) - 1:
            parts.append(f'<line class="link" x1="{width // 2}" y1="{top + height}" '
                         f'x2="{width // 2}" y2="{boxes[index + 1][3] - 3}" marker-end="url(#arr)"/>')
    parts.append("</svg>")
    return "".join(parts)


def pipeline_diagram(report) -> str:
    """What actually ran, with counts: transparency about the analysis."""
    meta, stats = report.meta, report.stats
    triage = meta.get("triage") or {}
    boxes = [("Source files", [f'{stats["files"]} files', f'{stats["lines"]} lines'])]
    static = sum(1 for f in report.findings if any(o in ("taint", "regex") for o in f.origins))
    boxes.append(("Static and taint analysis", [f"{static} finding(s)"]))
    if meta.get("semgrep"):
        boxes.append(("Semgrep", [f'{meta["semgrep"]["findings"]} finding(s)']))
    if "triage" in meta.get("llm_stages", []):
        boxes.append((f'AI triage ({meta.get("model")})',
                      [f'{triage.get("confirmed", 0)} confirmed', f'{triage.get("dismissed", 0)} dismissed']))
    if "discovery" in meta.get("llm_stages", []):
        added = sum(1 for f in report.findings if "llm-discovery" in f.origins)
        boxes.append(("AI discovery", [f"{added} added", f"{len(meta.get('rejected_llm_claims', []))} rejected"]))
    boxes.append(("Report", [f'{stats["total"]} finding(s)']))
    n = len(boxes)
    width, gap, height = 640, 22, 92
    box_w = (width - gap * (n - 1)) / n
    parts = [f'<svg class="chart" viewBox="0 0 {width} {height + 8}" role="img" aria-label="Analysis pipeline"><defs>'
             f'<marker id="arr2" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">'
             f'<path d="M0,0 L10,5 L0,10 z" class="arrow"/></marker></defs>']
    for i, (title, subs) in enumerate(boxes):
        x = i * (box_w + gap)
        parts.append(f'<rect class="node node-step" x="{x:.1f}" y="4" width="{box_w:.1f}" height="{height}" rx="6"/>')
        title_lines = _wrap(title, max(8, int(box_w / 7.2)), 2)
        for j, line in enumerate(title_lines):
            parts.append(f'<text class="lbl strong" x="{x + 8:.1f}" y="{22 + j * 14}">{_t(line)}</text>')
        for j, line in enumerate(subs[:2]):
            parts.append(f'<text class="sub" x="{x + 8:.1f}" y="{62 + j * 15}">{_t(line)}</text>')
        if i < n - 1:
            parts.append(f'<line class="link" x1="{x + box_w:.1f}" y1="{4 + height / 2}" x2="{x + box_w + gap - 2:.1f}" '
                         f'y2="{4 + height / 2}" marker-end="url(#arr2)"/>')
    parts.append("</svg>")
    return "".join(parts)
