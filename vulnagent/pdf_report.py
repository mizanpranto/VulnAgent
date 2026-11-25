"""Pentest-style PDF report (requires reportlab).

Layout: cover page, document control, contents, executive summary, scope and
methodology, findings summary, detailed findings, remediation roadmap, appendices.
Text is limited to the Latin-1 range because the built-in PDF fonts are used; the
DOCX report has no such limit.
"""

from __future__ import annotations

import io
import textwrap
from pathlib import Path
from xml.sax.saxutils import escape

from . import reportdoc
from .engagement import Engagement
from .models import SEVERITIES
from .standards import label as standards_label

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {"critical": "#d03b3b", "high": "#ec835a", "medium": "#fab219", "low": "#2a78d6", "info": "#7a7975"}
RISK_COLOR = {"Critical": "#d03b3b", "High": "#ec835a", "Medium": "#fab219", "Low": "#2a78d6",
              "None identified": "#3f7d58"}
BRAND, INK, INK2, GRID, SURFACE2 = "#0f4c5c", "#0b0b0b", "#52514e", "#d9d8d3", "#f4f3f0"
DEFAULT_TITLE = "Source Code Security Assessment"


def _latin(text) -> str:
    return str(text if text is not None else "").encode("latin-1", "replace").decode("latin-1")


def _para(text) -> str:
    return escape(_latin(text))


def build_pdf(report, destination, engagement: Engagement = None) -> Path:
    try:
        from reportlab.graphics.shapes import Drawing, Line, Rect, String
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.lib.utils import ImageReader
        from reportlab.platypus import (BaseDocTemplate, Frame, HRFlowable, KeepTogether, NextPageTemplate, PageBreak,
                                        PageTemplate, Paragraph, Preformatted, Spacer, Table, TableStyle)
        from reportlab.platypus.tableofcontents import TableOfContents
    except ImportError as error:  # pragma: no cover - exercised only without reportlab
        raise RuntimeError("PDF export needs reportlab: pip install reportlab") from error

    eng = engagement or report.engagement or Engagement()
    application = eng.application or report.project
    title = eng.title or DEFAULT_TITLE
    risk, risk_sentence = reportdoc.overall_risk(report.stats)
    stats, meta = report.stats, report.meta
    hexc = colors.HexColor
    W, H = A4
    LM = 20 * mm
    width = W - 2 * LM

    styles = getSampleStyleSheet()
    base = ParagraphStyle("base", parent=styles["BodyText"], fontName="Helvetica", fontSize=9.4, leading=13.6,
                          textColor=hexc(INK))
    muted = ParagraphStyle("muted", parent=base, textColor=hexc(INK2), fontSize=8.4, leading=12)
    cell = ParagraphStyle("cell", parent=base, fontSize=8.6, leading=11.4)
    cell_b = ParagraphStyle("cell_b", parent=cell, fontName="Helvetica-Bold")
    H1 = ParagraphStyle("H1", parent=base, fontName="Helvetica-Bold", fontSize=17, leading=21, spaceBefore=2,
                        spaceAfter=8, textColor=hexc(BRAND))
    H2 = ParagraphStyle("H2", parent=base, fontName="Helvetica-Bold", fontSize=11.5, leading=15, spaceBefore=12,
                        spaceAfter=5, textColor=hexc(INK))
    FH = ParagraphStyle("FH", parent=base, fontName="Helvetica-Bold", fontSize=10.5, leading=14, textColor=hexc(INK))
    label = ParagraphStyle("label", parent=muted, fontName="Helvetica-Bold", spaceBefore=7, spaceAfter=2,
                           textColor=hexc(BRAND))
    code = ParagraphStyle("code", parent=base, fontName="Courier", fontSize=7.8, leading=10,
                          backColor=hexc(SURFACE2), borderPadding=4, textColor=hexc(INK))

    def p(text, style=base):
        return Paragraph(_para(text), style)

    def grid_table(rows, col_widths, header=True, extra=()):
        t = Table(rows, colWidths=col_widths, repeatRows=1 if header else 0)
        style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, hexc(GRID)),
                 ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                 ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5)]
        if header:
            style += [("BACKGROUND", (0, 0), (-1, 0), hexc(BRAND)), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
        t.setStyle(TableStyle(style + list(extra)))
        return t

    def head(text):
        return Paragraph(_para(text), ParagraphStyle("hdr", parent=cell_b, textColor=colors.white))

    def sev_badge(severity):
        color = SEV_COLOR.get(severity, SEV_COLOR["info"])
        fg = INK if severity == "medium" else "#ffffff"
        return Paragraph(f'<font color="{fg}"><b>{_para(severity.capitalize())}</b></font>',
                         ParagraphStyle("badge", parent=cell, backColor=hexc(color), alignment=1, borderPadding=2))

    # ---- drawings ---------------------------------------------------------
    def bar_chart(rows, label_w, bar_max, row_h=19):
        d = Drawing(width, row_h * len(rows) + 6)
        top = max([r[1] for r in rows] + [1])
        for i, (text, value, color) in enumerate(rows):
            y = d.height - (i + 1) * row_h
            d.add(String(0, y + 5, _latin(text)[:48], fontName="Helvetica", fontSize=8.2, fillColor=hexc(INK2)))
            d.add(Line(label_w, y - 2, label_w, y + 14, strokeColor=hexc(GRID), strokeWidth=0.6))
            w = bar_max * value / top
            if w > 0:
                d.add(Rect(label_w, y, w, 12, fillColor=hexc(color), strokeColor=None, rx=2, ry=2))
            d.add(String(label_w + w + 6, y + 3, str(value), fontName="Helvetica-Bold", fontSize=8.2,
                         fillColor=hexc(INK)))
        return d

    def flow_drawing(finding):
        steps = [s for s in (finding.data_flow or []) if s]
        if len(steps) >= 2:
            nodes = [("source", steps[0])] + [("step", s) for s in steps[1:-1]] + [("sink", steps[-1])]
        else:
            return None
        wrapped = [(k, textwrap.wrap(_latin(t), 92)[:2] or [""]) for k, t in nodes]
        heights = [10 + 10 * len(lines) for _, lines in wrapped]
        total = sum(heights) + 14 * (len(wrapped) - 1) + 4
        d = Drawing(width, total)
        y = total - 2
        for index, ((kind, lines), h) in enumerate(zip(wrapped, heights)):
            edge = {"source": SEV_COLOR["low"], "sink": SEV_COLOR["critical"], "step": GRID}[kind]
            d.add(Rect(0, y - h, width, h, fillColor=hexc(SURFACE2), strokeColor=hexc(edge), strokeWidth=1.1,
                       rx=3, ry=3))
            for j, line in enumerate(lines):
                d.add(String(8, y - 11 - 10 * j, line, fontName="Courier", fontSize=7.4, fillColor=hexc(INK)))
            tag = {"source": "INPUT", "sink": "SINK", "step": ""}[kind]
            if tag:
                d.add(String(width - 8, y - 11, tag, fontName="Helvetica-Bold", fontSize=6.8, textAnchor="end",
                             fillColor=hexc(edge)))
            if index < len(wrapped) - 1:
                x = width / 2
                d.add(Line(x, y - h, x, y - h - 12, strokeColor=hexc(INK2), strokeWidth=1))
                d.add(Line(x - 3, y - h - 8, x, y - h - 12, strokeColor=hexc(INK2), strokeWidth=1))
                d.add(Line(x + 3, y - h - 8, x, y - h - 12, strokeColor=hexc(INK2), strokeWidth=1))
            y -= h + 14
        return d

    # ---- page furniture -----------------------------------------------------
    logo = ImageReader(io.BytesIO(eng.logo_png)) if eng.logo_png else None
    confidentiality = reportdoc.confidentiality_text(eng, application)

    def draw_cover(canvas, doc):
        canvas.saveState()
        band_h = 78 * mm
        canvas.setFillColor(hexc(BRAND))
        canvas.rect(0, H - band_h, W, band_h, stroke=0, fill=1)
        canvas.setFillColor(hexc("#0a3541"))
        canvas.rect(0, H - band_h, W, 3 * mm, stroke=0, fill=1)
        if logo:
            canvas.setFillColor(colors.white)
            canvas.roundRect(LM, H - 42 * mm, 62 * mm, 26 * mm, 3 * mm, stroke=0, fill=1)
            canvas.drawImage(logo, LM + 3 * mm, H - 40 * mm, 56 * mm, 22 * mm, preserveAspectRatio=True,
                             anchor="c", mask="auto")
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawRightString(W - LM, H - 20 * mm, _latin(eng.classification.upper()))
        canvas.setFont("Helvetica", 9)
        canvas.drawString(LM, H - band_h + 9 * mm, _latin(f"Assessment agent: {reportdoc.tool_line()}"))
        # title block
        y = H - band_h - 24 * mm
        canvas.setFillColor(hexc(INK))
        canvas.setFont("Helvetica-Bold", 28)
        for line in textwrap.wrap(_latin(title), 30)[:2]:
            canvas.drawString(LM, y, line)
            y -= 11 * mm
        canvas.setFillColor(hexc(BRAND))
        canvas.setFont("Helvetica-Bold", 16)
        for line in textwrap.wrap(_latin(application), 46)[:2]:
            canvas.drawString(LM, y - 1 * mm, line)
            y -= 8 * mm
        canvas.setStrokeColor(hexc(GRID))
        canvas.line(LM, y - 4 * mm, W - LM, y - 4 * mm)
        y -= 14 * mm
        rows = [("Assessment agent", reportdoc.tool_line(eng.agent_author)),
                ("Assessed by", eng.assessor), ("Company", eng.company), ("Contact", eng.contact),
                ("Prepared for", eng.client), ("Reviewed by", eng.reviewer),
                ("Report date", eng.resolved_date()), ("Version", eng.version),
                ("Classification", eng.classification)]
        for name, value in rows:
            if not value:
                continue
            canvas.setFillColor(hexc(INK2))
            canvas.setFont("Helvetica", 8.5)
            canvas.drawString(LM, y, name)
            canvas.setFillColor(hexc(INK))
            canvas.setFont("Helvetica-Bold", 10.5)
            canvas.drawString(LM + 42 * mm, y, _latin(value)[:70])
            y -= 8 * mm
        # overall risk chip
        canvas.setFillColor(hexc(RISK_COLOR.get(risk, INK2)))
        canvas.roundRect(LM, 40 * mm, 70 * mm, 14 * mm, 2 * mm, stroke=0, fill=1)
        canvas.setFillColor(hexc(INK) if risk == "Medium" else colors.white)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(LM + 4 * mm, 49 * mm, "OVERALL RISK")
        canvas.setFont("Helvetica-Bold", 13)
        canvas.drawString(LM + 4 * mm, 43.2 * mm, risk)
        canvas.setFillColor(hexc(INK2))
        canvas.setFont("Helvetica", 7.6)
        y = 28 * mm
        for line in textwrap.wrap(_latin(confidentiality), 118):
            canvas.drawString(LM, y, line)
            y -= 3.8 * mm
        canvas.restoreState()

    def draw_body(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(hexc(GRID))
        canvas.line(LM, H - 15 * mm, W - LM, H - 15 * mm)
        canvas.line(LM, 14 * mm, W - LM, 14 * mm)
        canvas.setFont("Helvetica", 7.8)
        canvas.setFillColor(hexc(INK2))
        canvas.drawString(LM, H - 12 * mm, _latin(f"{application}  |  {title}")[:90])
        canvas.drawRightString(W - LM, H - 12 * mm, _latin(eng.classification.upper()))
        canvas.drawString(LM, 9.5 * mm, _latin(" | ".join(x for x in (eng.company, f"v{eng.version}") if x)))
        canvas.drawRightString(W - LM, 9.5 * mm, f"Page {doc.page - 1}")
        canvas.restoreState()

    class Doc(BaseDocTemplate):
        def __init__(self, target, **kw):
            super().__init__(target, **kw)
            self._n = 0

        def beforeDocument(self):
            self._n = 0  # bookmark keys must be identical on every build pass

        def afterFlowable(self, flowable):
            if isinstance(flowable, Paragraph) and flowable.style.name == "H1":
                text = flowable.getPlainText()
                key = f"sec{self._n}"
                self._n += 1
                self.canv.bookmarkPage(key)
                self.canv.addOutlineEntry(text, key, 0, 0)
                self.notify("TOCEntry", (0, text, self.page - 1, key))

    if hasattr(destination, "write"):
        out, target = destination, destination
    else:
        out = Path(destination)
        out.parent.mkdir(parents=True, exist_ok=True)
        target = str(out)
    doc = Doc(target, pagesize=A4, leftMargin=LM, rightMargin=LM, topMargin=22 * mm, bottomMargin=20 * mm,
              title=_latin(f"{title} - {application}"), author=_latin(eng.assessor or "VulnAgent"),
              subject="Automated source code security assessment", creator="VulnAgent")
    cover_frame = Frame(LM, 20 * mm, width, 20 * mm, id="cover")
    body_frame = Frame(LM, 20 * mm, width, H - 42 * mm, id="body")
    doc.addPageTemplates([PageTemplate("cover", [cover_frame], onPage=draw_cover),
                          PageTemplate("body", [body_frame], onPage=draw_body)])

    story = [NextPageTemplate("body"), PageBreak()]

    # ---- document control + contents ---------------------------------------
    story += [Paragraph("Document control", H1)]
    control = [("Title", title), ("Application", application), ("Prepared for", eng.client),
               ("Prepared by", ", ".join(x for x in (eng.assessor, eng.company) if x)), ("Contact", eng.contact),
               ("Reviewed by", eng.reviewer), ("Report date", eng.resolved_date()), ("Version", eng.version),
               ("Classification", eng.classification), ("Assessment agent", reportdoc.tool_line(eng.agent_author))]
    story.append(grid_table([[p(k, cell_b), p(v, cell)] for k, v in control if v], [42 * mm, width - 42 * mm],
                            header=False))
    story += [Spacer(1, 10), Paragraph("Version history", H2),
              grid_table([[head("Version"), head("Date"), head("Author"), head("Description")],
                          [p(eng.version, cell), p(eng.resolved_date(), cell), p(eng.assessor or "VulnAgent", cell),
                           p("Initial release", cell)]],
                         [22 * mm, 28 * mm, 45 * mm, width - 95 * mm]),
              Spacer(1, 10), Paragraph("Confidentiality", H2), p(confidentiality), Spacer(1, 14),
              Paragraph("Contents", H2)]
    toc = TableOfContents()
    toc.dotsMinLevel = 0
    toc.levelStyles = [ParagraphStyle("toc0", parent=base, fontSize=10, leading=17, leftIndent=0, firstLineIndent=0)]
    story += [toc, PageBreak()]

    # ---- 1 executive summary -------------------------------------------------
    story.append(Paragraph("1. Executive summary", H1))
    risk_color = hexc(RISK_COLOR.get(risk, INK2))
    risk_fg = hexc(INK) if risk == "Medium" else colors.white
    box = Table([[Paragraph(f'<font color="{"#0b0b0b" if risk == "Medium" else "#ffffff"}" size="8">OVERALL RISK</font>'
                            f'<br/><font color="{"#0b0b0b" if risk == "Medium" else "#ffffff"}" size="15"><b>{_para(risk)}</b></font>',
                            ParagraphStyle("risk", parent=base, leading=18)),
                  p(risk_sentence, base)]], colWidths=[42 * mm, width - 42 * mm])
    box.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), risk_color), ("BACKGROUND", (1, 0), (1, 0), hexc(SURFACE2)),
                             ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 10),
                             ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9)]))
    story += [box, Spacer(1, 8)]
    for paragraph in reportdoc.executive_summary(report, application):
        story += [p(paragraph), Spacer(1, 4)]
    story += [Paragraph("Findings by severity", H2),
              bar_chart([(s.capitalize(), stats["severity"].get(s, 0), SEV_COLOR[s]) for s in SEV_ORDER], 60,
                        width - 110)]
    priorities = reportdoc.top_priorities(report)
    if priorities:
        story += [Paragraph("Top priorities", H2),
                  grid_table([[head("ID"), head("Finding"), head("Severity"), head("Location")]] +
                             [[p(fid, cell_b), p(f.title, cell), sev_badge(f.severity), p(f"{f.file}:{f.line}", cell)]
                              for fid, f in priorities],
                             [18 * mm, width - 88 * mm, 22 * mm, 48 * mm])]
    story.append(PageBreak())

    # ---- 2 scope and methodology ------------------------------------------------
    story.append(Paragraph("2. Scope and methodology", H1))
    story.append(Paragraph("Scope", H2))
    story.append(grid_table([[p(k, cell_b), p(v, cell)] for k, v in reportdoc.scope_rows(report, application)],
                            [42 * mm, width - 42 * mm], header=False))
    for note in report.notes:
        story += [Spacer(1, 4), p("Note: " + note, muted)]
    story.append(Paragraph("Methodology", H2))
    story.append(grid_table([[head("Step"), head("What was done")]] +
                            [[p(a, cell_b), p(b, cell)] for a, b in reportdoc.methodology_steps(report)],
                            [36 * mm, width - 36 * mm]))
    story.append(Paragraph("Severity ratings", H2))
    story.append(grid_table([[head("Rating"), head("Meaning")]] +
                            [[sev_badge(s), p(t, cell)] for s, t in reportdoc.SEVERITY_DEFINITIONS.items()],
                            [24 * mm, width - 24 * mm]))
    story.append(PageBreak())

    # ---- 3 findings summary -----------------------------------------------------
    story.append(Paragraph("3. Findings summary", H1))
    if report.active:
        rows = [[head("ID"), head("Finding"), head("Severity"), head("CWE"), head("Location")]]
        for index, f in enumerate(report.active, 1):
            rows.append([p(reportdoc.finding_id(index), cell_b), p(f.title, cell), sev_badge(f.severity),
                         p(f"CWE-{f.cwe}" if f.cwe else "-", cell), p(f"{f.file}:{f.line}", cell)])
        story.append(grid_table(rows, [17 * mm, width - 100 * mm, 20 * mm, 19 * mm, 44 * mm]))
    else:
        story.append(p("No findings were reported."))
    if stats["by_cwe"]:
        story += [Paragraph("Most common weakness types", H2),
                  bar_chart([(f"CWE-{r['cwe']} {r['name']}", r["count"], "#2a78d6") for r in stats["by_cwe"][:8]],
                            215, width - 265)]
    if stats.get("owasp"):
        story += [Paragraph(f"OWASP Top 10:2025 categories", H2),
                  bar_chart([(f"{r['id'][:3]} {r['name']}", r["count"], "#2a78d6") for r in stats["owasp"]],
                            215, width - 265),
                  p(f"{stats.get('top25', 0)} finding(s) are in the CWE Top 25 (2025).", muted)]
    if stats["by_file"]:
        story += [Paragraph("Files with the most findings", H2),
                  bar_chart([((("..." + r["file"][-40:]) if len(r["file"]) > 43 else r["file"]), r["count"], "#2a78d6")
                             for r in stats["by_file"][:8]], 215, width - 265)]
    story.append(PageBreak())

    # ---- 4 detailed findings --------------------------------------------------------
    def finding_block(fid, finding):
        color = SEV_COLOR.get(finding.severity, SEV_COLOR["info"])
        top = Table([[p(fid, FH), p(finding.title, FH), sev_badge(finding.severity)]],
                    colWidths=[18 * mm, width - 44 * mm, 24 * mm])
        top.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), hexc(SURFACE2)), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                 ("LINEBEFORE", (0, 0), (0, 0), 3, hexc(color)),
                                 ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        details = grid_table([[p(k, cell_b), p(v, cell)] for k, v in reportdoc.finding_fields(finding)],
                             [30 * mm, width - 30 * mm], header=False)
        block = [KeepTogether([top, details])]
        if finding.explanation:
            block += [Paragraph("Description", label), p(finding.explanation)]
        if finding.evidence:
            block += [Paragraph("Evidence", label),
                      Preformatted(_latin("\n".join(textwrap.wrap(finding.evidence, 105)[:4])), code)]
        flow = flow_drawing(finding)
        if flow is not None:
            block += [Paragraph("Attack path", label), flow]
        if finding.fix:
            block += [Paragraph("Recommendation", label), p(finding.fix)]
        if finding.impact and not finding.rule_id.startswith("A01-"):
            pass
        if finding.safe_example:
            block += [Paragraph("Secure example", label),
                      Preformatted(_latin("\n".join(finding.safe_example.splitlines()[:8])), code)]
        refs = reportdoc.references(finding)
        if refs:
            block += [Paragraph("References", label)] + [p(r, muted) for r in refs]
        block += [Spacer(1, 12), HRFlowable(width="100%", color=hexc(GRID)), Spacer(1, 10)]
        return block

    story.append(Paragraph("4. Detailed findings", H1))
    if not report.active:
        story.append(p("No findings were reported."))
    for index, finding in enumerate(report.active, 1):
        story += finding_block(reportdoc.finding_id(index), finding)

    # ---- 5 remediation roadmap ----------------------------------------------------
    story += [PageBreak(), Paragraph("5. Remediation roadmap", H1)]
    roadmap = reportdoc.remediation_roadmap(report)
    if roadmap:
        story.append(grid_table([[head("Timeframe"), head("Findings"), head("Focus")]] +
                                [[p(a, cell_b), p(str(b), cell), p(c, cell)] for a, b, c in roadmap],
                                [30 * mm, 22 * mm, width - 52 * mm]))
        story += [Spacer(1, 6), p("After fixes are applied, run the assessment again to confirm the findings are "
                                  "resolved and that no new issues were introduced.", muted)]
    else:
        story.append(p("No remediation actions are required based on the automated results."))

    # ---- appendices -------------------------------------------------------------------
    if report.dismissed:
        story += [PageBreak(), Paragraph("Appendix A. Findings dismissed by AI triage", H1),
                  p("The analyser reported these items, but the local model judged them likely false positives. They "
                    "are kept so a person can overrule the model.", muted), Spacer(1, 6)]
        for index, finding in enumerate(report.dismissed, 1):
            story += finding_block(f"D-{index:03d}", finding)
    letter = "B"
    if getattr(report, "a01", None):
        tiny = ParagraphStyle("tiny", parent=cell, fontSize=6.6, leading=8.2)
        tiny_b = ParagraphStyle("tiny_b", parent=tiny, fontName="Helvetica-Bold", textColor=colors.white)
        story += [PageBreak(), Paragraph("Appendix B. Access-control coverage (OWASP A01)", H1),
                  grid_table([[p(k, cell_b), p(v, cell)] for k, v in reportdoc.a01_coverage_rows(report)],
                             [45 * mm, width - 45 * mm], header=False)]
        headers, rows, hidden = reportdoc.a01_matrix(report)
        story += [PageBreak(), Paragraph("Appendix C. Entry-point authorization matrix", H1),
                  p("Every HTTP entry point the model found, with the guards that apply after router mounts, prefixes and global "
                    "security settings were resolved. Use it to verify the agent's model at a glance: 'NONE' means no authentication "
                    "guard was found; '(name only)' means the guard was recognised by its name, not by reading its code.", muted),
                  Spacer(1, 6)]
        widths = [14, 31, 29, 20, 16, 16, 20]
        widths.append(width / mm - sum(widths))
        data = [[Paragraph(_para(h), tiny_b) for h in headers]] + [[Paragraph(_para(str(c)), tiny) for c in r] for r in rows]
        t = Table(data, colWidths=[w * mm for w in widths], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), hexc(INK)), ("GRID", (0, 0), (-1, -1), 0.3, hexc(GRID)),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 2),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 2), ("LEFTPADDING", (0, 0), (-1, -1), 3)]))
        story.append(t)
        if hidden:
            story.append(p(f"{hidden} more entry point(s) are listed in the JSON report.", muted))
        letter = "D"
    story += [PageBreak(), Paragraph(f"Appendix {letter}. Limitations and disclaimer", H1)]
    for line in reportdoc.limitations(report):
        story += [p("- " + line), Spacer(1, 3)]
    story += [Spacer(1, 8), p(f"Report generated by {reportdoc.tool_line(eng.agent_author)} on "
                              f"{meta.get('started_at', '')}.", muted)]

    doc.multiBuild(story)
    return out
