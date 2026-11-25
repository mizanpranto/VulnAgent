"""Pentest-style Word (.docx) report; same content as the PDF (requires python-docx and Pillow).

Headings use Word's built-in Heading styles, so the Navigation Pane works and the table
of contents is a real Word field. The file asks Word to refresh fields when it opens, so
Word shows a one-time "update fields?" prompt; answer Yes to fill in the page numbers.
"""

from __future__ import annotations

import io
from pathlib import Path

from . import reportdoc
from .engagement import Engagement

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {"critical": "D03B3B", "high": "EC835A", "medium": "FAB219", "low": "2A78D6", "info": "7A7975"}
RISK_COLOR = {"Critical": "D03B3B", "High": "EC835A", "Medium": "FAB219", "Low": "2A78D6", "None identified": "3F7D58"}
BRAND, INK, INK2, GRID, SURFACE2 = "0F4C5C", "0B0B0B", "52514E", "D9D8D3", "F4F3F0"
DEFAULT_TITLE = "Source Code Security Assessment"


def _bar_png(rows, label_px=560, width_px=1700, color="2A78D6") -> bytes:
    """Horizontal bar chart as a PNG (rows: (label, value, hex colour or None))."""
    from PIL import Image, ImageDraw, ImageFont
    try:
        import reportlab
        fonts = Path(reportlab.__file__).parent / "fonts"
        regular = ImageFont.truetype(str(fonts / "Vera.ttf"), 30)
        bold = ImageFont.truetype(str(fonts / "VeraBd.ttf"), 30)
    except Exception:  # fonts missing: Pillow's built-in font still works
        regular = bold = ImageFont.load_default()
    row_h = 54
    image = Image.new("RGB", (width_px, row_h * len(rows) + 16), "white")
    draw = ImageDraw.Draw(image)
    top = max([r[1] for r in rows] + [1])
    bar_max = width_px - label_px - 120
    for i, (label, value, tint) in enumerate(rows):
        y = 8 + i * row_h
        text = label if len(label) <= 52 else label[:51] + "…"
        draw.text((0, y + 6), text, fill="#52514e", font=regular)
        draw.line([(label_px, y), (label_px, y + 40)], fill="#d9d8d3", width=2)
        w = int(bar_max * value / top)
        if w > 0:
            draw.rounded_rectangle([label_px, y + 2, label_px + w, y + 38], radius=5, fill="#" + (tint or color))
        draw.text((label_px + w + 14, y + 6), str(value), fill="#0b0b0b", font=bold)
    out = io.BytesIO()
    image.save(out, "PNG", dpi=(200, 200))
    return out.getvalue()


def _logo_on_white(png: bytes) -> bytes:
    from PIL import Image
    logo = Image.open(io.BytesIO(png)).convert("RGBA")
    pad = 24
    canvas = Image.new("RGBA", (logo.width + 2 * pad, logo.height + 2 * pad), "white")
    canvas.alpha_composite(logo, (pad, pad))
    out = io.BytesIO()
    canvas.convert("RGB").save(out, "PNG")
    return out.getvalue()


def build_docx(report, destination, engagement: Engagement = None) -> Path:
    try:
        from docx import Document
        from docx.enum.section import WD_SECTION
        from docx.enum.table import WD_TABLE_ALIGNMENT
        from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
        from docx.oxml import OxmlElement
        from docx.oxml.ns import qn
        from docx.shared import Cm, Pt, RGBColor
    except ImportError as error:  # pragma: no cover
        raise RuntimeError("DOCX export needs python-docx: pip install python-docx") from error

    eng = engagement or report.engagement or Engagement()
    application = eng.application or report.project
    title = eng.title or DEFAULT_TITLE
    risk, risk_sentence = reportdoc.overall_risk(report.stats)
    stats, meta = report.stats, report.meta
    confidentiality = reportdoc.confidentiality_text(eng, application)
    text_width = 17.0  # cm: A4 minus 2 x 2 cm margins

    doc = Document()
    rgb = lambda h: RGBColor.from_string(h)  # noqa: E731

    # ---- styles ------------------------------------------------------------------
    def set_font(style, name, size=None, bold=None, color=None):
        style.font.name = name
        rfonts = style.element.get_or_add_rPr().get_or_add_rFonts()
        for attr in ("asciiTheme", "hAnsiTheme", "eastAsiaTheme", "cstheme"):
            rfonts.attrib.pop(qn("w:" + attr), None)
        for attr in ("ascii", "hAnsi", "eastAsia", "cs"):
            rfonts.set(qn("w:" + attr), name)
        if size:
            style.font.size = Pt(size)
        if bold is not None:
            style.font.bold = bold
        if color:
            style.font.color.rgb = rgb(color)

    set_font(doc.styles["Normal"], "Calibri", 10, color=INK)
    doc.styles["Normal"].paragraph_format.space_after = Pt(4)
    doc.styles["Normal"].paragraph_format.line_spacing = 1.12
    set_font(doc.styles["Heading 1"], "Calibri", 18, True, BRAND)
    doc.styles["Heading 1"].paragraph_format.space_before = Pt(4)
    doc.styles["Heading 1"].paragraph_format.space_after = Pt(8)
    set_font(doc.styles["Heading 2"], "Calibri", 12, True, INK)
    doc.styles["Heading 2"].paragraph_format.space_before = Pt(12)
    doc.styles["Heading 2"].paragraph_format.space_after = Pt(4)
    set_font(doc.styles["Title"], "Calibri", 30, True, INK)

    section = doc.sections[0]
    section.page_width, section.page_height = Cm(21.0), Cm(29.7)
    for side in ("left_margin", "right_margin"):
        setattr(section, side, Cm(2.0))
    section.top_margin, section.bottom_margin = Cm(2.0), Cm(2.0)

    # ---- low-level helpers -------------------------------------------------------------
    def shade(cell, hex_fill):
        tcpr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), hex_fill)
        tcpr.append(shd)

    def cell_borders(cell, **edges):  # edges: top/bottom/left/right = (size_eighths_pt, hex) or None
        tcpr = cell._tc.get_or_add_tcPr()
        borders = OxmlElement("w:tcBorders")
        for edge in ("top", "left", "bottom", "right"):
            el = OxmlElement(f"w:{edge}")
            spec = edges.get(edge)
            if spec:
                el.set(qn("w:val"), "single")
                el.set(qn("w:sz"), str(spec[0]))
                el.set(qn("w:color"), spec[1])
            else:
                el.set(qn("w:val"), "nil")
            borders.append(el)
        tcpr.append(borders)

    def cell_margins(cell, top=60, bottom=60, left=100, right=100):
        tcpr = cell._tc.get_or_add_tcPr()
        mar = OxmlElement("w:tcMar")
        for name, val in (("top", top), ("left", left), ("bottom", bottom), ("right", right)):
            el = OxmlElement(f"w:{name}")
            el.set(qn("w:w"), str(val))
            el.set(qn("w:type"), "dxa")
            mar.append(el)
        tcpr.append(mar)

    def row_flags(row, header=False):
        trpr = row._tr.get_or_add_trPr()
        trpr.append(OxmlElement("w:cantSplit"))
        if header:
            trpr.append(OxmlElement("w:tblHeader"))

    def write(cell_or_par, text, bold=False, size=None, color=None, font=None, align=None, italic=False):
        par = cell_or_par.paragraphs[0] if hasattr(cell_or_par, "paragraphs") else cell_or_par
        run = par.add_run(str(text))
        run.bold, run.italic = bold, italic
        if size:
            run.font.size = Pt(size)
        if color:
            run.font.color.rgb = rgb(color)
        if font:
            run.font.name = font
            run._element.get_or_add_rPr().get_or_add_rFonts().set(qn("w:eastAsia"), font)
        if align is not None:
            par.alignment = align
        par.paragraph_format.space_after = Pt(0)
        return run

    def new_table(ncols, widths_cm):
        table = doc.add_table(rows=0, cols=ncols)
        table.alignment = WD_TABLE_ALIGNMENT.LEFT
        table.autofit = False
        tblpr = table._tbl.tblPr
        layout = OxmlElement("w:tblLayout")
        layout.set(qn("w:type"), "fixed")
        tblpr.append(layout)
        table._widths = widths_cm
        for column, width in zip(table.columns, widths_cm):
            column.width = Cm(width)  # writes the grid; Word and LibreOffice both need it
        total = OxmlElement("w:tblW")
        total.set(qn("w:w"), str(int(sum(widths_cm) * 567)))
        total.set(qn("w:type"), "dxa")
        for old in tblpr.findall(qn("w:tblW")):
            tblpr.remove(old)
        tblpr.append(total)
        return table

    def add_row(table, values, header=False, bold_first=False, fills=None, size=9):
        row = table.add_row()
        row_flags(row, header)
        for i, cell in enumerate(row.cells):
            cell.width = Cm(table._widths[i])
            cell_margins(cell)
            cell_borders(cell, bottom=(4, GRID))
            value = values[i] if i < len(values) else ""
            if header:
                shade(cell, BRAND)
                write(cell, value, bold=True, size=size, color="FFFFFF")
            else:
                write(cell, value, bold=(bold_first and i == 0), size=size)
        return row

    def badge(cell, severity, size=8.5):
        for p in list(cell.paragraphs)[1:]:
            p._element.getparent().remove(p._element)
        for r in list(cell.paragraphs[0].runs):
            r._element.getparent().remove(r._element)
        shade(cell, SEV_COLOR.get(severity, SEV_COLOR["info"]))
        write(cell, severity.capitalize(), bold=True, size=size, color=INK if severity == "medium" else "FFFFFF",
              align=WD_ALIGN_PARAGRAPH.CENTER)

    def spacer(pt=4):
        par = doc.add_paragraph()
        par.paragraph_format.space_after = Pt(0)
        par.paragraph_format.space_before = Pt(0)
        par.add_run().font.size = Pt(pt)
        return par

    def para(text, size=None, color=None, bold=False, after=4, keep_next=False, italic=False):
        par = doc.add_paragraph()
        run = par.add_run(text)
        run.bold, run.italic = bold, italic
        if size:
            run.font.size = Pt(size)
        if color:
            run.font.color.rgb = rgb(color)
        par.paragraph_format.space_after = Pt(after)
        par.paragraph_format.keep_with_next = keep_next
        return par

    def small_label(text):
        return para(text, size=8.5, color=BRAND, bold=True, after=2, keep_next=True)

    def page_break():
        doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    def picture(png, width_cm=16.0):
        par = doc.add_paragraph()
        par.add_run().add_picture(io.BytesIO(png), width=Cm(width_cm))
        par.paragraph_format.space_after = Pt(4)

    def field(par, instruction, placeholder=""):
        def fld(kind):
            run = par.add_run()
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), kind)
            run._r.append(el)
        fld("begin")
        run = par.add_run()
        instr = OxmlElement("w:instrText")
        instr.set(qn("xml:space"), "preserve")
        instr.text = f" {instruction} "
        run._r.append(instr)
        fld("separate")
        par.add_run(placeholder)
        fld("end")

    def code_box(text, size=8):
        table = new_table(1, [text_width])
        row = table.add_row()
        row_flags(row)
        cell = row.cells[0]
        cell.width = Cm(text_width)
        shade(cell, SURFACE2)
        cell_margins(cell, 80, 80, 120, 120)
        cell_borders(cell)
        lines = text.splitlines() or [""]
        cell.paragraphs[0].text = ""
        for i, line in enumerate(lines):
            par = cell.paragraphs[0] if i == 0 else cell.add_paragraph()
            write(par, line, size=size, font="Courier New")
        spacer(3)

    # ---- cover (section 1: no header or footer) ---------------------------------------
    band = new_table(2, [10.5, 6.5])
    row = band.add_row()
    for i, c in enumerate(row.cells):
        c.width = Cm(band._widths[i])
        shade(c, BRAND)
        cell_borders(c)
        cell_margins(c, 200, 200, 240, 240)
    if eng.logo_png:
        row.cells[0].paragraphs[0].add_run().add_picture(io.BytesIO(_logo_on_white(eng.logo_png)), height=Cm(2.2))
    else:
        write(row.cells[0], " ", size=10)
    write(row.cells[1], eng.classification.upper(), bold=True, size=9, color="FFFFFF", align=WD_ALIGN_PARAGRAPH.RIGHT)
    row2 = band.add_row()
    for i, c in enumerate(row2.cells):
        c.width = Cm(band._widths[i])
        shade(c, BRAND)
        cell_borders(c)
        cell_margins(c, 700, 200, 240, 240)
    write(row2.cells[0], f"Assessment agent: {reportdoc.tool_line()}", size=9, color="FFFFFF")
    write(row2.cells[1], " ", size=9)
    spacer(40)
    par = doc.add_paragraph(style="Title")
    par.add_run(title)
    par.paragraph_format.space_after = Pt(6)
    para(application, size=17, color=BRAND, bold=True, after=14)
    details = [("Assessment agent", reportdoc.tool_line(eng.agent_author)), ("Assessed by", eng.assessor),
               ("Company", eng.company), ("Contact", eng.contact), ("Prepared for", eng.client),
               ("Reviewed by", eng.reviewer), ("Report date", eng.resolved_date()), ("Version", eng.version),
               ("Classification", eng.classification)]
    dt = new_table(2, [4.2, 12.8])
    for k, v in details:
        if not v:
            continue
        r = dt.add_row()
        row_flags(r)
        for i, c in enumerate(r.cells):
            c.width = Cm(dt._widths[i])
            cell_margins(c, 70, 70, 60, 60)
            cell_borders(c, bottom=(4, GRID))
        write(r.cells[0], k, size=9, color=INK2)
        write(r.cells[1], v, bold=True, size=11)
    spacer(30)
    chip = new_table(1, [6.0])
    r = chip.add_row()
    row_flags(r)
    c = r.cells[0]
    c.width = Cm(6.0)
    shade(c, RISK_COLOR.get(risk, INK2))
    cell_borders(c)
    cell_margins(c, 120, 120, 200, 200)
    fg = INK if risk == "Medium" else "FFFFFF"
    write(c, "OVERALL RISK", size=7.5, color=fg)
    write(c.add_paragraph(), risk, bold=True, size=15, color=fg)
    spacer(24)
    para(confidentiality, size=8, color=INK2)

    # ---- body section --------------------------------------------------------------------
    body = doc.add_section(WD_SECTION.NEW_PAGE)
    body.header.is_linked_to_previous = False
    body.footer.is_linked_to_previous = False
    pg = OxmlElement("w:pgNumType")
    pg.set(qn("w:start"), "1")
    body._sectPr.append(pg)

    def set_tab(par, pos_cm):
        ppr = par._p.get_or_add_pPr()
        tabs = OxmlElement("w:tabs")
        for stale in (4680, 9360):  # the built-in Header/Footer styles define these; clear them
            gone = OxmlElement("w:tab")
            gone.set(qn("w:val"), "clear")
            gone.set(qn("w:pos"), str(stale))
            tabs.append(gone)
        tab = OxmlElement("w:tab")
        tab.set(qn("w:val"), "right")
        tab.set(qn("w:pos"), str(int(pos_cm * 567)))
        tabs.append(tab)
        ppr.append(tabs)

    hp = body.header.paragraphs[0]
    hp.text = ""
    set_tab(hp, text_width)
    write(hp, f"{application}  |  {title}\t{eng.classification.upper()}", size=8, color=INK2)
    fp = body.footer.paragraphs[0]
    fp.text = ""
    set_tab(fp, text_width)
    write(fp, " | ".join(x for x in (eng.company, f"v{eng.version}") if x) + "\tPage ", size=8, color=INK2)
    field(fp, "PAGE", "1")
    for run in fp.runs:
        run.font.size = Pt(8)
        run.font.color.rgb = rgb(INK2)

    # ---- document control and contents ---------------------------------------------------
    doc.add_heading("Document control", 1)
    control = [("Title", title), ("Application", application), ("Prepared for", eng.client),
               ("Prepared by", ", ".join(x for x in (eng.assessor, eng.company) if x)), ("Contact", eng.contact),
               ("Reviewed by", eng.reviewer), ("Report date", eng.resolved_date()), ("Version", eng.version),
               ("Classification", eng.classification), ("Assessment agent", reportdoc.tool_line(eng.agent_author))]
    t = new_table(2, [4.2, 12.8])
    for k, v in control:
        if v:
            add_row(t, [k, v], bold_first=True)
    doc.add_heading("Version history", 2)
    t = new_table(4, [2.4, 3.0, 5.0, 6.6])
    add_row(t, ["Version", "Date", "Author", "Description"], header=True)
    add_row(t, [eng.version, eng.resolved_date(), eng.assessor or "VulnAgent", "Initial release"])
    doc.add_heading("Confidentiality", 2)
    para(confidentiality)
    doc.add_heading("Contents", 2)
    sections = ["1. Executive summary", "2. Scope and methodology", "3. Findings summary", "4. Detailed findings",
                "5. Remediation roadmap"]
    if report.dismissed:
        sections.append("Appendix A. Findings dismissed by AI triage")
    if getattr(report, "a01", None):
        sections += ["Appendix B. Access-control coverage (OWASP A01)", "Appendix C. Entry-point authorization matrix",
                     "Appendix D. Limitations and disclaimer"]
    else:
        sections.append("Appendix B. Limitations and disclaimer")
    toc_first = doc.add_paragraph()
    field(toc_first, 'TOC \\o "1-1" \\h \\z \\u', "\n".join(sections))
    page_break()

    # ---- 1 executive summary -------------------------------------------------------------
    doc.add_heading("1. Executive summary", 1)
    box = new_table(2, [4.2, 12.8])
    r = box.add_row()
    row_flags(r)
    a, b = r.cells
    a.width, b.width = Cm(4.2), Cm(12.8)
    shade(a, RISK_COLOR.get(risk, INK2))
    shade(b, SURFACE2)
    for c in (a, b):
        cell_borders(c)
        cell_margins(c, 140, 140, 200, 160)
    fg = INK if risk == "Medium" else "FFFFFF"
    write(a, "OVERALL RISK", size=7.5, color=fg)
    write(a.add_paragraph(), risk, bold=True, size=15, color=fg)
    write(b, risk_sentence, size=10)
    spacer(6)
    for text in reportdoc.executive_summary(report, application):
        para(text)
    doc.add_heading("Findings by severity", 2)
    picture(_bar_png([(s.capitalize(), stats["severity"].get(s, 0), SEV_COLOR[s]) for s in SEV_ORDER], label_px=230))
    priorities = reportdoc.top_priorities(report)
    if priorities:
        doc.add_heading("Top priorities", 2)
        t = new_table(4, [2.0, 8.0, 2.6, 4.4])
        add_row(t, ["ID", "Finding", "Severity", "Location"], header=True)
        for fid, f in priorities:
            r = add_row(t, [fid, f.title, "", f"{f.file}:{f.line}"], bold_first=True)
            badge(r.cells[2], f.severity)
    page_break()

    # ---- 2 scope and methodology ------------------------------------------------------------
    doc.add_heading("2. Scope and methodology", 1)
    doc.add_heading("Scope", 2)
    t = new_table(2, [4.2, 12.8])
    for k, v in reportdoc.scope_rows(report, application):
        add_row(t, [k, v], bold_first=True)
    for note in report.notes:
        para("Note: " + note, size=8.5, color=INK2)
    doc.add_heading("Methodology", 2)
    t = new_table(2, [3.6, 13.4])
    add_row(t, ["Step", "What was done"], header=True)
    for a, b in reportdoc.methodology_steps(report):
        add_row(t, [a, b], bold_first=True)
    doc.add_heading("Severity ratings", 2)
    t = new_table(2, [2.6, 14.4])
    add_row(t, ["Rating", "Meaning"], header=True)
    for s, text in reportdoc.SEVERITY_DEFINITIONS.items():
        r = add_row(t, ["", text])
        badge(r.cells[0], s)
    page_break()

    # ---- 3 findings summary ---------------------------------------------------------------------
    doc.add_heading("3. Findings summary", 1)
    if report.active:
        t = new_table(5, [1.8, 7.0, 2.2, 2.0, 4.0])
        add_row(t, ["ID", "Finding", "Severity", "CWE", "Location"], header=True, size=8.5)
        for i, f in enumerate(report.active, 1):
            r = add_row(t, [reportdoc.finding_id(i), f.title, "", f"CWE-{f.cwe}" if f.cwe else "-",
                            f"{f.file}:{f.line}"], bold_first=True, size=8.5)
            badge(r.cells[2], f.severity, 8)
    else:
        para("No findings were reported.")
    if stats["by_cwe"]:
        doc.add_heading("Most common weakness types", 2)
        picture(_bar_png([(f"CWE-{r['cwe']} {r['name']}", r["count"], None) for r in stats["by_cwe"][:8]],
                         label_px=900))
    if stats.get("owasp"):
        doc.add_heading("OWASP Top 10:2025 categories", 2)
        picture(_bar_png([(f"{r['id'][:3]} {r['name']}", r["count"], None) for r in stats["owasp"]], label_px=900))
        para(f"{stats.get('top25', 0)} finding(s) are in the CWE Top 25 (2025).", size=8.5, color=INK2)
    if stats["by_file"]:
        doc.add_heading("Files with the most findings", 2)
        picture(_bar_png([((("…" + r["file"][-36:]) if len(r["file"]) > 38 else r["file"]), r["count"], None)
                          for r in stats["by_file"][:8]], label_px=900))
    page_break()

    # ---- findings (used by section 4 and appendix A) ----------------------------------------------
    def finding_block(fid, finding):
        color = SEV_COLOR.get(finding.severity, SEV_COLOR["info"])
        top = new_table(3, [2.0, 12.4, 2.6])
        r = top.add_row()
        row_flags(r)
        for i, c in enumerate(r.cells):
            c.width = Cm(top._widths[i])
            shade(c, SURFACE2)
            cell_margins(c, 90, 90, 120, 120)
            cell_borders(c, left=(24, color) if i == 0 else None)
        write(r.cells[0], fid, bold=True, size=10.5)
        write(r.cells[1], finding.title, bold=True, size=10.5)
        badge(r.cells[2], finding.severity)
        for c in r.cells:  # keep the header row with the table that follows
            for p in c.paragraphs:
                p.paragraph_format.keep_with_next = True
        t = new_table(2, [3.0, 14.0])
        for k, v in reportdoc.finding_fields(finding):
            rr = add_row(t, [k, v], bold_first=True, size=9)
            for c in rr.cells:
                for p in c.paragraphs:
                    p.paragraph_format.keep_with_next = True
        if finding.explanation:
            spacer(2)
            small_label("Description")
            para(finding.explanation)
        if finding.evidence:
            small_label("Evidence")
            code_box("\n".join(finding.evidence.splitlines()[:6]))
        steps = [s for s in (finding.data_flow or []) if s]
        if len(steps) >= 2:
            small_label("Attack path")
            flow = new_table(1, [text_width])
            for i, step in enumerate(steps):
                kind = "source" if i == 0 else "sink" if i == len(steps) - 1 else "step"
                fr = flow.add_row()
                row_flags(fr)
                c = fr.cells[0]
                c.width = Cm(text_width)
                shade(c, SURFACE2)
                cell_margins(c, 50, 50, 120, 120)
                edge = {"source": "2A78D6", "sink": "D03B3B", "step": GRID}[kind]
                cell_borders(c, left=(18, edge), bottom=(8, "FFFFFF"))
                tag = {"source": "INPUT  ", "sink": "SINK  ", "step": ""}[kind]
                run = write(c, tag, bold=True, size=7.5, color=edge)
                write(c.paragraphs[0], step, size=8, font="Courier New")
            spacer(3)
        if finding.fix:
            small_label("Recommendation")
            para(finding.fix)
        if finding.safe_example:
            small_label("Secure example")
            code_box("\n".join(finding.safe_example.splitlines()[:8]))
        refs = reportdoc.references(finding)
        if refs:
            small_label("References")
            for ref in refs:
                para(ref, size=8.5, color=INK2, after=1)
        spacer(10)

    doc.add_heading("4. Detailed findings", 1)
    if not report.active:
        para("No findings were reported.")
    for i, f in enumerate(report.active, 1):
        finding_block(reportdoc.finding_id(i), f)

    # ---- 5 roadmap and appendices ----------------------------------------------------------------------
    page_break()
    doc.add_heading("5. Remediation roadmap", 1)
    roadmap = reportdoc.remediation_roadmap(report)
    if roadmap:
        t = new_table(3, [3.2, 2.2, 11.6])
        add_row(t, ["Timeframe", "Findings", "Focus"], header=True)
        for a, b, c in roadmap:
            add_row(t, [a, str(b), c], bold_first=True)
        spacer(4)
        para("After fixes are applied, run the assessment again to confirm the findings are resolved and that no new "
             "issues were introduced.", size=9, color=INK2)
    else:
        para("No remediation actions are required based on the automated results.")
    if report.dismissed:
        page_break()
        doc.add_heading("Appendix A. Findings dismissed by AI triage", 1)
        para("The analyser reported these items, but the local model judged them likely false positives. They are "
             "kept so a person can overrule the model.", size=9, color=INK2)
        for i, f in enumerate(report.dismissed, 1):
            finding_block(f"D-{i:03d}", f)
    letter = "B"
    if getattr(report, "a01", None):
        page_break()
        doc.add_heading("Appendix B. Access-control coverage (OWASP A01)", 1)
        t = new_table(2, [5.0, 12.0])
        for k, v in reportdoc.a01_coverage_rows(report):
            add_row(t, [k, v], bold_first=True, size=9)
        page_break()
        doc.add_heading("Appendix C. Entry-point authorization matrix", 1)
        para("Every HTTP entry point the model found, with the guards that apply after router mounts, prefixes and global security "
             "settings were resolved. 'NONE' means no authentication guard was found; '(name only)' means a guard was recognised by "
             "its name rather than by reading its code.", size=9, color=INK2)
        headers, rows, hidden = reportdoc.a01_matrix(report)
        mt = new_table(8, [1.3, 3.2, 2.7, 2.0, 1.8, 1.7, 2.3, 2.0])
        add_row(mt, headers, header=True, size=7)
        for r in rows:
            add_row(mt, [str(c) for c in r], size=6.5)
        if hidden:
            para(f"{hidden} more entry point(s) are listed in the JSON report.", size=8.5, color=INK2)
        letter = "D"
    page_break()
    doc.add_heading(f"Appendix {letter}. Limitations and disclaimer", 1)
    for line in reportdoc.limitations(report):
        doc.add_paragraph(line, style="List Bullet")
    para(f"Report generated by {reportdoc.tool_line(eng.agent_author)} on {meta.get('started_at', '')}.",
         size=8.5, color=INK2)

    # ---- properties and field refresh ----------------------------------------------------------------
    props = doc.core_properties
    props.title = f"{title} - {application}"
    props.author = eng.assessor or "VulnAgent"
    props.subject = "Automated source code security assessment"
    props.comments = "Generated by VulnAgent"
    update = OxmlElement("w:updateFields")
    update.set(qn("w:val"), "true")
    doc.settings.element.append(update)

    if hasattr(destination, "write"):
        doc.save(destination)
        return destination
    out = Path(destination)
    out.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(out))
    return out
