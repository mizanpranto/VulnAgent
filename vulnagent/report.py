
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Preformatted,
    HRFlowable,
)


def safe(value):
    if value is None or value == "":
        return "Not provided"

    return str(value).strip()


def get_field(finding, *keys):
    """Return the first available field."""
    for key in keys:
        value = finding.get(key)

        if value is not None and value != "":
            return value

    return "Not provided"


def markdown_code(value):
    value = safe(value)
    return value.replace("```", "'''").replace("\r\n", "\n")


def write_markdown(result, destination):

    destination = Path(destination)

    if destination.suffix.lower() in (".md", ".pdf"):
        base = destination.with_suffix("")
    else:
        base = destination

    md_path = base.with_suffix(".md")
    pdf_path = base.with_suffix(".pdf")

    md_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# VulnAgent Security Assessment",
        "",
        f"**Project:** {safe(result.get('project'))}",
        f"**Model:** {safe(result.get('model'))}",
        f"**Files scanned:** {len(result.get('files_scanned', []))}",
        "",
        "> Automated security analysis. Manually validate findings.",
        "",
        "## Executive Summary",
        "",
        safe(result.get("summary")),
        "",
        "## AI Vulnerability Findings",
        ""
    ]

    findings = result.get("ai_findings", [])

    if not findings:
        lines.append("No AI findings returned.")

    for index, finding in enumerate(findings, 1):

        title = get_field(finding, "title")
        severity = get_field(finding, "severity")
        confidence = get_field(finding, "confidence")
        filename = get_field(finding, "file")
        line = get_field(finding, "line")
        cwe = get_field(finding, "cwe")

        vulnerable_code = get_field(
            finding, "vulnerable_code", "evidence"
        )

        lines.extend([
            f"### {index}. {title}",
            "",
            f"- **Severity:** {severity}",
            f"- **Confidence:** {confidence}",
            f"- **Location:** `{filename}:{line}`",
            f"- **CWE:** {cwe}",
            "",
            "#### 1. Where is the problem?",
            "",
            f"**Vulnerable function:** {get_field(finding, 'function')}",
            "",
            f"**Problematic statement:** {get_field(finding, 'problematic_statement')}",
            "",
            "**Vulnerable code:**",
            "",
            "```python",
            markdown_code(vulnerable_code),
            "```",
            "",
            f"**Problem identified:** {get_field(finding, 'problem')}",
            "",
            "#### 2. Why is it a vulnerability?",
            "",
            f"**Technical explanation:** {get_field(finding, 'explanation', 'technical_explanation')}",
            "",
            f"**Root cause:** {get_field(finding, 'root_cause')}",
            "",
            f"**Source:** {get_field(finding, 'source')}",
            "",
            f"**Vulnerable sink:** {get_field(finding, 'sink')}",
            "",
            f"**Data flow:** {get_field(finding, 'data_flow')}",
            "",
            "**Attack path:**",
            ""
        ])

        attack_path = finding.get("attack_path", [])

        if attack_path:
            for step, description in enumerate(attack_path, 1):
                lines.append(f"{step}. {safe(description)}")
        else:
            lines.append("Attack path not established.")

        lines.extend([
            "",
            f"**Potential impact:** {get_field(finding, 'impact')}",
            "",
            "#### 3. How do I fix it?",
            "",
            f"**Recommended solution:** {get_field(finding, 'fix', 'recommended_fix')}",
            "",
            f"**Why this solution works:** {get_field(finding, 'why_fix_works')}",
            "",
            "**Corrected code:**",
            "",
            "```python",
            markdown_code(get_field(finding, 'safe_example', 'corrected_code')),
            "```",
            "",
            "#### 4. How do I validate the fix?",
            "",
            f"**Test procedure:** {get_field(finding, 'validation', 'validation_steps')}",
            "",
            f"**Expected secure behavior:** {get_field(finding, 'expected_behavior')}",
            "",
            "---",
            ""
        ])

    lines.extend([
        "## Heuristic Scanner Findings",
        ""
    ])

    heuristic_findings = result.get("heuristic_findings", [])

    if not heuristic_findings:
        lines.append("No heuristic findings returned.")

    for finding in heuristic_findings:
        lines.append(
            f"- **{safe(finding.get('severity'))}** "
            f"{safe(finding.get('title'))} — "
            f"`{safe(finding.get('file'))}:{safe(finding.get('line'))}`"
        )

    lines.extend([
        "",
        "## Scanned Files",
        ""
    ])

    for filename in result.get("files_scanned", []):
        lines.append(f"- `{filename}`")

    md_path.write_text(
        "\n".join(lines),
        encoding="utf-8"
    )

    # Generate PDF using the same assessment data.
    write_pdf(result, pdf_path)

    return md_path, pdf_path


def write_pdf(result, destination):

    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontSize=23,
        leading=29,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#163A5F"),
        spaceAfter=15
    ))

    styles.add(ParagraphStyle(
        name="Section",
        parent=styles["Heading1"],
        fontSize=15,
        leading=19,
        textColor=colors.HexColor("#163A5F"),
        spaceBefore=14,
        spaceAfter=8
    ))

    styles.add(ParagraphStyle(
        name="SubSection",
        parent=styles["Heading2"],
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#24527A"),
        spaceBefore=10,
        spaceAfter=5
    ))

    styles.add(ParagraphStyle(
        name="BodyCustom",
        parent=styles["BodyText"],
        fontSize=9,
        leading=14,
        spaceAfter=6
    ))

    styles.add(ParagraphStyle(
        name="CodeCustom",
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        backColor=colors.HexColor("#F1F4F7"),
        borderColor=colors.HexColor("#D5DDE5"),
        borderWidth=0.5,
        borderPadding=7,
        leftIndent=5,
        rightIndent=5,
        spaceBefore=5,
        spaceAfter=9,
        wordWrap="CJK"
    ))

    story = []

    def paragraph(value, style="BodyCustom"):
        value = escape(safe(value)).replace("\n", "<br/>")
        story.append(Paragraph(value, styles[style]))

    def heading(value, style="Section"):
        story.append(Paragraph(escape(value), styles[style]))

    def code_block(value):
        value = escape(markdown_code(value))
        value = value.replace("\n", "<br/>")
        story.append(Paragraph(value, styles["CodeCustom"]))

    def separator():
        story.append(Spacer(1, 5))
        story.append(HRFlowable(
            width="100%",
            color=colors.HexColor("#D5DDE5"),
            thickness=0.7
        ))
        story.append(Spacer(1, 8))

    # Report header
    story.append(Paragraph(
        "VulnAgent Security Assessment",
        styles["ReportTitle"]
    ))

    paragraph(f"Project: {safe(result.get('project'))}")
    paragraph(f"Model: {safe(result.get('model'))}")
    paragraph(f"Files scanned: {len(result.get('files_scanned', []))}")

    paragraph(
        "Automated security analysis. All findings require manual validation."
    )

    heading("Executive Summary")
    paragraph(result.get("summary"))

    heading("AI Vulnerability Findings")

    findings = result.get("ai_findings", [])

    if not findings:
        paragraph("No AI findings returned.")

    for index, finding in enumerate(findings, 1):

        heading(f"{index}. {safe(finding.get('title'))}", "Section")

        paragraph(
            f"Severity: {safe(finding.get('severity'))} | "
            f"Confidence: {safe(finding.get('confidence'))}"
        )

        paragraph(
            f"Location: {safe(finding.get('file'))}:"
            f"{safe(finding.get('line'))}"
        )

        paragraph(f"CWE: {safe(finding.get('cwe'))}")

        heading("1. Where is the problem?", "SubSection")

        paragraph(
            f"Vulnerable function: "
            f"{get_field(finding, 'function')}"
        )

        paragraph(
            f"Problematic statement: "
            f"{get_field(finding, 'problematic_statement')}"
        )

        paragraph("Vulnerable code:")
        code_block(get_field(finding, "vulnerable_code", "evidence"))

        paragraph(
            f"Problem identified: {get_field(finding, 'problem')}"
        )

        heading("2. Why is it a vulnerability?", "SubSection")

        paragraph(
            f"Technical explanation: "
            f"{get_field(finding, 'explanation', 'technical_explanation')}"
        )

        paragraph(
            f"Root cause: {get_field(finding, 'root_cause')}"
        )

        paragraph(f"Source: {get_field(finding, 'source')}")
        paragraph(f"Vulnerable sink: {get_field(finding, 'sink')}")
        paragraph(f"Data flow: {get_field(finding, 'data_flow')}")

        heading("Attack Path", "SubSection")

        attack_path = finding.get("attack_path", [])

        if attack_path:
            for step, description in enumerate(attack_path, 1):
                paragraph(f"{step}. {description}")
        else:
            paragraph("Attack path not established.")

        paragraph(
            f"Potential impact: {get_field(finding, 'impact')}"
        )

        heading("3. How do I fix it?", "SubSection")

        paragraph(
            f"Recommended solution: "
            f"{get_field(finding, 'fix', 'recommended_fix')}"
        )

        paragraph(
            f"Why this solution works: "
            f"{get_field(finding, 'why_fix_works')}"
        )

        paragraph("Corrected code:")
        code_block(get_field(finding, "safe_example", "corrected_code"))

        heading("4. How do I validate the fix?", "SubSection")

        paragraph(
            f"Test procedure: "
            f"{get_field(finding, 'validation', 'validation_steps')}"
        )

        paragraph(
            f"Expected secure behavior: "
            f"{get_field(finding, 'expected_behavior')}"
        )

        separator()

    heading("Heuristic Scanner Findings")

    heuristic_findings = result.get("heuristic_findings", [])

    if not heuristic_findings:
        paragraph("No heuristic findings returned.")

    for finding in heuristic_findings:
        paragraph(
            f"{safe(finding.get('severity'))} - "
            f"{safe(finding.get('title'))} | "
            f"{safe(finding.get('file'))}:"
            f"{safe(finding.get('line'))}"
        )

    heading("Scanned Files")

    for filename in result.get("files_scanned", []):
        paragraph(f"- {filename}")

    # Page number and footer
    def add_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)

        canvas.drawString(
            20 * mm,
            12 * mm,
            "VulnAgent | Automated Security Assessment"
        )

        canvas.drawRightString(
            A4[0] - 20 * mm,
            12 * mm,
            f"Page {doc.page}"
        )

        canvas.restoreState()

    document = SimpleDocTemplate(
        str(destination),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=22 * mm,
        title="VulnAgent Security Assessment",
        author="VulnAgent"
    )

    document.build(
        story,
        onFirstPage=add_footer,
        onLaterPages=add_footer
    )
