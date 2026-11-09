from pathlib import Path


def safe(value):
    return str(value or "Not provided").replace("\n", " ").strip()


def write_markdown(result, destination):

    lines = [
        "# VulnAgent Security Assessment",
        "",
        f"**Project:** {safe(result.get('project'))}",
        f"**Model:** {safe(result.get('model'))}",
        f"**Files scanned:** {len(result.get('files_scanned', []))}",
        "",
        "> Automated analysis. Validate all findings manually.",
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

        lines.extend([
            f"### {index}. {safe(finding.get('title'))}",
            "",
            f"- **Severity:** {safe(finding.get('severity'))}",
            f"- **Confidence:** {safe(finding.get('confidence'))}",
            f"- **Location:** `{safe(finding.get('file'))}:{safe(finding.get('line'))}`",
            f"- **CWE:** {safe(finding.get('cwe'))}",
            "",
            "#### Evidence",
            "",
            "```text",
            safe(finding.get("evidence")),
            "```",
            "",
            "#### Source",
            safe(finding.get("source")),
            "",
            "#### Vulnerable Sink",
            safe(finding.get("sink")),
            "",
            "#### Data Flow",
            safe(finding.get("data_flow")),
            "",
            "#### Explanation",
            safe(finding.get("explanation")),
            "",
            "#### Attack Path"
        ])

        attack_path = finding.get("attack_path", [])

        if attack_path:
            for step, description in enumerate(attack_path, 1):
                lines.append(f"{step}. {description}")
        else:
            lines.append("Attack path not established.")

        lines.extend([
            "",
            "#### Potential Impact",
            safe(finding.get("impact")),
            "",
            "#### Recommended Fix",
            safe(finding.get("fix")),
            "",
            "#### Safer Example",
            "",
            "```text",
            safe(finding.get("safe_example")),
            "```",
            "",
            "#### Validation",
            safe(finding.get("validation")),
            "",
            "---",
            ""
        ])

    lines.extend([
        "## Heuristic Scanner Findings",
        ""
    ])

    for finding in result.get("heuristic_findings", []):

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

    destination = Path(destination)

    destination.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    destination.write_text(
        "\n".join(lines),
        encoding="utf-8"
    )