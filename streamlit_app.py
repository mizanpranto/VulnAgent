"""VulnAgent as a Streamlit app.

    pip install -r requirements.txt streamlit
    streamlit run streamlit_app.py

It uses the same scanner, safe zip extraction and report builders as the Flask web app
(`python -m vulnagent serve`). Uploaded source is extracted into a temporary folder,
only parsed (never executed), and deleted as soon as the scan ends.
"""

from __future__ import annotations

import io
import json
import shutil
import tempfile
from datetime import date
from pathlib import Path

import streamlit as st

from vulnagent import __version__
from vulnagent.engagement import CLASSIFICATIONS, DEFAULT_AGENT_AUTHOR, from_mapping
from vulnagent.ollama_client import OllamaClient
from vulnagent.pipeline import ScanOptions, run_scan
from vulnagent.report import render_markdown, to_sarif
from vulnagent.safe_zip import UnsafeArchive, safe_extract

MAX_UPLOAD_MB = 50
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}

st.set_page_config(page_title="VulnAgent", page_icon="🛡️", layout="wide")


def _scan(upload, options: ScanOptions, engagement, progress_bar, status):
    workdir = Path(tempfile.mkdtemp(prefix="vulnagent-st-"))
    try:
        archive = workdir / "upload.zip"
        archive.write_bytes(upload.getvalue())
        source = workdir / "src"
        safe_extract(archive, source)
        archive.unlink(missing_ok=True)

        def progress(stage, done, total, message):
            status.write(f"{stage}: {message}" if message else stage)
            progress_bar.progress(min(1.0, done / max(total, 1)))

        client = OllamaClient(options.host, options.model, num_ctx=options.num_ctx) if options.use_llm else None
        return run_scan(source, options, client=client, progress=progress,
                        project_name=Path(upload.name).stem, engagement=engagement)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)   # source never outlives the scan


def _downloads(report, name: str):
    from vulnagent.docx_report import build_docx
    from vulnagent.pdf_report import build_pdf

    pdf, docx = io.BytesIO(), io.BytesIO()
    build_pdf(report, pdf)
    build_docx(report, docx)
    cols = st.columns(5)
    cols[0].download_button("PDF report", pdf.getvalue(), f"vulnagent-{name}.pdf", "application/pdf")
    cols[1].download_button("Word report", docx.getvalue(), f"vulnagent-{name}.docx",
                            "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    cols[2].download_button("JSON", json.dumps(report.to_dict(), indent=2), f"vulnagent-{name}.json",
                            "application/json")
    cols[3].download_button("SARIF", json.dumps(to_sarif(report), indent=2), f"vulnagent-{name}.sarif",
                            "application/sarif+json")
    cols[4].download_button("Markdown", render_markdown(report), f"vulnagent-{name}.md", "text/markdown")


def _show(report):
    stats = report.stats
    st.subheader(report.project)
    counts = stats["severity"]
    cols = st.columns(5)
    for col, sev in zip(cols, SEVERITY_ORDER):
        col.metric(f"{SEVERITY_ICON[sev]} {sev.title()}", counts.get(sev, 0))

    left, right = st.columns(2)
    with left:
        st.markdown("**OWASP Top 10:2025 categories**")
        rows = stats.get("owasp", [])
        st.table([{"Category": f"{r['id']} {r['name']}", "Findings": r["count"]} for r in rows] or
                 [{"Category": "none", "Findings": 0}])
    with right:
        st.markdown("**Most common weakness types**")
        rows = stats.get("by_cwe", [])[:8]
        st.table([{"CWE": f"CWE-{r['cwe']} {r['name']}", "Findings": r["count"]} for r in rows] or
                 [{"CWE": "none", "Findings": 0}])

    st.markdown("### Findings")
    active = sorted(report.active, key=lambda f: SEVERITY_ORDER.index(f.severity)
                    if f.severity in SEVERITY_ORDER else 9)
    for f in active:
        cwe = f"CWE-{f.cwe}" if f.cwe else "no CWE"
        with st.expander(f"{SEVERITY_ICON.get(f.severity, '')} {f.severity.upper()} · {f.title} · {f.file}:{f.line}"):
            st.write(f"**Weakness:** {cwe} · **Confidence:** {f.confidence}")
            if f.evidence:
                st.code(f.evidence)
            if f.explanation:
                st.write(f"**Why it matters:** {f.explanation}")
            if f.fix:
                st.write(f"**Fix:** {f.fix}")
            if f.status and f.status != "confirmed":
                st.caption(f"Status: {f.status} (needs human review)")
    if report.dismissed:
        with st.expander(f"Dismissed by AI review ({len(report.dismissed)}), shown with reasons"):
            for f in report.dismissed:
                reason = (f.triage or {}).get("reason", "")
                st.write(f"- {f.title} · {f.file}:{f.line}. {reason}")
    for note in report.notes:
        st.info(note)


st.title("🛡️ VulnAgent")
st.caption(f"A local code-security scanner that shows its evidence · v{__version__}")
st.warning("Output is an **automated** result and has not been manually validated. It supports a qualified "
           "reviewer and does not replace one.", icon="⚠️")

with st.sidebar:
    st.header("Scan options")
    use_ai = st.checkbox("AI review (needs a local Ollama server)", value=False)
    discover = st.checkbox("AI discovery of extra issues", value=False, disabled=not use_ai)
    deps = st.checkbox("Check pinned dependencies (sends package names and versions to OSV)", value=False)
    model = st.text_input("Ollama model", "qwen3:8b", disabled=not use_ai)
    st.header("Report cover (optional)")
    assessor = st.text_input("Assessed by")
    company = st.text_input("Company")
    client_name = st.text_input("Prepared for (client)")
    application = st.text_input("Application name")
    classification = st.selectbox("Classification", list(CLASSIFICATIONS))
    st.text_input("Agent developed by", DEFAULT_AGENT_AUTHOR, disabled=True)

upload = st.file_uploader(f"Upload a project as a .zip (up to {MAX_UPLOAD_MB} MB)", type=["zip"])
if upload is not None and upload.size > MAX_UPLOAD_MB * 1024 * 1024:
    st.error(f"That file is larger than {MAX_UPLOAD_MB} MB.")
    upload = None

if st.button("Scan", type="primary", disabled=upload is None):
    engagement = from_mapping({"assessor": assessor, "company": company, "client": client_name,
                               "application": application or Path(upload.name).stem,
                               "classification": classification, "agent_author": DEFAULT_AGENT_AUTHOR,
                               "date": date.today().isoformat(), "version": "1.0"})
    options = ScanOptions(use_llm=use_ai, discover=discover and use_ai, deps=deps, model=model,
                          max_files=300, max_triage=30, max_discovery_chunks=25)
    bar, status = st.progress(0.0), st.empty()
    try:
        st.session_state["report"] = _scan(upload, options, engagement, bar, status)
        status.write("Finished. Your uploaded source has already been deleted.")
    except UnsafeArchive as error:
        st.session_state.pop("report", None)
        st.error(str(error))
    except Exception:                                    # keep the page alive, never show a raw traceback
        st.session_state.pop("report", None)
        st.error("The scan failed unexpectedly. Check the terminal where Streamlit is running.")
        raise

report = st.session_state.get("report")
if report is not None:
    _show(report)
    st.markdown("### Download")
    _downloads(report, report.project)
