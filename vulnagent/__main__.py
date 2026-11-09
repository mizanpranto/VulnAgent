import argparse
import json
import os
from pathlib import Path

from .scanner import scan_project
from .ollama_client import analyze_with_ollama
from .report import write_markdown


def main():

    parser = argparse.ArgumentParser(
        prog="vulnagent",
        description="AI-powered source code security analyzer"
    )

    parser.add_argument(
        "project",
        help="Path to the Python or JavaScript project"
    )

    parser.add_argument(
        "--model",
        default="qwen3:8b",
        help="Ollama model name"
    )

    parser.add_argument(
        "--ollama-host",
        default=os.getenv(
            "OLLAMA_HOST",
            "http://127.0.0.1:11434"
        )
    )

    parser.add_argument(
        "--output",
        default="vulnagent-report.md"
    )

    parser.add_argument(
        "--max-files",
        type=int,
        default=150
    )

    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Run heuristic analysis without AI"
    )

    args = parser.parse_args()

    project = Path(
        args.project
    ).expanduser().resolve()

    if not project.is_dir():
        parser.error(
            f"Project directory does not exist: {project}"
        )

    print("\n====================================")
    print("       VULNAGENT SECURITY SCAN")
    print("====================================\n")

    print(f"[+] Target: {project}")

    # Stage 1: Source code collection

    print("\n[1/4] Scanning source code...")

    files, heuristic_findings = scan_project(
        project,
        max_files=args.max_files
    )

    print(f"[+] Files collected: {len(files)}")
    print(f"[+] Potential issues: {len(heuristic_findings)}")

    if not files:
        print("[!] No supported source files found.")
        return

    # Stage 2: AI security analysis

    llm_result = {
        "findings": [],
        "summary": "AI analysis disabled."
    }

    if args.no_llm:

        print("\n[2/4] AI analysis skipped.")

    else:

        print("\n[2/4] Running Qwen3 security analysis...")

        try:

            llm_result = analyze_with_ollama(
                files=files,
                heuristic_findings=heuristic_findings,
                model=args.model,
                host=args.ollama_host
            )

            print("[+] AI analysis completed.")

        except Exception as error:

            print(f"[!] AI analysis failed: {error}")
            print("[!] Continuing with heuristic results.")

            llm_result = {
                "findings": [],
                "summary": f"AI analysis unavailable: {error}"
            }

    # Stage 3: Prepare report

    print("\n[3/4] Preparing security report...")

    result = {
        "project": str(project),
        "model": None if args.no_llm else args.model,
        "summary": llm_result.get("summary", ""),
        "heuristic_findings": heuristic_findings,
        "ai_findings": llm_result.get("findings", []),
        "files_scanned": [
            item["path"] for item in files
        ]
    }

    output = Path(args.output)

    json_output = output.with_suffix(".json")

    json_output.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    json_output.write_text(
        json.dumps(result, indent=2),
        encoding="utf-8"
    )

    write_markdown(
        result,
        output
    )

    # Stage 4: Completion

    print("\n[4/4] Scan completed.")

    print("\n====================================")
    print("          SCAN RESULTS")
    print("====================================")

    print(f"Files scanned: {len(files)}")
    print(f"Heuristic findings: {len(heuristic_findings)}")
    print(f"AI findings: {len(llm_result.get('findings', []))}")

    print("\nReports generated:")

    print(f"[+] Markdown: {output.resolve()}")
    print(f"[+] JSON:     {json_output.resolve()}")

    print("\nVulnAgent scan finished.\n")


if __name__ == "__main__":
    main()