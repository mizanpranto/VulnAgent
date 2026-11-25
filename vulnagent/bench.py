"""Benchmark runner: measures recall and precision against hand-written ground truth.

    python -m vulnagent.bench                      # deterministic stages only
    python -m vulnagent.bench --llm                # + AI triage with Ollama
    python -m vulnagent.bench --llm --discover --models qwen3:8b,llama3.1:8b

Targets live in benchmarks/targets/<name>/ with an expected.json. The
``flask_clean`` target has no expected issues: every active finding on it is a
false positive. Results are written to benchmarks/results/ as JSON.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from .pipeline import ScanOptions, run_scan

ROOT = Path(__file__).resolve().parent.parent
TARGETS = ROOT / "benchmarks" / "targets"


def load_truth(target: str) -> dict:
    path = TARGETS / target / "expected.json"
    if not path.exists():
        return {"items": [], "file": "app.py"}
    return json.loads(path.read_text(encoding="utf-8"))


def matches(finding, item, file_name: str) -> bool:
    """A finding matches a ground-truth item when one of its locations (primary or any ``affected`` entry point)
    lies in the item's line range and one of its CWEs (headline or the rule's list) is in the item's CWE set."""
    locations = [(finding.file, finding.line)] + [(a.get("file", ""), a.get("line", 0)) for a in (finding.affected or [])]
    cwes = {finding.cwe, *(finding.cwes or [])}
    return (any(f.endswith(file_name) and item["start"] <= ln <= item["end"] for f, ln in locations)
            and bool(cwes & set(item["cwes"])))


def evaluate(report, truth: dict) -> dict:
    items, file_name = truth.get("items", []), truth.get("file", "app.py")
    active, dismissed = report.active, report.dismissed
    found_ids, tp = set(), 0
    false_positives = []
    for finding in active:
        hit = [i for i in items if matches(finding, i, file_name)]
        if hit:
            tp += 1
            found_ids.update(i["id"] for i in hit)
        else:
            false_positives.append(f"{finding.file}:{finding.line} {finding.title}")
    bad_dismissals = [f"{f.file}:{f.line} {f.title}" for f in dismissed
                      if any(matches(f, i, file_name) for i in items)]
    good_dismissals = len(dismissed) - len(bad_dismissals)
    total = len(active)
    return {
        "items_total": len(items),
        "items_found": len(found_ids),
        "recall": round(len(found_ids) / len(items), 3) if items else None,
        "findings": total,
        "true_positive_findings": tp,
        "false_positives": len(false_positives),
        "precision": round(tp / total, 3) if items and total else (None if items else 0.0 if total else 1.0),
        "missed": [f"{i['id']} {i['title']}" for i in items if i["id"] not in found_ids],
        "false_positive_list": false_positives,
        "dismissed": len(dismissed),
        "good_dismissals": good_dismissals,
        "bad_dismissals": bad_dismissals,
    }


def run_target(target: str, options: ScanOptions, client=None) -> dict:
    started = time.time()
    report = run_scan(TARGETS / target, options, client=client)
    result = evaluate(report, load_truth(target))
    result.update(target=target, seconds=round(time.time() - started, 1), notes=report.notes,
                  rejected_ai_claims=len(report.meta.get("rejected_llm_claims", [])))
    return result


def _pct(value):
    return "n/a" if value is None else f"{value * 100:.0f}%"


def table(rows: list) -> str:
    lines = ["| Mode | Model | Recall (vuln app) | Precision (vuln app) | False positives on clean app | Time |",
             "|---|---|---|---|---|---|"]
    for row in rows:
        lines.append(f"| {row['mode']} | {row['model'] or '-'} | {_pct(row['vuln']['recall'])} "
                     f"({row['vuln']['items_found']}/{row['vuln']['items_total']}) | {_pct(row['vuln']['precision'])} "
                     f"({row['vuln']['true_positive_findings']}/{row['vuln']['findings']}) | "
                     f"{row['clean']['findings']} | {row['vuln']['seconds'] + row['clean']['seconds']:.0f} s |")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="vulnagent.bench")
    parser.add_argument("--llm", action="store_true", help="Also run AI triage via Ollama")
    parser.add_argument("--discover", action="store_true", help="Also run AI discovery (implies --llm)")
    parser.add_argument("--models", default="qwen3:8b", help="Comma separated Ollama models")
    parser.add_argument("--ollama-host", default=os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434"))
    parser.add_argument("--external", metavar="DIR", help="Score DIR against --truth instead of the bundled targets")
    parser.add_argument("--truth", metavar="JSON", help="Ground-truth file for --external")
    args = parser.parse_args(argv)

    if args.external:
        if not args.truth:
            parser.error("--external needs --truth")
        truth = json.loads(Path(args.truth).read_text(encoding="utf-8"))
        report = run_scan(Path(args.external), ScanOptions(use_llm=False))
        result = evaluate(report, truth)
        print(f"{truth.get('name', args.external)}: recall {_pct(result['recall'])} "
              f"({result['items_found']}/{result['items_total']}), precision {_pct(result['precision'])} "
              f"({result['true_positive_findings']}/{result['findings']})")
        for line in result["missed"]:
            print("  missed:", line)
        for line in result["false_positive_list"]:
            print("  false positive:", line)
        return 0

    rows = []
    base = ScanOptions(use_llm=False)
    rows.append({"mode": "static only", "model": None, "vuln": run_target("flask_vuln", base),
                 "clean": run_target("flask_clean", base)})
    if args.llm or args.discover:
        for model in [m.strip() for m in args.models.split(",") if m.strip()]:
            options = ScanOptions(use_llm=True, discover=args.discover, model=model, host=args.ollama_host)
            rows.append({"mode": "static + AI triage" + (" + discovery" if args.discover else ""), "model": model,
                         "vuln": run_target("flask_vuln", options), "clean": run_target("flask_clean", options)})

    print(table(rows))
    for row in rows:
        if row["vuln"]["missed"]:
            print(f"\nMissed in '{row['mode']}': " + "; ".join(row["vuln"]["missed"]))
        if row["vuln"]["bad_dismissals"]:
            print(f"\nWARNING: AI dismissed real findings: {row['vuln']['bad_dismissals']}")
    out_dir = ROOT / "benchmarks" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = out_dir / f"{stamp}.json"
    out.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"\nSaved {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
