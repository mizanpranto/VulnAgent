# Contributing to VulnAgent

VulnAgent is early and everyone is welcome to help. Small, focused pull requests are easiest to review.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-a01.txt pytest
python -m pytest -q
python -m vulnagent.bench        # static-only benchmark on the bundled apps
```

## Ground rules

- **Measure, don't claim.** If you change a detector, run the tests and the benchmark and put before/after numbers in the pull request. The bundled apps were used to develop the detectors, so also say what you checked on code the rule has never seen.
- **A rule that fires on its safe fixture is a bug.** Add one vulnerable and one safe fixture with every rule or extractor change.
- **No hard-coding.** Nothing may depend on a specific app, repo, route name or folder layout.
- **CWE, OWASP category and severity come from the registry** (`vulnagent/a01/rules.json`, `vulnagent/standards.py`), never from an extractor or the model.
- **The model labels; it never deletes.** Keep evidence grounding, the "Critical is never auto-dismissed" rule and prompt-injection handling intact.
- Absence-based findings must never be reported as "confirmed".

## Where things live

| Area | Path |
|---|---|
| Rules registry (declarative) | `vulnagent/a01/rules.json`, `registry.py`; docs in `docs/RULES.md` (regenerate it when you change a rule) |
| Entry-point / guard model | `vulnagent/a01/ir.py` |
| Language extractors | `vulnagent/a01/extractors/` (`py.py`, `js.py` are complete; `java.py`, `csharp.py` partial; `stubs.py` skeletons) |
| Rule logic and severity | `vulnagent/a01/engine.py` |
| Structured LLM review | `vulnagent/a01/llm_review.py` |
| Reports | `vulnagent/reportdoc.py` (shared content), `pdf_report.py`, `docx_report.py`, `report.py` |

## Taking an OWASP category

The Top 10:2025 categories are being added one by one (see the roadmap in the README). To take one, open an issue first so work is not duplicated, then use `vulnagent/a01/` as the template: a registry of rules (`rules.json`), a language-neutral model, per-language extractors, a vulnerable and a safe fixture for every rule, and a generated `docs/RULES.md` section. Do not mark a category done until it has been run on code the rules have never seen.

## Where help is most welcome

- A Rails, Laravel, Gin or Echo extractor (start from `extractors/stubs.py`).
- Per-rule vulnerable/safe fixtures for the rules listed in `docs/RULES.md` under known gaps.
- Ground-truth labels for a third-party vulnerable app, and a run of the benchmark against it.
- False positives and false negatives from real projects, as minimal reproductions.

## Reporting security issues in VulnAgent itself

Please open a private security advisory on GitHub rather than a public issue.
