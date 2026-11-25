# Roadmap: OWASP Top 10:2025, one category at a time

This file records what VulnAgent v2.1.0 covers for each OWASP Top 10:2025 category, what is missing, and the order I plan to build it in. It comes from reading the detectors (`scanner.py`, `taint.py`, `deps.py`, `a01/`), not from a benchmark, so "covered" means "a rule exists", not "it works well on real code". Effort sizes (S, M, L) are my own estimates.

## What exists today

| Category | Rules that exist today (CWE) | Status |
|---|---|---|
| **A01** Broken Access Control | 16 registry rules in `a01/rules.json` (authn/authz, IDOR, CSRF, CORS, path traversal, SSRF, open redirect, data exposure, insecure defaults, token/session). Python and JS/TS complete, Java and C# partial | **Dedicated layer** (in progress) |
| **A02** Security Misconfiguration | Flask debug mode (489); CORS (942, filed under A01 by the rule) | Partial |
| **A03** Software Supply Chain Failures | OSV lookup for `name==version` pins in `requirements*.txt` and `package-lock.json` (opt-in `--deps`) | Partial |
| **A04** Cryptographic Failures | Weak hash MD5/SHA-1 (327), predictable random for tokens (338) | Partial |
| **A05** Injection | SQL (89), OS command (78), eval (95), template injection (1336), XSS (79) in Python taint analysis; regex rules for JS/TS | Partial |
| **A06** Insecure Design | Unrestricted file upload (434) | Barely started |
| **A07** Authentication Failures | Hard-coded credentials (798); JWT without verification | Partial |
| **A08** Software or Data Integrity Failures | Unsafe deserialization: `pickle`, `yaml.load` (502) | Partial |
| **A09** Security Logging and Alerting Failures | Sensitive data written to logs (532), Python only | Barely started |
| **A10** Mishandling of Exceptional Conditions | Fail-open guards (in A01 rule `A01-GUARD-FAIL-OPEN`) | Barely started |

## Gaps that affect every category

These come first because each category depends on them.

1. **Rules live in two places.** A01 rules are declarative in `a01/rules.json`, but the older rules have their CWE, severity and text written inline in `scanner.py` and `taint.py`. That breaks the project's own rule ("CWE, category and severity come from one registry"). Move them into the registry before adding new ones. (M)
2. **Only code files are read.** `scanner.py` reads `.py`, `.js`, `.jsx`, `.ts`, `.tsx`. Config and infrastructure files (`.env`, YAML, JSON, `Dockerfile`, CI workflows, HTML templates, `settings.py`) are not scanned, and A02, A03 and A08 live mostly there. (M)
3. **Taint analysis is Python-only and within one function.** JS/TS injection uses regexes. There is no cross-function flow. Java, C#, PHP, Go and Ruby have no injection rules at all. (L)
4. **No per-rule fixtures.** A01 still lacks them, and the older rules were only tested through the `flask_vuln` app that they were developed against. Each rule needs one vulnerable and one safe fixture, run automatically. (M)
5. **No held-out benchmark.** Only one third-party app is labelled. Without more, nothing can honestly be called "done". (M, ongoing)

## What is missing, by category

**A01.** Finish what is in the README: per-rule fixtures, Java and C# completion, benchmark on Juice Shop, NodeGoat, DVNA, WebGoat, DVWA, VAmPI and django.nV. Then PHP, Go and Ruby extractors.

**A02 Security Misconfiguration.** XXE (611), missing cookie flags `Secure`/`HttpOnly`/`SameSite` (614, 1004), Django `DEBUG`, `SECRET_KEY` and `ALLOWED_HOSTS`, missing security headers, verbose error pages, default credentials, directory listing, exposed admin or actuator endpoints, permissive Docker and CI settings. Needs gap 2. (M)

**A03 Supply Chain.** Only exact pins are checked. Missing: unpinned or range versions, `Pipfile.lock`, `poetry.lock`, `yarn.lock`, `pnpm-lock.yaml`, `pom.xml`, `go.mod`; missing lockfile; typosquat-looking names; unpinned GitHub Actions; install scripts; `curl | sh` in build files. Needs gap 2. (M)

**A04 Cryptographic Failures.** Weak ciphers and modes (DES, RC4, ECB), hard-coded keys and IVs, fast hashes for passwords, short RSA or key sizes, `http://` for sensitive calls, static or reused nonces, disabled certificate checks outside `verify=False`, JS equivalents. Pattern-based, so precise and quick. (S)

**A05 Injection.** Real JS/TS taint tracking, NoSQL (Mongo operators), LDAP, XPath, header or CRLF injection, ORM raw queries, prototype pollution, SSTI in more engines, XSS in templates, and the non-Python server languages. Biggest category. (L)

**A06 Insecure Design.** Mostly needs a threat model, which a scanner cannot invent. What static analysis can do: missing rate limits on login, signup, password reset and OTP routes (reusing the A01 entry-point model), trust-boundary violations (501), time-of-check/time-of-use races (362), upload handling beyond 434, missing business-limit checks. Report these as design smells needing review, never "confirmed". (L)

**A07 Authentication Failures.** Weak password hashing (259, 916), no lockout or throttling on login (307), session fixation (384), sessions not rotated or invalidated, predictable reset tokens, default or hard-coded users, missing MFA hooks, JWT mistakes beyond the A01 token rule. Reuse the A01 entry-point model. (M)

**A08 Integrity Failures.** Deserialization in JS and non-Python languages (`ObjectInputStream`, `unserialize`, `Marshal.load`), missing Subresource Integrity on CDN scripts in HTML, unsigned or unverified downloads in build files, CI that runs untrusted input, auto-update without signature checks. Needs gap 2. (M)

**A09 Logging and Alerting Failures.** Login failures, access denials and admin actions with no logging (an absence-based rule on top of the A01 model), log injection (117), sensitive data in logs beyond Python (532), no alerting hooks, logging disabled. (M)

**A10 Mishandling of Exceptional Conditions.** New in 2025 and wholly unbuilt: bare `except` and `except Exception: pass` (390, 703), swallowed errors in auth or payment paths, fail-open on exception (636), stack traces or internals sent to the client (209), unchecked return values and null dereference (252, 476), resources not released on error paths, missing global error handler. Python AST makes this straightforward. (M)

## Recommended order

Easiest and most precise first, so each finished category adds credibility and teaches the process for the next one.

0. **Foundation:** gaps 1, 2, 4 and the fixture harness. No new category should start before this.
1. **A01:** finish it (fixtures, benchmark, Java/C#). It is the template.
2. **A04 Cryptographic Failures:** small, pattern-based, high precision.
3. **A10 Mishandling of Exceptional Conditions:** new category, Python AST, very few tools cover it.
4. **A05 Injection:** build on the existing taint engine; JS taint is the big piece.
5. **A02 Security Misconfiguration:** needs config-file scanning from the foundation.
6. **A07 Authentication Failures:** reuses the A01 entry-point model.
7. **A08 Integrity Failures:** reuses config-file scanning.
8. **A03 Supply Chain:** more manifests and CI files.
9. **A09 Logging and Alerting:** absence-based rules on the A01 model.
10. **A06 Insecure Design:** last, because it needs the most human judgement.

This order is my judgement and open to change. It is fine to take a category out of order if a contributor wants it.

## The same steps for every category

1. **Open an issue** naming the category so nobody duplicates it.
2. **List the CWEs** you will cover from the official OWASP 2025 list in `vulnagent/standards.py`.
3. **Write the rules in the registry** (CWE, severity, text, fix example). Never hard-code them in an extractor or the model.
4. **Add a vulnerable and a safe fixture for every rule.** A rule that fires on its safe fixture is a bug.
5. **Mark absence-based findings** as such; they are never "confirmed".
6. **Regenerate `docs/RULES.md`.**
7. **Run on code the rules have never seen** (a third-party vulnerable app and a clean app) and put before/after numbers in the pull request.
8. **Only then** change the README status to Done, with the measured numbers next to it.

## Definition of done for a category

- Every rule is in the registry with both fixtures and they pass in CI.
- The category is documented in `docs/RULES.md`.
- Recall and precision are recorded on at least one third-party app and one clean app, and the README says which.
- Known gaps for the category are listed in the README under Known limits.
