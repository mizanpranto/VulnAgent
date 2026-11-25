"""Industry-standard tags for findings: OWASP Top 10:2025 and the CWE Top 25 (2025).

Mappings are copied from the official sources (OWASP "List of Mapped CWEs" per
category; MITRE's 2025 CWE Top 25 ranking). When a source list is revised, update
the data below and the year labels. Findings whose CWE is not on a list simply get
no tag for that list; nothing is guessed, except the explicit INFERRED entries.
"""

from __future__ import annotations

OWASP_YEAR = 2025
TOP25_YEAR = 2025

OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

_OWASP_CWES = {
    "A01": [22, 23, 36, 59, 61, 65, 200, 201, 219, 276, 281, 282, 283, 284, 285, 352, 359, 377, 379, 402, 424, 425,
            441, 497, 538, 540, 548, 552, 566, 601, 615, 639, 668, 732, 749, 862, 863, 918, 922, 1275],
    "A02": [5, 11, 13, 15, 16, 260, 315, 489, 526, 547, 611, 614, 776, 942, 1004, 1174],
    "A03": [447, 1035, 1104, 1329, 1357, 1395],
    "A04": [261, 296, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 334, 335, 336, 337, 338,
            340, 342, 347, 523, 757, 759, 760, 780, 916, 1240, 1241],
    "A05": [20, 74, 76, 77, 78, 79, 80, 83, 86, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 103, 104, 112, 113, 114,
            115, 116, 129, 159, 470, 493, 500, 564, 610, 643, 644, 917],
    "A06": [73, 183, 256, 266, 269, 286, 311, 312, 313, 316, 362, 382, 419, 434, 436, 444, 451, 454, 472, 501, 522,
            525, 539, 598, 602, 628, 642, 646, 653, 656, 657, 676, 693, 799, 807, 841, 1021, 1022, 1125],
    "A07": [258, 259, 287, 288, 289, 290, 291, 293, 294, 295, 297, 298, 299, 300, 302, 303, 304, 305, 306, 307, 308,
            309, 346, 350, 384, 521, 613, 620, 640, 798, 940, 941, 1390, 1391, 1392, 1393],
    "A08": [345, 353, 426, 427, 494, 502, 506, 509, 565, 784, 829, 830, 915, 926],
    "A09": [117, 221, 223, 532, 778],
    "A10": [209, 215, 234, 235, 248, 252, 274, 280, 369, 390, 391, 394, 396, 397, 460, 476, 478, 484, 550, 636, 703,
            754, 755, 756],
}

# CWEs the official lists do not name but that are plain specialisations of a listed one.
# Reported with "inferred" so nobody mistakes them for the official mapping.
INFERRED_OWASP = {
    1336: "A05",   # template-engine injection: a form of injection (CWE-74 family)
    1333: None,    # ReDoS (CWE-400 family): no OWASP 2025 category lists it
}

# MITRE 2025 CWE Top 25, rank by CWE id.
TOP25_RANK = {79: 1, 89: 2, 352: 3, 862: 4, 787: 5, 22: 6, 416: 7, 125: 8, 78: 9, 94: 10, 120: 11, 434: 12,
              476: 13, 121: 14, 502: 15, 122: 16, 863: 17, 20: 18, 284: 19, 200: 20, 306: 21, 918: 22, 77: 23,
              639: 24, 770: 25}

_BY_CWE: dict = {}
for _cat, _cwes in _OWASP_CWES.items():
    for _cwe in _cwes:
        _BY_CWE.setdefault(_cwe, []).append(_cat)


def owasp_categories(cwe) -> list:
    """Official OWASP Top 10:2025 category ids for a CWE (possibly several, possibly none)."""
    return list(_BY_CWE.get(cwe, []))


def owasp_inferred(cwe):
    return INFERRED_OWASP.get(cwe) if cwe not in _BY_CWE else None


def top25_rank(cwe):
    return TOP25_RANK.get(cwe)


def tags_for(cwe) -> dict:
    """Everything the reports need for one CWE."""
    official = owasp_categories(cwe)
    inferred = owasp_inferred(cwe)
    return {
        "owasp": [f"A{c[1:]}:{OWASP_YEAR} {OWASP_CATEGORIES[c]}" for c in official]
                 + ([f"{inferred}:{OWASP_YEAR} {OWASP_CATEGORIES[inferred]} (inferred)"] if inferred else []),
        "owasp_ids": official + ([inferred] if inferred else []),
        "cwe_top25_rank": top25_rank(cwe),
    }


def label(cwe) -> str:
    """One-line human label, '' when the CWE is on neither list."""
    tags = tags_for(cwe)
    parts = []
    if tags["owasp"]:
        parts.append("OWASP Top 10 " + " / ".join(tags["owasp"]))
    if tags["cwe_top25_rank"]:
        parts.append(f"CWE Top 25 ({TOP25_YEAR}) #{tags['cwe_top25_rank']}")
    return "  ·  ".join(parts)
