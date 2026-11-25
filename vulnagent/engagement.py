"""Who the assessment is for and who did it: the details printed on a report's cover page.

Everything here comes from the user, so it is length-capped and stripped of control
characters before use. A logo is re-encoded as a small PNG so no foreign image
metadata or oversized file reaches the report.
"""

from __future__ import annotations

import io
import re
from dataclasses import dataclass, field
from datetime import date
from typing import Optional

CLASSIFICATIONS = ("Confidential", "Internal", "Restricted", "Public")
MAX_FIELD = 120
DEFAULT_AGENT_AUTHOR = "Mizanur Rahman Pranto"
MAX_LOGO_BYTES = 1_000_000
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def clean(value, limit: int = MAX_FIELD) -> str:
    return _CONTROL.sub(" ", str(value or "")).strip()[:limit]


@dataclass
class Engagement:
    title: str = ""             # e.g. "Source Code Security Assessment"
    application: str = ""       # application / project under review (defaults to the scan's project name)
    client: str = ""            # who the report is prepared for
    assessor: str = ""          # person who ran / is accountable for the assessment
    company: str = ""           # assessor's company
    contact: str = ""           # assessor's email or phone
    reviewer: str = ""          # peer reviewer / approver
    agent_author: str = DEFAULT_AGENT_AUTHOR   # who built the assessment agent (credit line; set "" to hide)
    classification: str = "Confidential"
    version: str = "1.0"
    date: str = ""              # ISO date; today when empty
    logo_png: Optional[bytes] = field(default=None, repr=False)

    def resolved_date(self) -> str:
        return self.date or date.today().isoformat()

    def to_dict(self) -> dict:
        """JSON-safe view (no logo bytes)."""
        return {"title": self.title, "application": self.application, "client": self.client,
                "assessor": self.assessor, "company": self.company, "contact": self.contact,
                "reviewer": self.reviewer, "agent_author": self.agent_author,
                "classification": self.classification, "version": self.version,
                "date": self.resolved_date(), "has_logo": bool(self.logo_png)}


def from_mapping(raw, logo_png: Optional[bytes] = None) -> Engagement:
    """Build a sanitised Engagement from a form / dict / argparse values."""
    raw = raw or {}
    get = lambda key, limit=MAX_FIELD: clean(raw.get(key, ""), limit)  # noqa: E731
    classification = get("classification")
    if classification.title() not in CLASSIFICATIONS:
        classification = "Confidential"
    when = get("date", 10)
    try:
        when = date.fromisoformat(when).isoformat() if when else ""
    except ValueError:
        when = ""
    return Engagement(title=get("title"), application=get("application"), client=get("client"),
                      assessor=get("assessor"), company=get("company"), contact=get("contact"),
                      reviewer=get("reviewer"),
                      agent_author=get("agent_author") if "agent_author" in raw else DEFAULT_AGENT_AUTHOR,
                      classification=classification.title(), version=get("version", 20) or "1.0",
                      date=when, logo_png=logo_png)


def process_logo(data: bytes) -> bytes:
    """Validate an uploaded PNG/JPEG logo and return it re-encoded as a bounded PNG.

    Raises ValueError with a user-presentable message when it is not usable.
    """
    if not data:
        raise ValueError("The logo file is empty.")
    if len(data) > MAX_LOGO_BYTES:
        raise ValueError("The logo is larger than 1 MB.")
    if not (data.startswith(b"\x89PNG\r\n\x1a\n") or data.startswith(b"\xff\xd8\xff")):
        raise ValueError("The logo must be a PNG or JPEG image.")
    try:
        from PIL import Image
    except ImportError as error:  # pragma: no cover
        raise ValueError("Logo support needs Pillow: pip install pillow") from error
    Image.MAX_IMAGE_PIXELS = 20_000_000
    try:
        image = Image.open(io.BytesIO(data))
        image.load()
    except Exception as error:  # corrupt, truncated or too many pixels
        raise ValueError("The logo could not be read as an image.") from error
    image = image.convert("RGBA")
    image.thumbnail((600, 300))
    out = io.BytesIO()
    image.save(out, "PNG")
    return out.getvalue()
