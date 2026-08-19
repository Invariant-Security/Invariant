"""Turns a raw artifact into structured extracted items."""

import re
from dataclasses import dataclass
from pathlib import Path

from pypdf import PdfReader

_HEADER_RE = re.compile(
    r"^(?P<id>\d+(?:\.\d+){1,4})\s+(?P<title>.+?)\s*\((?P<scored>Scored|Not Scored)\)\s*$"
)

_SECTION_LABELS = (
    "Profile Applicability",
    "Description",
    "Rationale",
    "Audit",
    "Remediation",
    "Default Value",
    "References",
    "CIS Controls",
    "Impact",
)


@dataclass
class ExtractedRecommendation:
    """One CIS benchmark recommendation, extracted as-is from the PDF text.

    This is PRD's "extracted_items" stage -- raw structured text, not yet
    normalized into a Control (that's invariant.normalizer's job).
    """

    external_id: str
    title: str
    scored: bool
    profile_applicability: list[str]
    description: str
    rationale: str
    audit: str
    remediation: str


def extract_recommendation(pdf_path: Path, external_id: str) -> ExtractedRecommendation:
    """Extract one recommendation by its CIS id (e.g. "5.2.10") from a
    downloaded CIS benchmark PDF.

    Recommendations follow a consistent layout, confirmed by inspecting the
    real CIS Debian Linux 10 Benchmark v1.0.0 PDF: a header line
    "<id> <title> (Scored|Not Scored)" followed by labeled sections
    (Profile Applicability/Description/Rationale/Audit/Remediation/...),
    ending at the next recommendation's header.
    """
    lines = _pdf_lines(pdf_path)

    start, header = None, None
    for i, line in enumerate(lines):
        match = _HEADER_RE.match(line.strip())
        if match and match.group("id") == external_id:
            start, header = i, match
            break
    if start is None:
        raise LookupError(f"recommendation not found: {external_id!r}")

    end = len(lines)
    for i in range(start + 1, len(lines)):
        if _HEADER_RE.match(lines[i].strip()):
            end = i
            break

    sections = _split_sections(lines[start + 1 : end])

    return ExtractedRecommendation(
        external_id=header.group("id"),
        title=header.group("title"),
        scored=header.group("scored") == "Scored",
        profile_applicability=_non_empty_lines(sections.get("Profile Applicability", "")),
        description=sections.get("Description", "").strip(),
        rationale=sections.get("Rationale", "").strip(),
        audit=sections.get("Audit", "").strip(),
        remediation=sections.get("Remediation", "").strip(),
    )


def _pdf_lines(pdf_path: Path) -> list[str]:
    reader = PdfReader(pdf_path)
    full_text = "\n".join(page.extract_text() for page in reader.pages)
    return full_text.splitlines()


def _split_sections(lines: list[str]) -> dict[str, str]:
    boundaries = [
        (line.strip().rstrip(":"), i)
        for i, line in enumerate(lines)
        if line.strip().rstrip(":") in _SECTION_LABELS and line.strip().endswith(":")
    ]

    sections = {}
    for i, (label, line_no) in enumerate(boundaries):
        next_line_no = boundaries[i + 1][1] if i + 1 < len(boundaries) else len(lines)
        sections[label] = "\n".join(lines[line_no + 1 : next_line_no]).strip()
    return sections


def _non_empty_lines(text: str) -> list[str]:
    # CIS benchmark PDFs are Word exports that render bullet points using a
    # Wingdings-style glyph (private-use-area U+F0B7), not a real "-"/"*".
    return [
        line.strip().lstrip("").strip()
        for line in text.splitlines()
        if line.strip()
    ]
