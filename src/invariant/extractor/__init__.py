"""Turns a raw artifact into structured extracted items."""

import re
from dataclasses import dataclass
from pathlib import Path

from pypdf import PdfReader

# Matches the start of a recommendation id line, e.g. "5.2.10 Ensure SSH...".
# Deliberately loose -- long titles wrap across a line break in the PDF
# text, so the "(Scored)"/"(Not Scored)" suffix isn't required here; see
# _find_headers() for how a real header is confirmed.
_ID_RE = re.compile(r"^(?P<id>\d+(?:\.\d+){1,4})\s+(?P<rest>.+)$")

# Confirms a header actually ends here (possibly after merging wrapped
# lines), not mid-sentence.
_SCORED_SUFFIX_RE = re.compile(r"\((?P<scored>Scored|Not Scored)\)\s*$")

# The one section that reliably comes immediately after every real
# recommendation header -- also true of the CIS Debian Linux 10 Benchmark's
# table of contents and appendix checklist, EXCEPT that neither of those is
# followed by this exact line, which is what makes it a safe anchor to
# distinguish a real header from those two lookalikes.
_ANCHOR_SECTION = "Profile Applicability:"

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

# A title is allowed to wrap across this many extra lines before giving up
# on finding a "(Scored)"/"(Not Scored)" suffix -- real titles never wrap
# more than once in this document.
_MAX_TITLE_WRAP_LINES = 3


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
    """Extract one recommendation by its CIS id (e.g. "5.2.10")."""
    for recommendation in extract_all_recommendations(pdf_path):
        if recommendation.external_id == external_id:
            return recommendation
    raise LookupError(f"recommendation not found: {external_id!r}")


def extract_all_recommendations(pdf_path: Path) -> list[ExtractedRecommendation]:
    """Extract every recommendation in a downloaded CIS benchmark PDF.

    Recommendations follow a consistent layout, confirmed by inspecting the
    real CIS Debian Linux 10 Benchmark v1.0.0 PDF: a header
    "<id> <title> (Scored|Not Scored)" (occasionally wrapped across two
    lines when the title is long) immediately followed by
    "Profile Applicability:", then more labeled sections (Description/
    Rationale/Audit/Remediation/...), ending at the next header.

    The same id+title+"(Scored)" pattern also appears in the table of
    contents and in a checklist appendix at the end of the document --
    neither is followed by "Profile Applicability:", which is what this
    function uses to tell a real header apart from those two lookalikes.
    """
    lines = _pdf_lines(pdf_path)
    headers = _find_headers(lines)

    recommendations = []
    for i, header in enumerate(headers):
        body_start = header["body_start"]
        body_end = headers[i + 1]["line_start"] if i + 1 < len(headers) else len(lines)
        sections = _split_sections(lines[body_start:body_end])

        recommendations.append(
            ExtractedRecommendation(
                external_id=header["id"],
                title=header["title"],
                scored=header["scored"],
                profile_applicability=_non_empty_lines(sections.get("Profile Applicability", "")),
                description=sections.get("Description", "").strip(),
                rationale=sections.get("Rationale", "").strip(),
                audit=sections.get("Audit", "").strip(),
                remediation=sections.get("Remediation", "").strip(),
            )
        )
    return recommendations


def _find_headers(lines: list[str]) -> list[dict]:
    headers = []
    i = 0
    while i < len(lines):
        match = _ID_RE.match(lines[i].strip())
        if not match:
            i += 1
            continue

        merged_text = match.group("rest")
        scored_match = _SCORED_SUFFIX_RE.search(merged_text)
        end_line = i
        while not scored_match and end_line < i + _MAX_TITLE_WRAP_LINES and end_line + 1 < len(lines):
            end_line += 1
            merged_text += " " + lines[end_line].strip()
            scored_match = _SCORED_SUFFIX_RE.search(merged_text)

        if scored_match:
            anchor_line = _next_non_blank(lines, end_line + 1)
            if anchor_line is not None and lines[anchor_line].strip() == _ANCHOR_SECTION:
                title = merged_text[: scored_match.start()].strip()
                headers.append(
                    {
                        "id": match.group("id"),
                        "title": title,
                        "scored": scored_match.group("scored") == "Scored",
                        "line_start": i,
                        "body_start": end_line + 1,
                    }
                )
                i = end_line + 1
                continue

        i += 1

    return headers


def _next_non_blank(lines: list[str], start: int) -> int | None:
    for i in range(start, len(lines)):
        if lines[i].strip():
            return i
    return None


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
