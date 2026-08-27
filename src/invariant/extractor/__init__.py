"""Turns a raw artifact into structured extracted items."""

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from pypdf import PdfReader

# Matches the start of a recommendation id line, e.g. "5.2.10 Ensure SSH...".
# Deliberately loose -- long titles wrap across a line break in the PDF
# text, so the scored/automated suffix isn't required here; see
# _find_headers() for how a real header is confirmed.
_ID_RE = re.compile(r"^(?P<id>\d+(?:\.\d+){1,4})\s+(?P<rest>.+)$")

# Confirms a header actually ends here (possibly after merging wrapped
# lines), not mid-sentence. CIS renamed "Scored"/"Not Scored" to
# "Automated"/"Manual" starting with some newer benchmark versions
# (confirmed: CIS Debian Linux 10 v1.0.0 uses "Scored", v2.0.0 uses
# "Automated" -- same underlying concept, different wording) -- both
# vocabularies show up depending on which document this is.
_SCORED_SUFFIX_RE = re.compile(r"\((?P<scored>Scored|Not Scored|Automated|Manual)\)\s*$")
_SCORED_TERMS = {"Scored", "Automated"}

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

# Matches a label anywhere in the text, not just at the start of a line --
# see _split_sections() for why. Sorted longest-first so a multi-word label
# never loses to a shorter one that happens to be a prefix of it.
_SECTION_LABEL_RE = re.compile(
    r"(?:(?<=\s)|^)(?P<label>"
    + "|".join(re.escape(label) for label in sorted(_SECTION_LABELS, key=len, reverse=True))
    + r"):\s*"
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
    # 1-based PDF page numbers this recommendation's header-through-body text
    # was found on (PRD sec. 47, the reproducibility invariant: every
    # extracted field must be traceable to an exact page range of the raw
    # artifact identified by its SHA-256). 0 means "not set" -- only real
    # extraction via extract_all_recommendations() fills these in; hand-built
    # ExtractedRecommendation instances in tests don't need to care.
    source_page_start: int = 0
    source_page_end: int = 0


class ExtractionError(Exception):
    """Raised when a document's extraction fails the fail-closed contract
    (PRD sec. 47, the reproducibility invariant; codexplan.md Fase 2): never
    persist a result that looks like success but silently dropped or
    misidentified content. Callers must not catch this to fall back to a
    partial/best-effort persist -- the document should just fail, visibly.
    """


@dataclass
class ExtractionWarning:
    """A non-fatal data-quality note about one recommendation -- reported,
    never silently dropped, but doesn't fail the document."""

    external_id: str
    field: str
    detail: str


@dataclass
class ExtractionResult:
    recommendations: list[ExtractedRecommendation]
    warnings: list[ExtractionWarning]


# Empty in 0 of 235-389 recommendations across all 18 real CIS Debian/Ubuntu
# PDFs characterized so far (see docs/decisions/cis-parser-characterization.md
# and docs/cis_characterization_report.json) -- treated as a hard failure,
# not normalized away, per codexplan.md Fase 2's required-field list.
_HARD_REQUIRED_FIELDS = ("external_id", "title", "description", "audit", "remediation")

# Legitimately empty in a handful of items in real, newer-vocabulary CIS
# documents (same characterization report) -- a data fact about the source,
# not an extraction bug, so it's a warning, not a failure.
_SOFT_REQUIRED_FIELDS = ("rationale",)


def extract_and_validate(pdf_path: Path) -> ExtractionResult:
    """extract_all_recommendations() plus the fail-closed contract.

    Raises ExtractionError when:
    - no recommendations were found at all (also covers "format could not be
      identified" -- if the header/anchor pattern never matches, this is
      exactly what happens);
    - any external_id is duplicated;
    - any hard-required field is empty for some recommendation.

    Does not check for a count regression against a previous document
    version -- that requires document history, which lives in the database,
    not here (see invariant.cli.extract for that check).
    """
    recommendations = extract_all_recommendations(pdf_path)

    if not recommendations:
        raise ExtractionError(f"no recommendations found in {pdf_path}")

    ids = Counter(r.external_id for r in recommendations)
    duplicates = sorted(external_id for external_id, count in ids.items() if count > 1)
    if duplicates:
        raise ExtractionError(f"duplicate external_id(s) in {pdf_path}: {duplicates}")

    warnings = []
    for rec in recommendations:
        for field in _HARD_REQUIRED_FIELDS:
            if not getattr(rec, field):
                raise ExtractionError(
                    f"{pdf_path}: recommendation {rec.external_id!r} has empty "
                    f"required field {field!r}"
                )
        for field in _SOFT_REQUIRED_FIELDS:
            if not getattr(rec, field):
                warnings.append(ExtractionWarning(rec.external_id, field, "empty"))

    return ExtractionResult(recommendations=recommendations, warnings=warnings)


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

    Page provenance (codexplan.md Fase 3): a recommendation whose body is
    split across pages is still reconstructed as one recommendation (header
    detection and section splitting both just walk the flat `lines` list,
    same as before page tracking existed) -- what's new is that
    source_page_start/source_page_end record the real page range that
    reconstruction pulled from, via `line_pages` (parallel to `lines`).
    """
    lines, line_pages = _pdf_lines(pdf_path)
    headers = _find_headers(lines)

    recommendations = []
    for i, header in enumerate(headers):
        body_start = header["body_start"]
        body_end = headers[i + 1]["line_start"] if i + 1 < len(headers) else len(lines)
        sections = _split_sections(lines[body_start:body_end])
        end_line_index = (body_end - 1) if body_end > body_start else header["line_start"]

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
                source_page_start=line_pages[header["line_start"]],
                source_page_end=line_pages[end_line_index],
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
                        "scored": scored_match.group("scored") in _SCORED_TERMS,
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


def _pdf_lines(pdf_path: Path) -> tuple[list[str], list[int]]:
    """Returns (lines, line_pages): line_pages[i] is the 1-based PDF page
    lines[i] came from. Reads page by page (not one joined blob) specifically
    so that per-line page of origin is never lost -- see Fase 3 provenance
    note on extract_all_recommendations().
    """
    reader = PdfReader(pdf_path)
    lines: list[str] = []
    line_pages: list[int] = []
    for page_number, page in enumerate(reader.pages, start=1):
        page_lines = page.extract_text().splitlines()
        lines.extend(page_lines)
        line_pages.extend([page_number] * len(page_lines))
    return lines, line_pages


def _split_sections(lines: list[str]) -> dict[str, str]:
    # Section labels are normally on their own line, but some older CIS
    # PDFs run a label straight into the end of the previous sentence with
    # no line break (confirmed: CIS Ubuntu 12.04 LTS Server Benchmark
    # v1.1.0, section 3.1 -- "...changing the file. Audit:  Perform the
    # following..."). Matching by position in the joined text (not by
    # whole-line equality) handles both cases the same way.
    text = "\n".join(lines)
    matches = list(_SECTION_LABEL_RE.finditer(text))

    sections = {}
    for i, match in enumerate(matches):
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        sections[match.group("label")] = text[start:end].strip()
    return sections


def _non_empty_lines(text: str) -> list[str]:
    # CIS benchmark PDFs are Word exports that render bullet points as
    # either a Wingdings-style glyph (private-use-area U+F0B7, older
    # documents) or a real bullet character (U+2022, newer documents) --
    # never a plain "-"/"*".
    return [
        line.strip().lstrip("\uf0b7\u2022").strip()
        for line in text.splitlines()
        if line.strip()
    ]
