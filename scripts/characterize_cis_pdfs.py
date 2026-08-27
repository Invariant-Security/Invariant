"""Fase 1 of the CIS parser validation plan: catalog every Debian/Ubuntu CIS
PDF under data/raw/cis/ against the extractor, with no inferences hidden --
every number in the report either came straight out of the PDF/extractor or
is explicitly labeled as a heuristic proxy.

Read-only: never writes to the database, never touches the extractor, never
modifies a PDF. Only reads data/raw/cis/**/*.pdf.

Reuses extractor._pdf_lines()/_find_headers()/_split_sections() directly
(same private-function reuse tests/extractor/test_header_parsing.py already
does) instead of calling the public extract_all_recommendations() *and*
extracting the full text separately -- text extraction is the expensive
part (~30s for the biggest PDF here), and doing it twice per document
pushed the full 18-PDF run past this environment's background-command time
budget. One extraction pass per document, full stop.

Run: .venv/bin/python scripts/characterize_cis_pdfs.py
Writes: docs/cis_characterization_report.json (+ prints a summary table)
"""

import json
import re
import resource
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from pypdf import PdfReader

from invariant.extractor import ExtractedRecommendation, _find_headers, _non_empty_lines, _pdf_lines, _split_sections

REPO_ROOT = Path(__file__).resolve().parents[1]
CIS_RAW_DIR = REPO_ROOT / "data" / "raw" / "cis"
REPORT_PATH = REPO_ROOT / "docs" / "cis_characterization_report.json"

# Filename shape written by collector.save_raw_artifact(): cis_<slug>_<version>_<hash12>.ext
# The version token is the only underscore-separated segment containing a dot
# (OS version numbers in the slug, e.g. "20", "04", "12", never do) -- see
# codexplan.md Fase 1 step 1. This is filename-derived labeling only, used
# for the report's grouping/display columns; it is NOT assumed to match the
# `document` field recorded in a JSON sidecar (see KNOWN DISCREPANCY note in
# the report footer -- some older artifacts' filenames and sidecar
# `document` values disagree on whether the slug includes "linux").
_VERSION_TOKEN_RE = re.compile(r"^\d+(?:\.\d+)+$")

# Required fields for characterization purposes (Fase 2 hasn't defined the
# real fail-closed contract yet -- this is just what Fase 1 checks for
# emptiness, per codexplan.md's list). `rationale` is tracked but not
# counted as a required-field gap, since the plan notes it's legitimately
# empty in some real documents.
_REQUIRED_FIELDS = ("external_id", "title", "description", "audit", "remediation")

# Ground truth pulled from tests/extractor/test_extractor.py, the one
# human-verified count in this repo (not derived from this script or the
# extractor itself) -- genuinely independent evidence for exactly this one
# document/version.
_KNOWN_GOOD_COUNTS = {
    ("debian_linux_10", "1.0.0"): 235,
}


@dataclass
class DocumentCharacterization:
    filename: str
    path: str
    family: str  # "debian" | "ubuntu", from the parent directory
    slug: str  # filename-derived, see _VERSION_TOKEN_RE comment
    version: str
    is_stig: bool
    page_count: int
    scoring_vocabulary: list[str]  # which of Scored/Not Scored/Automated/Manual appear in raw text
    recommendation_count: int
    duplicate_ids: list[str]
    empty_required_field_ids: dict[str, list[str]]  # field -> [external_id, ...]
    empty_rationale_ids: list[str]
    elapsed_seconds: float
    peak_rss_delta_mb: float
    independent_count_source: str | None  # what, if anything, corroborates recommendation_count
    independent_count_value: int | None
    error: str | None = None


def _parse_filename(pdf_path: Path) -> tuple[str, str]:
    """Split a collector-written filename into (slug, version)."""
    stem = pdf_path.stem  # cis_<slug>_<version>_<hash12>
    tokens = stem.split("_")
    assert tokens[0] == "cis" and len(tokens) >= 3, f"unexpected filename shape: {pdf_path.name!r}"
    tokens = tokens[1:-1]  # drop "cis" prefix and the trailing hash12 token

    version_indices = [i for i, tok in enumerate(tokens) if _VERSION_TOKEN_RE.match(tok)]
    if len(version_indices) != 1:
        raise ValueError(
            f"cannot uniquely locate the version token in {pdf_path.name!r} "
            f"(candidates: {[tokens[i] for i in version_indices]})"
        )
    version_index = version_indices[0]
    slug = "_".join(tokens[:version_index])
    version = tokens[version_index]
    return slug, version


def _scoring_vocabulary(raw_text: str) -> list[str]:
    found = []
    for term in ("Scored", "Not Scored", "Automated", "Manual"):
        if re.search(rf"\({re.escape(term)}\)", raw_text):
            found.append(term)
    return found


def _independent_evidence(slug: str, version: str, raw_text: str, extracted_count: int):
    known = _KNOWN_GOOD_COUNTS.get((slug, version))
    if known is not None:
        return "human-verified test assertion (tests/extractor/test_extractor.py)", known

    # Heuristic proxy, not ground truth: "Description:" is the one section
    # label that (per extractor's own header-detection docstring) only
    # follows a real recommendation header, never the TOC or checklist
    # appendix lookalikes. A big gap from extracted_count is worth a human
    # look, but this count can itself be off (e.g. "Description:" appearing
    # inside a quoted audit command) -- report it, don't trust it blindly.
    description_label_count = len(re.findall(r"\bDescription:\s", raw_text))
    return "heuristic: 'Description:' label occurrences in raw text", description_label_count


def _recommendations_from_headers(lines: list[str], headers: list[dict]) -> list[ExtractedRecommendation]:
    """Mirrors extract_all_recommendations()'s assembly loop exactly (see
    invariant/extractor/__init__.py), but takes already-loaded `lines` so
    the caller controls how many times the PDF gets text-extracted.
    """
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


def characterize(pdf_path: Path) -> DocumentCharacterization:
    family = pdf_path.parent.name
    slug, version = _parse_filename(pdf_path)
    is_stig = "stig" in slug.lower()

    page_count = len(PdfReader(pdf_path).pages)  # page-tree only, doesn't extract text -- cheap

    error = None
    recommendations = []
    raw_text = ""
    # ru_maxrss is the *process-wide* peak RSS (KB on Linux) and only ever
    # grows -- it can't be reset per document. Reading it before/after and
    # reporting the delta still surfaces which documents actually grow the
    # peak (near-zero overhead, unlike tracemalloc: tried tracing every
    # allocation first, measured a 6x slowdown on the 1192-page Debian 11
    # STIG PDF alone -- 194s vs 31s for the same extraction -- not worth it
    # for an approximate number).
    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    start = time.monotonic()
    try:
        lines = _pdf_lines(pdf_path)  # the one and only full-text pass
        raw_text = "\n".join(lines)
        headers = _find_headers(lines)
        recommendations = _recommendations_from_headers(lines, headers)
    except Exception as exc:  # noqa: BLE001 -- deliberately broad: report, don't crash the matrix run
        error = f"{type(exc).__name__}: {exc}"
    elapsed = time.monotonic() - start
    rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    peak_rss_delta_mb = (rss_after - rss_before) / 1024

    scoring_vocabulary = _scoring_vocabulary(raw_text)

    ids = [r.external_id for r in recommendations]
    seen: set[str] = set()
    duplicate_ids = sorted({i for i in ids if i in seen or seen.add(i)})

    empty_required_field_ids: dict[str, list[str]] = {field: [] for field in _REQUIRED_FIELDS}
    empty_rationale_ids = []
    for rec in recommendations:
        for field in _REQUIRED_FIELDS:
            if not getattr(rec, field):
                empty_required_field_ids[field].append(rec.external_id)
        if not rec.rationale:
            empty_rationale_ids.append(rec.external_id)
    empty_required_field_ids = {k: v for k, v in empty_required_field_ids.items() if v}

    independent_source, independent_value = _independent_evidence(
        slug, version, raw_text, len(recommendations)
    )

    return DocumentCharacterization(
        filename=pdf_path.name,
        path=str(pdf_path.relative_to(REPO_ROOT)),
        family=family,
        slug=slug,
        version=version,
        is_stig=is_stig,
        page_count=page_count,
        scoring_vocabulary=scoring_vocabulary,
        recommendation_count=len(recommendations),
        duplicate_ids=duplicate_ids,
        empty_required_field_ids=empty_required_field_ids,
        empty_rationale_ids=empty_rationale_ids,
        elapsed_seconds=round(elapsed, 2),
        peak_rss_delta_mb=round(peak_rss_delta_mb, 2),
        independent_count_source=independent_source,
        independent_count_value=independent_value,
        error=error,
    )


def main() -> None:
    pdf_paths = sorted(CIS_RAW_DIR.rglob("*.pdf"))
    if not pdf_paths:
        raise SystemExit(f"no PDFs found under {CIS_RAW_DIR}")

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    results = []
    for pdf_path in pdf_paths:
        print(f"characterizing {pdf_path.relative_to(REPO_ROOT)} ...", flush=True)
        result = characterize(pdf_path)
        results.append(result)
        status = "ERROR" if result.error else "ok"
        print(
            f"  [{status}] {result.recommendation_count} recommendations, "
            f"{result.page_count} pages, {result.elapsed_seconds}s, "
            f"peak rss delta {result.peak_rss_delta_mb} MB",
            flush=True,
        )
        if result.error:
            print(f"  error: {result.error}", flush=True)
        # Write after every document, not just at the end -- a run this long
        # (minutes) shouldn't lose everything if it's interrupted partway.
        REPORT_PATH.write_text(json.dumps([asdict(r) for r in results], indent=2) + "\n")

    print(f"\nwrote {REPORT_PATH.relative_to(REPO_ROOT)} ({len(results)} documents)", flush=True)

    print("\n--- flags for human review ---")
    for r in results:
        flags = []
        if r.error:
            flags.append(f"ERROR: {r.error}")
        if r.recommendation_count == 0:
            flags.append("zero recommendations extracted")
        if r.duplicate_ids:
            flags.append(f"duplicate ids: {r.duplicate_ids}")
        if r.empty_required_field_ids:
            flags.append(f"empty required fields: {r.empty_required_field_ids}")
        if (
            r.independent_count_value is not None
            and r.independent_count_value != r.recommendation_count
        ):
            flags.append(
                f"count mismatch vs independent evidence ({r.independent_count_source}): "
                f"extracted={r.recommendation_count} independent={r.independent_count_value}"
            )
        if flags:
            print(f"{r.filename}: " + "; ".join(flags))


if __name__ == "__main__":
    main()
