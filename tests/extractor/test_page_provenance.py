"""Fase 3 of the CIS parser validation plan: every extracted recommendation
must carry the page range it came from, traceable back to the raw artifact
(PRD sec. 47, the reproducibility invariant).

Uses the real, already-committed CIS Debian Linux 10 Benchmark v1.0.0 PDF
directly from data/raw/cis/ (not the network-downloading fixture
tests/extractor/test_extractor.py uses) -- no network call needed, so this
isn't marked integration.
"""

from pathlib import Path

import pytest

from invariant.extractor import extract_all_recommendations

DEBIAN_10_PDF = Path("data/raw/cis/debian/cis_debian_linux_10_1.0.0_8abac02af919.pdf")

pytestmark = pytest.mark.skipif(
    not DEBIAN_10_PDF.exists(), reason=f"{DEBIAN_10_PDF} not present in this checkout"
)


def test_recommendations_carry_a_plausible_page_range():
    recommendations = {r.external_id: r for r in extract_all_recommendations(DEBIAN_10_PDF)}

    rec = recommendations["5.2.10"]
    assert rec.source_page_start > 0
    assert rec.source_page_end >= rec.source_page_start
    # 509-page document -- both ends of the range must be real pages in it.
    assert rec.source_page_end <= 509


def test_page_ranges_advance_in_document_order():
    """Recommendations are found walking the document top to bottom, so
    their page ranges should never go backwards -- a regression here would
    mean a recommendation got attributed to the wrong page range.
    """
    recommendations = extract_all_recommendations(DEBIAN_10_PDF)

    for earlier, later in zip(recommendations, recommendations[1:]):
        assert later.source_page_start >= earlier.source_page_start


def test_wrapped_title_recommendation_still_gets_a_page_range():
    """1.9's title wraps across two lines (see
    test_extractor.py::test_extract_all_recommendations_reconstructs_wrapped_titles)
    -- page provenance must survive that too.
    """
    recommendations = {r.external_id: r for r in extract_all_recommendations(DEBIAN_10_PDF)}

    rec = recommendations["1.9"]
    assert rec.source_page_start > 0
    assert rec.source_page_end >= rec.source_page_start
