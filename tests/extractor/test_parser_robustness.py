"""Fase 4 of the CIS parser validation plan: parser robustness fixes,
verified against the real, already-committed CIS Debian Linux 10 Benchmark
v1.0.0 PDF (no network call needed, so this isn't marked integration).
"""

import time
from pathlib import Path

import pytest

from invariant.extractor import extract_all_recommendations

DEBIAN_10_PDF = Path("data/raw/cis/debian/cis_debian_linux_10_1.0.0_8abac02af919.pdf")
DEBIAN_11_STIG_PDF = Path("data/raw/cis/debian/cis_debian_linux_11_stig_1.0.0_107148dbd6f9.pdf")


@pytest.mark.skipif(not DEBIAN_10_PDF.exists(), reason=f"{DEBIAN_10_PDF} not present in this checkout")
def test_last_recommendation_does_not_swallow_the_appendix():
    """Regression test for the bug found while wiring up CIS Controls
    (item 5): before the item-4 fix, the last recommendation's body ran
    unbounded to end-of-document, so its CIS Controls field absorbed the
    entire "Appendix: Change History" section (~17KB of unrelated content,
    including the full recommendation checklist) instead of just its own
    ~400 bytes of real content.
    """
    recommendations = extract_all_recommendations(DEBIAN_10_PDF)
    last = recommendations[-1]

    assert last.external_id == "6.2.20"
    assert "Appendix" not in last.cis_controls
    assert len(last.cis_controls) < 1000
    # The appendix used to stretch the last recommendation's page range all
    # the way to the document's final page (509) -- it should now be tight.
    assert last.source_page_end - last.source_page_start <= 2


@pytest.mark.skipif(not DEBIAN_10_PDF.exists(), reason=f"{DEBIAN_10_PDF} not present in this checkout")
def test_default_value_references_cis_controls_impact_are_preserved_when_present():
    """Fase 4 item 5: these sections were already correctly delimited by
    _split_sections() (used to bound the fields around them) but silently
    discarded -- never stored on ExtractedRecommendation.
    """
    recommendations = {r.external_id: r for r in extract_all_recommendations(DEBIAN_10_PDF)}

    # 5.2.10 has a CIS Controls section in the real PDF (confirmed).
    assert recommendations["5.2.10"].cis_controls != ""
    # Not every recommendation has every optional section, so check across
    # all of them that each field is wired up to capture real content
    # somewhere rather than assuming one specific id has all four.
    assert any(r.references for r in recommendations.values())
    assert any(r.default_value for r in recommendations.values())
    assert any(r.impact for r in recommendations.values())


@pytest.mark.skipif(
    not DEBIAN_11_STIG_PDF.exists(), reason=f"{DEBIAN_11_STIG_PDF} not present in this checkout"
)
def test_debian_11_stig_extracts_within_a_generous_time_budget():
    """Fase 4 item 6: investigate Debian 11 STIG's performance and add a
    time budget to the test. Investigated in Fase 1 (see
    docs/decisions/cis-parser-characterization.md): the "significantly
    higher cost" observed in the earlier exploratory validation was a
    tracemalloc instrumentation artifact (6x overhead measured), not the
    document -- single-pass extraction measured ~30s. 120s gives generous
    headroom (4x) over that measurement while still catching a real
    performance regression.
    """
    start = time.monotonic()
    recommendations = extract_all_recommendations(DEBIAN_11_STIG_PDF)
    elapsed = time.monotonic() - start

    assert recommendations  # sanity: didn't silently return nothing
    assert elapsed < 120, f"Debian 11 STIG extraction took {elapsed:.1f}s, budget is 120s"
