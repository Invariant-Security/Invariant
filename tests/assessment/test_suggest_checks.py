import pytest

from invariant.assessment.suggestions import suggest_checks

pytestmark = pytest.mark.integration


def test_suggest_checks_returns_candidates_sorted_by_document_count():
    candidates = suggest_checks(min_documents=1)

    assert len(candidates) > 0
    document_counts = [c.document_count for c in candidates]
    assert document_counts == sorted(document_counts, reverse=True)


def test_suggest_checks_min_documents_filters_out_rare_ones():
    all_candidates = suggest_checks(min_documents=1)
    broad_candidates = suggest_checks(min_documents=5)

    assert len(broad_candidates) < len(all_candidates)
    assert all(c.document_count >= 5 for c in broad_candidates)


def test_suggest_checks_includes_a_known_control():
    """Sanity check: one of the controls we already hand-implemented as a
    real Check (/etc/shadow permissions -- its audit text has exactly one
    command, unlike the SSH one, which has a second example for match
    blocks and so isn't a "simple" candidate) should show up here too --
    confirms the extraction logic finds real, known-good commands, not
    just noise.
    """
    candidates = {c.title: c for c in suggest_checks(min_documents=1)}

    assert "Ensure permissions on /etc/shadow are configured" in candidates
    shadow_candidate = candidates["Ensure permissions on /etc/shadow are configured"]
    assert shadow_candidate.document_count > 0
