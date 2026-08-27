"""Fase 2 of the CIS parser validation plan: extract_and_validate() must
never return a result for a document that looks fine but silently dropped
or misidentified content -- it should raise ExtractionError instead. These
are unit tests against extract_all_recommendations() (monkeypatched), not
real PDFs -- same style tests/cli/test_extract.py already uses for the CLI
layer.
"""

from pathlib import Path

import pytest

from invariant import extractor
from invariant.extractor import ExtractedRecommendation, ExtractionError, extract_and_validate


def _rec(**overrides) -> ExtractedRecommendation:
    fields = dict(
        external_id="5.2.10",
        title="Ensure SSH root login is disabled",
        scored=True,
        profile_applicability=["Level 1 - Server"],
        description="desc",
        rationale="rationale",
        audit="audit",
        remediation="remediation",
    )
    fields.update(overrides)
    return ExtractedRecommendation(**fields)


def test_raises_when_no_recommendations_found(monkeypatch):
    monkeypatch.setattr(extractor, "extract_all_recommendations", lambda path: [])

    with pytest.raises(ExtractionError, match="no recommendations found"):
        extract_and_validate(Path("/fake.pdf"))


def test_raises_on_duplicate_external_id(monkeypatch):
    monkeypatch.setattr(
        extractor,
        "extract_all_recommendations",
        lambda path: [_rec(external_id="1.1"), _rec(external_id="1.1")],
    )

    with pytest.raises(ExtractionError, match="duplicate external_id"):
        extract_and_validate(Path("/fake.pdf"))


@pytest.mark.parametrize("field", ["external_id", "title", "description", "audit", "remediation"])
def test_raises_when_hard_required_field_is_empty(monkeypatch, field):
    monkeypatch.setattr(
        extractor, "extract_all_recommendations", lambda path: [_rec(**{field: ""})]
    )

    with pytest.raises(ExtractionError, match=field):
        extract_and_validate(Path("/fake.pdf"))


def test_empty_rationale_is_a_warning_not_a_failure(monkeypatch):
    monkeypatch.setattr(
        extractor, "extract_all_recommendations", lambda path: [_rec(rationale="")]
    )

    result = extract_and_validate(Path("/fake.pdf"))

    assert len(result.recommendations) == 1
    assert len(result.warnings) == 1
    assert result.warnings[0].external_id == "5.2.10"
    assert result.warnings[0].field == "rationale"


def test_clean_extraction_has_no_warnings(monkeypatch):
    monkeypatch.setattr(
        extractor,
        "extract_all_recommendations",
        lambda path: [_rec(external_id="1.1"), _rec(external_id="1.2")],
    )

    result = extract_and_validate(Path("/fake.pdf"))

    assert len(result.recommendations) == 2
    assert result.warnings == []
