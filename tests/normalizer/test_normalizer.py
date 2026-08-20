from invariant.normalizer import ProfileLevel, normalize


def _normalize(**overrides):
    fields = {
        "external_id": "5.2.10",
        "title": "Ensure SSH root login is disabled",
        "description": "some description",
        "scored": True,
        "profile_applicability": ["Level 1 - Server", "Level 1 - Workstation"],
        "rationale": "some rationale",
        "audit": "some audit",
        "remediation": "some remediation",
    }
    fields.update(overrides)
    return normalize(**fields)


def test_normalize_parses_profile_applicability_into_structured_levels():
    control = _normalize(profile_applicability=["Level 1 - Server", "Level 2 - Workstation"])

    assert control.applicability == [
        ProfileLevel(level=1, applies_to="Server"),
        ProfileLevel(level=2, applies_to="Workstation"),
    ]


def test_normalize_strips_stray_bullet_glyph_from_text_fields():
    bullet = ""
    control = _normalize(description=f"first line\n{bullet} bullet item\nsecond line")

    assert "" not in control.description
    assert "bullet item" in control.description


def test_normalize_keeps_scored_and_core_fields():
    control = _normalize(scored=False, title="Some title", external_id="1.2.3")

    assert control.scored is False
    assert control.title == "Some title"
    assert control.external_id == "1.2.3"


def test_normalize_keeps_non_level_entries_as_applicability_tags():
    """CIS Debian 11 STIG tags some recommendations with a bare "STIG"
    marker (no level number) alongside the normal "Level N - X" entries --
    confirmed against the real PDF. Not an error, just a different kind
    of tag; don't fabricate a fake level number for it.
    """
    control = _normalize(profile_applicability=["Level 1 - Server", "STIG"])

    assert control.applicability == [ProfileLevel(level=1, applies_to="Server")]
    assert control.applicability_tags == ["STIG"]


def test_normalize_accepts_en_dash_in_profile_applicability():
    """CIS Debian 11 STIG mixes a plain hyphen and an en dash (U+2013) for
    the same "Level N <dash> X" pattern -- confirmed against the real PDF.
    """
    control = _normalize(profile_applicability=["Level 1 – Server", "Level 2 - Workstation"])

    assert control.applicability == [
        ProfileLevel(level=1, applies_to="Server"),
        ProfileLevel(level=2, applies_to="Workstation"),
    ]
