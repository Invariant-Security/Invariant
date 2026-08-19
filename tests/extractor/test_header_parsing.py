from invariant.extractor import _find_headers, _non_empty_lines


def _lines(text: str) -> list[str]:
    return text.splitlines()


def test_find_headers_recognizes_scored_vocabulary():
    lines = _lines(
        "5.2.10 Ensure SSH root login is disabled (Scored)\n"
        "Profile Applicability:\n"
        "Level 1 - Server\n"
    )

    headers = _find_headers(lines)

    assert len(headers) == 1
    assert headers[0]["id"] == "5.2.10"
    assert headers[0]["scored"] is True


def test_find_headers_recognizes_automated_manual_vocabulary():
    """CIS renamed "Scored"/"Not Scored" to "Automated"/"Manual" in some
    newer benchmark versions (e.g. CIS Debian Linux 10 v2.0.0) -- same
    concept, different wording, confirmed against the real PDFs.
    """
    lines = _lines(
        "1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Automated)\n"
        "Profile Applicability:\n"
        "Level 1 - Server\n"
        "5.4.1 Ensure some manual check is documented (Manual)\n"
        "Profile Applicability:\n"
        "Level 1 - Server\n"
    )

    headers = _find_headers(lines)

    assert len(headers) == 2
    assert headers[0]["id"] == "1.1.1.1"
    assert headers[0]["scored"] is True
    assert headers[1]["id"] == "5.4.1"
    assert headers[1]["scored"] is False


def test_find_headers_ignores_lines_without_profile_applicability_anchor():
    lines = _lines(
        "5.2.10 Ensure SSH root login is disabled (Scored) .......................  21\n"
        "5.2.11 Ensure something else is disabled (Scored)\n"
    )

    headers = _find_headers(lines)

    assert headers == []


def test_non_empty_lines_strips_both_bullet_glyph_variants():
    old_style_bullet = "\uf0b7"
    new_style_bullet = "\u2022"
    text = f"{old_style_bullet} Level 1 - Server\n{new_style_bullet} Level 1 - Workstation\n"

    assert _non_empty_lines(text) == ["Level 1 - Server", "Level 1 - Workstation"]
