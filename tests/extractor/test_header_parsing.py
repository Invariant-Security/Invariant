from invariant.extractor import _end_before_appendix, _find_headers, _non_empty_lines, _split_sections


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


def test_split_sections_handles_label_glued_to_previous_sentence():
    """Some older CIS PDFs run a section label straight into the end of the
    previous sentence with no line break -- confirmed against the real CIS
    Ubuntu 12.04 LTS Server Benchmark v1.1.0 PDF, section 3.1 ("...changing
    the file. Audit:  Perform the following...").
    """
    lines = _lines(
        "Rationale:\n"
        "Setting the owner and group to root prevents non-root users from changing the file. Audit:\n"
        "Perform the following to determine if the file has the correct ownership.\n"
        "Remediation:\n"
        "Run the following command.\n"
    )

    sections = _split_sections(lines)

    assert sections["Rationale"] == (
        "Setting the owner and group to root prevents non-root users from changing the file."
    )
    assert sections["Audit"] == "Perform the following to determine if the file has the correct ownership."
    assert sections["Remediation"] == "Run the following command."


def test_non_empty_lines_strips_both_bullet_glyph_variants():
    old_style_bullet = "\uf0b7"
    new_style_bullet = "\u2022"
    text = f"{old_style_bullet} Level 1 - Server\n{new_style_bullet} Level 1 - Workstation\n"

    assert _non_empty_lines(text) == ["Level 1 - Server", "Level 1 - Workstation"]


def test_end_before_appendix_clips_the_last_bodys_unbounded_range():
    """The last recommendation in a benchmark has no following header to
    stop it -- confirmed against the real CIS Debian Linux 10 v1.0.0 PDF,
    where the last recommendation's CIS Controls section absorbed a 17KB
    appendix before this fix (codexplan.md Fase 4 item 4).
    """
    lines = _lines(
        "Remediation:\n"
        "Run the following command.\n"
        "CIS Controls:\n"
        "Version 7\n"
        "Appendix: Change History\n"
        "Feb 13, 2020 1.0.0 Published\n"
    )

    end = _end_before_appendix(lines, body_start=0, body_end=len(lines))

    assert end == 4
    assert lines[end] == "Appendix: Change History"


def test_end_before_appendix_is_a_no_op_when_no_appendix_marker_is_present():
    lines = _lines("Remediation:\nRun the following command.\n")

    end = _end_before_appendix(lines, body_start=0, body_end=len(lines))

    assert end == len(lines)
