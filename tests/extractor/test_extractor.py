from pathlib import Path

import pytest

from invariant.extractor import extract_all_recommendations, extract_recommendation
from invariant.source import CIS

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def debian10_pdf(tmp_path_factory) -> Path:
    """Downloads the real CIS Debian Linux 10 Benchmark v1.0.0 PDF once
    (no login needed, see CIS.download_benchmark) and reuses it for every
    test in this module -- avoids re-downloading per test.
    """
    content, extension = CIS().download_benchmark(
        "Debian Linux", "CIS Debian Linux 10 Benchmark v1.0.0"
    )
    path = tmp_path_factory.mktemp("cis") / f"debian10.{extension}"
    path.write_bytes(content)
    return path


def test_extract_ssh_root_login_recommendation(debian10_pdf):
    rec = extract_recommendation(debian10_pdf, "5.2.10")

    assert rec.external_id == "5.2.10"
    assert rec.title == "Ensure SSH root login is disabled"
    assert rec.scored is True
    assert rec.profile_applicability == ["Level 1 - Server", "Level 1 - Workstation"]
    assert "PermitRootLogin" in rec.description
    assert "sshd -T | grep permitrootlogin" in rec.audit
    assert "PermitRootLogin no" in rec.remediation


def test_extract_etc_shadow_permissions_recommendation(debian10_pdf):
    rec = extract_recommendation(debian10_pdf, "6.1.4")

    assert rec.title == "Ensure permissions on /etc/shadow are configured"
    assert "stat /etc/shadow" in rec.audit
    assert "chmod o-rwx,g-wx /etc/shadow" in rec.remediation


def test_extract_duplicate_uid0_recommendation(debian10_pdf):
    rec = extract_recommendation(debian10_pdf, "6.2.6")

    assert rec.title == "Ensure root is the only UID 0 account"
    assert "UID 0" in rec.description


def test_extract_recommendation_not_found_raises(debian10_pdf):
    with pytest.raises(LookupError):
        extract_recommendation(debian10_pdf, "99.99.99")


def test_extract_all_recommendations_finds_every_one_with_no_duplicates(debian10_pdf):
    recommendations = extract_all_recommendations(debian10_pdf)

    ids = [r.external_id for r in recommendations]
    assert len(recommendations) == 235
    assert len(ids) == len(set(ids))


def test_extract_all_recommendations_reconstructs_wrapped_titles(debian10_pdf):
    """1.9's title is long enough to wrap across two lines in the PDF's
    extracted text -- regression test for that line-wrap handling.
    """
    recommendations = {r.external_id: r for r in extract_all_recommendations(debian10_pdf)}

    assert recommendations["1.9"].title == (
        "Ensure updates, patches, and additional security software are installed"
    )
    assert recommendations["1.9"].scored is False


def test_extract_all_recommendations_excludes_toc_and_appendix(debian10_pdf):
    """The table of contents and the checklist appendix both contain
    "<id> <title> (Scored)"-shaped lines too -- neither should be mistaken
    for a real recommendation.
    """
    recommendations = extract_all_recommendations(debian10_pdf)

    for rec in recommendations:
        assert rec.description, f"{rec.external_id} has no Description -- likely a TOC/appendix false positive"
        assert rec.audit, f"{rec.external_id} has no Audit -- likely a TOC/appendix false positive"
