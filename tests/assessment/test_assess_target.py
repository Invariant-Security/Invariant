import pytest

from invariant.assessment import assess_target
from invariant.assessment.facts import collect_facts

pytestmark = pytest.mark.integration


def test_collect_facts_reads_real_debian_container():
    facts = collect_facts("invariant-debian-baseline")

    assert facts.os_id == "debian"
    assert facts.os_version_id == "11"
    assert facts.sshd_config["permitrootlogin"] == "no"
    assert facts.file_stats["/etc/shadow"].mode == 0o640


def test_collect_facts_reads_real_ubuntu_container():
    facts = collect_facts("invariant-ubuntu-baseline")

    assert facts.os_id == "ubuntu"
    assert facts.os_version_id == "20.04"


def test_assess_debian_baseline_passes_both_controls():
    findings = assess_target("invariant-debian-baseline")

    assert {f.external_id: f.status for f in findings} == {"5.1.20": "PASS", "7.1.5": "PASS"}


def test_assess_debian_ssh_bad_fails_only_ssh_control():
    findings = assess_target("invariant-debian-ssh-bad")

    assert {f.external_id: f.status for f in findings} == {"5.1.20": "FAIL", "7.1.5": "PASS"}


def test_assess_debian_permissions_bad_fails_only_shadow_control():
    findings = assess_target("invariant-debian-permissions-bad")

    assert {f.external_id: f.status for f in findings} == {"5.1.21": "PASS", "7.1.5": "FAIL"}


def test_assess_ubuntu_baseline_passes_both_controls():
    findings = assess_target("invariant-ubuntu-baseline")

    assert {f.external_id: f.status for f in findings} == {"5.1.20": "PASS", "7.1.5": "PASS"}


def test_assess_ubuntu_ssh_bad_fails_only_ssh_control():
    findings = assess_target("invariant-ubuntu-ssh-bad")

    assert {f.external_id: f.status for f in findings} == {"5.1.20": "FAIL", "7.1.5": "PASS"}


def test_assess_ubuntu_permissions_bad_fails_only_shadow_control():
    findings = assess_target("invariant-ubuntu-permissions-bad")

    assert {f.external_id: f.status for f in findings} == {"5.1.20": "PASS", "7.1.5": "FAIL"}


def test_assess_finding_carries_full_traceability_chain():
    findings = assess_target("invariant-debian-baseline")
    finding = next(f for f in findings if f.external_id == "5.1.20")

    assert finding.source_name == "cis"
    assert finding.document_name == "debian_linux_11"
    assert finding.control_title == "Ensure sshd PermitRootLogin is disabled"
    assert "permitrootlogin" in finding.evidence_output.lower()


def test_assess_target_raises_when_os_cannot_be_detected():
    """No static target list to validate against anymore -- an unknown or
    unreachable container just fails OS detection naturally.
    """
    with pytest.raises(LookupError):
        assess_target("not-a-real-container")
