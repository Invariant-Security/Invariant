import pytest

from invariant.assessment import CHECKS, assess_target
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


def _assert_fails_only(findings, expected_failing_ids):
    """Every check in CHECKS runs per target -- rather than hardcode every
    external_id (they drift per document, e.g. Debian 13 uses 5.1.21 where
    the rest use 5.1.20) or a check count that grows as more checks are
    added, assert the demo's "known problems per machine" story: exactly
    the given set of FAILs, everything else PASS.
    """
    statuses = {f.external_id: f.status for f in findings}
    assert len(statuses) == len(CHECKS)
    for external_id in expected_failing_ids:
        assert statuses[external_id] == "FAIL", f"expected {external_id} to FAIL, got {statuses[external_id]}"
    assert all(
        status == "PASS" for eid, status in statuses.items() if eid not in expected_failing_ids
    )


# Every target -- including both "baseline" containers -- now also includes
# this fixed set of 8 in its expected failures, on top of whatever that
# target's own story is meant to demonstrate. Confirmed against all 6 live
# containers: none of the 6 Dockerfiles were ever updated to satisfy the
# hardening Groups C and D added checks for (PAM faillock/pwquality/
# pwhistory, nullok, umask, sshd Ciphers, sshd DisableForwarding, and
# sshd_config's own file mode) -- those groups validated their evaluators
# against private throwaway containers, not this shared fleet, so the gap
# went unnoticed until now. Real, systemic, not a bug in any check -- left
# as-is rather than editing the shared Dockerfiles while other agents are
# actively using these same live containers in parallel; worth a follow-up
# to harden the images.
#
# Group J added "1.4.2" ("Ensure access to bootloader config is
# configured"): confirmed the same external_id across all 6 real documents,
# and confirmed empirically that none of the 6 live containers have a
# /boot/grub/grub.cfg at all (no bootloader installed in a container) --
# facts.py's own documented "not configured" signal, and the check fails
# closed on it per this group's design (see _evaluate_bootloader_config_
# permissions' docstring). A second, genuinely new systemic gap: none of
# the 6 Dockerfiles configure journald's Compress/Storage/log-rotation
# directives either, but those 3 checks' external_ids drift per document
# (nested "6.2.1.1.X" for debian_linux_11, flatter "6.2.1.X"/"6.2.2.X" for
# ubuntu_linux_20_04, "6.1.1.1.X" for the rest) -- rather than force them
# into this shared cross-document set, they're added per-target below,
# following the exact same pattern already used for "5.1.20"/"7.1.5".
_SYSTEMIC_GAPS = {
    "5.1.1",
    "5.1.6",
    "5.1.8",
    "5.3.2.2",
    "5.3.2.3",
    "5.3.2.4",
    "5.3.3.4.1",
    "5.4.3.3",
    "1.4.2",
}


def test_assess_debian_baseline_fails_only_sshd_config_permissions():
    findings = assess_target("invariant-debian-baseline")

    assert len(findings) == len(CHECKS)
    _assert_fails_only(findings, _SYSTEMIC_GAPS | {"6.2.1.1.3", "6.2.1.1.5", "6.2.1.1.6"})


def test_assess_debian_ssh_bad_fails_only_ssh_and_sshd_config_permissions():
    findings = assess_target("invariant-debian-ssh-bad")

    _assert_fails_only(findings, _SYSTEMIC_GAPS | {"5.1.20", "6.1.1.1.5", "6.1.1.1.6", "6.1.1.1.7"})


def test_assess_debian_permissions_bad_fails_only_shadow_and_sshd_config_permissions():
    findings = assess_target("invariant-debian-permissions-bad")

    _assert_fails_only(findings, _SYSTEMIC_GAPS | {"7.1.5", "6.1.1.1.3", "6.1.1.1.5", "6.1.1.1.6"})


def test_assess_ubuntu_baseline_fails_only_sshd_config_permissions():
    findings = assess_target("invariant-ubuntu-baseline")

    assert len(findings) == len(CHECKS)
    _assert_fails_only(findings, _SYSTEMIC_GAPS | {"6.2.1.3", "6.2.2.3", "6.2.2.4"})


def test_assess_ubuntu_ssh_bad_fails_only_ssh_and_sshd_config_permissions():
    findings = assess_target("invariant-ubuntu-ssh-bad")

    _assert_fails_only(findings, _SYSTEMIC_GAPS | {"5.1.20", "6.1.1.1.3", "6.1.1.1.5", "6.1.1.1.6"})


def test_assess_ubuntu_permissions_bad_fails_only_shadow_and_sshd_config_permissions():
    findings = assess_target("invariant-ubuntu-permissions-bad")

    _assert_fails_only(findings, _SYSTEMIC_GAPS | {"7.1.5", "6.1.1.1.5", "6.1.1.1.6", "6.1.1.1.7"})


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
