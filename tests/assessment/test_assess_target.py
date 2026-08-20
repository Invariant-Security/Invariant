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
        # Not every gap id necessarily applies to every document: section
        # numbering drifts between the debian_11/ubuntu_20_04 CIS documents
        # backing these targets (confirmed for the Group I audit-file-
        # ownership controls -- debian_11 numbers them 6.4.x, ubuntu_20_04
        # numbers the same controls 6.3.x), so _SYSTEMIC_GAPS carries both
        # id variants and this loop only asserts FAIL for whichever variant
        # is actually present in this target's findings.
        if external_id not in statuses:
            continue
        assert statuses[external_id] == "FAIL", f"expected {external_id} to FAIL, got {statuses[external_id]}"
    assert all(
        status == "PASS" for eid, status in statuses.items() if eid not in expected_failing_ids
    )


# Every target -- including both "baseline" containers -- now also includes
# this fixed set in its expected failures, on top of whatever that target's
# own story is meant to demonstrate. Confirmed against all 6 live
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
# Group G adds 8 more of the same shape: libpam-pwquality isn't installed on
# any of the 6 images (same underlying gap as 5.3.2.3/5.3.2.4 above), so
# /etc/security/pwquality.conf and /etc/security/pwhistory.conf don't exist
# there either -- confirmed with a read-only collect_facts() against all 6
# live containers (no modification made to any of them). 5.3.3.2.1 (changed
# characters/difok), 5.3.3.2.2 (minlen), 5.3.3.2.3 (complexity), 5.3.3.2.4
# (same consecutive characters/maxrepeat), 5.3.3.2.5 (maximum sequential
# characters/maxsequence), 5.3.3.2.8 (quality enforced for root), 5.3.3.3.1
# (history remember), 5.3.3.3.2 (history enforced for root).
#
# Group I adds the 5 auditd config/tooling ownership + rules-immutability
# checks (see the id-alias comment further down, above _SYSTEMIC_GAPS'
# 6.x.x.x entries) -- same underlying "package never installed on any of
# the 6 images" story.
#
# Group H adds another, same shape: none of the 6 Dockerfiles have `sudo`
# or `cron` installed at all (confirmed: /etc/sudoers and /etc/crontab
# both come back "No such file or directory" on every one of the 6 live
# containers), so every cron-file-permission check fails (missing file/dir
# -> stat() fails -> evaluate() returns False, the same "not found is not
# a pass" posture already established for the Group A permission checks),
# and "Ensure sudo log file exists" fails the same way (no /etc/sudoers to
# hold a Defaults logfile= line). The two sudoers *content* checks (no
# NOPASSWD, no !authenticate) pass vacuously instead -- an empty/missing
# sudoers has no offending line to find -- so those two are NOT added
# here. /etc/cron.d's external_id itself drifts per document (2.4.1.7 for
# debian_linux_11, 2.4.1.8 for every other document, which inserts an
# unimplemented cron.yearly control at 2.4.1.7 first) -- the common
# "2.4.1.8" id covers 5 of the 6 real targets; debian_linux_11 (the
# debian-baseline target) needs "2.4.1.7" added on its own call below
# instead of the shared set, same as this file already does for 5.1.20 /
# 7.1.5's own per-document drift.
_SYSTEMIC_GAPS = {
    "5.1.1",
    "5.1.6",
    "5.1.8",
    "5.3.2.2",
    "5.3.2.3",
    "5.3.2.4",
    "5.3.3.2.1",
    "5.3.3.2.2",
    "5.3.3.2.3",
    "5.3.3.2.4",
    "5.3.3.2.5",
    "5.3.3.2.8",
    "5.3.3.3.1",
    "5.3.3.3.2",
    "5.3.3.4.1",
    "5.4.3.3",
    # Group I: auditd config/tooling file ownership + rules immutability.
    # None of the 6 Dockerfiles install auditd at all (confirmed: `dpkg -s
    # auditd` fails, /etc/audit and /sbin/auditctl don't exist on all 6 live
    # containers), so every one of these 5 new checks fails closed on every
    # live demo target -- same "real, systemic, not a bug in any check"
    # story as the existing gaps above, just discovered by this group
    # instead. Unlike the section-5.x gaps above, each of our 6 targets maps
    # to a genuinely different CIS document (debian_11/12/13,
    # ubuntu_20_04/22_04/24_04, confirmed via each container's
    # /etc/os-release) and this section's numbering isn't shared across all
    # of them the way section 5.x happened to be -- debian_11 uses 6.4.x,
    # everything else uses 6.2.x/6.3.x, and even within that the "immutable"
    # control's id differs per document. So every distinct id (verified via
    # Postgres) is listed below; _assert_fails_only skips whichever ids
    # aren't present for a given target's document.
    "6.4.4.6",  # debian_11: Ensure audit configuration files owner is configured
    "6.3.4.6",  # ubuntu_20_04: same control
    "6.2.4.6",  # debian_12/13, ubuntu_22_04/24_04: same control
    "6.4.4.7",  # debian_11: Ensure audit configuration files group owner is configured
    "6.3.4.7",  # ubuntu_20_04: same control
    "6.2.4.7",  # debian_12/13, ubuntu_22_04/24_04: same control
    "6.4.4.9",  # debian_11: Ensure audit tools owner is configured
    "6.3.4.9",  # ubuntu_20_04: same control
    "6.2.4.9",  # debian_12/13, ubuntu_22_04/24_04: same control
    "6.4.4.10",  # debian_11: Ensure audit tools group owner is configured
    "6.3.4.10",  # ubuntu_20_04: same control
    "6.2.4.10",  # debian_12/13, ubuntu_22_04/24_04: same control
    "6.4.3.20",  # debian_11: Ensure the audit configuration is immutable
    "6.3.3.20",  # ubuntu_20_04: same control
    "6.2.3.29",  # debian_12, ubuntu_24_04: same control
    "6.2.3.36",  # debian_13: same control
    "6.2.3.20",  # ubuntu_22_04: same control
    # Group H: sudoers + cron file permissions -- same "package never
    # installed" story (see the comment near the top of this set).
    "2.4.1.2",  # /etc/crontab
    "2.4.1.3",  # /etc/cron.hourly
    "2.4.1.4",  # /etc/cron.daily
    "2.4.1.5",  # /etc/cron.weekly
    "2.4.1.6",  # /etc/cron.monthly
    "2.4.1.8",  # /etc/cron.d (debian_linux_11 uses 2.4.1.7 instead, see below)
    "5.2.3",  # Ensure sudo log file exists
}


def test_assess_debian_baseline_fails_only_sshd_config_permissions():
    findings = assess_target("invariant-debian-baseline")

    assert len(findings) == len(CHECKS)
    # debian_linux_11 (this target's document) has no cron.yearly control,
    # so its /etc/cron.d control is 2.4.1.7, not the 2.4.1.8 every other
    # real target document uses -- see _SYSTEMIC_GAPS's comment above.
    _assert_fails_only(findings, (_SYSTEMIC_GAPS - {"2.4.1.8"}) | {"2.4.1.7"})


def test_assess_debian_ssh_bad_fails_only_ssh_and_sshd_config_permissions():
    findings = assess_target("invariant-debian-ssh-bad")

    _assert_fails_only(findings, _SYSTEMIC_GAPS | {"5.1.20"})


def test_assess_debian_permissions_bad_fails_only_shadow_and_sshd_config_permissions():
    findings = assess_target("invariant-debian-permissions-bad")

    _assert_fails_only(findings, _SYSTEMIC_GAPS | {"7.1.5"})


def test_assess_ubuntu_baseline_fails_only_sshd_config_permissions():
    findings = assess_target("invariant-ubuntu-baseline")

    assert len(findings) == len(CHECKS)
    _assert_fails_only(findings, _SYSTEMIC_GAPS)


def test_assess_ubuntu_ssh_bad_fails_only_ssh_and_sshd_config_permissions():
    findings = assess_target("invariant-ubuntu-ssh-bad")

    _assert_fails_only(findings, _SYSTEMIC_GAPS | {"5.1.20"})


def test_assess_ubuntu_permissions_bad_fails_only_shadow_and_sshd_config_permissions():
    findings = assess_target("invariant-ubuntu-permissions-bad")

    _assert_fails_only(findings, _SYSTEMIC_GAPS | {"7.1.5"})


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
