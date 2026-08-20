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
    the given set of FAILs, everything else PASS. Deliberately strict about
    every id in expected_failing_ids actually existing in `findings` (a
    plain statuses[external_id] lookup, not .get()) -- an id that doesn't
    resolve for this target's document is a caller bug, not something to
    paper over: e.g. "5.1.18" is Group F's MaxStartups check on
    debian_linux_11/ubuntu_linux_20_04/22_04, but a *different*,
    legitimately-passing check ("Ensure sshd MaxSessions is configured") on
    debian_linux_12/13 and ubuntu_linux_24_04 -- silently skipping a
    missing id would have masked exactly that collision instead of
    surfacing it as the KeyError it should be. See
    _MAC_MAX_STARTUPS_GAP_BY_DOCUMENT below for how the two ids that
    actually drift across documents are kept id-collision-safe per target.
    """
    statuses = {f.external_id: f.status for f in findings}
    assert len(statuses) == len(CHECKS)
    for external_id in expected_failing_ids:
        assert statuses[external_id] == "FAIL", f"expected {external_id} to FAIL, got {statuses[external_id]}"
    assert all(
        status == "PASS" for eid, status in statuses.items() if eid not in expected_failing_ids
    )


# Every target -- including both "baseline" containers -- now also includes
# this fixed set of 7 in its expected failures, on top of whatever that
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
# Group F adds 2 more stable ones (pam_unix/pam_pwhistory both include
# use_authtok), confirmed the same way against all 6 live containers: none
# of the 6 Dockerfiles' PAM config sets use_authtok on either module's
# line, nor configures pwhistory.conf at all on 4 of the 6 (the other 2
# have a pwhistory.conf present but fully commented out).
_SYSTEMIC_GAPS = {
    "5.1.1",
    "5.1.6",
    "5.1.8",
    "5.3.2.2",
    "5.3.2.3",
    "5.3.2.4",
    "5.3.3.4.1",
    "5.4.3.3",
    "5.3.3.4.4",  # pam_unix includes use_authtok
    "5.3.3.3.3",  # pam_pwhistory includes use_authtok
}

# Group F also found sshd's stock default MACs list includes
# umac-64@openssh.com (flagged weak by CIS) and a stock MaxStartups of
# 10:30:100 (100 > the 60-or-less ceiling) on all 6 live containers --
# neither Dockerfile sets either directive explicitly, same "never
# hardened for it" story as the rest of _SYSTEMIC_GAPS. But unlike every
# id in that flat set, MACs' and MaxStartups' external_id both drift
# *and* collide with other, unrelated, legitimately-passing checks
# depending on the document (confirmed via Postgres: "5.1.18" is
# MaxStartups on debian_linux_11/ubuntu_linux_20_04/22_04, but "Ensure
# sshd MaxSessions is configured" -- a different check entirely -- on
# debian_linux_12/13 and ubuntu_linux_24_04), so a single flat id can't
# represent them safely across all 6 targets. Looked up by the target's
# own document instead.
_MAC_MAX_STARTUPS_GAP_BY_DOCUMENT = {
    "debian_linux_11": {"5.1.15", "5.1.18"},
    "debian_linux_12": {"5.1.15", "5.1.17"},
    "debian_linux_13": {"5.1.16", "5.1.19"},
    "ubuntu_linux_20_04": {"5.1.15", "5.1.18"},
    "ubuntu_linux_22_04": {"5.1.15", "5.1.18"},
    "ubuntu_linux_24_04": {"5.1.15", "5.1.17"},
}


def test_assess_debian_baseline_fails_only_sshd_config_permissions():
    findings = assess_target("invariant-debian-baseline")

    assert len(findings) == len(CHECKS)
    _assert_fails_only(findings, _SYSTEMIC_GAPS | _MAC_MAX_STARTUPS_GAP_BY_DOCUMENT["debian_linux_11"])


def test_assess_debian_ssh_bad_fails_only_ssh_and_sshd_config_permissions():
    # invariant-debian-ssh-bad runs debian:12, not debian:11 -- confirmed
    # via collect_facts() (os_version_id "12").
    findings = assess_target("invariant-debian-ssh-bad")

    _assert_fails_only(
        findings,
        _SYSTEMIC_GAPS | _MAC_MAX_STARTUPS_GAP_BY_DOCUMENT["debian_linux_12"] | {"5.1.20"},
    )


def test_assess_debian_permissions_bad_fails_only_shadow_and_sshd_config_permissions():
    # invariant-debian-permissions-bad runs debian:13, not debian:11 --
    # confirmed via collect_facts() (os_version_id "13").
    findings = assess_target("invariant-debian-permissions-bad")

    _assert_fails_only(
        findings,
        _SYSTEMIC_GAPS | _MAC_MAX_STARTUPS_GAP_BY_DOCUMENT["debian_linux_13"] | {"7.1.5"},
    )


def test_assess_ubuntu_baseline_fails_only_sshd_config_permissions():
    findings = assess_target("invariant-ubuntu-baseline")

    assert len(findings) == len(CHECKS)
    _assert_fails_only(findings, _SYSTEMIC_GAPS | _MAC_MAX_STARTUPS_GAP_BY_DOCUMENT["ubuntu_linux_20_04"])


def test_assess_ubuntu_ssh_bad_fails_only_ssh_and_sshd_config_permissions():
    # invariant-ubuntu-ssh-bad runs ubuntu:22.04, not ubuntu:20.04 --
    # confirmed via collect_facts() (os_version_id "22.04").
    findings = assess_target("invariant-ubuntu-ssh-bad")

    _assert_fails_only(
        findings,
        _SYSTEMIC_GAPS | _MAC_MAX_STARTUPS_GAP_BY_DOCUMENT["ubuntu_linux_22_04"] | {"5.1.20"},
    )


def test_assess_ubuntu_permissions_bad_fails_only_shadow_and_sshd_config_permissions():
    # invariant-ubuntu-permissions-bad runs ubuntu:24.04, not ubuntu:20.04
    # -- confirmed via collect_facts() (os_version_id "24.04").
    findings = assess_target("invariant-ubuntu-permissions-bad")

    _assert_fails_only(
        findings,
        _SYSTEMIC_GAPS | _MAC_MAX_STARTUPS_GAP_BY_DOCUMENT["ubuntu_linux_24_04"] | {"7.1.5"},
    )


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
