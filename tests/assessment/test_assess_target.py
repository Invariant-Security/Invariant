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
    _MAC_MAX_STARTUPS_GAP_BY_DOCUMENT and _AUDIT_FILES_GAP_BY_DOCUMENT below
    for how every id that actually drifts across documents is kept
    id-collision-safe by looking it up per target instead of assuming one
    literal resolves everywhere.
    """
    statuses = {f.external_id: f.status for f in findings}
    assert len(statuses) == len(CHECKS)
    for external_id in expected_failing_ids:
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
    "5.3.3.4.4",  # pam_unix includes use_authtok
    "5.3.3.3.3",  # pam_pwhistory includes use_authtok
    # Group H: sudoers + cron file permissions -- same "package never
    # installed" story (see the comment near the top of this set).
    "2.4.1.2",  # /etc/crontab
    "2.4.1.3",  # /etc/cron.hourly
    "2.4.1.4",  # /etc/cron.daily
    "2.4.1.5",  # /etc/cron.weekly
    "2.4.1.6",  # /etc/cron.monthly
    "2.4.1.8",  # /etc/cron.d (debian_linux_11 uses 2.4.1.7 instead, see below)
    "5.2.3",  # Ensure sudo log file exists
    "1.4.2",  # Ensure access to bootloader config is configured (Group J)
    # Group K: "Ensure ufw is installed" -- ufw isn't installed on any of
    # the 6 live containers (same "package never installed, never hardened
    # for it" story as the rest of this set), confirmed via
    # assess_target() against all 6. Id is "4.1.1" on 5 of 6 real target
    # documents; ubuntu_linux_20_04 (the ubuntu-baseline target) uses
    # "4.2.1" instead -- excluded/re-added per-target below, same pattern
    # already used for "2.4.1.8"/"2.4.1.7".
    "4.1.1",
    # Round 2 (Groups L-Q): 6 of the 9 newly-added checks that fail on all
    # 6 live containers share the same external_id everywhere (confirmed
    # via assess_target() against all 6) -- none of the 6 Dockerfiles set
    # sshd AllowUsers/AllowGroups/DenyUsers/DenyGroups, sshd Banner,
    # ClientAliveInterval/CountMax, install sudo, or configure password
    # expiration (login.defs PASS_MAX_DAYS/shadow max-days), same
    # "package/directive never hardened for it" story as the rest of this
    # set. The other 3 (MaxAuthTries, auditd packages, AIDE) drift per
    # document -- see _ROUND2_GAP_BY_DOCUMENT below.
    "5.1.4",  # Ensure sshd access is configured
    "5.1.5",  # Ensure sshd Banner is configured
    "5.1.7",  # Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured
    "5.2.1",  # Ensure sudo is installed
    "5.2.2",  # Ensure sudo commands use pty
    "5.4.1.1",  # Ensure password expiration is configured
    # Round 3 (kernel modules, faillock, su-restriction, root-umask, full-fs
    # scans): only 2 of the 20 newly-added checks fail on the 6 live
    # containers, both with the same external_id on all 6 (confirmed via
    # assess_target()) -- none of the 6 Dockerfiles configure
    # /etc/pam.d/su's pam_wheel.so line, or set even_deny_root/
    # root_unlock_time in faillock.conf. Everything else this round
    # (12 kernel-module checks -- /lib/modules never exists in any of the 6
    # containers, so they PASS vacuously per CIS's own documented passing
    # state; 2 more faillock checks; root umask; world-writable/unowned/
    # root-PATH) already passes with zero further changes.
    "5.2.7",  # Ensure access to the su command is restricted
    "5.3.3.1.3",  # Ensure password failed attempts lockout includes root account
    # checks-backlog.md Group B, resolved: none of the 6 Dockerfiles
    # configure /etc/systemd/timesyncd.conf (confirmed via assess_target()
    # against all 6 live containers -- the file doesn't exist, same "package
    # never hardened for it" story as the rest of this set), same
    # external_id "2.3.2.1" on every document. The other Group B check,
    # "Ensure systemd-journal-remote service is not in use", passes
    # vacuously everywhere instead (see facts.journal_remote_status_text),
    # so it isn't listed here.
    "2.3.2.1",
    # checks-backlog.md Group C's partition family: 25 of 26 candidates
    # (19 "<option> set on <mount>" + 7 "separate partition exists"/"is a
    # separate partition") pass on all 6 real containers now that
    # infra/docker-compose.yml tmpfs-mounts /tmp, /home, /var/tmp, /var/log,
    # /var/log/audit (/dev/shm is already tmpfs by Docker's own default) --
    # confirmed via assess_target() against all 6, same external_id
    # everywhere (see the Postgres check that confirmed this). The one
    # exception, stable "1.1.2.4.1" on every document: /var itself is
    # deliberately NOT tmpfs-mounted (see docker-compose.yml's own comment
    # above the 6 services -- it would blank /var/lib/dpkg, breaking every
    # package-presence check's `installed_packages` collection), so "Ensure
    # separate partition exists for /var" stays failing. The nodev/nosuid
    # option checks *on* /var don't need listing here: CIS's own audit for
    # those is conditional ("- IF - a separate partition exists for /var"),
    # so leaving /var unmounted makes them pass vacuously instead.
    "1.1.2.4.1",
}

# Round 2: the other 3 of the 9 newly-failing checks drift per document.
# MaxAuthTries is "5.1.16" everywhere except debian_linux_13 ("5.1.17");
# auditd/AIDE's numbering follows the same per-document section drift
# already established by _AUDIT_FILES_GAP_BY_DOCUMENT above (debian_11 uses
# 6.4.x/6.1.x, ubuntu_20_04 uses 6.3.x/6.1.x, the other 4 use 6.2.x/6.3.x)
# -- confirmed via assess_target() against all 6 live containers, not
# guessed.
_ROUND2_GAP_BY_DOCUMENT = {
    "debian_linux_11": {"5.1.16", "6.1.1", "6.4.1.1"},
    "debian_linux_12": {"5.1.16", "6.2.1.1", "6.3.1"},
    "debian_linux_13": {"5.1.17", "6.2.1.1", "6.3.1"},
    "ubuntu_linux_20_04": {"5.1.16", "6.1.1", "6.3.1.1"},
    "ubuntu_linux_22_04": {"5.1.16", "6.2.1.1", "6.3.1"},
    "ubuntu_linux_24_04": {"5.1.16", "6.2.1.1", "6.3.1"},
}

# Group I: auditd config/tooling file ownership + rules immutability. None
# of the 6 Dockerfiles install auditd at all (confirmed: `dpkg -s auditd`
# fails, /etc/audit and /sbin/auditctl don't exist on all 6 live
# containers), so every one of these 5 new checks fails closed on every
# live demo target -- same "real, systemic, not a bug in any check" story
# as the rest of _SYSTEMIC_GAPS, just discovered by this group instead.
# Unlike that flat set, this section's numbering isn't shared across all 6
# real target documents (debian_11 uses 6.4.x, ubuntu_20_04 uses 6.3.x,
# the other 4 use 6.2.x, and even within that the "immutable" control's id
# differs per document) -- looked up by the target's own document, same
# collision-safety reasoning as _MAC_MAX_STARTUPS_GAP_BY_DOCUMENT below,
# rather than lumped into one flat set relying on a silent skip.
_AUDIT_FILES_GAP_BY_DOCUMENT = {
    "debian_linux_11": {"6.4.4.6", "6.4.4.7", "6.4.4.9", "6.4.4.10", "6.4.3.20"},
    "debian_linux_12": {"6.2.4.6", "6.2.4.7", "6.2.4.9", "6.2.4.10", "6.2.3.29"},
    "debian_linux_13": {"6.2.4.6", "6.2.4.7", "6.2.4.9", "6.2.4.10", "6.2.3.36"},
    "ubuntu_linux_20_04": {"6.3.4.6", "6.3.4.7", "6.3.4.9", "6.3.4.10", "6.3.3.20"},
    "ubuntu_linux_22_04": {"6.2.4.6", "6.2.4.7", "6.2.4.9", "6.2.4.10", "6.2.3.20"},
    "ubuntu_linux_24_04": {"6.2.4.6", "6.2.4.7", "6.2.4.9", "6.2.4.10", "6.2.3.29"},
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

# Round 4 (auditd.conf family + audit rule collection + single time-sync
# daemon): 16 of the 23 newly-added checks fail on all 6 live containers,
# same "package/rule never configured for it" story as the rest of this
# file -- confirmed via assess_target() against all 6, not guessed. None of
# the 6 Dockerfiles install chrony or systemd-timesyncd explicitly (the
# single-time-sync-daemon check wants exactly one, neither counts as a
# fail, external_id "2.3.1.1" on every document), configure any real
# auditd.conf directive beyond its shipped defaults (7 of the 10 auditd.conf-
# family checks already pass on the untouched defaults; the other 3 --
# storage size, not-auto-deleted, disabled/warns-on-full -- and the log
# file/dir/tools mode checks fail because the shipped defaults don't meet
# CIS's stricter modes/values), or load any real audit rule (all 8
# audit-rule-collection checks fail closed on an empty audit.rules). Same
# per-document numbering drift as _AUDIT_FILES_GAP_BY_DOCUMENT above
# (this whole family lives in the same 6.x audit section), looked up by
# document for the same collision-safety reason.
_ROUND4_GAP_BY_DOCUMENT = {
    "debian_linux_11": {
        "2.3.1.1",
        "6.4.2.1", "6.4.2.2", "6.4.2.3", "6.4.2.4",
        "6.4.3.2", "6.4.3.3", "6.4.3.4", "6.4.3.7",
        "6.4.3.10", "6.4.3.11", "6.4.3.12", "6.4.3.14",
        "6.4.4.1", "6.4.4.4", "6.4.4.8",
    },
    "debian_linux_12": {
        "2.3.1.1",
        "6.2.2.1", "6.2.2.2", "6.2.2.3", "6.2.2.4",
        "6.2.3.2", "6.2.3.3", "6.2.3.4", "6.2.3.17",
        "6.2.3.19", "6.2.3.20", "6.2.3.21", "6.2.3.23",
        "6.2.4.1", "6.2.4.2", "6.2.4.8",
    },
    "debian_linux_13": {
        "2.3.1.1",
        "6.2.2.1", "6.2.2.2", "6.2.2.3", "6.2.2.4",
        "6.2.3.2", "6.2.3.3", "6.2.3.4", "6.2.3.11",
        "6.2.3.21", "6.2.3.22", "6.2.3.23", "6.2.3.26",
        "6.2.4.1", "6.2.4.4", "6.2.4.8",
    },
    "ubuntu_linux_20_04": {
        "2.3.1.1",
        "6.3.2.1", "6.3.2.2", "6.3.2.3", "6.3.2.4",
        "6.3.3.2", "6.3.3.3", "6.3.3.4", "6.3.3.7",
        "6.3.3.10", "6.3.3.11", "6.3.3.12", "6.3.3.14",
        "6.3.4.1", "6.3.4.4", "6.3.4.8",
    },
    "ubuntu_linux_22_04": {
        "2.3.1.1",
        "6.2.2.1", "6.2.2.2", "6.2.2.3", "6.2.2.4",
        "6.2.3.2", "6.2.3.3", "6.2.3.4", "6.2.3.7",
        "6.2.3.10", "6.2.3.11", "6.2.3.12", "6.2.3.14",
        "6.2.4.1", "6.2.4.4", "6.2.4.8",
    },
    "ubuntu_linux_24_04": {
        "2.3.1.1",
        "6.2.2.1", "6.2.2.2", "6.2.2.3", "6.2.2.4",
        "6.2.3.2", "6.2.3.3", "6.2.3.4", "6.2.3.17",
        "6.2.3.19", "6.2.3.20", "6.2.3.21", "6.2.3.23",
        "6.2.4.1", "6.2.4.2", "6.2.4.8",
    },
}

# checks-backlog.md "Grupo C -- systemd real" (6 checks, previously
# entirely unimplemented -- no facts.py field, no Check existed for any of
# them). None of the 6 live containers run systemd as PID 1 or install
# auditd, so of the 6 new checks only the 2 *unconditional* ones fail here
# (auditd enabled+active, running-matches-on-disk) -- confirmed via
# assess_target() against all 6, not guessed. The other 4 are gated
# "- IF - <daemon> is in use" in CIS's own audit text and pass vacuously
# (chrony/cron/systemd-timesyncd are all absent, same substitution already
# used by _SYSTEMIC_GAPS's "2.3.1.1" single-time-sync-daemon entry).
# Stable external_ids across all 6 documents for the auditd check would be
# nice but aren't -- same 6.x-section drift as _AUDIT_FILES_GAP_BY_DOCUMENT
# above (this family lives in that same section), looked up by document.
_SYSTEMD_REAL_GAP_BY_DOCUMENT = {
    "debian_linux_11": {"6.4.1.2", "6.4.3.21"},
    "debian_linux_12": {"6.2.1.2", "6.2.3.30"},
    "debian_linux_13": {"6.2.1.2", "6.2.3.37"},
    "ubuntu_linux_20_04": {"6.3.1.2", "6.3.3.21"},
    "ubuntu_linux_22_04": {"6.2.1.2", "6.2.3.21"},
    "ubuntu_linux_24_04": {"6.2.1.2", "6.2.3.30"},
}


def test_assess_debian_baseline_fails_only_sshd_config_permissions():
    findings = assess_target("invariant-debian-baseline")

    assert len(findings) == len(CHECKS)
    # debian_linux_11 (this target's document) has no cron.yearly control,
    # so its /etc/cron.d control is 2.4.1.7, not the 2.4.1.8 every other
    # real target document uses -- see _SYSTEMIC_GAPS's comment above. It
    # also has its own nested journald external_ids (Group J).
    _assert_fails_only(
        findings,
        (_SYSTEMIC_GAPS - {"2.4.1.8"})
        | {"2.4.1.7", "6.2.1.1.3", "6.2.1.1.5", "6.2.1.1.6"}
        | _AUDIT_FILES_GAP_BY_DOCUMENT["debian_linux_11"]
        | _MAC_MAX_STARTUPS_GAP_BY_DOCUMENT["debian_linux_11"]
        | _ROUND2_GAP_BY_DOCUMENT["debian_linux_11"]
        | _ROUND4_GAP_BY_DOCUMENT["debian_linux_11"]
        | _SYSTEMD_REAL_GAP_BY_DOCUMENT["debian_linux_11"],
    )


def test_assess_debian_ssh_bad_fails_only_ssh_and_sshd_config_permissions():
    # invariant-debian-ssh-bad runs debian:12, not debian:11 -- confirmed
    # via collect_facts() (os_version_id "12").
    findings = assess_target("invariant-debian-ssh-bad")

    _assert_fails_only(
        findings,
        _SYSTEMIC_GAPS
        | {"5.1.20", "6.1.1.1.5", "6.1.1.1.6", "6.1.1.1.7"}
        | _AUDIT_FILES_GAP_BY_DOCUMENT["debian_linux_12"]
        | _MAC_MAX_STARTUPS_GAP_BY_DOCUMENT["debian_linux_12"]
        | _ROUND2_GAP_BY_DOCUMENT["debian_linux_12"]
        | _ROUND4_GAP_BY_DOCUMENT["debian_linux_12"]
        | _SYSTEMD_REAL_GAP_BY_DOCUMENT["debian_linux_12"],
    )


def test_assess_debian_permissions_bad_fails_only_shadow_and_sshd_config_permissions():
    # invariant-debian-permissions-bad runs debian:13, not debian:11 --
    # confirmed via collect_facts() (os_version_id "13").
    findings = assess_target("invariant-debian-permissions-bad")

    _assert_fails_only(
        findings,
        _SYSTEMIC_GAPS
        | {"7.1.5", "6.1.1.1.3", "6.1.1.1.5", "6.1.1.1.6"}
        | _AUDIT_FILES_GAP_BY_DOCUMENT["debian_linux_13"]
        | _MAC_MAX_STARTUPS_GAP_BY_DOCUMENT["debian_linux_13"]
        | _ROUND2_GAP_BY_DOCUMENT["debian_linux_13"]
        | _ROUND4_GAP_BY_DOCUMENT["debian_linux_13"]
        | _SYSTEMD_REAL_GAP_BY_DOCUMENT["debian_linux_13"],
    )


def test_assess_ubuntu_baseline_fails_only_sshd_config_permissions():
    findings = assess_target("invariant-ubuntu-baseline")

    assert len(findings) == len(CHECKS)
    # ubuntu_linux_20_04 (this target's document) uses "4.2.1" for "Ensure
    # ufw is installed", not the "4.1.1" every other real target document
    # uses -- see _SYSTEMIC_GAPS's Group K comment above.
    _assert_fails_only(
        findings,
        (_SYSTEMIC_GAPS - {"4.1.1"})
        | {"4.2.1", "6.2.1.3", "6.2.2.3", "6.2.2.4"}
        | _AUDIT_FILES_GAP_BY_DOCUMENT["ubuntu_linux_20_04"]
        | _MAC_MAX_STARTUPS_GAP_BY_DOCUMENT["ubuntu_linux_20_04"]
        | _ROUND2_GAP_BY_DOCUMENT["ubuntu_linux_20_04"]
        | _ROUND4_GAP_BY_DOCUMENT["ubuntu_linux_20_04"]
        | _SYSTEMD_REAL_GAP_BY_DOCUMENT["ubuntu_linux_20_04"],
    )


def test_assess_ubuntu_ssh_bad_fails_only_ssh_and_sshd_config_permissions():
    # invariant-ubuntu-ssh-bad runs ubuntu:22.04, not ubuntu:20.04 --
    # confirmed via collect_facts() (os_version_id "22.04").
    findings = assess_target("invariant-ubuntu-ssh-bad")

    _assert_fails_only(
        findings,
        _SYSTEMIC_GAPS
        | {"5.1.20", "6.1.1.1.3", "6.1.1.1.5", "6.1.1.1.6"}
        | _AUDIT_FILES_GAP_BY_DOCUMENT["ubuntu_linux_22_04"]
        | _MAC_MAX_STARTUPS_GAP_BY_DOCUMENT["ubuntu_linux_22_04"]
        | _ROUND2_GAP_BY_DOCUMENT["ubuntu_linux_22_04"]
        | _ROUND4_GAP_BY_DOCUMENT["ubuntu_linux_22_04"]
        | _SYSTEMD_REAL_GAP_BY_DOCUMENT["ubuntu_linux_22_04"],
    )


def test_assess_ubuntu_permissions_bad_fails_only_shadow_and_sshd_config_permissions():
    # invariant-ubuntu-permissions-bad runs ubuntu:24.04, not ubuntu:20.04
    # -- confirmed via collect_facts() (os_version_id "24.04").
    findings = assess_target("invariant-ubuntu-permissions-bad")

    _assert_fails_only(
        findings,
        _SYSTEMIC_GAPS
        | {"7.1.5", "6.1.1.1.5", "6.1.1.1.6", "6.1.1.1.7"}
        | _AUDIT_FILES_GAP_BY_DOCUMENT["ubuntu_linux_24_04"]
        | _MAC_MAX_STARTUPS_GAP_BY_DOCUMENT["ubuntu_linux_24_04"]
        | _ROUND2_GAP_BY_DOCUMENT["ubuntu_linux_24_04"]
        | _ROUND4_GAP_BY_DOCUMENT["ubuntu_linux_24_04"]
        | _SYSTEMD_REAL_GAP_BY_DOCUMENT["ubuntu_linux_24_04"],
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
