import pytest

from invariant.assessment import (
    _evaluate_bootloader_config_permissions,
    _evaluate_default_umask,
    _evaluate_etc_group_minus_permissions,
    _evaluate_etc_group_permissions,
    _evaluate_etc_gshadow_minus_permissions,
    _evaluate_etc_gshadow_permissions,
    _evaluate_etc_issue_net_permissions,
    _evaluate_etc_issue_permissions,
    _evaluate_etc_motd_permissions,
    _evaluate_etc_passwd_minus_permissions,
    _evaluate_etc_passwd_permissions,
    _evaluate_etc_shadow_minus_permissions,
    _evaluate_etc_shells_permissions,
    _evaluate_ftp_client_not_installed,
    _evaluate_journald_compress,
    _evaluate_journald_log_rotation,
    _evaluate_journald_storage,
    _evaluate_ldap_client_not_installed,
    _evaluate_nis_client_not_installed,
    _evaluate_only_root_group_has_gid0,
    _evaluate_pam_faillock_enabled,
    _evaluate_pam_no_nullok,
    _evaluate_pam_pwhistory_enabled,
    _evaluate_pam_pwquality_enabled,
    _evaluate_passwd_accounts_use_shadowed_passwords,
    _evaluate_prelink_not_installed,
    _evaluate_root_only_gid0_account,
    _evaluate_root_only_uid0_account,
    _evaluate_rsh_client_not_installed,
    _evaluate_rsync_not_installed,
    _evaluate_shadow_password_fields_not_empty,
    _evaluate_shadow_permissions,
    _evaluate_shells_no_nologin,
    _evaluate_ssh_ciphers,
    _evaluate_ssh_disable_forwarding,
    _evaluate_ssh_ignore_rhosts,
    _evaluate_ssh_kex_algorithms,
    _evaluate_ssh_log_level,
    _evaluate_ssh_login_grace_time,
    _evaluate_ssh_max_sessions,
    _evaluate_ssh_permit_root_login,
    _evaluate_ssh_permit_user_environment,
    _evaluate_ssh_private_host_key_permissions,
    _evaluate_ssh_public_host_key_permissions,
    _evaluate_ssh_use_pam,
    _evaluate_sshd_config_permissions,
    _evaluate_talk_client_not_installed,
    _evaluate_telnet_client_not_installed,
    _evaluate_x_window_not_installed,
    _evaluate_xinetd_not_installed,
)
from invariant.assessment.facts import FileStat, SystemFacts


def _facts(
    sshd_config=None,
    shadow_stat=None,
    file_stats=None,
    passwd_text="",
    group_text="",
    shadow_text="",
    pam_common_auth="",
    pam_common_password="",
    pam_common_account="",
    login_defs_text="",
    installed_packages=None,
    shells_text="",
    rsyslog_text="",
    journald_text="",
) -> SystemFacts:
    stats = dict(file_stats or {})
    if shadow_stat:
        stats["/etc/shadow"] = shadow_stat
    return SystemFacts(
        os_id="debian",
        os_version_id="11",
        sshd_config=sshd_config or {},
        file_stats=stats,
        passwd_text=passwd_text,
        group_text=group_text,
        shadow_text=shadow_text,
        pam_common_auth=pam_common_auth,
        pam_common_password=pam_common_password,
        pam_common_account=pam_common_account,
        login_defs_text=login_defs_text,
        installed_packages=installed_packages or set(),
        shells_text=shells_text,
        rsyslog_text=rsyslog_text,
        journald_text=journald_text,
    )


def test_ssh_evaluator_passes_when_root_login_disabled():
    facts = _facts(sshd_config={"permitrootlogin": "no"})
    assert _evaluate_ssh_permit_root_login(facts) is True


def test_ssh_evaluator_fails_when_root_login_enabled():
    facts = _facts(sshd_config={"permitrootlogin": "yes"})
    assert _evaluate_ssh_permit_root_login(facts) is False


def test_ssh_evaluator_fails_when_directive_missing():
    facts = _facts(sshd_config={})
    assert _evaluate_ssh_permit_root_login(facts) is False


def test_shadow_evaluator_passes_on_640_root_shadow():
    stat = FileStat(mode=0o640, uid=0, gid=42, gname="shadow")
    assert _evaluate_shadow_permissions(_facts(shadow_stat=stat)) is True


def test_shadow_evaluator_passes_on_more_restrictive_than_640():
    stat = FileStat(mode=0o600, uid=0, gid=0, gname="root")
    assert _evaluate_shadow_permissions(_facts(shadow_stat=stat)) is True


def test_shadow_evaluator_fails_on_world_readable():
    stat = FileStat(mode=0o644, uid=0, gid=42, gname="shadow")
    assert _evaluate_shadow_permissions(_facts(shadow_stat=stat)) is False


def test_shadow_evaluator_fails_when_not_owned_by_root():
    stat = FileStat(mode=0o640, uid=1000, gid=42, gname="shadow")
    assert _evaluate_shadow_permissions(_facts(shadow_stat=stat)) is False


def test_shadow_evaluator_fails_when_stat_missing():
    assert _evaluate_shadow_permissions(_facts()) is False


def test_permit_user_environment_evaluator_passes_when_disabled():
    facts = _facts(sshd_config={"permituserenvironment": "no"})
    assert _evaluate_ssh_permit_user_environment(facts) is True


def test_permit_user_environment_evaluator_fails_when_enabled():
    facts = _facts(sshd_config={"permituserenvironment": "yes"})
    assert _evaluate_ssh_permit_user_environment(facts) is False


def test_ignore_rhosts_evaluator_passes_when_enabled():
    facts = _facts(sshd_config={"ignorerhosts": "yes"})
    assert _evaluate_ssh_ignore_rhosts(facts) is True


def test_ignore_rhosts_evaluator_fails_when_disabled():
    facts = _facts(sshd_config={"ignorerhosts": "no"})
    assert _evaluate_ssh_ignore_rhosts(facts) is False


def test_login_grace_time_evaluator_passes_within_range():
    facts = _facts(sshd_config={"logingracetime": "30"})
    assert _evaluate_ssh_login_grace_time(facts) is True


def test_login_grace_time_evaluator_passes_at_boundaries():
    assert _evaluate_ssh_login_grace_time(_facts(sshd_config={"logingracetime": "1"})) is True
    assert _evaluate_ssh_login_grace_time(_facts(sshd_config={"logingracetime": "60"})) is True


def test_login_grace_time_evaluator_fails_above_60():
    facts = _facts(sshd_config={"logingracetime": "120"})
    assert _evaluate_ssh_login_grace_time(facts) is False


def test_login_grace_time_evaluator_fails_at_zero():
    """0 means "no timeout" in OpenSSH -- outside the 1-60s range CIS wants."""
    facts = _facts(sshd_config={"logingracetime": "0"})
    assert _evaluate_ssh_login_grace_time(facts) is False


def test_login_grace_time_evaluator_fails_on_non_numeric_value():
    facts = _facts(sshd_config={"logingracetime": "not-a-number"})
    assert _evaluate_ssh_login_grace_time(facts) is False


# --- Group A: plain file-permission checks -------------------------------
# All share the same real audit pattern confirmed against live containers
# (see _permissions_ok in invariant.assessment): stat mode <= a ceiling,
# Uid 0/root, Gid 0/root (or, for the shadow-family files, root/shadow).

_MODE_644_CASES = [
    ("etc_issue", _evaluate_etc_issue_permissions, "/etc/issue"),
    ("etc_issue_net", _evaluate_etc_issue_net_permissions, "/etc/issue.net"),
    ("etc_passwd", _evaluate_etc_passwd_permissions, "/etc/passwd"),
    ("etc_passwd_minus", _evaluate_etc_passwd_minus_permissions, "/etc/passwd-"),
    ("etc_group", _evaluate_etc_group_permissions, "/etc/group"),
    ("etc_group_minus", _evaluate_etc_group_minus_permissions, "/etc/group-"),
    ("etc_shells", _evaluate_etc_shells_permissions, "/etc/shells"),
]


@pytest.mark.parametrize("name,evaluate,path", _MODE_644_CASES, ids=[c[0] for c in _MODE_644_CASES])
def test_644_permission_evaluator_passes_at_boundary(name, evaluate, path):
    stat = FileStat(mode=0o644, uid=0, gid=0, gname="root")
    assert evaluate(_facts(file_stats={path: stat})) is True


@pytest.mark.parametrize("name,evaluate,path", _MODE_644_CASES, ids=[c[0] for c in _MODE_644_CASES])
def test_644_permission_evaluator_passes_more_restrictive(name, evaluate, path):
    stat = FileStat(mode=0o600, uid=0, gid=0, gname="root")
    assert evaluate(_facts(file_stats={path: stat})) is True


@pytest.mark.parametrize("name,evaluate,path", _MODE_644_CASES, ids=[c[0] for c in _MODE_644_CASES])
def test_644_permission_evaluator_fails_when_world_writable(name, evaluate, path):
    stat = FileStat(mode=0o666, uid=0, gid=0, gname="root")
    assert evaluate(_facts(file_stats={path: stat})) is False


@pytest.mark.parametrize("name,evaluate,path", _MODE_644_CASES, ids=[c[0] for c in _MODE_644_CASES])
def test_644_permission_evaluator_fails_when_not_owned_by_root(name, evaluate, path):
    stat = FileStat(mode=0o644, uid=1000, gid=0, gname="root")
    assert evaluate(_facts(file_stats={path: stat})) is False


@pytest.mark.parametrize("name,evaluate,path", _MODE_644_CASES, ids=[c[0] for c in _MODE_644_CASES])
def test_644_permission_evaluator_fails_when_stat_missing(name, evaluate, path):
    assert evaluate(_facts()) is False


_MODE_640_SHADOW_GROUP_CASES = [
    ("etc_shadow_minus", _evaluate_etc_shadow_minus_permissions, "/etc/shadow-"),
    ("etc_gshadow", _evaluate_etc_gshadow_permissions, "/etc/gshadow"),
    ("etc_gshadow_minus", _evaluate_etc_gshadow_minus_permissions, "/etc/gshadow-"),
]


@pytest.mark.parametrize(
    "name,evaluate,path", _MODE_640_SHADOW_GROUP_CASES, ids=[c[0] for c in _MODE_640_SHADOW_GROUP_CASES]
)
def test_640_shadow_group_evaluator_passes_on_640_root_shadow(name, evaluate, path):
    stat = FileStat(mode=0o640, uid=0, gid=42, gname="shadow")
    assert evaluate(_facts(file_stats={path: stat})) is True


@pytest.mark.parametrize(
    "name,evaluate,path", _MODE_640_SHADOW_GROUP_CASES, ids=[c[0] for c in _MODE_640_SHADOW_GROUP_CASES]
)
def test_640_shadow_group_evaluator_passes_on_600_root_root(name, evaluate, path):
    stat = FileStat(mode=0o600, uid=0, gid=0, gname="root")
    assert evaluate(_facts(file_stats={path: stat})) is True


@pytest.mark.parametrize(
    "name,evaluate,path", _MODE_640_SHADOW_GROUP_CASES, ids=[c[0] for c in _MODE_640_SHADOW_GROUP_CASES]
)
def test_640_shadow_group_evaluator_fails_when_world_readable(name, evaluate, path):
    stat = FileStat(mode=0o644, uid=0, gid=42, gname="shadow")
    assert evaluate(_facts(file_stats={path: stat})) is False


@pytest.mark.parametrize(
    "name,evaluate,path", _MODE_640_SHADOW_GROUP_CASES, ids=[c[0] for c in _MODE_640_SHADOW_GROUP_CASES]
)
def test_640_shadow_group_evaluator_fails_when_group_not_root_or_shadow(name, evaluate, path):
    stat = FileStat(mode=0o640, uid=0, gid=100, gname="users")
    assert evaluate(_facts(file_stats={path: stat})) is False


@pytest.mark.parametrize(
    "name,evaluate,path", _MODE_640_SHADOW_GROUP_CASES, ids=[c[0] for c in _MODE_640_SHADOW_GROUP_CASES]
)
def test_640_shadow_group_evaluator_fails_when_stat_missing(name, evaluate, path):
    assert evaluate(_facts()) is False


def test_sshd_config_permissions_evaluator_passes_at_600_root_root():
    stat = FileStat(mode=0o600, uid=0, gid=0, gname="root")
    assert _evaluate_sshd_config_permissions(_facts(file_stats={"/etc/ssh/sshd_config": stat})) is True


def test_sshd_config_permissions_evaluator_fails_at_644():
    """Real gotcha found validating against a live container: openssh-server's
    packaged default is mode 644, which fails CIS's 600-or-more-restrictive
    requirement -- confirmed against invariant-debian-baseline, whose Dockerfile
    was only curated to pass the 2 controls implemented before this one.
    """
    stat = FileStat(mode=0o644, uid=0, gid=0, gname="root")
    assert _evaluate_sshd_config_permissions(_facts(file_stats={"/etc/ssh/sshd_config": stat})) is False


def test_sshd_config_permissions_evaluator_fails_when_not_owned_by_root():
    stat = FileStat(mode=0o600, uid=1000, gid=0, gname="root")
    assert _evaluate_sshd_config_permissions(_facts(file_stats={"/etc/ssh/sshd_config": stat})) is False


def test_sshd_config_permissions_evaluator_fails_when_stat_missing():
    assert _evaluate_sshd_config_permissions(_facts()) is False


# --- Ensure /etc/shadow password fields are not empty ---


def test_shadow_password_fields_evaluator_passes_when_all_set():
    facts = _facts(shadow_text="root:*:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::")
    assert _evaluate_shadow_password_fields_not_empty(facts) is True


def test_shadow_password_fields_evaluator_fails_when_one_empty():
    facts = _facts(shadow_text="root::19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::")
    assert _evaluate_shadow_password_fields_not_empty(facts) is False


def test_shadow_password_fields_evaluator_passes_on_empty_text():
    """No lines to complain about is vacuously true -- an unreadable file
    is a collection concern, not something this evaluator can detect from
    text alone.
    """
    assert _evaluate_shadow_password_fields_not_empty(_facts()) is True


# --- Ensure accounts in /etc/passwd use shadowed passwords ---


def test_passwd_shadowed_evaluator_passes_when_all_x():
    facts = _facts(passwd_text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin")
    assert _evaluate_passwd_accounts_use_shadowed_passwords(facts) is True


def test_passwd_shadowed_evaluator_fails_when_hash_inline():
    facts = _facts(passwd_text="root:$6$fakehash$abc:0:0:root:/root:/bin/bash")
    assert _evaluate_passwd_accounts_use_shadowed_passwords(facts) is False


# --- Ensure root is the only GID 0 account (primary GID in /etc/passwd) ---


def test_root_only_gid0_account_evaluator_passes():
    facts = _facts(passwd_text="root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash")
    assert _evaluate_root_only_gid0_account(facts) is True


def test_root_only_gid0_account_evaluator_fails_when_another_account_has_gid0():
    facts = _facts(passwd_text="root:x:0:0:root:/root:/bin/bash\nrogue:x:5000:0::/home/rogue:/bin/sh")
    assert _evaluate_root_only_gid0_account(facts) is False


def test_root_only_gid0_account_evaluator_excludes_known_system_accounts():
    """CIS's own audit excludes sync/shutdown/halt/operator by name --
    those legitimately carry primary GID 0 without being a finding.
    """
    facts = _facts(
        passwd_text=(
            "root:x:0:0:root:/root:/bin/bash\n"
            "sync:x:4:0:sync:/bin:/bin/sync\n"
            "shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown\n"
            "halt:x:7:0:halt:/sbin:/sbin/halt\n"
            "operator:x:37:0:Operator:/var:/bin/sh"
        )
    )
    assert _evaluate_root_only_gid0_account(facts) is True


# --- Ensure root is the only UID 0 account ---


def test_root_only_uid0_account_evaluator_passes():
    facts = _facts(passwd_text="root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash")
    assert _evaluate_root_only_uid0_account(facts) is True


def test_root_only_uid0_account_evaluator_fails_when_another_account_has_uid0():
    facts = _facts(passwd_text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:0:1:daemon:/usr/sbin:/usr/sbin/nologin")
    assert _evaluate_root_only_uid0_account(facts) is False


# --- Ensure group root is the only GID 0 group ---


def test_only_root_group_has_gid0_evaluator_passes():
    facts = _facts(group_text="root:x:0:\ndaemon:x:1:")
    assert _evaluate_only_root_group_has_gid0(facts) is True


def test_only_root_group_has_gid0_evaluator_fails_when_another_group_has_gid0():
    facts = _facts(group_text="root:x:0:\ndaemon:x:0:")
    assert _evaluate_only_root_group_has_gid0(facts) is False


def test_faillock_evaluator_passes_when_present_in_both_files():
    facts = _facts(
        pam_common_auth="auth requisite pam_faillock.so preauth",
        pam_common_account="account required pam_faillock.so",
    )
    assert _evaluate_pam_faillock_enabled(facts) is True


def test_faillock_evaluator_fails_when_missing_from_auth():
    facts = _facts(
        pam_common_auth="auth [success=1 default=ignore] pam_unix.so",
        pam_common_account="account required pam_faillock.so",
    )
    assert _evaluate_pam_faillock_enabled(facts) is False


def test_faillock_evaluator_fails_when_missing_from_account():
    facts = _facts(
        pam_common_auth="auth requisite pam_faillock.so preauth",
        pam_common_account="account [success=1 default=ignore] pam_unix.so",
    )
    assert _evaluate_pam_faillock_enabled(facts) is False


def test_faillock_evaluator_fails_when_missing_entirely():
    assert _evaluate_pam_faillock_enabled(_facts()) is False


def test_pwquality_evaluator_passes_when_present():
    facts = _facts(pam_common_password="password requisite pam_pwquality.so retry=3")
    assert _evaluate_pam_pwquality_enabled(facts) is True


def test_pwquality_evaluator_fails_when_missing():
    facts = _facts(pam_common_password="password [success=1 default=ignore] pam_unix.so")
    assert _evaluate_pam_pwquality_enabled(facts) is False


def test_pwhistory_evaluator_passes_when_present():
    facts = _facts(pam_common_password="password requisite pam_pwhistory.so remember=24")
    assert _evaluate_pam_pwhistory_enabled(facts) is True


def test_pwhistory_evaluator_fails_when_missing():
    facts = _facts(pam_common_password="password [success=1 default=ignore] pam_unix.so")
    assert _evaluate_pam_pwhistory_enabled(facts) is False


def test_no_nullok_evaluator_passes_when_absent():
    facts = _facts(
        pam_common_auth="auth [success=1 default=ignore] pam_unix.so",
        pam_common_password="password [success=1 default=ignore] pam_unix.so obscure yescrypt",
        pam_common_account="account [success=1 default=ignore] pam_unix.so",
    )
    assert _evaluate_pam_no_nullok(facts) is True


def test_no_nullok_evaluator_fails_when_present_in_auth():
    facts = _facts(pam_common_auth="auth [success=1 default=ignore] pam_unix.so nullok")
    assert _evaluate_pam_no_nullok(facts) is False


def test_no_nullok_evaluator_fails_when_present_in_password():
    facts = _facts(pam_common_password="password [success=1 default=ignore] pam_unix.so nullok")
    assert _evaluate_pam_no_nullok(facts) is False


def test_no_nullok_evaluator_ignores_nullok_on_unrelated_module():
    """Only a nullok argument on the pam_unix.so line itself is a finding --
    e.g. a comment mentioning "nullok" elsewhere on the same file shouldn't
    trip the check for a different module's line."""
    facts = _facts(pam_common_auth="auth requisite pam_faillock.so preauth\n# nullok is dangerous")
    assert _evaluate_pam_no_nullok(facts) is True


def test_default_umask_evaluator_passes_at_027():
    facts = _facts(login_defs_text="UMASK\t\t027")
    assert _evaluate_default_umask(facts) is True


def test_default_umask_evaluator_passes_at_more_restrictive_than_027():
    facts = _facts(login_defs_text="UMASK\t\t077")
    assert _evaluate_default_umask(facts) is True


def test_default_umask_evaluator_fails_at_022():
    facts = _facts(login_defs_text="UMASK\t\t022")
    assert _evaluate_default_umask(facts) is False


def test_default_umask_evaluator_fails_when_missing():
    assert _evaluate_default_umask(_facts()) is False


def test_default_umask_evaluator_fails_on_non_octal_value():
    facts = _facts(login_defs_text="UMASK\t\tnot-a-number")
    assert _evaluate_default_umask(facts) is False


def test_max_sessions_evaluator_passes_at_10():
    assert _evaluate_ssh_max_sessions(_facts(sshd_config={"maxsessions": "10"})) is True


def test_max_sessions_evaluator_passes_below_10():
    assert _evaluate_ssh_max_sessions(_facts(sshd_config={"maxsessions": "5"})) is True


def test_max_sessions_evaluator_fails_above_10():
    assert _evaluate_ssh_max_sessions(_facts(sshd_config={"maxsessions": "50"})) is False


def test_max_sessions_evaluator_fails_when_directive_missing():
    assert _evaluate_ssh_max_sessions(_facts()) is False


def test_max_sessions_evaluator_fails_on_non_numeric_value():
    assert _evaluate_ssh_max_sessions(_facts(sshd_config={"maxsessions": "many"})) is False


def test_log_level_evaluator_passes_on_info():
    assert _evaluate_ssh_log_level(_facts(sshd_config={"loglevel": "INFO"})) is True


def test_log_level_evaluator_passes_on_verbose():
    """The audit text for our two demo documents (debian_linux_11,
    ubuntu_linux_20_04) explicitly accepts VERBOSE as well as INFO."""
    assert _evaluate_ssh_log_level(_facts(sshd_config={"loglevel": "VERBOSE"})) is True


def test_log_level_evaluator_fails_on_debug():
    assert _evaluate_ssh_log_level(_facts(sshd_config={"loglevel": "DEBUG3"})) is False


def test_log_level_evaluator_fails_when_directive_missing():
    assert _evaluate_ssh_log_level(_facts()) is False


def test_use_pam_evaluator_passes_when_enabled():
    assert _evaluate_ssh_use_pam(_facts(sshd_config={"usepam": "yes"})) is True


def test_use_pam_evaluator_fails_when_disabled():
    assert _evaluate_ssh_use_pam(_facts(sshd_config={"usepam": "no"})) is False


def test_use_pam_evaluator_fails_when_directive_missing():
    assert _evaluate_ssh_use_pam(_facts()) is False


def test_disable_forwarding_evaluator_passes_when_enabled():
    assert _evaluate_ssh_disable_forwarding(_facts(sshd_config={"disableforwarding": "yes"})) is True


def test_disable_forwarding_evaluator_fails_when_disabled():
    """OpenSSH's own default is "no" -- confirmed against a stock Debian 11
    container with no sshd_config hardening applied."""
    assert _evaluate_ssh_disable_forwarding(_facts(sshd_config={"disableforwarding": "no"})) is False


def test_disable_forwarding_evaluator_fails_when_directive_missing():
    assert _evaluate_ssh_disable_forwarding(_facts()) is False


def test_ciphers_evaluator_passes_with_only_strong_ciphers():
    facts = _facts(sshd_config={"ciphers": "aes256-gcm@openssh.com,aes128-ctr"})
    assert _evaluate_ssh_ciphers(facts) is True


def test_ciphers_evaluator_fails_with_cbc_cipher():
    facts = _facts(sshd_config={"ciphers": "aes256-gcm@openssh.com,3des-cbc"})
    assert _evaluate_ssh_ciphers(facts) is False


def test_ciphers_evaluator_fails_with_arcfour():
    facts = _facts(sshd_config={"ciphers": "arcfour"})
    assert _evaluate_ssh_ciphers(facts) is False


def test_ciphers_evaluator_fails_with_chacha20_poly1305():
    """Flagged by the real CIS audit regex (CVE-2023-48795 / Terrapin) --
    facts.py doesn't collect a patch level, so it's treated as weak."""
    facts = _facts(sshd_config={"ciphers": "chacha20-poly1305@openssh.com"})
    assert _evaluate_ssh_ciphers(facts) is False


def test_ciphers_evaluator_fails_when_directive_missing():
    assert _evaluate_ssh_ciphers(_facts()) is False


def test_kex_algorithms_evaluator_passes_with_only_strong_algorithms():
    facts = _facts(sshd_config={"kexalgorithms": "curve25519-sha256,ecdh-sha2-nistp256"})
    assert _evaluate_ssh_kex_algorithms(facts) is True


def test_kex_algorithms_evaluator_fails_with_weak_algorithm():
    facts = _facts(sshd_config={"kexalgorithms": "curve25519-sha256,diffie-hellman-group1-sha1"})
    assert _evaluate_ssh_kex_algorithms(facts) is False


def test_kex_algorithms_evaluator_fails_when_directive_missing():
    assert _evaluate_ssh_kex_algorithms(_facts()) is False


def test_private_host_key_permissions_passes_on_600_root():
    stat = FileStat(mode=0o600, uid=0, gid=0, gname="root")
    facts = _facts(file_stats={"/etc/ssh/ssh_host_rsa_key": stat})
    assert _evaluate_ssh_private_host_key_permissions(facts) is True


def test_private_host_key_permissions_fails_on_world_readable():
    stat = FileStat(mode=0o644, uid=0, gid=0, gname="root")
    facts = _facts(file_stats={"/etc/ssh/ssh_host_rsa_key": stat})
    assert _evaluate_ssh_private_host_key_permissions(facts) is False


def test_private_host_key_permissions_fails_when_not_owned_by_root():
    stat = FileStat(mode=0o600, uid=1000, gid=1000, gname="baduser")
    facts = _facts(file_stats={"/etc/ssh/ssh_host_rsa_key": stat})
    assert _evaluate_ssh_private_host_key_permissions(facts) is False


def test_private_host_key_permissions_passes_when_no_keys_present():
    """Matches the real CIS audit script's own "No openSSH private keys
    found" -> PASS outcome -- nothing to secure isn't a misconfiguration."""
    assert _evaluate_ssh_private_host_key_permissions(_facts()) is True


def test_private_host_key_permissions_checks_all_present_keys():
    good = FileStat(mode=0o600, uid=0, gid=0, gname="root")
    bad = FileStat(mode=0o644, uid=0, gid=0, gname="root")
    facts = _facts(
        file_stats={
            "/etc/ssh/ssh_host_rsa_key": good,
            "/etc/ssh/ssh_host_ed25519_key": bad,
        }
    )
    assert _evaluate_ssh_private_host_key_permissions(facts) is False


def test_public_host_key_permissions_passes_on_644_root():
    stat = FileStat(mode=0o644, uid=0, gid=0, gname="root")
    facts = _facts(file_stats={"/etc/ssh/ssh_host_rsa_key.pub": stat})
    assert _evaluate_ssh_public_host_key_permissions(facts) is True


def test_public_host_key_permissions_fails_on_world_writable():
    stat = FileStat(mode=0o666, uid=0, gid=0, gname="root")
    facts = _facts(file_stats={"/etc/ssh/ssh_host_rsa_key.pub": stat})
    assert _evaluate_ssh_public_host_key_permissions(facts) is False


def test_public_host_key_permissions_fails_when_not_owned_by_root():
    stat = FileStat(mode=0o644, uid=1000, gid=1000, gname="baduser")
    facts = _facts(file_stats={"/etc/ssh/ssh_host_rsa_key.pub": stat})
    assert _evaluate_ssh_public_host_key_permissions(facts) is False


def test_public_host_key_permissions_passes_when_no_keys_present():
    assert _evaluate_ssh_public_host_key_permissions(_facts()) is True


def test_ldap_client_evaluator_passes_when_absent():
    assert _evaluate_ldap_client_not_installed(_facts()) is True


def test_ldap_client_evaluator_fails_when_installed():
    facts = _facts(installed_packages={"ldap-utils"})
    assert _evaluate_ldap_client_not_installed(facts) is False


def test_nis_client_evaluator_passes_when_absent():
    assert _evaluate_nis_client_not_installed(_facts()) is True


def test_nis_client_evaluator_fails_when_installed():
    facts = _facts(installed_packages={"nis"})
    assert _evaluate_nis_client_not_installed(facts) is False


def test_xinetd_evaluator_passes_when_absent():
    assert _evaluate_xinetd_not_installed(_facts()) is True


def test_xinetd_evaluator_fails_when_installed():
    facts = _facts(installed_packages={"xinetd"})
    assert _evaluate_xinetd_not_installed(facts) is False


def test_rsync_evaluator_passes_when_absent():
    assert _evaluate_rsync_not_installed(_facts()) is True


def test_rsync_evaluator_fails_when_installed():
    facts = _facts(installed_packages={"rsync"})
    assert _evaluate_rsync_not_installed(facts) is False


def test_x_window_evaluator_passes_when_absent():
    assert _evaluate_x_window_not_installed(_facts()) is True


def test_x_window_evaluator_fails_when_installed():
    facts = _facts(installed_packages={"xserver-common"})
    assert _evaluate_x_window_not_installed(facts) is False


def test_telnet_client_evaluator_passes_when_absent():
    assert _evaluate_telnet_client_not_installed(_facts()) is True


def test_telnet_client_evaluator_fails_when_telnet_installed():
    facts = _facts(installed_packages={"telnet"})
    assert _evaluate_telnet_client_not_installed(facts) is False


def test_telnet_client_evaluator_fails_when_inetutils_telnet_installed():
    """Newer CIS docs (Debian 12/13, Ubuntu 24.04) also forbid the
    inetutils-telnet alternative, not just the "telnet" package name."""
    facts = _facts(installed_packages={"inetutils-telnet"})
    assert _evaluate_telnet_client_not_installed(facts) is False


def test_rsh_client_evaluator_passes_when_absent():
    assert _evaluate_rsh_client_not_installed(_facts()) is True


def test_rsh_client_evaluator_fails_when_installed():
    facts = _facts(installed_packages={"rsh-client"})
    assert _evaluate_rsh_client_not_installed(facts) is False


def test_ftp_client_evaluator_passes_when_absent():
    assert _evaluate_ftp_client_not_installed(_facts()) is True


def test_ftp_client_evaluator_fails_when_ftp_installed():
    facts = _facts(installed_packages={"ftp"})
    assert _evaluate_ftp_client_not_installed(facts) is False


def test_ftp_client_evaluator_fails_when_tnftp_installed():
    """Newer CIS docs (Debian 12/13, Ubuntu 22.04/24.04) also forbid the
    tnftp alternative, not just the "ftp" package name."""
    facts = _facts(installed_packages={"tnftp"})
    assert _evaluate_ftp_client_not_installed(facts) is False


def test_talk_client_evaluator_passes_when_absent():
    assert _evaluate_talk_client_not_installed(_facts()) is True


def test_talk_client_evaluator_fails_when_installed():
    facts = _facts(installed_packages={"talk"})
    assert _evaluate_talk_client_not_installed(facts) is False


def test_prelink_evaluator_passes_when_absent():
    assert _evaluate_prelink_not_installed(_facts()) is True


def test_prelink_evaluator_fails_when_installed():
    facts = _facts(installed_packages={"prelink"})
    assert _evaluate_prelink_not_installed(facts) is False


# --- Group J: journald config + standalone file checks -------------------


def test_journald_compress_evaluator_passes_when_yes():
    facts = _facts(journald_text="[Journal]\nCompress=yes\n")
    assert _evaluate_journald_compress(facts) is True


def test_journald_compress_evaluator_fails_when_no():
    facts = _facts(journald_text="[Journal]\nCompress=no\n")
    assert _evaluate_journald_compress(facts) is False


def test_journald_compress_evaluator_fails_when_not_set():
    facts = _facts(journald_text="[Journal]\n")
    assert _evaluate_journald_compress(facts) is False


def test_journald_compress_evaluator_ignores_commented_lines():
    facts = _facts(journald_text="[Journal]\n#Compress=yes\n")
    assert _evaluate_journald_compress(facts) is False


def test_journald_storage_evaluator_passes_when_persistent():
    facts = _facts(journald_text="[Journal]\nStorage=persistent\n")
    assert _evaluate_journald_storage(facts) is True


def test_journald_storage_evaluator_fails_when_auto():
    facts = _facts(journald_text="[Journal]\nStorage=auto\n")
    assert _evaluate_journald_storage(facts) is False


def test_journald_storage_evaluator_fails_when_not_set():
    assert _evaluate_journald_storage(_facts(journald_text="[Journal]\n")) is False


def test_journald_log_rotation_evaluator_passes_when_one_directive_set():
    facts = _facts(journald_text="[Journal]\nSystemMaxUse=500M\n")
    assert _evaluate_journald_log_rotation(facts) is True


def test_journald_log_rotation_evaluator_passes_when_different_directive_set():
    facts = _facts(journald_text="[Journal]\nRuntimeKeepFree=1G\n")
    assert _evaluate_journald_log_rotation(facts) is True


def test_journald_log_rotation_evaluator_fails_when_none_set():
    facts = _facts(journald_text="[Journal]\nCompress=yes\n")
    assert _evaluate_journald_log_rotation(facts) is False


def test_shells_no_nologin_evaluator_passes_on_normal_shells():
    facts = _facts(shells_text="# /etc/shells\n/bin/sh\n/bin/bash\n/bin/dash\n")
    assert _evaluate_shells_no_nologin(facts) is True


def test_shells_no_nologin_evaluator_fails_when_usr_sbin_nologin_listed():
    facts = _facts(shells_text="# /etc/shells\n/bin/sh\n/usr/sbin/nologin\n")
    assert _evaluate_shells_no_nologin(facts) is False


def test_shells_no_nologin_evaluator_fails_when_sbin_nologin_listed():
    facts = _facts(shells_text="# /etc/shells\n/sbin/nologin\n")
    assert _evaluate_shells_no_nologin(facts) is False


def test_shells_no_nologin_evaluator_ignores_commented_lines():
    facts = _facts(shells_text="# /usr/sbin/nologin\n/bin/sh\n")
    assert _evaluate_shells_no_nologin(facts) is True


def test_motd_permissions_evaluator_passes_on_644_root():
    stat = FileStat(mode=0o644, uid=0, gid=0, gname="root")
    assert _evaluate_etc_motd_permissions(_facts(file_stats={"/etc/motd": stat})) is True


def test_motd_permissions_evaluator_fails_when_world_writable():
    stat = FileStat(mode=0o666, uid=0, gid=0, gname="root")
    assert _evaluate_etc_motd_permissions(_facts(file_stats={"/etc/motd": stat})) is False


def test_motd_permissions_evaluator_fails_when_not_owned_by_root():
    stat = FileStat(mode=0o644, uid=1000, gid=0, gname="root")
    assert _evaluate_etc_motd_permissions(_facts(file_stats={"/etc/motd": stat})) is False


def test_motd_permissions_evaluator_passes_when_file_absent():
    """Real audit's own documented pass condition: "-- OR -- Nothing is
    returned" when /etc/motd doesn't exist at all (confirmed empirically:
    plain ubuntu:22.04 ships with no /etc/motd)."""
    assert _evaluate_etc_motd_permissions(_facts()) is True


def test_bootloader_config_permissions_evaluator_passes_on_600_root():
    stat = FileStat(mode=0o600, uid=0, gid=0, gname="root")
    assert _evaluate_bootloader_config_permissions(_facts(file_stats={"/boot/grub/grub.cfg": stat})) is True


def test_bootloader_config_permissions_evaluator_fails_when_world_readable():
    stat = FileStat(mode=0o644, uid=0, gid=0, gname="root")
    assert _evaluate_bootloader_config_permissions(_facts(file_stats={"/boot/grub/grub.cfg": stat})) is False


def test_bootloader_config_permissions_evaluator_fails_when_not_owned_by_root():
    stat = FileStat(mode=0o600, uid=1000, gid=0, gname="root")
    assert _evaluate_bootloader_config_permissions(_facts(file_stats={"/boot/grub/grub.cfg": stat})) is False


def test_bootloader_config_permissions_evaluator_fails_when_file_absent():
    """Unlike /etc/motd, the real audit has no "file absent -> PASS" clause
    for the bootloader config -- fails closed (confirmed empirically that
    bare debian:12/ubuntu:22.04 containers have no /boot/grub/grub.cfg at
    all, since no bootloader is installed in a container)."""
    assert _evaluate_bootloader_config_permissions(_facts()) is False
