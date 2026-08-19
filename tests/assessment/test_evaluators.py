from invariant.assessment import (
    _evaluate_shadow_permissions,
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
)
from invariant.assessment.facts import FileStat, SystemFacts


def _facts(sshd_config=None, shadow_stat=None, file_stats=None) -> SystemFacts:
    stats = dict(file_stats or {})
    if shadow_stat:
        stats["/etc/shadow"] = shadow_stat
    return SystemFacts(
        os_id="debian",
        os_version_id="11",
        sshd_config=sshd_config or {},
        file_stats=stats,
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
