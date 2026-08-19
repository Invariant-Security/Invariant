from invariant.assessment import (
    _evaluate_default_umask,
    _evaluate_pam_faillock_enabled,
    _evaluate_pam_no_nullok,
    _evaluate_pam_pwhistory_enabled,
    _evaluate_pam_pwquality_enabled,
    _evaluate_shadow_permissions,
    _evaluate_ssh_ignore_rhosts,
    _evaluate_ssh_login_grace_time,
    _evaluate_ssh_permit_root_login,
    _evaluate_ssh_permit_user_environment,
)
from invariant.assessment.facts import FileStat, SystemFacts


def _facts(
    sshd_config=None,
    shadow_stat=None,
    pam_common_auth="",
    pam_common_password="",
    pam_common_account="",
    login_defs_text="",
) -> SystemFacts:
    return SystemFacts(
        os_id="debian",
        os_version_id="11",
        sshd_config=sshd_config or {},
        file_stats={"/etc/shadow": shadow_stat} if shadow_stat else {},
        pam_common_auth=pam_common_auth,
        pam_common_password=pam_common_password,
        pam_common_account=pam_common_account,
        login_defs_text=login_defs_text,
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
