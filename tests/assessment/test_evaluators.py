from invariant.assessment import (
    _evaluate_only_root_group_has_gid0,
    _evaluate_passwd_accounts_use_shadowed_passwords,
    _evaluate_root_only_gid0_account,
    _evaluate_root_only_uid0_account,
    _evaluate_shadow_password_fields_not_empty,
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
    passwd_text="",
    group_text="",
    shadow_text="",
) -> SystemFacts:
    return SystemFacts(
        os_id="debian",
        os_version_id="11",
        sshd_config=sshd_config or {},
        file_stats={"/etc/shadow": shadow_stat} if shadow_stat else {},
        passwd_text=passwd_text,
        group_text=group_text,
        shadow_text=shadow_text,
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
