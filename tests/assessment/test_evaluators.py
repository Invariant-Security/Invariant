from invariant.assessment import (
    _evaluate_shadow_permissions,
    _evaluate_ssh_ignore_rhosts,
    _evaluate_ssh_login_grace_time,
    _evaluate_ssh_permit_root_login,
    _evaluate_ssh_permit_user_environment,
)
from invariant.assessment.facts import FileStat, SystemFacts


def _facts(sshd_config=None, shadow_stat=None) -> SystemFacts:
    return SystemFacts(
        os_id="debian",
        os_version_id="11",
        sshd_config=sshd_config or {},
        file_stats={"/etc/shadow": shadow_stat} if shadow_stat else {},
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
