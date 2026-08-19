import pytest

from invariant.assessment import (
    _evaluate_etc_group_minus_permissions,
    _evaluate_etc_group_permissions,
    _evaluate_etc_gshadow_minus_permissions,
    _evaluate_etc_gshadow_permissions,
    _evaluate_etc_issue_net_permissions,
    _evaluate_etc_issue_permissions,
    _evaluate_etc_passwd_minus_permissions,
    _evaluate_etc_passwd_permissions,
    _evaluate_etc_shadow_minus_permissions,
    _evaluate_etc_shells_permissions,
    _evaluate_shadow_permissions,
    _evaluate_ssh_ignore_rhosts,
    _evaluate_ssh_login_grace_time,
    _evaluate_ssh_permit_root_login,
    _evaluate_ssh_permit_user_environment,
    _evaluate_sshd_config_permissions,
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
