from invariant.assessment import (
    _evaluate_ftp_client_not_installed,
    _evaluate_ldap_client_not_installed,
    _evaluate_nis_client_not_installed,
    _evaluate_prelink_not_installed,
    _evaluate_rsh_client_not_installed,
    _evaluate_rsync_not_installed,
    _evaluate_shadow_permissions,
    _evaluate_ssh_ignore_rhosts,
    _evaluate_ssh_login_grace_time,
    _evaluate_ssh_permit_root_login,
    _evaluate_ssh_permit_user_environment,
    _evaluate_talk_client_not_installed,
    _evaluate_telnet_client_not_installed,
    _evaluate_x_window_not_installed,
    _evaluate_xinetd_not_installed,
)
from invariant.assessment.facts import FileStat, SystemFacts


def _facts(sshd_config=None, shadow_stat=None, installed_packages=None) -> SystemFacts:
    return SystemFacts(
        os_id="debian",
        os_version_id="11",
        sshd_config=sshd_config or {},
        file_stats={"/etc/shadow": shadow_stat} if shadow_stat else {},
        installed_packages=installed_packages or set(),
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
