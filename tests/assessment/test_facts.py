import pytest

from invariant.assessment.facts import (
    _MARKER_OS_RELEASE,
    _MARKER_SSHD_CONFIG,
    _MARKER_STAT_PREFIX,
    _STAT_PATHS,
    _TEXT_BLOCKS,
    _parse_collect_output,
    _parse_installed_packages,
    _parse_stat_line,
    is_running_in_container,
    parse_sshd_config,
)


def _build_full_output(overrides: dict[str, str] | None = None) -> str:
    """Builds a synthetic docker-exec output matching what _collect_script()
    produces, driven off the real marker lists so this fixture doesn't rot
    as more text blocks / stat paths are added.
    """
    overrides = overrides or {}
    parts = [f"{_MARKER_OS_RELEASE}\nID=debian\nVERSION_ID=\"11\"\n"]
    parts.append(f"{_MARKER_SSHD_CONFIG}\nPermitRootLogin no\n")
    for attr, marker, _cmd in _TEXT_BLOCKS:
        parts.append(f"{marker}\n{overrides.get(attr, '')}\n")
    for path in _STAT_PATHS:
        parts.append(f"{_MARKER_STAT_PREFIX}{path}===\nmode=640 uid=0 gid=42 gname=shadow\n")
    return "".join(parts)


def test_parse_sshd_config_lowercases_directives():
    text = "PermitRootLogin no\nPasswordAuthentication yes\n"
    assert parse_sshd_config(text) == {"permitrootlogin": "no", "passwordauthentication": "yes"}


def test_parse_sshd_config_skips_comments_and_blank_lines():
    text = "# this is a comment\n\nPermitRootLogin no\n   \n"
    assert parse_sshd_config(text) == {"permitrootlogin": "no"}


def test_parse_sshd_config_later_line_wins_on_duplicate():
    text = "PermitRootLogin no\nPermitRootLogin yes\n"
    assert parse_sshd_config(text) == {"permitrootlogin": "yes"}


def test_parse_stat_line_extracts_mode_uid_gid():
    stat = _parse_stat_line("mode=640 uid=0 gid=42 gname=shadow")
    assert stat.mode == 0o640
    assert stat.uid == 0
    assert stat.gid == 42
    assert stat.gname == "shadow"


def test_parse_stat_line_returns_none_fields_on_stat_error():
    stat = _parse_stat_line("stat: cannot statx '/etc/shadow': No such file or directory")
    assert stat.mode is None
    assert stat.uid is None


def test_parse_installed_packages_splits_lines_and_strips_blank():
    assert _parse_installed_packages("bash\n\ncoreutils\n") == {"bash", "coreutils"}


def test_parse_installed_packages_empty_on_no_output():
    assert _parse_installed_packages("") == set()


def test_parse_collect_output_full_script_output():
    output = _build_full_output(
        {
            "passwd_text": "root:x:0:0:root:/root:/bin/bash",
            "installed_packages_text": "bash\ncoreutils\nopenssh-server\n",
        }
    )

    facts = _parse_collect_output(output)

    assert facts.os_id == "debian"
    assert facts.os_version_id == "11"
    assert facts.sshd_config == {"permitrootlogin": "no"}
    assert facts.file_stats["/etc/shadow"].mode == 0o640
    assert facts.passwd_text == "root:x:0:0:root:/root:/bin/bash"
    assert facts.installed_packages == {"bash", "coreutils", "openssh-server"}


def test_parse_collect_output_text_block_defaults_to_empty_string():
    output = _build_full_output()

    facts = _parse_collect_output(output)

    assert facts.group_text == ""
    assert facts.pam_common_auth == ""
    assert facts.login_defs_text == ""


def test_parse_collect_output_raises_when_markers_missing():
    with pytest.raises(LookupError):
        _parse_collect_output("Error response from daemon: No such container: nope\n")


def test_is_running_in_container_detects_dockerenv():
    facts = _parse_collect_output(
        _build_full_output({"container_detection_text": "/.dockerenv:present\n0::/"})
    )
    assert is_running_in_container(facts) is True


def test_is_running_in_container_detects_cgroup_marker():
    facts = _parse_collect_output(
        _build_full_output({"container_detection_text": "/.dockerenv:absent\n0::/docker/abc123"})
    )
    assert is_running_in_container(facts) is True


def test_is_running_in_container_false_on_bare_metal():
    facts = _parse_collect_output(
        _build_full_output({"container_detection_text": "/.dockerenv:absent\n0::/"})
    )
    assert is_running_in_container(facts) is False
