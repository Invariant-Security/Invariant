import pytest

from invariant.assessment.facts import _parse_collect_output, _parse_stat_line, parse_sshd_config


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


def test_parse_collect_output_full_script_output():
    output = (
        "===OS_RELEASE===\nID=debian\nVERSION_ID=\"11\"\n"
        "===SSHD_CONFIG===\nPermitRootLogin no\n"
        "===STAT:/etc/shadow===\nmode=640 uid=0 gid=42 gname=shadow\n"
    )

    facts = _parse_collect_output(output)

    assert facts.os_id == "debian"
    assert facts.os_version_id == "11"
    assert facts.sshd_config == {"permitrootlogin": "no"}
    assert facts.file_stats["/etc/shadow"].mode == 0o640


def test_parse_collect_output_raises_when_markers_missing():
    with pytest.raises(LookupError):
        _parse_collect_output("Error response from daemon: No such container: nope\n")
