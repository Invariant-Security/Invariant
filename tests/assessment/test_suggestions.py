from invariant.assessment.suggestions import extract_simple_command


def test_extract_simple_command_returns_the_single_command():
    audit = "Run the following command to verify X:\n# sshd -T | grep permitrootlogin\n\npermitrootlogin no"
    assert extract_simple_command(audit) == "sshd -T | grep permitrootlogin"


def test_extract_simple_command_returns_none_with_multiple_commands():
    audit = "# first command\nsome text\n# second command\n"
    assert extract_simple_command(audit) is None


def test_extract_simple_command_returns_none_with_no_command():
    audit = "Manually verify the configuration matches organizational policy."
    assert extract_simple_command(audit) is None


def test_extract_simple_command_returns_none_for_empty_audit():
    assert extract_simple_command("") is None
    assert extract_simple_command(None) is None


def test_extract_simple_command_strips_whitespace():
    audit = "#   stat -Lc '%a' /etc/shadow   \n"
    assert extract_simple_command(audit) == "stat -Lc '%a' /etc/shadow"
