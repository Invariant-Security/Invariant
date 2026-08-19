from invariant.assessment import _evaluate_shadow_permissions, _evaluate_ssh_permit_root_login


def test_ssh_evaluator_passes_when_root_login_disabled():
    assert _evaluate_ssh_permit_root_login("permitrootlogin no") is True


def test_ssh_evaluator_fails_when_root_login_enabled():
    assert _evaluate_ssh_permit_root_login("permitrootlogin yes") is False


def test_ssh_evaluator_fails_on_unexpected_output():
    assert _evaluate_ssh_permit_root_login("sshd: command not found") is False


def test_shadow_evaluator_passes_on_640_root_shadow():
    output = "Access: (0640/-rw-r-----)  Uid: ( 0/ root) Gid: ( 42/ shadow)"
    assert _evaluate_shadow_permissions(output) is True


def test_shadow_evaluator_passes_on_more_restrictive_than_640():
    output = "Access: (0600/-rw-------)  Uid: ( 0/ root) Gid: ( 0/ root)"
    assert _evaluate_shadow_permissions(output) is True


def test_shadow_evaluator_fails_on_world_readable():
    output = "Access: (0644/-rw-r--r--)  Uid: ( 0/ root) Gid: ( 42/ shadow)"
    assert _evaluate_shadow_permissions(output) is False


def test_shadow_evaluator_fails_when_not_owned_by_root():
    output = "Access: (0640/-rw-r-----)  Uid: ( 1000/ someuser) Gid: ( 42/ shadow)"
    assert _evaluate_shadow_permissions(output) is False


def test_shadow_evaluator_fails_on_unparseable_output():
    assert _evaluate_shadow_permissions("stat: cannot statx '/etc/shadow': No such file or directory") is False
