"""deploy/detect_changed_services.sh is the one piece of non-trivial logic
in the deploy pipeline (path-pattern branching) -- everything else in
deploy.yml/deploy-dev.yml is a fixed sequence of commands. Runs the real
script as a subprocess against a real temporary git repo, not a
reimplementation of its logic in Python.
"""

import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "detect_changed_services.sh"


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=tmp_path, check=True)
    for rel in ("src/invariant/x.py", "frontend/src/App.jsx", "deploy/Dockerfile.api", "README.md"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("v1")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=tmp_path, check=True)
    return tmp_path


def sha(repo, ref="HEAD"):
    return subprocess.run(
        ["git", "rev-parse", ref], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def commit(repo, rel_path, message="change"):
    (repo / rel_path).write_text("v2")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", message], cwd=repo, check=True)
    return sha(repo)


def run_script(repo, old_sha, new_sha):
    result = subprocess.run(
        [str(SCRIPT), old_sha, new_sha], cwd=repo, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def test_backend_only_change_builds_only_api(repo):
    old = sha(repo)
    new = commit(repo, "src/invariant/x.py")
    assert run_script(repo, old, new) == "api"


def test_frontend_only_change_builds_only_web(repo):
    old = sha(repo)
    new = commit(repo, "frontend/src/App.jsx")
    assert run_script(repo, old, new) == "web"


def test_unrelated_change_builds_nothing(repo):
    old = sha(repo)
    new = commit(repo, "README.md")
    assert run_script(repo, old, new) == ""


def test_both_changed_builds_both(repo):
    old = sha(repo)
    (repo / "src/invariant/x.py").write_text("v2")
    (repo / "frontend/src/App.jsx").write_text("v2")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "both"], cwd=repo, check=True)
    new = sha(repo)
    assert run_script(repo, old, new) == "api web"


def test_compose_file_change_builds_both(repo):
    old = sha(repo)
    new = commit(repo, "deploy/docker-compose.dev.yml")
    assert run_script(repo, old, new) == "api web"


def test_no_old_sha_builds_both(repo):
    new = sha(repo)
    assert run_script(repo, "", new) == "api web"


def test_same_sha_builds_nothing(repo):
    current = sha(repo)
    assert run_script(repo, current, current) == ""
