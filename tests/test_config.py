import os
from pathlib import Path

from invariant.config import load_dotenv


def test_load_dotenv_sets_new_vars(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("SOME_NEW_VAR", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("SOME_NEW_VAR=hello\n")

    load_dotenv(env_file)

    assert os.environ["SOME_NEW_VAR"] == "hello"


def test_load_dotenv_skips_blank_and_comment_lines(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("A", raising=False)
    monkeypatch.delenv("B", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("\n# a comment\nA=1\n\nB=2\n")

    load_dotenv(env_file)

    assert os.environ["A"] == "1"
    assert os.environ["B"] == "2"


def test_load_dotenv_never_overrides_existing_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ALREADY_SET", "real_value")
    env_file = tmp_path / ".env"
    env_file.write_text("ALREADY_SET=from_file\n")

    load_dotenv(env_file)

    assert os.environ["ALREADY_SET"] == "real_value"


def test_load_dotenv_missing_file_is_a_noop(tmp_path: Path):
    load_dotenv(tmp_path / "does_not_exist.env")
