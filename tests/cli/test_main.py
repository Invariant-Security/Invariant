from typer.testing import CliRunner

from invariant.cli.main import app

runner = CliRunner()


def test_cli_help_lists_registered_commands():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    for command in ("fetch", "diff", "check_updates", "notify", "import_document"):
        assert command in result.output


def test_fetch_unknown_source_fails():
    result = runner.invoke(app, ["fetch", "not-a-real-source"])

    assert result.exit_code != 0
