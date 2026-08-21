from typer.testing import CliRunner

from invariant.cli import assess as assess_module
from invariant.cli.main import app

runner = CliRunner()


def _fake_findings(target):
    from invariant.assessment import Finding

    return [
        Finding(
            target=target,
            external_id="1.1.1",
            status="PASS",
            control_title="fake control",
            source_name="cis",
            document_name="debian_linux_11",
            document_version="2.0.0",
            evidence_output="fake evidence",
            collected_at="2026-01-01T00:00:00+00:00",
        )
    ]


def test_assess_with_no_target_option_uses_assessment_targets(monkeypatch):
    calls = []

    def fake_assess_targets(targets):
        calls.append(list(targets))
        return {t: _fake_findings(t) for t in targets}

    monkeypatch.setattr(assess_module.assessment, "assess_targets", fake_assess_targets)

    result = runner.invoke(app, ["assess"])

    assert result.exit_code == 0
    assert calls == [assess_module.assessment.TARGETS]


def test_assess_with_target_option_overrides_default_targets(monkeypatch):
    calls = []

    def fake_assess_targets(targets):
        calls.append(list(targets))
        return {t: _fake_findings(t) for t in targets}

    monkeypatch.setattr(assess_module.assessment, "assess_targets", fake_assess_targets)

    result = runner.invoke(app, ["assess", "--target", "foo", "--target", "bar"])

    assert result.exit_code == 0
    assert calls == [["foo", "bar"]]
    assert "foo" in result.output
    assert "bar" in result.output


def test_assess_prints_fail_finding_chain(monkeypatch):
    def fake_assess_targets(targets):
        findings = _fake_findings(targets[0])
        findings[0].status = "FAIL"
        return {targets[0]: findings}

    monkeypatch.setattr(assess_module.assessment, "assess_targets", fake_assess_targets)

    result = runner.invoke(app, ["assess", "--target", "some-container"])

    assert result.exit_code == 0
    assert "Finding: some-container / 1.1.1" in result.output
    assert "Control: fake control" in result.output
