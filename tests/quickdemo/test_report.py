import json

import report
from misconfig_catalog import STRUCTURAL_GAP_TITLES

from invariant.assessment import Finding


def _finding(target: str, external_id: str, title: str, status: str = "FAIL") -> Finding:
    return Finding(
        target=target,
        external_id=external_id,
        status=status,
        control_title=title,
        source_name="cis",
        document_name="debian_linux_11",
        document_version="2.0.0",
        evidence_output="fake evidence",
        collected_at="2026-01-01T00:00:00+00:00",
    )


def _write_manifest(tmp_path, manifest: dict) -> str:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    return path


def test_build_report_classifies_environmental_story_and_unexplained(tmp_path, monkeypatch):
    """Same three-way split the old quickdemo.sh step 9 heredoc computed
    inline: a FAIL matching STRUCTURAL_GAP_TITLES is "environmental", a
    FAIL matching a manifest recipe's check_titles is "story", and
    anything else is "unexplained".
    """
    structural_title = next(iter(STRUCTURAL_GAP_TITLES))
    story_title = "Ensure sshd PermitRootLogin is disabled"
    unexplained_title = "some made-up control that matches no recipe"

    manifest = {
        "container-a": [
            {"check_titles": [story_title], "id": "ssh-permit-root-login"},
        ]
    }
    manifest_path = _write_manifest(tmp_path, manifest)

    findings = [
        _finding("container-a", "1.1.1", structural_title),
        _finding("container-a", "5.1.20", story_title),
        _finding("container-a", "9.9.9", unexplained_title),
        _finding("container-a", "2.2.2", "some passing control", status="PASS"),
    ]

    monkeypatch.setattr(report, "assess_targets", lambda targets: {"container-a": findings})

    result = report.build_report(["container-a"], manifest_path=manifest_path)

    data = result["containers"]["container-a"]
    assert data["total_findings"] == 4
    assert data["fail_count"] == 3
    assert data["pass_count"] == 1
    assert [f["control_title"] for f in data["environmental"]] == [structural_title]
    assert [f["control_title"] for f in data["story"]] == [story_title]
    assert [f["control_title"] for f in data["unexplained"]] == [unexplained_title]
    assert result["unexplained_total"] == 1


def test_build_report_container_with_no_manifest_entry_has_no_story(tmp_path, monkeypatch):
    """The hardened baseline never appears in the manifest (only the 4
    "problem" containers do) -- build_report() must not blow up on a
    missing key, same as the original heredoc's manifest.get(container, {}).
    """
    manifest_path = _write_manifest(tmp_path, {})
    structural_title = next(iter(STRUCTURAL_GAP_TITLES))
    findings = [_finding("hardened", "1.1.1", structural_title)]

    monkeypatch.setattr(report, "assess_targets", lambda targets: {"hardened": findings})

    result = report.build_report(["hardened"], manifest_path=manifest_path)

    data = result["containers"]["hardened"]
    assert data["story"] == []
    assert data["unexplained"] == []
    assert result["unexplained_total"] == 0


def test_build_report_with_no_fails_is_all_clean(tmp_path, monkeypatch):
    manifest_path = _write_manifest(tmp_path, {})
    findings = [_finding("container-a", "1.1.1", "a passing control", status="PASS")]

    monkeypatch.setattr(report, "assess_targets", lambda targets: {"container-a": findings})

    result = report.build_report(["container-a"], manifest_path=manifest_path)

    data = result["containers"]["container-a"]
    assert data["fail_count"] == 0
    assert data["pass_count"] == 1
    assert result["unexplained_total"] == 0


def test_print_report_warns_on_unexplained_fails(capsys):
    report_dict = {
        "targets": ["container-a"],
        "containers": {
            "container-a": {
                "total_findings": 2,
                "fail_count": 1,
                "pass_count": 1,
                "environmental": [],
                "story": [],
                "unexplained": [{"external_id": "9.9.9", "control_title": "mystery control"}],
            }
        },
        "unexplained_total": 1,
    }

    report.print_report(report_dict, hardened="container-a")

    out = capsys.readouterr().out
    assert "container-a: 1 FAIL(s)" in out
    assert "mystery control" in out
    assert "WARNING: 1 unexplained FAIL(s)" in out


def test_print_report_all_accounted_for_when_no_unexplained(capsys):
    report_dict = {
        "targets": ["container-a"],
        "containers": {
            "container-a": {
                "total_findings": 1,
                "fail_count": 0,
                "pass_count": 1,
                "environmental": [],
                "story": [],
                "unexplained": [],
            }
        },
        "unexplained_total": 0,
    }

    report.print_report(report_dict, hardened="container-a")

    out = capsys.readouterr().out
    assert "Every FAIL across all demo containers is accounted for." in out
