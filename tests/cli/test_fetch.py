import pytest

from invariant.cli import fetch as fetch_module
from invariant.collector import RawArtifact


def test_fetch_wires_cis_download_into_collector(monkeypatch, capsys):
    calls = {}

    def fake_download_benchmark(self, product_label, version_label):
        calls["product_label"] = product_label
        calls["version_label"] = version_label
        return b"%PDF-fake-content", "pdf"

    def fake_save_raw_artifact(content, *, source, document, version, extension):
        calls["save_raw_artifact_args"] = (content, source, document, version, extension)
        return RawArtifact(
            source=source,
            document=document,
            version=version,
            content_hash="deadbeef",
            retrieved_at="2026-01-01T00:00:00+00:00",
            path="/tmp/fake/path.pdf",
        )

    monkeypatch.setattr(fetch_module.source.CIS, "download_benchmark", fake_download_benchmark)
    monkeypatch.setattr(fetch_module.collector, "save_raw_artifact", fake_save_raw_artifact)

    artifact = fetch_module.fetch("cis-debian-linux-10")

    assert calls["product_label"] == "Debian Linux"
    assert calls["version_label"] == "CIS Debian Linux 10 Benchmark v1.0.0"
    assert calls["save_raw_artifact_args"] == (b"%PDF-fake-content", "cis", "debian_linux_10", "1.0.0", "pdf")
    assert artifact.content_hash == "deadbeef"
    assert "deadbeef" in capsys.readouterr().out


def test_fetch_rejects_unknown_source():
    with pytest.raises(ValueError):
        fetch_module.fetch("not-a-real-source")
