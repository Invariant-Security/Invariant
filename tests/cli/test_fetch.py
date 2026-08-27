import pytest

from invariant.cli import fetch as fetch_module
from invariant.collector import RawArtifact
from invariant.source import DownloadableBenchmark


def _benchmark(slug: str, version: str, document_id: int = 1):
    family = "Debian Linux" if slug.startswith("debian") else "Ubuntu Linux"
    return DownloadableBenchmark(
        document_id=document_id,
        document_slug=slug,
        product_label=family,
        title=f"CIS {family} 13 Benchmark",
        technology_version="13",
        benchmark_version=version,
        file_name=f"{slug}_{version}.pdf",
        pardot_path="/l/example",
        published_at="2026-01-01 00:00:00",
    )


def _fake_save(calls):
    def save(content, *, source, document, version, extension):
        calls.append((content, source, document, version, extension))
        return RawArtifact(
            source=source,
            document=document,
            version=version,
            content_hash=f"hash-{version}",
            retrieved_at="2026-01-01T00:00:00+00:00",
            path=f"/tmp/{document}-{version}.pdf",
        )
    return save


def test_fetch_document_discovers_and_downloads_latest_version(monkeypatch, capsys):
    downloads = []
    saved = []
    old = _benchmark("debian_linux_13", "1.0.0", 10)
    latest = _benchmark("debian_linux_13", "1.1.0", 11)

    monkeypatch.setattr(
        fetch_module.source.CIS,
        "discover_benchmarks",
        lambda self: [old, latest],
    )
    monkeypatch.setattr(
        fetch_module.source.CIS,
        "download_discovered",
        lambda self, benchmark: downloads.append(benchmark) or (b"%PDF-latest", "pdf"),
    )
    monkeypatch.setattr(fetch_module.collector, "save_raw_artifact", _fake_save(saved))

    artifact = fetch_module.fetch("cis-debian-linux-13")

    assert downloads == [latest]
    assert saved == [(b"%PDF-latest", "cis", "debian_linux_13", "1.1.0", "pdf")]
    assert artifact.version == "1.1.0"
    assert "hash-1.1.0" in capsys.readouterr().out


def test_fetch_cis_downloads_every_discovered_pdf(monkeypatch):
    downloads = []
    saved = []
    catalog = [
        _benchmark("debian_linux_13", "1.0.0", 10),
        _benchmark("debian_linux_13", "1.1.0", 11),
        _benchmark("ubuntu_linux_24_04", "2.0.0", 12),
    ]

    monkeypatch.setattr(
        fetch_module.source.CIS,
        "discover_benchmarks",
        lambda self: catalog,
    )
    monkeypatch.setattr(
        fetch_module.source.CIS,
        "download_discovered",
        lambda self, benchmark: downloads.append(benchmark) or (b"%PDF-content", "pdf"),
    )
    monkeypatch.setattr(fetch_module.collector, "save_raw_artifact", _fake_save(saved))

    artifacts = fetch_module.fetch("cis")

    assert downloads == catalog
    assert [artifact.version for artifact in artifacts] == ["1.0.0", "1.1.0", "2.0.0"]
    assert len(saved) == 3


def test_fetch_rejects_unknown_source():
    with pytest.raises(ValueError):
        fetch_module.fetch("not-a-real-source")
