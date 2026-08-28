import hashlib
import json

import pytest

from invariant.source import (
    KNOWN_CIS_DOCUMENTS,
    CIS,
    _document_slug,
    _extract_jss_state,
    _parse_catalog_benchmarks,
)

_FIXTURE_STATE = {
    "sitecore": {
        "route": {
            "fields": {
                "benchmarkVersions": [
                    {
                        "fields": {
                            "technologyVersion": {"value": "10"},
                            "benchmarkVersion": {"value": "1.0.0"},
                            "documents": [
                                {
                                    "fields": {
                                        "fileName": {
                                            "value": "CIS_Debian_Linux_10_Benchmark_v1.0.0_ARCHIVE.pdf"
                                        },
                                        "location": {
                                            "value": "https://workbench.cisecurity.org/cis/api/v1/file/2658/download"
                                        },
                                        "pardotId": {"value": "/l/799323/2020-06-17/swvz"},
                                        "title": {
                                            "value": "CIS Debian Linux 10 Benchmark v1.0.0 ARCHIVE - pdf"
                                        },
                                    }
                                }
                            ],
                        }
                    },
                    {
                        "fields": {
                            "technologyVersion": {"value": "12"},
                            "benchmarkVersion": {"value": "2.0.0"},
                            "documents": [],
                        }
                    },
                ]
            }
        }
    }
}


def _fixture_html() -> str:
    return (
        "<html><body>"
        '<script type="application/json" id="__JSS_STATE__">'
        + json.dumps(_FIXTURE_STATE)
        + "</script>"
        "</body></html>"
    )


class _FakeResponse:
    def __init__(self, text: str):
        self.text = text

    def raise_for_status(self):
        pass


def test_extract_jss_state_parses_embedded_json():
    state = _extract_jss_state(_fixture_html())

    assert state == _FIXTURE_STATE


def test_extract_jss_state_raises_when_tag_missing():
    with pytest.raises(LookupError):
        _extract_jss_state("<html><body>no state here</body></html>")


def test_find_benchmark_returns_matching_version(monkeypatch):
    monkeypatch.setattr(
        "invariant.source.httpx.get", lambda *a, **k: _FakeResponse(_fixture_html())
    )

    metadata = CIS().find_benchmark("debian_linux", "10", "1.0.0")

    assert metadata.title == "CIS Debian Linux 10 Benchmark v1.0.0 ARCHIVE - pdf"
    assert metadata.file_name == "CIS_Debian_Linux_10_Benchmark_v1.0.0_ARCHIVE.pdf"
    assert metadata.download_url == "https://workbench.cisecurity.org/cis/api/v1/file/2658/download"
    assert metadata.source_page == "https://www.cisecurity.org/benchmark/debian_linux"


def test_find_benchmark_raises_when_version_not_found(monkeypatch):
    monkeypatch.setattr(
        "invariant.source.httpx.get", lambda *a, **k: _FakeResponse(_fixture_html())
    )

    with pytest.raises(LookupError):
        CIS().find_benchmark("debian_linux", "10", "9.9.9")


@pytest.mark.integration
def test_download_benchmark_matches_known_good_hash():
    """Hits the real downloads.cisecurity.org site -- no login needed.

    Locks in a regression test against the exact known-good CIS Debian
    Linux 10 Benchmark v1.0.0 PDF (509 pages, confirmed by downloading it
    both via this anonymous flow and via an authenticated CIS WorkBench
    session and comparing SHA-256 hashes).
    """
    content, extension = CIS().download_benchmark(
        "Debian Linux", "CIS Debian Linux 10 Benchmark v1.0.0"
    )

    assert extension == "pdf"
    assert content[:4] == b"%PDF"
    assert (
        hashlib.sha256(content).hexdigest()
        == "8abac02af919fee395b40bfda16d95e1b9040a2131fb62668fd89d8543e4030b"
    )


def test_known_cis_documents_has_the_6_debian_and_10_ubuntu_benchmarks():
    assert set(KNOWN_CIS_DOCUMENTS) == {
        "cis-debian-linux-9",
        "cis-debian-linux-10",
        "cis-debian-linux-11",
        "cis-debian-linux-11-stig",
        "cis-debian-linux-12",
        "cis-debian-linux-13",
        "cis-ubuntu-linux-12-04",
        "cis-ubuntu-linux-14-04",
        "cis-ubuntu-linux-16-04",
        "cis-ubuntu-linux-18-04",
        "cis-ubuntu-linux-20-04",
        "cis-ubuntu-linux-20-04-stig",
        "cis-ubuntu-linux-22-04",
        "cis-ubuntu-linux-22-04-stig",
        "cis-ubuntu-linux-24-04",
        "cis-ubuntu-linux-24-04-stig",
    }


def test_known_cis_documents_entries_have_required_fields():
    required_fields = {
        "document_slug",
        "product_slug",
        "technology_version",
        "benchmark_version",
        "product_label",
        "version_label",
    }
    for name, entry in KNOWN_CIS_DOCUMENTS.items():
        assert set(entry) == required_fields, name
        assert all(entry.values()), f"{name} has an empty field"


def test_known_cis_documents_document_slugs_are_unique():
    slugs = [entry["document_slug"] for entry in KNOWN_CIS_DOCUMENTS.values()]

    assert len(slugs) == len(set(slugs))


@pytest.mark.integration
@pytest.mark.parametrize("document_name", list(KNOWN_CIS_DOCUMENTS))
def test_find_benchmark_resolves_every_known_document(document_name):
    """Hits the real cisecurity.org page for each known document -- confirms
    the hardcoded technology_version/benchmark_version pairs in
    KNOWN_CIS_DOCUMENTS still resolve to a real entry (this is exactly the
    kind of thing that silently breaks if CIS reorganizes their site).
    """
    entry = KNOWN_CIS_DOCUMENTS[document_name]

    metadata = CIS().find_benchmark(
        entry["product_slug"], entry["technology_version"], entry["benchmark_version"]
    )

    # CIS's own `title` field isn't perfectly consistent (e.g. the Ubuntu
    # 12.04 v1.1.0 entry's title is just its filename, no "CIS " prefix) --
    # only assert what's actually reliable: it's non-empty and the version
    # we asked for is the version we got back.
    assert metadata.title
    assert metadata.benchmark_version == entry["benchmark_version"]


def test_document_slug_supports_debian_ubuntu_and_stig():
    assert _document_slug("Debian Linux", "CIS Debian Linux 13 Benchmark") == "debian_linux_13"
    assert (
        _document_slug("Ubuntu Linux", "CIS Ubuntu Linux 24.04 LTS STIG Benchmark")
        == "ubuntu_linux_24_04_stig"
    )


def test_parse_catalog_benchmarks_keeps_every_pdf_version():
    rows = [
        {
            "title": "CIS Debian Linux 13 Benchmark",
            "technology_version": "13",
            "version": "1.1.0",
            "published": "2026-08-27 01:30:35",
            "documents": [
                {
                    "id": 70179,
                    "pardot-id": "/l/799323/example",
                    "filename": "CIS_Debian_Linux_13_Benchmark_v1.1.0.pdf",
                }
            ],
        },
        {
            "title": "CIS Debian Linux 13 Benchmark",
            "technology_version": "13",
            "version": "1.0.0",
            "published": "2026-01-01 00:00:00",
            "documents": [
                {
                    "id": 70000,
                    "pardot-id": "/l/799323/old",
                    "filename": "CIS_Debian_Linux_13_Benchmark_v1.0.0.pdf",
                }
            ],
        },
    ]

    benchmarks = _parse_catalog_benchmarks("Debian Linux", rows)

    assert [item.benchmark_version for item in benchmarks] == ["1.1.0", "1.0.0"]
    assert {item.document_slug for item in benchmarks} == {"debian_linux_13"}
    assert benchmarks[0].document_id == 70179
    assert benchmarks[0].download_url == "https://learn.cisecurity.org/l/799323/example"


@pytest.mark.integration
def test_discover_benchmarks_crawls_only_monitored_linux_products():
    benchmarks = CIS().discover_benchmarks()

    assert benchmarks
    assert {item.product_label for item in benchmarks} == {"Debian Linux", "Ubuntu Linux"}
    assert all(item.file_name.lower().endswith(".pdf") for item in benchmarks)
    assert all(item.pardot_path.startswith("/l/") for item in benchmarks)
