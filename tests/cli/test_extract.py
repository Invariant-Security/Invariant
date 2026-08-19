import json
from pathlib import Path

import pytest

from invariant.cli import extract as extract_module
from invariant.extractor import ExtractedRecommendation


def test_latest_raw_artifact_metadata_picks_most_recent(tmp_path, monkeypatch):
    monkeypatch.setattr(extract_module, "DEFAULT_RAW_DIR", tmp_path)
    older = {
        "source": "cis", "document": "debian_linux_10", "path": "older.pdf",
        "retrieved_at": "2026-01-01T00:00:00+00:00",
    }
    newer = {
        "source": "cis", "document": "debian_linux_10", "path": "newer.pdf",
        "retrieved_at": "2026-02-01T00:00:00+00:00",
    }
    (tmp_path / "cis_debian_linux_10_1.0.0_aaa.json").write_text(json.dumps(older))
    (tmp_path / "cis_debian_linux_10_1.0.0_zzz.json").write_text(json.dumps(newer))

    metadata = extract_module._latest_raw_artifact_metadata(source="cis", document="debian_linux_10")

    assert metadata["path"] == "newer.pdf"


def test_latest_raw_artifact_metadata_does_not_match_by_filename_prefix(tmp_path, monkeypatch):
    """debian_linux_11 is a strict filename prefix of debian_linux_11_stig
    -- regression test for a real bug where glob("*debian_linux_11*")
    silently picked up the STIG artifact instead of raising/returning
    nothing for a document that was never actually fetched.
    """
    monkeypatch.setattr(extract_module, "DEFAULT_RAW_DIR", tmp_path)
    stig = {
        "source": "cis", "document": "debian_linux_11_stig", "path": "stig.pdf",
        "retrieved_at": "2026-01-01T00:00:00+00:00",
    }
    (tmp_path / "cis_debian_linux_11_stig_1.0.0_aaa.json").write_text(json.dumps(stig))

    with pytest.raises(FileNotFoundError):
        extract_module._latest_raw_artifact_metadata(source="cis", document="debian_linux_11")


def test_latest_raw_artifact_metadata_raises_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(extract_module, "DEFAULT_RAW_DIR", tmp_path)

    with pytest.raises(FileNotFoundError):
        extract_module._latest_raw_artifact_metadata(source="cis", document="debian_linux_10")


def test_extract_rejects_unknown_document():
    with pytest.raises(ValueError):
        extract_module.extract("not-a-real-document")


def test_extract_wires_extractor_output_into_storage(monkeypatch, capsys):
    calls = {"upserted_items": []}

    monkeypatch.setattr(
        extract_module,
        "_latest_raw_artifact_metadata",
        lambda **kwargs: {
            "source": "cis",
            "document": "debian_linux_10",
            "path": "/fake/path.pdf",
            "version": "1.0.0",
            "content_hash": "deadbeef",
            "retrieved_at": "2026-01-01T00:00:00+00:00",
        },
    )

    fake_recommendations = [
        ExtractedRecommendation(
            external_id="5.2.10",
            title="Ensure SSH root login is disabled",
            scored=True,
            profile_applicability=["Level 1 - Server"],
            description="desc",
            rationale="rationale",
            audit="audit",
            remediation="remediation",
        ),
        ExtractedRecommendation(
            external_id="6.1.4",
            title="Ensure permissions on /etc/shadow are configured",
            scored=True,
            profile_applicability=["Level 1 - Server"],
            description="desc-2",
            rationale="rationale-2",
            audit="audit-2",
            remediation="remediation-2",
        ),
    ]
    monkeypatch.setattr(
        extract_module.extractor, "extract_all_recommendations", lambda path: fake_recommendations
    )

    class _FakeConn:
        def commit(self):
            calls["committed"] = True

        def close(self):
            calls["closed"] = True

    monkeypatch.setattr(extract_module.db, "connect", lambda: _FakeConn())
    monkeypatch.setattr(extract_module.db, "upsert_source", lambda conn, **kwargs: 1)
    monkeypatch.setattr(extract_module.db, "upsert_document", lambda conn, **kwargs: 2)
    monkeypatch.setattr(extract_module.db, "upsert_document_version", lambda conn, **kwargs: 3)

    def fake_upsert_extracted_item(conn, **kwargs):
        calls["upserted_items"].append(kwargs)
        return len(calls["upserted_items"])

    monkeypatch.setattr(extract_module.db, "upsert_extracted_item", fake_upsert_extracted_item)

    item_ids = extract_module.extract("cis-debian-linux-10")

    assert item_ids == [1, 2]
    assert len(calls["upserted_items"]) == 2
    assert calls["upserted_items"][0]["document_version_id"] == 3
    assert calls["upserted_items"][0]["external_id"] == "5.2.10"
    assert calls["upserted_items"][0]["raw_data"] == {
        "scored": True,
        "profile_applicability": ["Level 1 - Server"],
        "rationale": "rationale",
        "audit": "audit",
        "remediation": "remediation",
    }
    assert calls["upserted_items"][1]["external_id"] == "6.1.4"
    assert calls["committed"] is True
    assert calls["closed"] is True
    output = capsys.readouterr().out
    assert "extracted 5.2.10" in output
    assert "extracted 6.1.4" in output
