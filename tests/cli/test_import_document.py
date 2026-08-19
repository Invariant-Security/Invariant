import pytest

from invariant.cli import import_document as import_module


def test_import_document_rejects_unknown_document():
    with pytest.raises(ValueError):
        import_module.import_document("not-a-real-document")


def test_import_document_raises_when_no_document_version(monkeypatch):
    class _FakeConn:
        def close(self):
            pass

    monkeypatch.setattr(import_module.db, "connect", lambda: _FakeConn())
    monkeypatch.setattr(import_module.db, "select_latest_document_version_id", lambda conn, **kwargs: None)

    with pytest.raises(LookupError):
        import_module.import_document("cis-debian-linux-10")


def test_import_document_wires_extracted_items_into_normalizer_and_storage(monkeypatch, capsys):
    calls = {"upserted_controls": []}

    class _FakeConn:
        def commit(self):
            calls["committed"] = True

        def close(self):
            calls["closed"] = True

    monkeypatch.setattr(import_module.db, "connect", lambda: _FakeConn())
    monkeypatch.setattr(import_module.db, "select_latest_document_version_id", lambda conn, **kwargs: 3)
    monkeypatch.setattr(
        import_module.db,
        "select_extracted_items",
        lambda conn, **kwargs: [
            {
                "external_id": "5.2.10",
                "title": "Ensure SSH root login is disabled",
                "description": "desc",
                "raw_data": {
                    "scored": True,
                    "profile_applicability": ["Level 1 - Server"],
                    "rationale": "rationale",
                    "audit": "audit",
                    "remediation": "remediation",
                },
            }
        ],
    )

    def fake_upsert_control(conn, **kwargs):
        calls["upserted_controls"].append(kwargs)
        return len(calls["upserted_controls"])

    monkeypatch.setattr(import_module.db, "upsert_control", fake_upsert_control)

    control_ids = import_module.import_document("cis-debian-linux-10")

    assert control_ids == [1]
    assert len(calls["upserted_controls"]) == 1
    upserted = calls["upserted_controls"][0]
    assert upserted["document_version_id"] == 3
    assert upserted["external_id"] == "5.2.10"
    assert upserted["normalized_data"] == {
        "scored": True,
        "applicability": [{"level": 1, "applies_to": "Server"}],
        "rationale": "rationale",
        "audit": "audit",
        "remediation": "remediation",
    }
    assert calls["committed"] is True
    assert calls["closed"] is True
    assert "normalized 5.2.10" in capsys.readouterr().out
