import psycopg
import pytest

from invariant.storage import postgres as db

pytestmark = pytest.mark.integration


@pytest.fixture
def conn():
    """A real connection to DATABASE_URL, rolled back after every test so
    nothing written here lingers in the dev database.
    """
    try:
        connection = db.connect()
    except (KeyError, psycopg.OperationalError) as exc:
        pytest.skip(f"no reachable DATABASE_URL configured: {exc}")
    yield connection
    connection.rollback()
    connection.close()


def test_upsert_source_returns_same_id_on_conflict(conn):
    first_id = db.upsert_source(conn, name="test-source", type="benchmark_publisher")
    second_id = db.upsert_source(conn, name="test-source", type="benchmark_publisher")

    assert first_id == second_id


def test_upsert_document_scoped_to_source(conn):
    source_id = db.upsert_source(conn, name="test-source-2", type="benchmark_publisher")

    document_id = db.upsert_document(
        conn, source_id=source_id, name="test-doc", document_type="benchmark"
    )

    with conn.cursor() as cur:
        cur.execute("SELECT source_id, name, document_type FROM documents WHERE id = %s", (document_id,))
        row = cur.fetchone()

    assert row == (source_id, "test-doc", "benchmark")


def test_upsert_document_version_upsert_updates_hash(conn):
    source_id = db.upsert_source(conn, name="test-source-3", type="benchmark_publisher")
    document_id = db.upsert_document(conn, source_id=source_id, name="test-doc-2", document_type="benchmark")

    version_id = db.upsert_document_version(
        conn,
        document_id=document_id,
        publisher_version="1.0.0",
        content_hash="hash-a",
        retrieved_at="2026-01-01T00:00:00+00:00",
        raw_artifact_path="/tmp/a.pdf",
    )
    same_version_id = db.upsert_document_version(
        conn,
        document_id=document_id,
        publisher_version="1.0.0",
        content_hash="hash-b",
        retrieved_at="2026-01-02T00:00:00+00:00",
        raw_artifact_path="/tmp/b.pdf",
    )

    assert version_id == same_version_id
    with conn.cursor() as cur:
        cur.execute("SELECT content_hash FROM document_versions WHERE id = %s", (version_id,))
        assert cur.fetchone() == ("hash-b",)


def test_upsert_extracted_item_stores_raw_data_as_jsonb(conn):
    source_id = db.upsert_source(conn, name="test-source-4", type="benchmark_publisher")
    document_id = db.upsert_document(conn, source_id=source_id, name="test-doc-3", document_type="benchmark")
    version_id = db.upsert_document_version(
        conn,
        document_id=document_id,
        publisher_version="1.0.0",
        content_hash="hash-c",
        retrieved_at="2026-01-01T00:00:00+00:00",
        raw_artifact_path="/tmp/c.pdf",
    )

    item_id = db.upsert_extracted_item(
        conn,
        document_version_id=version_id,
        external_id="5.2.10",
        title="Ensure SSH root login is disabled",
        description="some description",
        category=None,
        raw_data={"scored": True, "audit": "sshd -T | grep permitrootlogin"},
    )

    with conn.cursor() as cur:
        cur.execute("SELECT external_id, raw_data FROM extracted_items WHERE id = %s", (item_id,))
        external_id, raw_data = cur.fetchone()

    assert external_id == "5.2.10"
    assert raw_data == {"scored": True, "audit": "sshd -T | grep permitrootlogin"}
