"""Wires hand-written SQL (from sql/queries and sql/schema) to the
storage interfaces via psycopg.
"""

import os
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

from invariant.config import load_dotenv

_QUERIES_DIR = Path(__file__).resolve().parents[4] / "sql" / "queries"

_UPSERT_SOURCE = (_QUERIES_DIR / "upsert_source.sql").read_text()
_UPSERT_DOCUMENT = (_QUERIES_DIR / "upsert_document.sql").read_text()
_UPSERT_DOCUMENT_VERSION = (_QUERIES_DIR / "upsert_document_version.sql").read_text()
_UPSERT_EXTRACTED_ITEM = (_QUERIES_DIR / "upsert_extracted_item.sql").read_text()
_UPSERT_CONTROL = (_QUERIES_DIR / "upsert_control.sql").read_text()
_SELECT_LATEST_DOCUMENT_VERSION_ID = (_QUERIES_DIR / "select_latest_document_version_id.sql").read_text()
_SELECT_EXTRACTED_ITEMS = (_QUERIES_DIR / "select_extracted_items.sql").read_text()
_SELECT_CONTROL_BY_EXTERNAL_ID = (_QUERIES_DIR / "select_control_by_external_id.sql").read_text()
_SELECT_CONTROL_BY_TITLE = (_QUERIES_DIR / "select_control_by_title.sql").read_text()


def connect() -> psycopg.Connection:
    """Open a connection using DATABASE_URL from .env / the environment."""
    load_dotenv()
    return psycopg.connect(os.environ["DATABASE_URL"])


def upsert_source(conn: psycopg.Connection, *, name: str, type: str, base_url: str | None = None) -> int:
    with conn.cursor() as cur:
        cur.execute(_UPSERT_SOURCE, {"name": name, "type": type, "base_url": base_url})
        return cur.fetchone()[0]


def upsert_document(conn: psycopg.Connection, *, source_id: int, name: str, document_type: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            _UPSERT_DOCUMENT,
            {"source_id": source_id, "name": name, "document_type": document_type},
        )
        return cur.fetchone()[0]


def upsert_document_version(
    conn: psycopg.Connection,
    *,
    document_id: int,
    publisher_version: str,
    content_hash: str,
    retrieved_at: str,
    raw_artifact_path: str,
    parser_version: str | None = None,
    collector_version: str | None = None,
) -> int:
    with conn.cursor() as cur:
        cur.execute(
            _UPSERT_DOCUMENT_VERSION,
            {
                "document_id": document_id,
                "publisher_version": publisher_version,
                "content_hash": content_hash,
                "retrieved_at": retrieved_at,
                "raw_artifact_path": raw_artifact_path,
                "parser_version": parser_version,
                "collector_version": collector_version,
            },
        )
        return cur.fetchone()[0]


def upsert_extracted_item(
    conn: psycopg.Connection,
    *,
    document_version_id: int,
    external_id: str,
    title: str,
    description: str | None,
    category: str | None,
    raw_data: dict,
) -> int:
    with conn.cursor() as cur:
        cur.execute(
            _UPSERT_EXTRACTED_ITEM,
            {
                "document_version_id": document_version_id,
                "external_id": external_id,
                "title": title,
                "description": description,
                "category": category,
                "raw_data": Jsonb(raw_data),
            },
        )
        return cur.fetchone()[0]


def upsert_control(
    conn: psycopg.Connection,
    *,
    document_version_id: int,
    external_id: str,
    title: str,
    description: str | None,
    category: str | None,
    normalized_data: dict,
) -> int:
    with conn.cursor() as cur:
        cur.execute(
            _UPSERT_CONTROL,
            {
                "document_version_id": document_version_id,
                "external_id": external_id,
                "title": title,
                "description": description,
                "category": category,
                "normalized_data": Jsonb(normalized_data),
            },
        )
        return cur.fetchone()[0]


def select_latest_document_version_id(conn: psycopg.Connection, *, source: str, document: str) -> int | None:
    with conn.cursor() as cur:
        cur.execute(_SELECT_LATEST_DOCUMENT_VERSION_ID, {"source": source, "document": document})
        row = cur.fetchone()
        return row[0] if row else None


def select_extracted_items(conn: psycopg.Connection, *, document_version_id: int) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(_SELECT_EXTRACTED_ITEMS, {"document_version_id": document_version_id})
        return [
            {"external_id": external_id, "title": title, "description": description, "raw_data": raw_data}
            for external_id, title, description, raw_data in cur.fetchall()
        ]


def select_control_by_external_id(conn: psycopg.Connection, *, document: str, external_id: str) -> dict | None:
    with conn.cursor() as cur:
        cur.execute(_SELECT_CONTROL_BY_EXTERNAL_ID, {"document": document, "external_id": external_id})
        row = cur.fetchone()
        if row is None:
            return None
        title, normalized_data, source_name, document_name, publisher_version = row
        return {
            "title": title,
            "normalized_data": normalized_data,
            "source_name": source_name,
            "document_name": document_name,
            "publisher_version": publisher_version,
        }


def select_control_by_title(conn: psycopg.Connection, *, document: str, titles: list[str]) -> dict | None:
    """Looks up a control by one of several known title variants -- exact
    title wording drifts a little between CIS documents (confirmed:
    "Ensure permissions on /etc/shadow are configured" vs "Ensure access to
    /etc/shadow is configured" for the same underlying check), so callers
    pass every variant they know about rather than relying on one exact
    string or a stable external_id (also confirmed to drift between
    documents).
    """
    with conn.cursor() as cur:
        cur.execute(_SELECT_CONTROL_BY_TITLE, {"document": document, "titles": titles})
        row = cur.fetchone()
        if row is None:
            return None
        external_id, title, source_name, document_name, publisher_version = row
        return {
            "external_id": external_id,
            "title": title,
            "source_name": source_name,
            "document_name": document_name,
            "publisher_version": publisher_version,
        }
