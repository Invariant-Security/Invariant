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
