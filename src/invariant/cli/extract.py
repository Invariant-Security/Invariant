# TODO: `invariant extract <document>` -- run the extractor over a stored raw artifact.
# Only "cis-debian-linux-10" is wired up so far (same scope as fetch.py).

import glob
import json
from dataclasses import asdict
from pathlib import Path

from invariant import extractor
from invariant.collector import DEFAULT_RAW_DIR
from invariant.storage import postgres as db


def extract(document: str):
    if document != "cis-debian-linux-10":
        raise ValueError(f"unknown document: {document!r} (only 'cis-debian-linux-10' for now)")

    metadata = _latest_raw_artifact_metadata(source="cis", document="debian_linux_10")
    pdf_path = Path(metadata["path"])

    conn = db.connect()
    source_id = db.upsert_source(
        conn, name=metadata["source"], type="benchmark_publisher", base_url="https://www.cisecurity.org"
    )
    document_id = db.upsert_document(
        conn, source_id=source_id, name=metadata["document"], document_type="benchmark"
    )
    version_id = db.upsert_document_version(
        conn,
        document_id=document_id,
        publisher_version=metadata["version"],
        content_hash=metadata["content_hash"],
        retrieved_at=metadata["retrieved_at"],
        raw_artifact_path=metadata["path"],
    )

    item_ids = []
    for rec in extractor.extract_all_recommendations(pdf_path):
        raw_data = asdict(rec)
        for column in ("external_id", "title", "description"):
            raw_data.pop(column)

        item_id = db.upsert_extracted_item(
            conn,
            document_version_id=version_id,
            external_id=rec.external_id,
            title=rec.title,
            description=rec.description,
            category=None,
            raw_data=raw_data,
        )
        item_ids.append(item_id)
        print(f"extracted {rec.external_id} -> extracted_items.id={item_id}")

    conn.commit()
    conn.close()
    return item_ids


def _latest_raw_artifact_metadata(*, source: str, document: str) -> dict:
    pattern = str(DEFAULT_RAW_DIR / f"{source}_{document}_*.json")
    matches = sorted(glob.glob(pattern))
    if not matches:
        raise FileNotFoundError(
            f"no raw artifact metadata found for {source}/{document} in {DEFAULT_RAW_DIR} "
            "-- run `invariant fetch cis-debian-linux-10` first"
        )
    return json.loads(Path(matches[-1]).read_text())
