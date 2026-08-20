# TODO: `invariant extract <document>` -- run the extractor over a stored raw artifact.
# Only the documents in source.KNOWN_CIS_DOCUMENTS are wired up so far
# (same scope as fetch.py).

import json
from dataclasses import asdict
from pathlib import Path

from invariant import extractor, observability, source
from invariant.collector import DEFAULT_RAW_DIR
from invariant.storage import postgres as db


def extract(document: str):
    known = source.KNOWN_CIS_DOCUMENTS.get(document)
    if known is None:
        known_keys = ", ".join(source.KNOWN_CIS_DOCUMENTS)
        raise ValueError(f"unknown document: {document!r} (known: {known_keys})")

    document_slug = known["document_slug"]
    metadata = _latest_raw_artifact_metadata(source="cis", document=document_slug)
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

    with observability.timed(f"parse:{document}"):
        recommendations = extractor.extract_all_recommendations(pdf_path)

    item_ids = []
    with observability.timed(f"persist_extracted_items:{document}"):
        for rec in recommendations:
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
    # Filename-prefix globbing isn't safe here: "debian_linux_11" is a
    # strict prefix of "debian_linux_11_stig"'s filename, so a glob like
    # "cis_debian_linux_11_*.json" also matches the STIG one (confirmed:
    # this silently returned the wrong artifact until fixed). Glob broadly,
    # then filter on each file's own recorded `source`/`document` fields.
    # rglob (not glob) since save_raw_artifact() nests CIS artifacts under
    # data/raw/cis/<debian|ubuntu>/.
    pattern = f"{source}_*.json"
    candidates = [json.loads(path.read_text()) for path in sorted(DEFAULT_RAW_DIR.rglob(pattern))]
    matches = [m for m in candidates if m["source"] == source and m["document"] == document]
    if not matches:
        raise FileNotFoundError(
            f"no raw artifact metadata found for {source}/{document} in {DEFAULT_RAW_DIR} "
            f"-- run `invariant fetch` for it first"
        )
    return max(matches, key=lambda m: m["retrieved_at"])
