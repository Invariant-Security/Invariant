# TODO: `invariant import <document>` -- normalize extracted items and persist them.
# Only the documents in source.KNOWN_CIS_DOCUMENTS are wired up so far
# (same scope as fetch.py/extract.py).

from dataclasses import asdict

from invariant import normalizer, source
from invariant.storage import postgres as db


def import_document(document: str):
    known = source.KNOWN_CIS_DOCUMENTS.get(document)
    if known is None:
        known_keys = ", ".join(source.KNOWN_CIS_DOCUMENTS)
        raise ValueError(f"unknown document: {document!r} (known: {known_keys})")

    document_slug = known["document_slug"]
    conn = db.connect()
    version_id = db.select_latest_document_version_id(conn, source="cis", document=document_slug)
    if version_id is None:
        raise LookupError(
            f"no document_version found for cis/{document_slug} in the database "
            f"-- run `invariant extract {document}` first"
        )

    control_ids = []
    for item in db.select_extracted_items(conn, document_version_id=version_id):
        raw_data = item["raw_data"]
        control = normalizer.normalize(
            external_id=item["external_id"],
            title=item["title"],
            description=item["description"] or "",
            scored=raw_data["scored"],
            profile_applicability=raw_data["profile_applicability"],
            rationale=raw_data["rationale"],
            audit=raw_data["audit"],
            remediation=raw_data["remediation"],
        )

        normalized_data = asdict(control)
        for column in ("external_id", "title", "description"):
            normalized_data.pop(column)

        control_id = db.upsert_control(
            conn,
            document_version_id=version_id,
            external_id=control.external_id,
            title=control.title,
            description=control.description,
            category=None,
            normalized_data=normalized_data,
        )
        control_ids.append(control_id)
        print(f"normalized {control.external_id} -> controls.id={control_id}")

    conn.commit()
    conn.close()
    return control_ids
