# TODO: `invariant import <document>` -- normalize extracted items and persist them.
# Only "cis-debian-linux-10" is wired up so far (same scope as fetch.py/extract.py).

from dataclasses import asdict

from invariant import normalizer
from invariant.storage import postgres as db


def import_document(document: str):
    if document != "cis-debian-linux-10":
        raise ValueError(f"unknown document: {document!r} (only 'cis-debian-linux-10' for now)")

    conn = db.connect()
    version_id = db.select_latest_document_version_id(conn, source="cis", document="debian_linux_10")
    if version_id is None:
        raise LookupError(
            "no document_version found for cis/debian_linux_10 in the database "
            "-- run `invariant extract cis-debian-linux-10` first"
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
