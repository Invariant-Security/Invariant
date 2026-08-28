# `invariant extract <document>` -- run the extractor over a stored raw artifact.
# `document` is either a KNOWN_CIS_DOCUMENTS CLI alias (e.g.
# "cis-debian-linux-10", kept for backward compatibility and readability) or
# a raw document_slug directly (e.g. "debian_linux_13") -- `invariant fetch
# cis` already saves an artifact under its document_slug for every Debian/
# Ubuntu PDF the live catalog has, whether or not that document has a
# KNOWN_CIS_DOCUMENTS entry (codexplan.md Fase 6 item 1: KNOWN_CIS_DOCUMENTS
# is no longer the authority for what extract() accepts).

import json
from dataclasses import asdict
from pathlib import Path

from invariant import extractor, observability, source
from invariant.collector import DEFAULT_RAW_DIR
from invariant.storage import postgres as db


def extract(document: str):
    known = source.KNOWN_CIS_DOCUMENTS.get(document)
    document_slug = known["document_slug"] if known is not None else document
    metadata = _latest_raw_artifact_metadata(source="cis", document=document_slug)
    pdf_path = Path(metadata["path"])

    # Fail-closed (codexplan.md Fase 2): parse and validate before touching
    # the database at all -- a document that fails the contract never
    # creates so much as a document_versions row.
    with observability.timed(f"parse:{document}"):
        result = extractor.extract_and_validate(pdf_path)
    for warning in result.warnings:
        print(f"warning: {warning.external_id} has empty {warning.field}")

    conn = db.connect()
    try:
        source_id = db.upsert_source(
            conn, name=metadata["source"], type="benchmark_publisher", base_url="https://www.cisecurity.org"
        )
        document_id = db.upsert_document(
            conn, source_id=source_id, name=metadata["document"], document_type="benchmark"
        )

        # Fail-closed count-regression check: compare against whatever
        # document_version is currently latest for this document -- either
        # an older publisher_version, or this same one from a prior parser
        # run (which makes this also a parser-regression check, not just a
        # publisher-content check). Every real CIS Debian/Ubuntu version
        # history observed so far only grows the recommendation count (see
        # docs/decisions/cis-parser-characterization.md), so any decrease
        # is treated as suspicious, not normal churn.
        previous_version_id = db.select_latest_document_version_id(
            conn, source=metadata["source"], document=document_slug
        )
        previous_count = (
            len(db.select_extracted_items(conn, document_version_id=previous_version_id))
            if previous_version_id is not None
            else None
        )
        if previous_count is not None and len(result.recommendations) < previous_count:
            raise extractor.ExtractionError(
                f"{document}: extracted {len(result.recommendations)} recommendations, "
                f"down from {previous_count} in the previous document_version -- "
                f"refusing to persist a regressed extraction"
            )

        version_id = db.upsert_document_version(
            conn,
            document_id=document_id,
            publisher_version=metadata["version"],
            content_hash=metadata["content_hash"],
            retrieved_at=metadata["retrieved_at"],
            raw_artifact_path=metadata["path"],
            # Independent of publisher_version -- lets a future query tell
            # "this document_version was extracted by an older parser" apart
            # from "the publisher republished this version" (codexplan.md
            # Fase 6 item 2). Re-running `extract` always re-parses and
            # re-upserts unconditionally (no skip-if-already-done check
            # exists anywhere in this CLI), so a parser change is already
            # picked up on the next run -- item 3 falls out of item 2 for
            # free, nothing else needed.
            parser_version=extractor.PARSER_VERSION,
        )

        item_ids = []
        with observability.timed(f"persist_extracted_items:{document}"):
            for rec in result.recommendations:
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
    except Exception:
        conn.rollback()
        raise
    finally:
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
