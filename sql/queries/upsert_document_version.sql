INSERT INTO document_versions (
    document_id, publisher_version, content_hash, retrieved_at,
    raw_artifact_path, parser_version, collector_version
)
VALUES (
    %(document_id)s, %(publisher_version)s, %(content_hash)s, %(retrieved_at)s,
    %(raw_artifact_path)s, %(parser_version)s, %(collector_version)s
)
ON CONFLICT (document_id, publisher_version) DO UPDATE SET
    content_hash = EXCLUDED.content_hash,
    retrieved_at = EXCLUDED.retrieved_at,
    raw_artifact_path = EXCLUDED.raw_artifact_path,
    parser_version = EXCLUDED.parser_version,
    collector_version = EXCLUDED.collector_version
RETURNING id;
