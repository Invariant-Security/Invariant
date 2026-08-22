SELECT
    c.external_id,
    c.title,
    s.name AS source_name,
    d.name AS document_name,
    dv.publisher_version,
    c.normalized_data,
    dv.raw_artifact_path,
    dv.content_hash,
    dv.retrieved_at
FROM controls c
JOIN document_versions dv ON dv.id = c.document_version_id
JOIN documents d ON d.id = dv.document_id
JOIN sources s ON s.id = d.source_id
WHERE d.name = %(document)s AND c.title = ANY(%(titles)s)
ORDER BY dv.id DESC
LIMIT 1;
