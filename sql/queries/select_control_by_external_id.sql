SELECT
    c.title,
    c.normalized_data,
    s.name AS source_name,
    d.name AS document_name,
    dv.publisher_version
FROM controls c
JOIN document_versions dv ON dv.id = c.document_version_id
JOIN documents d ON d.id = dv.document_id
JOIN sources s ON s.id = d.source_id
WHERE d.name = %(document)s AND c.external_id = %(external_id)s
ORDER BY dv.id DESC
LIMIT 1;
