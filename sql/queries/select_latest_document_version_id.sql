SELECT document_versions.id
FROM document_versions
JOIN documents ON documents.id = document_versions.document_id
JOIN sources ON sources.id = documents.source_id
WHERE sources.name = %(source)s AND documents.name = %(document)s
ORDER BY document_versions.id DESC
LIMIT 1;
