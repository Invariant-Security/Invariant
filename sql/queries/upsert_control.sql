INSERT INTO controls (
    document_version_id, external_id, title, description, category, normalized_data
)
VALUES (
    %(document_version_id)s, %(external_id)s, %(title)s, %(description)s,
    %(category)s, %(normalized_data)s
)
ON CONFLICT (document_version_id, external_id) DO UPDATE SET
    title = EXCLUDED.title,
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    normalized_data = EXCLUDED.normalized_data
RETURNING id;
