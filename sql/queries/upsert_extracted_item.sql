INSERT INTO extracted_items (
    document_version_id, external_id, title, description, category, raw_data
)
VALUES (
    %(document_version_id)s, %(external_id)s, %(title)s, %(description)s,
    %(category)s, %(raw_data)s
)
ON CONFLICT (document_version_id, external_id) DO UPDATE SET
    title = EXCLUDED.title,
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    raw_data = EXCLUDED.raw_data
RETURNING id;
