SELECT external_id, title, description, raw_data
FROM extracted_items
WHERE document_version_id = %(document_version_id)s
ORDER BY id;
