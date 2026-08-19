INSERT INTO documents (source_id, name, document_type)
VALUES (%(source_id)s, %(name)s, %(document_type)s)
ON CONFLICT (source_id, name) DO UPDATE SET document_type = EXCLUDED.document_type
RETURNING id;
