INSERT INTO sources (name, type, base_url)
VALUES (%(name)s, %(type)s, %(base_url)s)
ON CONFLICT (name) DO UPDATE SET type = EXCLUDED.type, base_url = EXCLUDED.base_url
RETURNING id;
