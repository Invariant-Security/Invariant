-- Normalized Control (PRD sec. 21) -- one row per invariant.normalizer.Control,
-- built from an extracted_items row. `category` is intentionally still
-- NULL: deriving it (from the benchmark's section headers) needs a
-- separate, less mechanical extraction pass, not built yet.
CREATE TABLE controls (
    id SERIAL PRIMARY KEY,
    document_version_id INTEGER NOT NULL REFERENCES document_versions (id),
    external_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT,
    normalized_data JSONB NOT NULL,
    UNIQUE (document_version_id, external_id)
);
