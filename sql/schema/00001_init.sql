-- Sources / Document / Document Version / Extracted Item (PRD sec. 21).
-- controls / references / scores come later, once invariant.normalizer
-- exists -- extracted_items is as far as invariant.extractor gets today.

CREATE TABLE sources (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    base_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources (id),
    name TEXT NOT NULL,
    document_type TEXT NOT NULL,
    UNIQUE (source_id, name)
);

CREATE TABLE document_versions (
    id SERIAL PRIMARY KEY,
    document_id INTEGER NOT NULL REFERENCES documents (id),
    publisher_version TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    retrieved_at TIMESTAMPTZ NOT NULL,
    raw_artifact_path TEXT NOT NULL,
    parser_version TEXT,
    collector_version TEXT,
    UNIQUE (document_id, publisher_version)
);

-- One row per recommendation as extracted from the raw PDF text, before
-- any normalization. `raw_data` carries everything extract_recommendation()
-- produces beyond title/description (scored, profile_applicability,
-- rationale, audit, remediation) so nothing gets lost between what the
-- extractor knows and what's queryable -- normalization decides later
-- what's worth promoting to real columns.
CREATE TABLE extracted_items (
    id SERIAL PRIMARY KEY,
    document_version_id INTEGER NOT NULL REFERENCES document_versions (id),
    external_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT,
    raw_data JSONB NOT NULL,
    UNIQUE (document_version_id, external_id)
);
