# TODO: `invariant fetch <source>` -- download a source document and preserve the raw artifact.
# Only the documents in source.KNOWN_CIS_DOCUMENTS are wired up so far (see
# docs/decisions/ for why these, ahead of the PRD's official first
# benchmark, CIS AWS Foundations -- it's the bxsec branch, a parallel demo
# track). Extending this to non-CIS sources still needs the TODOs below
# (a general Source registry keyed by name, DB persistence instead of just
# printing the result).

from invariant import collector, observability, source


def fetch(source_name: str):
    document = source.KNOWN_CIS_DOCUMENTS.get(source_name)
    if document is None:
        known = ", ".join(source.KNOWN_CIS_DOCUMENTS)
        raise ValueError(f"unknown source: {source_name!r} (known: {known})")

    cis = source.CIS()
    with observability.timed(f"download:{source_name}"):
        content, extension = cis.download_benchmark(document["product_label"], document["version_label"])
    artifact = collector.save_raw_artifact(
        content,
        source="cis",
        document=document["document_slug"],
        version=document["benchmark_version"],
        extension=extension,
    )
    print(f"saved {artifact.path} (sha256={artifact.content_hash})")
    return artifact
