"""Fetch CIS artifacts from the live anonymous Downloads catalog."""

from invariant import collector, observability, source


def _save(benchmark: source.DownloadableBenchmark, content: bytes, extension: str):
    artifact = collector.save_raw_artifact(
        content,
        source="cis",
        document=benchmark.document_slug,
        version=benchmark.benchmark_version,
        extension=extension,
    )
    print(f"saved {artifact.path} (sha256={artifact.content_hash})")
    return artifact


def _version_key(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError as error:
        raise ValueError(f"invalid CIS benchmark version: {version!r}") from error


def _latest_for_document(
    benchmarks: list[source.DownloadableBenchmark], document_slug: str
) -> source.DownloadableBenchmark:
    matches = [item for item in benchmarks if item.document_slug == document_slug]
    if not matches:
        raise LookupError(f"document not found in CIS Downloads: {document_slug!r}")
    return max(matches, key=lambda item: (_version_key(item.benchmark_version), item.published_at))


def fetch(source_name: str):
    document = source.KNOWN_CIS_DOCUMENTS.get(source_name)
    if source_name != "cis" and document is None:
        known = ", ".join(source.KNOWN_CIS_DOCUMENTS)
        raise ValueError(f"unknown source: {source_name!r} (known: cis, {known})")

    cis = source.CIS()
    with observability.timed("discover:cis"):
        benchmarks = cis.discover_benchmarks()

    selected = (
        benchmarks
        if source_name == "cis"
        else [_latest_for_document(benchmarks, document["document_slug"])]
    )
    artifacts = []
    for benchmark in selected:
        with observability.timed(f"download:{benchmark.cli_name}:v{benchmark.benchmark_version}"):
            content, extension = cis.download_discovered(benchmark)
        artifacts.append(_save(benchmark, content, extension))

    return artifacts if source_name == "cis" else artifacts[0]
