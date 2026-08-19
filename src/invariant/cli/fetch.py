# TODO: `invariant fetch <source>` -- download a source document and preserve the raw artifact.
# Only "cis-debian-linux-10" is wired up so far (see docs/decisions/ for why
# this document, ahead of the PRD's official first benchmark, CIS AWS
# Foundations -- it's the bxsec branch, a parallel demo track). Extending
# this to other sources still needs the TODOs below once a second one
# exists (a Source registry keyed by name, DB persistence instead of just
# printing the result).

from invariant import collector, source


def fetch(source_name: str):
    if source_name != "cis-debian-linux-10":
        raise ValueError(f"unknown source: {source_name!r} (only 'cis-debian-linux-10' for now)")

    cis = source.CIS()
    content, extension = cis.download_benchmark("Debian Linux", "CIS Debian Linux 10 Benchmark v1.0.0")
    artifact = collector.save_raw_artifact(
        content,
        source="cis",
        document="debian_linux_10",
        version="1.0.0",
        extension=extension,
    )
    print(f"saved {artifact.path} (sha256={artifact.content_hash})")
    return artifact
