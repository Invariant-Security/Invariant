"""Downloads raw artifacts from a source and preserves them on disk,
computing their content hash.
"""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_RAW_DIR = Path(__file__).resolve().parents[3] / "data" / "raw"


def _cis_os_family(document: str) -> str | None:
    """Map a CIS document slug to its OS subdirectory (data/raw/cis/<family>/).

    Returns None for documents that aren't OS-specific (or aren't CIS),
    so save_raw_artifact() falls back to no subdivision for those.
    """
    if document.startswith("debian_linux"):
        return "debian"
    if document.startswith("ubuntu_linux"):
        return "ubuntu"
    return None


@dataclass
class RawArtifact:
    """A preserved raw document, with the metadata needed to trace it back
    to its source, document and version (PRD sec. 47, the reproducibility
    invariant).
    """

    source: str
    document: str
    version: str
    content_hash: str
    retrieved_at: str
    path: str


def save_raw_artifact(
    content: bytes,
    *,
    source: str,
    document: str,
    version: str,
    extension: str,
    raw_dir: Path = DEFAULT_RAW_DIR,
) -> RawArtifact:
    """Hash and preserve one downloaded document, plus a metadata sidecar.

    Filenames are content-addressed by hash (not by download timestamp) so
    re-fetching identical bytes never creates a duplicate file.
    """
    target_dir = raw_dir / source
    os_family = _cis_os_family(document) if source == "cis" else None
    if os_family is not None:
        target_dir = target_dir / os_family
    target_dir.mkdir(parents=True, exist_ok=True)

    content_hash = hashlib.sha256(content).hexdigest()
    retrieved_at = datetime.now(timezone.utc).isoformat()

    stem = f"{source}_{document}_{version}_{content_hash[:12]}"
    artifact_path = target_dir / f"{stem}.{extension}"
    artifact_path.write_bytes(content)

    artifact = RawArtifact(
        source=source,
        document=document,
        version=version,
        content_hash=content_hash,
        retrieved_at=retrieved_at,
        path=str(artifact_path),
    )
    metadata_path = target_dir / f"{stem}.json"
    metadata_path.write_text(json.dumps(asdict(artifact), indent=2))

    return artifact
