import hashlib
import json
from pathlib import Path

from invariant.collector import _cis_os_family, save_raw_artifact


def test_cis_os_family_maps_debian_and_ubuntu_documents():
    assert _cis_os_family("debian_linux_10") == "debian"
    assert _cis_os_family("ubuntu_linux_22_04_stig") == "ubuntu"


def test_cis_os_family_returns_none_for_unrecognized_document():
    assert _cis_os_family("aws_foundations") is None


def test_save_raw_artifact_nests_ubuntu_documents_under_cis_ubuntu(tmp_path: Path):
    artifact = save_raw_artifact(
        b"content",
        source="cis",
        document="ubuntu_linux_22_04",
        version="3.0.0",
        extension="pdf",
        raw_dir=tmp_path,
    )

    assert Path(artifact.path).parent == tmp_path / "cis" / "ubuntu"


def test_save_raw_artifact_does_not_nest_by_os_for_non_cis_sources(tmp_path: Path):
    artifact = save_raw_artifact(
        b"content",
        source="aws",
        document="security_pillar",
        version="1.0.0",
        extension="pdf",
        raw_dir=tmp_path,
    )

    assert Path(artifact.path).parent == tmp_path / "aws"


def test_save_raw_artifact_writes_file_and_hashes_correctly(tmp_path: Path):
    content = b"hello world"
    expected_hash = hashlib.sha256(content).hexdigest()

    artifact = save_raw_artifact(
        content,
        source="cis",
        document="debian_linux_10",
        version="1.0.0",
        extension="pdf",
        raw_dir=tmp_path,
    )

    assert artifact.content_hash == expected_hash
    assert Path(artifact.path).read_bytes() == content
    assert Path(artifact.path).parent == tmp_path / "cis" / "debian"
    assert artifact.source == "cis"
    assert artifact.document == "debian_linux_10"
    assert artifact.version == "1.0.0"


def test_save_raw_artifact_writes_metadata_sidecar(tmp_path: Path):
    artifact = save_raw_artifact(
        b"content",
        source="cis",
        document="debian_linux_10",
        version="1.0.0",
        extension="pdf",
        raw_dir=tmp_path,
    )

    sidecar_path = Path(artifact.path).with_suffix(".json")
    sidecar = json.loads(sidecar_path.read_text())

    assert sidecar["content_hash"] == artifact.content_hash
    assert sidecar["path"] == artifact.path
    assert "retrieved_at" in sidecar


def test_save_raw_artifact_creates_missing_raw_dir(tmp_path: Path):
    raw_dir = tmp_path / "nested" / "raw"

    save_raw_artifact(
        b"content",
        source="cis",
        document="debian_linux_10",
        version="1.0.0",
        extension="pdf",
        raw_dir=raw_dir,
    )

    assert raw_dir.is_dir()


def test_save_raw_artifact_is_content_addressed(tmp_path: Path):
    same_content = b"identical bytes"

    first = save_raw_artifact(
        same_content, source="cis", document="doc", version="1.0.0", extension="pdf", raw_dir=tmp_path
    )
    second = save_raw_artifact(
        same_content, source="cis", document="doc", version="1.0.0", extension="pdf", raw_dir=tmp_path
    )

    assert first.path == second.path
