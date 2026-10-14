# SPDX-License-Identifier: MIT
"""Exercise the R1 oracle against recorded image-metadata deployments."""

import json
import shutil

import pytest

from tests.integration import kas_env, test_deployed_artifact_oracle as oracle
from tests.integration.conftest import KasBuildResult, RunRecord


@pytest.fixture
def image_build(tmp_path):
    build = KasBuildResult("podman", 0, ["build completed\n"], tmp_path)
    build.deploy_dir.mkdir(parents=True)
    build.deployed(kas_env.SBOM_NAME).write_text(json.dumps({"serialNumber": "sbom"}))
    build.deployed(kas_env.VEX_NAME).write_text(json.dumps({"serialNumber": "vex"}))
    build.deployed(kas_env.MANIFEST_NAME).write_text("busybox qemux86_64 1.38.0\n")
    return build


def metadata_directory(build):
    return build.build_dir / "tmp/cyclonedx/image/qemux86_64/core-image-minimal"


def deploy_metadata(build):
    directory = metadata_directory(build)
    directory.mkdir(parents=True)
    (directory / "manifest.json").write_text(json.dumps({
        "sbom": "bom.json", "vex": "vex.json",
    }))
    (directory / "bom.json").write_text(build.deployed(kas_env.SBOM_NAME).read_text())
    (directory / "vex.json").write_text(build.deployed(kas_env.VEX_NAME).read_text())
    return directory


def assert_metadata(record):
    oracle.test_image_metadata_bom_manifest_pair_deployed(record.documents)


def test_rootfs_package_manifest_cannot_substitute_for_image_metadata(image_build):
    record = RunRecord("cold", image_build, [])
    with pytest.raises(AssertionError):
        assert_metadata(record)


def test_metadata_manifest_must_resolve_its_document_paths(image_build):
    directory = deploy_metadata(image_build)
    (directory / "manifest.json").write_text(json.dumps({
        "sbom": "missing.json", "vex": "vex.json",
    }))
    record = RunRecord("cold", image_build, [])
    with pytest.raises(AssertionError):
        assert_metadata(record)


def test_metadata_documents_must_match_the_deployed_pair(image_build):
    directory = deploy_metadata(image_build)
    (directory / "vex.json").write_text(json.dumps({"serialNumber": "stale-vex"}))
    record = RunRecord("cold", image_build, [])
    with pytest.raises(AssertionError):
        assert_metadata(record)


def test_metadata_evidence_is_captured_before_later_runs(image_build):
    directory = deploy_metadata(image_build)
    cold = RunRecord("cold", image_build, [])
    shutil.rmtree(directory)
    later = RunRecord("later", image_build, [])
    assert_metadata(cold)
    with pytest.raises(AssertionError):
        assert_metadata(later)
