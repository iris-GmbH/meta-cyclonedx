# SPDX-License-Identifier: MIT
"""R1 — full deployed-artifact oracle over the recorded cold-run evidence.

Every structural claim about the cold acceptance build is its own named
test, so a failing run identifies the observation by name; every failure
carries the build-log tail. The module-wide `build_succeeded` autouse
fixture guards every evidence test: a failed build can never let stale
deploy-dir artifacts from an earlier run pass the oracle. Selected with
``pytest -m integration``; default runs stay unit-only.
"""

import json
import re

import pytest

from tests.integration import kas_env

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def build_succeeded(kas_build):
    """No evidence observation is made over a failed or aborted build."""
    assert kas_build.returncode == 0, (
        f"the cold run it would report on failed via {kas_build.engine} "
        f"(exit {kas_build.returncode}); build-log tail:\n"
        f"{kas_build.output_tail}"
    )

#: A rootfs package whose presence in `core-image-minimal` is certain —
#: cross-checked against the deployed image manifest, which records the
#: actual rootfs package list.
ROOTFS_PACKAGE = "busybox"

#: CycloneDX cross-document reference (a bom-ref in another document's
#: object space): urn:cdx:<serial>/<version>#<bom-ref>. The adapter emits
#: exactly this shape in the VEX affects list.
CDX_REFERENCE = re.compile(r"urn:cdx:(?P<serial>[^/]+)/(?P<version>\d+)#(?P<ref>.+)\Z")

#: The IMAGE_VERSION_SUFFIX build timestamp shared by the deployed image
#: artifact names and the SBOM's primary-component version.
BUILD_TIMESTAMP = re.compile(r"(\d{14})\Z")

#: Versionless dated rootfs image artifacts: the built image itself.
ROOTFS_IMAGE_GLOB = f"{kas_env.TARGET}-{kas_env.MACHINE}.rootfs-*.ext4.zst"


def _component_refs(sbom):
    """All bom-refs the dependency graph and VEX may point at."""
    refs = set()
    for component in [sbom.get("metadata", {}).get("component", {}),
                      *sbom.get("components", [])]:
        ref = component.get("bom-ref")
        if ref:
            refs.add(ref)
    return refs


def test_sbom_validates_against_vendored_cyclonedx_16_schema(
    cold_run, cyclonedx_16_validator
):
    from tests.integration import schema_validation

    sbom = cold_run.sbom
    assert sbom.get("specVersion") == "1.6", (
        f"deployed SBOM declares specVersion {sbom.get('specVersion')!r}, "
        "not the CycloneDX 1.6 the vendored schema validates; build-log "
        f"tail:\n{cold_run.build.output_tail}"
    )
    violations = list(cyclonedx_16_validator.iter_errors(sbom))
    assert not violations, (
        f"deployed SBOM violates the vendored CycloneDX 1.6 schema:\n"
        f"{schema_validation.describe_errors(violations)}\n"
        f"build-log tail:\n{cold_run.build.output_tail}"
    )


def test_vex_deployed_alongside_and_structurally_sound(
    cold_run, cyclonedx_16_validator
):
    from tests.integration import schema_validation

    vex = cold_run.vex
    assert vex.get("specVersion") == "1.6", (
        f"deployed VEX declares specVersion {vex.get('specVersion')!r}, "
        "not the CycloneDX 1.6 the vendored schema validates; build-log "
        f"tail:\n{cold_run.build.output_tail}"
    )
    assert vex.get("serialNumber") != cold_run.sbom.get("serialNumber"), (
        "the VEX document is not a separate document: it shares the SBOM's "
        f"serialNumber {vex.get('serialNumber')!r}; build-log tail:\n"
        f"{cold_run.build.output_tail}"
    )
    assert vex.get("vulnerabilities"), (
        "the deployed VEX correlates no vulnerabilities at all; build-log "
        f"tail:\n{cold_run.build.output_tail}"
    )
    violations = list(cyclonedx_16_validator.iter_errors(vex))
    assert not violations, (
        f"deployed VEX violates the vendored CycloneDX 1.6 schema:\n"
        f"{schema_validation.describe_errors(violations)}\n"
        f"build-log tail:\n{cold_run.build.output_tail}"
    )


def test_primary_component_identifies_built_image_and_version(cold_run):
    component = cold_run.sbom.get("metadata", {}).get("component", {})
    assert component.get("name") == kas_env.TARGET, (
        f"primary component names {component.get('name')!r}, expected the "
        f"built image {kas_env.TARGET!r}; build-log tail:\n"
        f"{cold_run.build.output_tail}"
    )
    assert component.get("type") == "firmware", (
        f"primary component type is {component.get('type')!r}, expected "
        f"'firmware' (the layer default); build-log tail:\n"
        f"{cold_run.build.output_tail}"
    )
    # The version's build timestamp must name a real build; when this
    # run generated the documents (its do_deploy_cyclonedx reran — the
    # install step of the export, whose hash covers the document
    # contents), the timestamp must be the very image this invocation
    # built, taken from the deploy state captured as the invocation
    # completed. The tie is exact only over documents this invocation
    # generated: a served do_deploy_cyclonedx installs bytes whose
    # timestamp names whatever build populated the sstate cache, and
    # that build's dated images may since have been pruned — the
    # deploy dir carries no cross-generation link between a document
    # and an image artifact. Over served documents the check is
    # structural only (a rerun of the image chain alone does not
    # regenerate them anyway: do_deploy_cyclonedx's hash does not
    # cover do_rootfs output); byte-level identity of served
    # artifacts — including their version stamps — is R2's claim, and
    # R3's revert exercises the regenerate-back route. Later runs
    # also rotate the dated artifacts (BitBake regenerates DATETIME
    # on recipe re-parses), which is why the captured state — not the
    # live directory — is the evidence.
    version = component.get("version") or ""
    stamp = BUILD_TIMESTAMP.search(version)
    assert stamp, (
        f"primary component version {version!r} carries no build timestamp "
        "to tie it to an image artifact; build-log tail:\n"
        f"{cold_run.build.output_tail}"
    )
    if any(
        name.endswith(":do_deploy_cyclonedx")
        for name in cold_run.record.reran_tasks
    ):
        built = {
            dated.group(1)
            for name in cold_run.record.checksums
            if (dated := re.search(r"rootfs-(\d{14})\.ext4\.zst\Z", name))
        }
        assert built, (
            f"no dated rootfs artifact {ROOTFS_IMAGE_GLOB} in the deploy "
            f"state captured from {cold_run.build.deploy_dir}; build-log "
            f"tail:\n{cold_run.build.output_tail}"
        )
        assert stamp.group(1) == max(built), (
            f"primary component version {version!r} names build "
            f"{stamp.group(1)}, but this invocation built "
            f"{max(built)}; build-log tail:\n{cold_run.build.output_tail}"
        )
    else:
        # Not silent: -ra reports this as a skipped tie, while the
        # structural claims above (a real build timestamp is present)
        # still executed. Byte-level identity of served artifacts —
        # version stamp included — is R2's claim.
        pytest.skip(
            "documents served from cache; the version-to-image tie is "
            "enforced on the invocation that generated the documents"
        )


def test_known_rootfs_package_appears_as_component(cold_run):
    manifest = cold_run.deployed(kas_env.MANIFEST_NAME, "rootfs manifest")
    packages = {
        line.split()[0] for line in manifest.read_text().splitlines()
        if line.split()
    }
    assert ROOTFS_PACKAGE in packages, (
        f"{ROOTFS_PACKAGE!r} is not in the deployed rootfs manifest "
        f"{manifest.name}; build-log tail:\n{cold_run.build.output_tail}"
    )
    names = {c.get("name") for c in cold_run.sbom.get("components", [])}
    assert ROOTFS_PACKAGE in names, (
        f"{ROOTFS_PACKAGE!r} is installed in the rootfs per the manifest "
        f"but missing from the SBOM components ({len(names)} components); "
        f"build-log tail:\n{cold_run.build.output_tail}"
    )


def test_dependency_graph_nonempty_with_resolving_references(cold_run):
    sbom = cold_run.sbom
    dependencies = sbom.get("dependencies") or []
    assert dependencies, (
        f"SBOM dependency section is empty; build-log tail:\n"
        f"{cold_run.build.output_tail}"
    )
    refs = _component_refs(sbom)
    unresolved = sorted(
        {
            ref
            for entry in dependencies
            for ref in [entry.get("ref"), *entry.get("dependsOn", [])]
            if ref not in refs
        }
    )
    assert not unresolved, (
        f"{len(dependencies)} dependency entries, but "
        f"{len(unresolved)} references resolve to no component bom-ref, "
        f"e.g. {unresolved[:5]}; build-log tail:\n"
        f"{cold_run.build.output_tail}"
    )


def test_vex_affects_references_resolve_against_sbom(cold_run):
    sbom, vex = cold_run.sbom, cold_run.vex
    serial = (sbom.get("serialNumber") or "").removeprefix("urn:uuid:")
    version = str(sbom.get("version", 1))
    refs = _component_refs(sbom)

    def resolves(ref):
        match = CDX_REFERENCE.fullmatch(ref)
        return (match is not None
                and match["serial"] == serial
                and match["version"] == version
                and match["ref"] in refs)

    dangling = [
        (vulnerability.get("id"), affect.get("ref"))
        for vulnerability in vex.get("vulnerabilities", [])
        for affect in vulnerability.get("affects", [])
        if not resolves(affect.get("ref", ""))
    ]
    total = sum(len(v.get("affects", [])) for v in vex.get("vulnerabilities", []))
    assert not dangling, (
        f"{len(dangling)} of {total} VEX affects-references do not resolve "
        f"against the SBOM's component instances, e.g. {dangling[:5]}; "
        f"build-log tail:\n{cold_run.build.output_tail}"
    )


def test_image_metadata_bom_manifest_pair_deployed(cold_run):
    captures = cold_run.record.image_metadata_captures
    context = (
        f"image metadata under {cold_run.build.image_metadata_dir}; "
        f"build-log tail:\n{cold_run.build.output_tail}"
    )

    def document(name):
        assert isinstance(name, str) and name in captures, (
            f"missing image-metadata document {name!r}; {context}"
        )
        try:
            return json.loads(captures[name])
        except ValueError as exc:
            pytest.fail(f"image-metadata document {name!r} is invalid JSON: {exc}; {context}")

    manifest = document("manifest.json")
    assert isinstance(manifest, dict), f"image-metadata manifest is not an object; {context}"
    for kind, deployed in (("sbom", cold_run.sbom), ("vex", cold_run.vex)):
        assert document(manifest.get(kind)) == deployed, (
            f"image-metadata {kind} differs from the deployed document; {context}"
        )
