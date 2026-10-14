# SPDX-License-Identifier: MIT
"""R3/R5 — regeneration runs: signature mutation and image content change.

R3 mutates the *signature-carrying generator source* named by the harness
parameter ``kas_env.SIGNATURE_SOURCE`` — one inert comment, placed where
BitBake folds the file's content into the generation tasks' signatures —
and proves the deployed documents regenerate: serial numbers differ, the
raw documents stay schema-valid, and the canonicalized documents
(volatiles removed by ``document_compare.canonicalize``) compare equal to
the cold run. Teardown reverts the mutation byte-exactly, and a
follow-up invocation must restore byte-identity: the sstate objects the
cold run fed are still there, so the reverted signatures serve the very
same bytes again.

R5 changes the image instead of the generator: one small harness-owned
package joins the install list — via CORE_IMAGE_EXTRA_INSTALL, which the
R5 invocation sets inside the build container (the wrapper's
--runtime-args channel; the kas.yml ``env:`` block then forwards it to
BitBake) — and the deployed documents must show it as a component with
a dependency edge, cross-checked against the rootfs manifest in the
cold-run oracle's assertion style.

Cross-regeneration comparisons use `canonicalize`; cache-reuse
comparisons (R2, R4 — see test_cache_semantics) stay byte-level.
"""

from types import SimpleNamespace

import pytest

from tests.integration import deploy_compare, document_compare, kas_env

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def build_succeeded(kas_build):
    """No evidence observation is made over a failed or aborted build."""
    assert kas_build.returncode == 0, (
        f"the cold run it would report on failed via {kas_build.engine} "
        f"(exit {kas_build.returncode}); build-log tail:\n"
        f"{kas_build.output_tail}"
    )


@pytest.fixture(scope="module")
def mutation_runs(kas_runs, kas_build):
    """R3: mutate → re-invoke → revert (in `finally`) → re-invoke.

    The revert lands before the follow-up invocation, so that run
    observes the restored tree, and an invocation crash can never leave
    the layer under test mutated.
    """
    source_status_before = kas_env.working_tree_status(kas_env.SIGNATURE_SOURCE)
    source_before = kas_env.mutate_signature_source()
    try:
        mutated = kas_runs.invoke("signature-mutation")
    finally:
        kas_env.revert_signature_source(source_before)
    reverted = (
        kas_runs.invoke("mutation-reverted")
        if mutated.returncode == 0
        else None
    )
    return SimpleNamespace(
        mutated=mutated, reverted=reverted, source_before=source_before,
        source_status_before=source_status_before,
    )


@pytest.fixture(scope="module")
def image_change(kas_runs, kas_build, mutation_runs):
    """R5: one small package joins the image install list, then re-invoke.

    Depends on `mutation_runs` so the signature-mutation evidence is
    recorded before changing the image install list. The delta
    is exactly one package: the recipe rides untracked in the fixture
    layer, the install-list change rides the environment, and teardown
    removes both plus the fixture-layer repository.
    """
    kas_env.ensure_fixture_layer()
    kas_env.revert_fixture_mutations()
    kas_env.add_image_extra_recipe()
    try:
        yield kas_runs.invoke(
            "image-change", extra_env=kas_env.IMAGE_EXTRA_INSTALL_ENV
        )
    finally:
        kas_env.revert_fixture_mutations()
        kas_env.remove_fixture_layer()


def _record_guard(record, label):
    assert record is not None, (
        f"the {label} run never executed — the run it depends on failed"
    )
    assert record.returncode == 0, (
        f"the {label} run failed via {record.build.engine} "
        f"(exit {record.returncode}); build-log tail:\n{record.output_tail}"
    )


def _assert_equal_canonicalized(label, cold, again):
    """Compare the pair together so VEX references retain SBOM identity."""
    difference = document_compare.first_difference(
        document_compare.canonicalize({"sbom": cold.sbom, "vex": cold.vex}),
        document_compare.canonicalize({"sbom": again.sbom, "vex": again.vex}),
    )
    assert difference is None, (
        f"the {label} run's canonicalized documents differ from the cold "
        f"run: {difference}; build-log tail:\n{again.build.output_tail}"
    )


def test_mutation_target_is_a_tracked_harness_parameter():
    # The matrix code reads the R3 target only through the parameter; on
    # this pre-seam branch the parameter names the class file, and its
    # content reaches the generation tasks' signatures only because the
    # build mounts this tracked working tree in place.
    assert kas_env.SIGNATURE_SOURCE.is_relative_to(kas_env.REPO_ROOT)
    assert kas_env.is_tracked(kas_env.SIGNATURE_SOURCE), (
        f"{kas_env.SIGNATURE_SOURCE} must be tracked: R3 proves the "
        "signature wiring of the layer's own generator source"
    )


def test_signature_mutation_regenerates_with_new_serial_numbers(
    mutation_runs, cold_run
):
    _record_guard(mutation_runs.mutated, "signature-mutation")
    again = mutation_runs.mutated.documents
    assert again.sbom.get("serialNumber") != cold_run.sbom.get("serialNumber"), (
        "the deployed SBOM kept its serialNumber across the signature "
        f"mutation — it did not regenerate; build-log tail:\n"
        f"{mutation_runs.mutated.output_tail}"
    )
    assert again.vex.get("serialNumber") != cold_run.vex.get("serialNumber"), (
        "the deployed VEX kept its serialNumber across the signature "
        f"mutation — it did not regenerate; build-log tail:\n"
        f"{mutation_runs.mutated.output_tail}"
    )


def test_mutated_documents_remain_schema_valid(
    mutation_runs, cyclonedx_16_validator
):
    from tests.integration import schema_validation

    _record_guard(mutation_runs.mutated, "signature-mutation")
    for label, document in (
        ("SBOM", mutation_runs.mutated.documents.sbom),
        ("VEX", mutation_runs.mutated.documents.vex),
    ):
        violations = list(cyclonedx_16_validator.iter_errors(document))
        assert not violations, (
            f"the regenerated {label} violates the vendored CycloneDX "
            f"1.6 schema:\n{schema_validation.describe_errors(violations)}\n"
            f"build-log tail:\n{mutation_runs.mutated.output_tail}"
        )


def test_canonicalized_documents_match_the_cold_run(mutation_runs, cold_run):
    _record_guard(mutation_runs.mutated, "signature-mutation")
    _assert_equal_canonicalized(
        "signature-mutation",
        cold_run,
        mutation_runs.mutated.documents,
    )


def test_signature_mutation_reran_the_generation_tasks(mutation_runs):
    """The log observation behind the regeneration: the signatures moved.

    Byte-equal content served from sstate is what R2/R4 claim; here the
    opposite must hold — mutating the signature-carrying source makes
    BitBake redo the task that produces the documents. do_rootfs has no
    sstate to restore from, so a moved signature always reruns it.
    do_deploy_cyclonedx may legitimately arrive either way: a first
    sighting of the mutated hash runs it; once its object is in the
    cache, restoring it serves the mutated run's own bytes — which the
    serial-number test asserts separately.
    """
    _record_guard(mutation_runs.mutated, "signature-mutation")
    reran = mutation_runs.mutated.reran_tasks
    assert any(name.endswith(":do_rootfs") for name in reran), (
        f"no recipe's :do_rootfs reran although the signature-carrying "
        f"source changed; build-log tail:\n"
        f"{mutation_runs.mutated.output_tail}"
    )
    delivered = reran | kas_env.setscene_restored_tasks(
        mutation_runs.mutated.log
    )
    assert any(
        name.endswith(":do_deploy_cyclonedx") for name in delivered
    ), (
        "no recipe's :do_deploy_cyclonedx reran or was restored in the "
        "mutated run; build-log tail:\n"
        f"{mutation_runs.mutated.output_tail}"
    )


def test_teardown_restored_the_generator_source(mutation_runs):
    assert (
        kas_env.SIGNATURE_SOURCE.read_text() == mutation_runs.source_before
    ), "teardown did not restore the signature-carrying source byte-exactly"
    dirt = kas_env.working_tree_status(kas_env.SIGNATURE_SOURCE)
    assert dirt == mutation_runs.source_status_before, (
        f"the mutation run changed the generator's pre-existing git status:\n{dirt}"
    )


def test_reverted_run_restores_deployed_byte_identity(kas_runs, mutation_runs):
    """The revert restores the deployed CycloneDX artifacts byte-for-byte.

    Byte identity is claimed for the artifacts, via do_deploy_cyclonedx's
    sstate object — and only for them: the mutation and revert runs
    re-parse every recipe, BitBake regenerates DATETIME on re-parse, and
    the *image* artifacts are named after it, so their dated names and
    links rotate with each such run. The CycloneDX document names embed
    no DATETIME; those bytes are the layer's output and the claim's
    subject.
    """
    _record_guard(mutation_runs.reverted, "mutation-reverted")
    _record_guard(mutation_runs.mutated, "signature-mutation")
    cold = kas_runs["cold"]
    assert deploy_compare.cyclonedx_checksums(
        mutation_runs.reverted.checksums
    ) == deploy_compare.cyclonedx_checksums(
        cold.checksums
    ), deploy_compare.identity_report(
        mutation_runs.reverted, cold, subset=deploy_compare.cyclonedx_checksums
    )


def test_image_extra_package_is_installed_in_the_rootfs(image_change):
    """The manifest of the R5 run names the new package: it is installed.

    Proven before the SBOM claim, so a missing component can be told
    apart from a package that never reached the rootfs.
    """
    _record_guard(image_change, "image-change")
    manifest = image_change.documents.deployed(
        kas_env.MANIFEST_NAME, "rootfs manifest"
    )
    packages = {
        line.split()[0] for line in manifest.read_text().splitlines()
        if line.split()
    }
    assert kas_env.IMAGE_EXTRA_RECIPE_NAME in packages, (
        f"{kas_env.IMAGE_EXTRA_RECIPE_NAME!r} is not in the deployed "
        f"rootfs manifest {manifest.name}; build-log tail:\n"
        f"{image_change.output_tail}"
    )


def test_image_extra_package_appears_as_component_with_dependency_edge(
    image_change,
):
    """The artifacts track the real rootfs: the new package is in the graph.

    The edge is the fixture's own RDEPENDS (busybox, already installed),
    so the component cannot float unconnected.
    """
    _record_guard(image_change, "image-change")
    sbom = image_change.documents.sbom
    components = sbom.get("components", [])
    ref = next(
        (
            c.get("bom-ref")
            for c in components
            if c.get("name") == kas_env.IMAGE_EXTRA_RECIPE_NAME
        ),
        None,
    )
    assert ref, (
        f"{kas_env.IMAGE_EXTRA_RECIPE_NAME!r} is installed per the "
        f"manifest but missing from the SBOM components "
        f"({len(components)} present); build-log tail:\n"
        f"{image_change.output_tail}"
    )
    names = {c.get("bom-ref"): c.get("name") for c in components}
    edges = [
        entry
        for entry in sbom.get("dependencies", [])
        if entry.get("ref") == ref and entry.get("dependsOn")
    ]
    assert edges, (
        f"no dependency entry connects {kas_env.IMAGE_EXTRA_RECIPE_NAME!r}; "
        f"build-log tail:\n{image_change.output_tail}"
    )
    assert any(
        "busybox" in {names.get(r) for r in entry["dependsOn"]}
        for entry in edges
    ), (
        f"{kas_env.IMAGE_EXTRA_RECIPE_NAME!r}'s dependency edges resolve to "
        f"none of the busybox components; build-log tail:\n"
        f"{image_change.output_tail}"
    )


def test_image_change_documents_stay_schema_valid(
    image_change, cyclonedx_16_validator
):
    from tests.integration import schema_validation

    _record_guard(image_change, "image-change")
    for label, document in (
        ("SBOM", image_change.documents.sbom),
        ("VEX", image_change.documents.vex),
    ):
        violations = list(cyclonedx_16_validator.iter_errors(document))
        assert not violations, (
            f"the image-change {label} violates the vendored CycloneDX 1.6 "
            f"schema:\n{schema_validation.describe_errors(violations)}\n"
            f"build-log tail:\n{image_change.output_tail}"
        )
