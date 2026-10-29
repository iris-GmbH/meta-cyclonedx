# SPDX-License-Identifier: MIT
"""Real kernel/module packaging and deployed VEX, with a tiny synthetic CVE DB.

Run independently with:
    pytest -m integration tests/integration/test_kernel_cve_build.py
The normal R1-R5 profile keeps CVE filtering off. This profile exercises it
without fetching the full CVEProject repository or mocking source collection.
"""

import json
from types import SimpleNamespace

import pytest

from tests.integration import document_compare, kas_env
from tests.integration.conftest import KasRunRecorder

pytestmark = pytest.mark.integration

CONFIG = "tests/integration/kas/kernel-cve.yml"
REVISION_ONE = "0000000000000000000000000000000000000001"
REVISION_TWO = "0000000000000000000000000000000000000002"
EXCLUDED = "CVE-2099-0001"
PATCHED = "CVE-2099-0008"
IGNORED = "CVE-2099-0009"
ADDED = "CVE-2099-0011"
RETAINED = {f"CVE-2099-{number:04d}" for number in (2, 3, 4, 5, 6, 7, 10)}


@pytest.fixture(scope="module")
def kernel_cve_runs(container_runtime):
    recorder = KasRunRecorder(container_runtime)
    results = {}
    for name, enabled, revision in (
        ("disabled", "0", REVISION_ONE),
        ("enabled", "1", REVISION_ONE),
        ("updated", "1", REVISION_TWO),
    ):
        record = recorder.invoke(
            "kernel-cve-" + name, config=CONFIG,
            extra_env={"CYCLONEDX_VEX_ADD_KERNEL_CVE": enabled,
                       "CYCLONEDX_KERNEL_CVE_DB_SRCREV": revision},
        )
        capture = kas_env.WORKSPACE / "kernel-cve-evidence" / name
        capture.mkdir(parents=True, exist_ok=True)
        (capture / "build.log").write_text(record.log)
        assert record.returncode == 0, (
            f"kernel CVE {name} build failed:\n{record.output_tail}")
        paths = list((record.build.build_dir / "tmp/cyclonedx/pn").glob(
            "*/linux-yocto.kernel-cve-evidence.json"))
        assert len(paths) == 1, (
            f"expected one kernel packaging evidence file, got {paths};\n{record.output_tail}")
        evidence = json.loads(paths[0].read_text())
        documents = record.documents
        # Capture immediately: later profiles reuse the same deploy paths.
        for filename, data in (("bom.json", documents.sbom), ("vex.json", documents.vex),
                               ("packaging.json", evidence)):
            (capture / filename).write_text(json.dumps(data, indent=2))
        results[name] = SimpleNamespace(record=record, documents=documents, evidence=evidence)
    return results


def statements(run):
    entries = run.documents.vex.get("vulnerabilities", [])
    return {entry["id"]: entry for entry in entries if entry["id"].startswith("CVE-2099-")}


def test_kernel_and_module_have_real_packaging_debug_evidence(kernel_cve_runs):
    for run in kernel_cve_runs.values():
        evidence = run.evidence
        assert evidence["debug_info"] and evidence["dummy_module"], evidence
        assert evidence["vmlinux_records"] and evidence["main_source_present"], evidence
        assert evidence["dummy_records"] and evidence["dummy_source_present"], evidence
        assert evidence["fixture_sources_exist"], evidence


def test_disabled_filter_adds_no_database_task_or_automatic_assessment(kernel_cve_runs):
    run = kernel_cve_runs["disabled"]
    assert run.evidence["database_in_graph"] is False
    assert set(statements(run)) == {PATCHED, IGNORED}


def test_only_uncompiled_c_case_is_automatically_excluded(kernel_cve_runs):
    run = kernel_cve_runs["enabled"]
    assert run.evidence["database_in_graph"] is True
    cves = statements(run)
    assert set(cves) == {EXCLUDED, PATCHED, IGNORED}
    assert RETAINED.isdisjoint(cves)
    analysis = cves[EXCLUDED]["analysis"]
    assert analysis["state"] == "not_affected"
    assert analysis["justification"] == "code_not_present"


def test_patch_and_explicit_recipe_decisions_take_precedence(kernel_cve_runs):
    for run in kernel_cve_runs.values():
        cves = statements(run)
        assert cves[PATCHED]["analysis"]["state"] == "resolved"
        assert cves[IGNORED]["analysis"]["state"] == "not_affected"
        assert cves[IGNORED]["analysis"].get("justification") != "code_not_present"
        assert "CVE-2099-0007" not in cves  # Explicit Unpatched must not be excluded.


def test_kernel_assessments_cover_all_components_once_and_resolve(kernel_cve_runs):
    for name in ("enabled", "updated"):
        run = kernel_cve_runs[name]
        cves = statements(run)
        expected = {affect["ref"] for affect in cves[PATCHED]["affects"]}
        actual = [affect["ref"] for affect in cves[EXCLUDED]["affects"]]
        assert expected and set(actual) == expected
        assert len(actual) == len(set(actual))
        sbom = run.documents.sbom
        serial = sbom["serialNumber"].removeprefix("urn:uuid:")
        refs = {component["bom-ref"] for component in sbom["components"]}
        for ref in actual:
            assert ref.startswith(f"urn:cdx:{serial}/1#")
            assert ref.rsplit("#", 1)[1] in refs
        ids = [entry["id"] for entry in run.documents.vex.get("vulnerabilities", [])
               if entry["id"].startswith("CVE-2099-")]
        assert len(ids) == len(set(ids))


def test_filtering_leaves_image_sbom_unchanged(kernel_cve_runs):
    sboms = [document_compare.canonicalize({"sbom": run.documents.sbom,
                                          "vex": run.documents.vex})["sbom"]
             for run in kernel_cve_runs.values()]
    for sbom in sboms[1:]:
        assert document_compare.first_difference(sboms[0], sbom) is None


def test_database_revision_refreshes_assessment_without_kernel_recompilation(kernel_cve_runs):
    before, after = kernel_cve_runs["enabled"], kernel_cve_runs["updated"]
    assert before.evidence["database_revision"] == REVISION_ONE
    assert after.evidence["database_revision"] == REVISION_TWO
    assert ADDED not in statements(before)
    assert set(statements(after)) == {EXCLUDED, PATCHED, IGNORED, ADDED}
    tasks = after.record.reran_tasks
    assert any("/linux-yocto_" in task and task.endswith(":do_populate_cyclonedx")
               for task in tasks), after.record.output_tail
    assert not any("/linux-yocto_" in task and task.endswith(":do_compile")
                   for task in tasks), after.record.output_tail


def test_kernel_filter_documents_match_cyclonedx_schema(kernel_cve_runs, cyclonedx_17_validator):
    for run in kernel_cve_runs.values():
        cyclonedx_17_validator.validate(run.documents.sbom)
        cyclonedx_17_validator.validate(run.documents.vex)
