# SPDX-License-Identifier: MIT
"""R2/R4 — cache semantics of re-invocations against one workspace.

Both claims are named tests over before/after checksums of the deployed
files: an unchanged re-invocation leaves every deployed artifact
byte-identical (nothing reran; sstate served everything), and adding one
trivial unused recipe to the fixture layer — nothing in the image depends
on it — leaves them byte-identical too (graph isolation: unrelated
changes cannot churn SBOM output). The re-invocation plumbing (the
`kas_runs` recorder) snapshots per-run checksums and log observations.
"""

import pytest

from tests.integration import deploy_compare, kas_env

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
def warm_rerun(kas_runs, kas_build):
    """R2: re-invoke unchanged, directly on the recorded cold workspace."""
    return kas_runs.invoke("warm-rerun")


@pytest.fixture(scope="module")
def graph_isolation(kas_runs, warm_rerun):
    """R4: re-invoke with one trivial unused recipe in the fixture layer.

    Depends on `warm_rerun` so the unchanged run still observes the
    pristine cold workspace. Teardown reverts the mutation and removes the
    fixture repository; `revert_fixture_mutations` raises if the layer's
    tracked tree took any damage, so an incomplete revert surfaces as an
    error instead of a silently dirty workspace.
    """
    kas_env.ensure_fixture_layer()
    kas_env.add_fixture_recipe()
    try:
        yield kas_runs.invoke("graph-isolation")
    finally:
        kas_env.revert_fixture_mutations()
        kas_env.remove_fixture_layer()


def test_unchanged_rerun_leaves_deployed_artifacts_byte_identical(
    kas_runs, warm_rerun
):
    assert warm_rerun.returncode == 0, (
        f"the unchanged re-run failed via {warm_rerun.build.engine} "
        f"(exit {warm_rerun.returncode}); build-log tail:\n"
        f"{warm_rerun.output_tail}"
    )
    cold = kas_runs["cold"]
    assert warm_rerun.checksums == cold.checksums, (
        deploy_compare.identity_report(warm_rerun, cold)
    )


def test_unchanged_rerun_reran_no_work_tasks(warm_rerun):
    """The log observation behind byte-identity: sstate served everything.

    BitBake's own accounting counts its always-executing bookkeeping tail
    (noexec tasks, the image's `do_rm_work`) as reruns even when no work
    redid anything; the claim over the log is that not one real task reran.
    """
    unexpected = sorted(
        task
        for task in warm_rerun.reran_tasks
        if not task.endswith(":do_rm_work")
    )
    assert not unexpected, (
        f"work tasks reran on the unchanged re-run: {unexpected}; "
        f"build-log tail:\n{warm_rerun.output_tail}"
    )


def test_fixture_layer_is_a_url_less_entry_in_the_build_configuration():
    """kas.yml registers the fixture layer as a local (URL-less) repository.

    Read as text, deliberately: kas.yml is fixed input to every run, and
    adding a YAML parser dependency for one structural claim would make
    it a fourth integration-layer prerequisite.
    """
    lines = (kas_env.REPO_ROOT / "kas.yml").read_text().splitlines()
    entry = []
    for line in lines[lines.index("  fixtures:") + 1:]:
        if not line.startswith("    "):
            break
        entry.append(line.strip())
    assert "path: .integration/fixtures" in entry
    assert not any(line.startswith("url:") for line in entry), (
        "the fixture layer must be a local repository"
    )
    assert any(line.startswith("meta-integration-fixtures") for line in entry)


def test_fixture_layer_participates_in_the_build(graph_isolation):
    """BitBake's build-configuration banner names the fixture layer.

    The byte-identity claims are only meaningful if the layer actually
    took part in the run — kas.yml alone would not prove it.
    """
    assert graph_isolation.returncode == 0, (
        f"graph-isolation build failed; build-log tail:\n"
        f"{graph_isolation.output_tail}"
    )
    assert "meta-integration-fixtures = " in graph_isolation.log, (
        "the fixture layer is not in the build configuration of the "
        f"graph-isolation run; build-log tail:\n{graph_isolation.output_tail}"
    )


def test_graph_isolation_recipe_keeps_deployed_artifacts_byte_identical(
    kas_runs, graph_isolation
):
    assert graph_isolation.returncode == 0, (
        f"the graph-isolation run failed via "
        f"{graph_isolation.build.engine} (exit {graph_isolation.returncode}); "
        f"build-log tail:\n{graph_isolation.output_tail}"
    )
    cold = kas_runs["cold"]
    assert graph_isolation.checksums == cold.checksums, (
        deploy_compare.identity_report(graph_isolation, cold)
    )


def test_fixture_recipe_participates_as_an_untracked_change_only(
    graph_isolation,
):
    """While recorded, the mutation is untracked; the tracked tree is clean.

    Byte-identity would be worthless if the claim held only over a recipe
    the run had committed somewhere in the build inputs.
    """
    assert graph_isolation.returncode == 0, (
        f"graph-isolation build failed; build-log tail:\n"
        f"{graph_isolation.output_tail}"
    )
    assert kas_env.FIXTURES_RECIPE.is_file()
    assert kas_env.fixture_status(tracked_only=True) == ""
    dirt = [
        line
        for line in kas_env.fixture_status().splitlines()
        if not line.startswith("?? ")
    ]
    assert dirt == [], f"tracked-tree damage during the run: {dirt}"
