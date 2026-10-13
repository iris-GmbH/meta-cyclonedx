# SPDX-License-Identifier: MIT
"""Unit tests for the run-observation helpers (no build, no container).

Byte-identity comparisons and log observations are the assertions the
cache-semantics runs (R2, R4) make over recorded runs; the observation
functions themselves are pure and unit-tested here.
"""

import hashlib
from types import SimpleNamespace

import pytest

from tests.integration import kas_env


# --- deployed-artifact checksums --------------------------------------------


def test_checksums_cover_files_and_symlinks_by_relative_path(tmp_path):
    (tmp_path / "image.ext4").write_bytes(b"a")
    (tmp_path / "latest.link").symlink_to("image.ext4")
    assert kas_env.artifact_checksums(tmp_path) == {
        "image.ext4": "sha256:"
        + "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        "latest.link": "link:image.ext4",
    }


def test_checksums_recurse_into_subdirectories(tmp_path):
    nested = tmp_path / "sub" / "deeper"
    nested.mkdir(parents=True)
    (nested / "f").write_bytes(b"f")
    assert kas_env.artifact_checksums(tmp_path) == {
        "sub": "dir",
        "sub/deeper": "dir",
        "sub/deeper/f": "sha256:" + hashlib.sha256(b"f").hexdigest(),
    }


def test_checksums_change_when_content_changes(tmp_path):
    (tmp_path / "f").write_bytes(b"a")
    before = kas_env.artifact_checksums(tmp_path)
    (tmp_path / "f").write_bytes(b"b")
    after = kas_env.artifact_checksums(tmp_path)
    assert before != after


def test_checksums_of_empty_deploy_dir_are_empty(tmp_path):
    assert kas_env.artifact_checksums(tmp_path) == {}


def test_checksums_of_missing_root_fail_loudly(tmp_path):
    # An empty mapping is what "identical" compares against; silently
    # returning {} for a missing deploy dir would make every run trivially
    # "byte-identical" to every other.
    with pytest.raises(FileNotFoundError):
        kas_env.artifact_checksums(tmp_path / "nope")


# --- BitBake task-execution observations ------------------------------------


def test_work_tasks_reran_lists_real_task_runs_only():
    log = (
        "NOTE: Running setscene task 1 of 3 (a.bb:do_package_setscene)\n"
        "NOTE: Running task 2 of 3 (b.bb:do_rm_work)\n"
        "NOTE: Running noexec task 3 of 3 (c.bb:do_build)\n"
    )
    assert kas_env.work_tasks_reran(log) == {"b.bb:do_rm_work"}


def test_work_tasks_reran_empty_for_a_fully_served_run():
    log = (
        "NOTE: Running setscene task 1 of 2 (a.bb:do_package_setscene)\n"
        "NOTE: Running noexec task 2 of 2 (b.bb:do_build)\n"
    )
    assert kas_env.work_tasks_reran(log) == set()


def test_setscene_restored_lists_served_outputs_without_suffix():
    log = (
        "NOTE: Running setscene task 1 of 3 (a.bb:do_package_setscene)\n"
        "NOTE: Running task 2 of 3 (b.bb:do_rootfs)\n"
        "NOTE: Running setscene task 3 of 3 "
        "(c.bb:do_deploy_cyclonedx_setscene)\n"
    )
    restored = kas_env.setscene_restored_tasks(log)
    assert restored == {"a.bb:do_package", "c.bb:do_deploy_cyclonedx"}
    # The two observations answer different questions and never overlap:
    # work done versus outputs served from cache.
    assert restored & kas_env.work_tasks_reran(log) == set()


# --- fixture-layer sources --------------------------------------------------


def test_fixture_layer_conf_is_a_parseable_minimal_layer():
    text = kas_env.fixture_layer_conf_text("blacksail")
    assert "BBFILE_COLLECTIONS += \"integration-fixtures\"" in text
    # The layer must declare compatibility with the series under test — the
    # value is a parameter, never hardcoded.
    assert "LAYERSERIES_COMPAT_integration-fixtures = \"blacksail\"" in text


def test_fixture_recipe_is_a_trivial_unused_recipe():
    text = kas_env.fixture_recipe_text()
    # Parses standalone and builds nothing: no fetch, no dependencies on
    # anything in the image graph.
    assert "INHIBIT_DEFAULT_DEPS = \"1\"" in text
    assert "SRC_URI" not in text


# --- byte-identity reporting -------------------------------------------------


def _rec(name, checksums):
    return SimpleNamespace(name=name, checksums=checksums, output_tail="tail")


def test_identity_report_classifies_added_removed_and_changed():
    from tests.integration import deploy_compare

    report = deploy_compare.identity_report(
        _rec("warm-rerun", {"a": "1", "b": "2", "c": "3"}),
        {"a": "1", "b": "X", "d": "4"},
    )
    assert "added:   ['c']" in report
    assert "removed: ['d']" in report
    assert "changed: ['b']" in report
    assert "warm-rerun" in report



def test_identity_report_subset_restricts_the_claim():
    from tests.integration import deploy_compare

    cold = _rec(
        "cold",
        {
            "img-20261012.rootfs.ext4.zst": "1",
            "image.cyclonedx.bom.json": "2",
        },
    )
    mutated = _rec(
        "signature-mutation",
        {
            "img-20261013.rootfs.ext4.zst": "1",
            "image.cyclonedx.bom.json": "2",
        },
    )
    # Whole-map: the rotated dated artifact registers. Subset to the
    # CycloneDX claim: byte-identical.
    whole = deploy_compare.identity_report(mutated, cold)
    assert "added:" in whole and "removed:" in whole
    scoped = deploy_compare.identity_report(
        mutated, cold, subset=deploy_compare.cyclonedx_checksums
    )
    assert "added:   []" in scoped
    assert "removed: []" in scoped and "changed: []" in scoped
