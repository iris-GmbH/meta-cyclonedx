# SPDX-License-Identifier: MIT
"""Unit tests for the workspace layout (no build, no container)."""

import pytest

from tests.integration import kas_env


def make_workspace(tmp_path):
    workspace = tmp_path / "repo" / ".integration"
    workspace.mkdir(parents=True)
    return workspace


def test_build_dir_is_repo_local_without_nfs(tmp_path):
    workspace = make_workspace(tmp_path)
    got = kas_env.build_dir(workspace=workspace, environ={}, fs_type=lambda _: "ext4")
    assert got == workspace / "build"
    assert got.is_dir()


def test_build_dir_moves_off_nfs_behind_a_symlink(tmp_path):
    workspace = make_workspace(tmp_path)
    got = kas_env.build_dir(
        workspace=workspace,
        environ={"TMPDIR": str(tmp_path / "scratch")},
        fs_type=lambda _: "nfs",
    )
    assert got.is_relative_to(tmp_path / "scratch")
    assert (workspace / "build").resolve() == got


def test_nfs_redirect_is_per_checkout(tmp_path, monkeypatch):
    ids = set()
    for name in ("a", "b"):
        repo = tmp_path / name / "meta-cyclonedx"
        workspace = repo / ".integration"
        workspace.mkdir(parents=True)
        monkeypatch.setattr(kas_env, "REPO_ROOT", repo)
        got = kas_env.build_dir(
            workspace=workspace,
            environ={"TMPDIR": str(tmp_path / "scratch")},
            fs_type=lambda _: "nfs",
        )
        ids.add(got)
    assert len(ids) == 2, "backport checkouts must not share a build dir"

def test_nfs_redirect_refuses_to_clobber_a_populated_build_dir(tmp_path):
    workspace = make_workspace(tmp_path)
    stale = workspace / "build"
    stale.mkdir()
    (stale / "something").write_text("keep")
    with pytest.raises(RuntimeError, match="delete it"):
        kas_env.build_dir(workspace=workspace, environ={}, fs_type=lambda _: "nfs")
    assert (stale / "something").read_text() == "keep"
