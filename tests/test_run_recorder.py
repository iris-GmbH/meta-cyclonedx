# SPDX-License-Identifier: MIT
"""Unit tests for the matrix stage gate in the run recorder (no build)."""

import pytest

from tests.integration import kas_env
from tests.integration.conftest import (
    KasBuildResult,
    KasRunRecorder,
    RunRecord,
)

FAILURE_LINES = [
    "NOTE: Tasks Summary: Attempted 3914 tasks.\n",
    "ERROR: Task (/build/meta/recipes-kernel/linux/linux-yocto_6.6.bb:"
    "do_compile) failed with exit code '1'\n",
]


def recorder_with(name, returncode, build_dir):
    """A recorder whose single recorded invocation exited with *returncode*."""
    recorder = KasRunRecorder("podman")
    recorder.results[name] = RunRecord(
        name,
        KasBuildResult("podman", returncode, FAILURE_LINES, build_dir),
        FAILURE_LINES,
    )
    recorder._pinned = True
    return recorder


def deploy_dir(tmp_path):
    """Make the build dir look like one that deployed artifacts."""
    (tmp_path / "tmp" / "deploy" / "images" / kas_env.MACHINE).mkdir(
        parents=True, exist_ok=True
    )
    return tmp_path


def launch_attempt(*args, **kwargs):
    raise AssertionError("bitbake must not launch after a failed invocation")


def patch_stage_environment(monkeypatch, recorder, tmp_path, stream=None):
    monkeypatch.setattr(recorder, "_stream", stream or launch_attempt)
    monkeypatch.setattr(kas_env, "ensure_fixture_layer", lambda: None)
    monkeypatch.setattr(kas_env, "workspace_env", dict)
    monkeypatch.setattr(kas_env, "build_dir", lambda: deploy_dir(tmp_path))


def test_failed_invocation_skips_later_stages(monkeypatch, tmp_path):
    recorder = recorder_with("cold", 2, deploy_dir(tmp_path))
    patch_stage_environment(monkeypatch, recorder, tmp_path)

    with pytest.raises(pytest.skip.Exception) as excinfo:
        recorder.invoke("mutation")

    reason = str(excinfo.value)
    assert "cold" in reason
    assert "exit 2" in reason
    # The skip carries the build-log tail, so CI shows the actual error.
    assert "do_compile" in reason


def test_zero_exit_invocation_leaves_later_stages_unaffected(monkeypatch, tmp_path):
    recorder = recorder_with("cold", 0, deploy_dir(tmp_path))
    launched = []

    def stream(command, env):
        launched.append(command)
        return 0, FAILURE_LINES

    patch_stage_environment(monkeypatch, recorder, tmp_path, stream=stream)
    record = recorder.invoke("warm")

    assert launched, "the warm stage must still launch"
    assert record.returncode == 0


def test_recorded_failure_is_not_relunched_under_its_own_name(monkeypatch, tmp_path):
    recorder = recorder_with("cold", 2, deploy_dir(tmp_path))
    patch_stage_environment(monkeypatch, recorder, tmp_path)

    record = recorder.invoke("cold")

    assert record.returncode == 2
