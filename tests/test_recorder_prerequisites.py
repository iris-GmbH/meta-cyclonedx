# SPDX-License-Identifier: MIT
"""Unit tests for how the run recorder reports prerequisite gaps.

Contributor documentation promises the integration matrix *skips* —
never errors — when a prerequisite is missing. The prerequisite probes
run inside the recorder's first invocation, so the skip contract is
asserted here against the recorder itself.
"""

import subprocess

import pytest

from tests.integration import kas_env
from tests.integration.conftest import KasRunRecorder


def _raise(exc):
    def raiser(*args, **kwargs):
        raise exc

    return raiser


def test_unfetchable_submodule_skips_instead_of_erroring(monkeypatch):
    # A submodule that is registered but not checked out triggers a git
    # fetch; offline, that raises CalledProcessError — not RuntimeError.
    monkeypatch.setattr(
        kas_env,
        "ensure_kas_submodule",
        _raise(subprocess.CalledProcessError(128, "git submodule update")),
    )
    recorder = KasRunRecorder("podman")
    with pytest.raises(pytest.skip.Exception):
        recorder.invoke("cold")


def test_missing_wrapper_skips_with_the_reason(monkeypatch):
    monkeypatch.setattr(
        kas_env,
        "ensure_kas_submodule",
        _raise(RuntimeError("kas-container is missing")),
    )
    recorder = KasRunRecorder("podman")
    with pytest.raises(pytest.skip.Exception, match="kas-container is missing"):
        recorder.invoke("cold")
