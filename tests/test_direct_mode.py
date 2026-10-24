# SPDX-License-Identifier: MIT
"""Unit tests for harness direct mode (no build, no network).

The seams are the integration harness's kas-environment helpers: launch
construction, the pin/version tie, and the R5 install-list channel —
exercised through their injection points only.
"""

import pytest

from tests.integration import kas_env


def test_container_mode_launch_keeps_the_wrapper():
    command, env = kas_env.kas_invocation("podman")
    assert command == [str(kas_env.KAS_CONTAINER), "build", "kas.yml"]
    assert env == {}


def test_direct_mode_launch_is_a_plain_kas_invocation():
    command, env = kas_env.kas_invocation(kas_env.KAS_DIRECT)
    assert command == ["kas", "build", "kas.yml"]
    assert env == {}


def test_container_mode_r5_rides_the_runtime_args_channel():
    command, env = kas_env.kas_invocation(
        "podman", extra_env=kas_env.IMAGE_EXTRA_INSTALL_ENV
    )
    assert command == [
        str(kas_env.KAS_CONTAINER),
        "--runtime-args",
        "-e CORE_IMAGE_EXTRA_INSTALL=harness-image-extra",
        "build",
        "kas.yml",
    ]
    assert env == {}


def test_direct_mode_r5_rides_the_process_environment():
    """R5's claim is mode-independent: same package, mode-appropriate channel."""
    command, env = kas_env.kas_invocation(
        kas_env.KAS_DIRECT, extra_env=kas_env.IMAGE_EXTRA_INSTALL_ENV
    )
    assert command == ["kas", "build", "kas.yml"]
    assert "--runtime-args" not in command
    assert env == {**kas_env.IMAGE_EXTRA_INSTALL_ENV}


class _Completed:
    def __init__(self, stdout):
        self.stdout = stdout


def test_direct_kas_version_parses_the_reported_string():
    reported = kas_env.direct_kas_version(
        which=lambda name: "/usr/bin/kas",
        run=lambda *a, **kw: _Completed(
            "kas 5.5 (configuration format version 19, "
            "earliest compatible version 14)"
        ),
    )
    assert reported == "5.5"


def test_direct_kas_version_without_kas_on_path_never_runs_anything():
    def no_run(*a, **kw):
        raise AssertionError("must not exec when no kas binary is present")

    assert kas_env.direct_kas_version(which=lambda name: None, run=no_run) is None


def test_direct_version_tie_passes_on_equal_versions():
    assert kas_env.check_kas_pin(
        running_version="5.5", describe=lambda: "5.5"
    ) == ("5.5", "5.5")


def test_direct_version_tie_normalizes_the_v_prefix():
    assert kas_env.check_kas_pin(
        running_version="v5.5", describe=lambda: "v5.5"
    ) == ("v5.5", "5.5")


def test_direct_version_tie_mismatch_names_both_sides():
    with pytest.raises(RuntimeError) as excinfo:
        kas_env.check_kas_pin(running_version="6.0", describe=lambda: "5.5")
    assert "6.0" in str(excinfo.value) and "5.5" in str(excinfo.value)
