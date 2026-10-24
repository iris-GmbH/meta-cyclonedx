# SPDX-License-Identifier: MIT
"""Unit tests for the container-runtime probe (no build, no network)."""

import pytest

from tests.integration import kas_env


def probe(engine_var=None, available=()):
    return kas_env.detect_container_runtime(
        which=lambda name: name in available,
        get=lambda key, default=None: (
            engine_var if key == "KAS_CONTAINER_ENGINE" else default
        ),
    )


def test_podman_is_preferred_over_docker():
    assert probe(available={"podman", "docker"}) == "podman"


def test_docker_is_accepted_without_podman():
    assert probe(available={"docker"}) == "docker"


def test_engine_env_var_overrides_the_probe():
    assert probe(engine_var="docker", available={"podman", "docker"}) == "docker"


def test_engine_env_var_naming_a_missing_binary_yields_no_runtime():
    assert probe(engine_var="podman", available={"docker"}) is None


def test_no_container_runtime_yields_no_runtime():
    assert probe(available=set()) is None


def test_none_override_never_falls_back_to_the_probe():
    def no_probe(name):
        raise AssertionError("an explicit direct-mode override must not probe")

    assert (
        kas_env.detect_container_runtime(
            which=no_probe,
            get=lambda key, default=None: (
                "none" if key == "KAS_CONTAINER_ENGINE" else default
            ),
        )
        == kas_env.KAS_DIRECT
    )


def test_direct_mode_indicator_survives_available_engines():
    assert probe(engine_var="none", available={"podman", "docker"}) == kas_env.KAS_DIRECT


def test_skip_hint_names_the_installation_options():
    hint = kas_env.SKIP_HINT
    assert "podman" in hint.lower() and "docker" in hint.lower()
