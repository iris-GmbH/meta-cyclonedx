# SPDX-License-Identifier: MIT
"""Tracer bullet: one kas build end to end, one deployed SBOM.

Selected explicitly with ``pytest -m integration``; default runs stay
unit-only. Without a working container runtime the whole layer skips with an
install hint instead of failing.
"""

import pytest

from tests.integration import kas_env

pytestmark = pytest.mark.integration


def test_kas_build_completes(kas_build):
    assert kas_build.returncode == 0, (
        f"kas build via {kas_build.engine} failed "
        f"(exit {kas_build.returncode}); build-log tail:\n{kas_build.output_tail}"
    )


def test_image_sbom_deployed_to_documented_location(kas_build):
    sbom = kas_build.deployed(kas_env.SBOM_NAME)
    assert sbom.is_file(), (
        f"image SBOM {sbom} not deployed; build-log tail:\n{kas_build.output_tail}"
    )
