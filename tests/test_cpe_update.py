# SPDX-License-Identifier: MIT

"""Regression tests for CPE update handling (issue #149)."""

import pytest

from meta_cyclonedx import component_identity


def test_release_cpe_has_no_applicable_update():
    # CVE-2026-46728 lists U-Boot 2026.04-rc1/rc2/rc3 as vulnerable,
    # but not the final 2026.04 release.
    pkg = component_identity(
        "denx:u-boot", "2026.04", "-", "pkg:yocto/u-boot@2026.04"
    )[0]

    assert pkg["cpe"] == "cpe:2.3:*:denx:u-boot:2026.04:-:*:*:*:*:*:*"


@pytest.mark.parametrize("update", ["rc1", "rc2", "rc3", "*"])
def test_explicit_cpe_update(update):
    pkg = component_identity(
        "denx:u-boot", "2026.04", update, "pkg:yocto/u-boot@2026.04"
    )[0]

    assert pkg["cpe"] == f"cpe:2.3:*:denx:u-boot:2026.04:{update}:*:*:*:*:*:*"
    assert pkg["version"] == "2026.04"
