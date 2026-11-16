"""Kernel CVE filtering results mapped onto a rendered VEX document."""

import meta_cyclonedx

from helpers import document, pkg

SERIAL = "bbbb0000-0000-4000-8000-000000000000"
PREFIX = f"urn:cdx:{SERIAL}/1#"


def kernel_sbom():
    return document(SERIAL, components=[
        pkg("linux_kernel", "6.12.1", "ref-k1",
            purl="pkg:yocto/core/linux-yocto@6.12.1"),
        pkg("linux", "6.12.1", "ref-k2", cpe="cpe:2.3:*:linux:linux:6.12.1:*:*:*:*:*:*:*",
            purl="pkg:yocto/core/linux-yocto@6.12.1"),
        pkg("openssl", "3.2", "ref-o"),
    ], dependencies=[])


def test_statements_affect_every_kernel_component():
    vex = {"vulnerabilities": []}
    added = meta_cyclonedx.merge_kernel_cves(
        kernel_sbom(), vex, "linux-yocto", {"CVE-2024-1": "file never compiled"})

    assert added == 1
    statement = vex["vulnerabilities"][0]
    assert statement["id"] == "CVE-2024-1"
    assert statement["analysis"] == {
        "state": "not_affected",
        "justification": "code_not_present",
        "detail": "file never compiled",
    }
    assert statement["affects"] == [{"ref": PREFIX + "ref-k1"}, {"ref": PREFIX + "ref-k2"}]


def test_pairs_the_vex_already_covers_are_skipped():
    vex = {"vulnerabilities": [{
        "id": "CVE-2024-1", "analysis": {"state": "resolved"},
        "affects": [{"ref": PREFIX + "ref-k1"}],
    }]}
    added = meta_cyclonedx.merge_kernel_cves(
        kernel_sbom(), vex, "linux-yocto",
        {"CVE-2024-1": "not compiled", "CVE-2024-2": "not compiled"})

    assert added == 2
    by_id = {}
    for statement in vex["vulnerabilities"][1:]:
        by_id[statement["id"]] = statement["affects"]
    assert by_id["CVE-2024-1"] == [{"ref": PREFIX + "ref-k2"}]
    assert by_id["CVE-2024-2"] == [{"ref": PREFIX + "ref-k1"}, {"ref": PREFIX + "ref-k2"}]


def test_nothing_is_added_without_a_kernel_component():
    vex = {"vulnerabilities": []}
    messages = []
    added = meta_cyclonedx.merge_kernel_cves(
        kernel_sbom(), vex, "linux-other", {"CVE-2024-1": "not compiled"},
        log=lambda level, message: messages.append(message))

    assert added == 0
    assert vex["vulnerabilities"] == []
    assert messages == ["No SBOM component for the kernel recipe linux-other"]
