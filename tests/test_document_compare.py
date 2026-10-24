# SPDX-License-Identifier: MIT
"""Unit tests for the cross-regeneration comparison helper (no build).

`canonicalize` is used *only* to compare documents produced by different
regenerations of the same content: document serial numbers (the CycloneDX
serials and every bom-ref / urn:cdx reference derived from them),
statement and tool timestamps, and the git-state properties describing
the working tree must not make equal documents compare unequal. A real
content difference must still compare unequal — the helper may not mask
its way to a vacuous pass.
"""

import copy
import uuid

from tests.integration import document_compare

SERIAL_A = "3eda7c78-d471-4e61-b942-4b5df4e6ea81"
SERIAL_B = "9c1a6b2a-5c00-4908-a28f-6b3f0f474f9b"
REF_A = "faa29a51-f7d2-4de8-ac7f-3061ff3de25c"
REF_B = "1d2c9f56-78b5-4536-a57c-2f7725525a13"


def _documents(serial, ref, timestamp):
    tool_ref = str(uuid.uuid5(uuid.NAMESPACE_URL, ref + "/tool"))
    image_ref = str(uuid.uuid5(uuid.NAMESPACE_URL, ref + "/image"))
    libc_ref = str(uuid.uuid5(uuid.NAMESPACE_URL, ref + "/libc"))
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {"type": "application", "name": "yocto", "bom-ref": tool_ref}
                ]
            },
            "component": {"name": "core-image-minimal", "bom-ref": image_ref},
        },
        "components": [
            {"name": "busybox", "version": "1.38.0", "bom-ref": ref},
            {"name": "libc", "version": "2.42", "bom-ref": libc_ref},
        ],
        "dependencies": [
            {"ref": image_ref, "dependsOn": [ref]},
            {"ref": ref, "dependsOn": [libc_ref]},
            {"ref": libc_ref, "dependsOn": []},
        ],
    }
    vex = {
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, serial + '/vex')}",
        "metadata": {"timestamp": timestamp},
        "vulnerabilities": [
            {
                "id": "CVE-2024-0001",
                "affects": [{"ref": f"urn:cdx:{serial}/1#{ref}"}],
            }
        ],
    }
    return sbom, vex


def test_volatiles_alone_compare_equal():
    a_sbom, a_vex = _documents(SERIAL_A, REF_A, "2026-10-12T22:28:47.615773+00:00")
    b_sbom, b_vex = _documents(SERIAL_B, REF_B, "2026-10-13T09:01:02.000000+00:00")
    assert document_compare.canonicalize(
        {"sbom": a_sbom, "vex": a_vex}
    ) == document_compare.canonicalize({"sbom": b_sbom, "vex": b_vex})


def test_dependency_target_change_survives_canonicalization():
    original, _ = _documents(SERIAL_A, REF_A, "2026-10-12T22:28:47+00:00")
    changed = copy.deepcopy(original)
    changed["dependencies"][0]["dependsOn"] = [
        changed["components"][1]["bom-ref"]
    ]
    assert document_compare.canonicalize(original) != document_compare.canonicalize(changed)


def test_dangling_vex_reference_survives_canonicalization():
    sbom, vex = _documents(SERIAL_A, REF_A, "2026-10-12T22:28:47+00:00")
    changed = copy.deepcopy(vex)
    changed["vulnerabilities"][0]["affects"][0]["ref"] = (
        f"urn:cdx:{SERIAL_A}/1#{REF_B}"
    )
    assert document_compare.canonicalize(
        {"sbom": sbom, "vex": vex}
    ) != document_compare.canonicalize({"sbom": sbom, "vex": changed})


def test_vex_reference_to_the_wrong_document_survives_canonicalization():
    sbom, vex = _documents(SERIAL_A, REF_A, "2026-10-12T22:28:47+00:00")
    changed = copy.deepcopy(vex)
    wrong_serial = vex["serialNumber"].removeprefix("urn:uuid:")
    changed["vulnerabilities"][0]["affects"][0]["ref"] = (
        f"urn:cdx:{wrong_serial}/1#{REF_A}"
    )
    assert document_compare.canonicalize(
        {"sbom": sbom, "vex": vex}
    ) != document_compare.canonicalize({"sbom": sbom, "vex": changed})


def test_content_difference_survives_canonicalization():
    a, _ = _documents(SERIAL_A, REF_A, "2026-10-12T22:28:47.615773+00:00")
    b, _ = _documents(SERIAL_B, REF_B, "2026-10-12T22:28:47.615773+00:00")
    b["components"][0]["version"] = "1.39.0"
    assert document_compare.canonicalize(a) != document_compare.canonicalize(b)
    difference = document_compare.first_difference(
        document_compare.canonicalize(a), document_compare.canonicalize(b)
    )
    assert difference is not None
    assert "components[0].version" in difference


def test_identical_documents_have_no_first_difference():
    a, _ = _documents(SERIAL_A, REF_A, "2026-10-12T22:28:47.615773+00:00")
    b, _ = _documents(SERIAL_A, REF_A, "2026-10-12T22:28:47.615773+00:00")
    assert document_compare.first_difference(a, b) is None


def test_layer_git_state_properties_are_dropped():
    # The layer-under-test entry's rev/is_modified properties record the
    # harness working tree at export time, not document content: a cold run
    # recorded under one commit must compare equal to a regenerated run
    # under another.
    a = {
        "externalReferences": [
            {
                "type": "build-system",
                "url": "https://example.invalid/repo",
                "properties": [
                    {"name": "yocto:layer:name", "value": "meta-cyclonedx"},
                    {"name": "yocto:layer:rev", "value": "a" * 40},
                    {"name": "yocto:layer:is_modified", "value": "false"},
                ],
            }
        ]
    }
    b = {
        "externalReferences": [
            {
                "type": "build-system",
                "url": "https://example.invalid/repo",
                "properties": [
                    {"name": "yocto:layer:name", "value": "meta-cyclonedx"},
                    {"name": "yocto:layer:rev", "value": "b" * 40},
                    {"name": "yocto:layer:is_modified", "value": "true"},
                ],
            }
        ]
    }
    canonical_b = document_compare.canonicalize(b)
    assert document_compare.canonicalize(a) == canonical_b
    # The stable parts survive: the reference is not emptied wholesale.
    assert canonical_b["externalReferences"][0]["url"] == "https://example.invalid/repo"
    names = [
        p["name"] for p in canonical_b["externalReferences"][0]["properties"]
    ]
    assert names == ["yocto:layer:name"]


def test_canonicalization_does_not_mutate_the_input():
    sbom, _ = _documents(SERIAL_A, REF_A, "2026-10-12T22:28:47.615773+00:00")
    snapshot = copy.deepcopy(sbom)
    document_compare.canonicalize(sbom)
    assert sbom == snapshot


def _layer_ref(url, rev):
    return {
        "externalReferences": [
            {
                "type": "build-system",
                "url": url,
                "properties": [
                    {"name": "yocto:layer:name", "value": "repo"},
                    {"name": "yocto:layer:rev", "value": rev},
                ],
            }
        ]
    }


def test_layer_checkout_baked_into_the_url_compares_equal():
    # The layer reference url spells the checkout: <remote>@<rev>, plus
    # " -- modified" while the tree is dirty (R3 dirties it by design).
    clean = _layer_ref("git@example.invalid/repo.git@" + "a" * 40, "a" * 40)
    dirty = _layer_ref(
        "git@example.invalid/repo.git@" + "b" * 40 + " -- modified", "b" * 40
    )
    assert document_compare.canonicalize(clean) == document_compare.canonicalize(dirty)
    # The remote itself keeps its teeth.
    assert (
        document_compare.canonicalize(dirty)["externalReferences"][0]["url"]
        == "git@example.invalid/repo.git"
    )


def test_layer_references_without_properties_compare_equal():
    # 1.6 (and older) documents cannot carry properties on external
    # references, so the class's constant comment is the layer marker;
    # the release branches validate exactly that profile.
    def ref(url):
        return {
            "externalReferences": [
                {
                    "type": "vcs",
                    "url": url,
                    "comment": "Yocto metadata layer meta-cyclonedx",
                }
            ]
        }

    clean = ref("git@example.invalid/repo.git@" + "a" * 40)
    dirty = ref("git@example.invalid/repo.git@" + "b" * 40 + " -- modified")
    assert document_compare.canonicalize(clean) == document_compare.canonicalize(dirty)
    assert (
        document_compare.canonicalize(dirty)["externalReferences"][0]["url"]
        == "git@example.invalid/repo.git"
    )
    # A vcs url without the layer comment is a package's own checkout.
    other = {
        "externalReferences": [
            {"type": "vcs", "url": "git@example.invalid/x.git@" + "c" * 40}
        ]
    }
    assert document_compare.canonicalize(other) == other


def test_package_vcs_urls_keep_their_rev():
    # Only layer references (by comment or yocto:layer:* properties)
    # carry harness git state; a component's own SRCREV url must not be
    # normalized away.
    package = {
        "components": [
            {
                "name": "gitpkg",
                "externalReferences": [
                    {"type": "vcs", "url": "git://git.example/x.git@" + "c" * 40}
                ],
            }
        ]
    }
    assert document_compare.canonicalize(package) == package


def test_build_datetime_in_the_image_version_compares_equal():
    def versioned(stamp):
        return {
            "metadata": {
                "component": {
                    "name": "core-image-minimal",
                    "version": f"6.1.99+snapshot-{'d' * 40}-{stamp}",
                }
            }
        }

    assert document_compare.canonicalize(
        versioned("20261012222744")
    ) == document_compare.canonicalize(versioned("20261013054708"))
    # Ordinary package versions — including trailing digit runs that
    # are not a 14-digit DATETIME — survive untouched.
    package = {"components": [{"version": "1.36.1-r0"}, {"version": "20250101"}]}
    assert document_compare.canonicalize(package) == package


def test_vulnerability_statement_timestamps_compare_equal():
    # firstIssued/lastUpdated record when a VEX statement was (re-)issued;
    # populate documents re-stamp them whenever a populate task reruns.
    # Post-seam that means every R3 run, where the renderer module rides
    # the populate signatures. The issuance time is volatile; statement
    # content (state, detail, affects) must survive.
    a = {"vulnerabilities": [{
        "id": "CVE-2026-0001",
        "analysis": {"state": "not_affected", "detail": "STATUS: resolved\n",
                     "firstIssued": "2026-10-13T08:51:04.532035+00:00",
                     "lastUpdated": "2026-10-13T08:51:04.532035+00:00"},
    }]}
    b = copy.deepcopy(a)
    issued = b["vulnerabilities"][0]["analysis"]
    issued["firstIssued"] = "2026-10-13T08:53:57.902082+00:00"
    issued["lastUpdated"] = "2026-10-13T08:53:57.902082+00:00"
    assert document_compare.first_difference(
        document_compare.canonicalize(a), document_compare.canonicalize(b)
    ) is None
    issued["state"] = "affected"
    assert "analysis.state" in document_compare.first_difference(
        document_compare.canonicalize(a), document_compare.canonicalize(b)
    )
