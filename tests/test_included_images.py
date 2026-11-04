"""Embedded image composition: CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES merging."""

from helpers import (affect_refs, component_by_name, default_facts, document,
                     fragment, pkg, ref_of, render_docs, root_entry, vuln,
                     vex_document)

INC_SERIAL = "11111111-2222-3333-4444-555555555555"
CPE_Z = "cpe:2.3:*:*:zlib:1.3:*:*:*:*:*:*:*"


def parent_facts(**overrides):
    facts = default_facts(fragments={
        "zlib": fragment(pkgs=[pkg("zlib", "1.3", "ref-z", cpe=CPE_Z)]),
        "app": fragment(pkgs=[pkg("app", "1.0", "ref-app")]),
    }, runtime_recipes=["zlib", "app"], image_install_recipes=["app"])
    facts.update(overrides)
    return facts


def included_image(vex=..., **sbom_kwargs):
    sbom = document(
        INC_SERIAL,
        components=[
            pkg("zlib", "1.3", "inc-z", cpe=CPE_Z, scope="excluded"),
            pkg("busybox", "1.36", "inc-u", purl="pkg:yocto/busybox@1.36"),
        ],
        dependencies=[
            {"ref": "inc-z", "dependsOn": ["inc-u"]},
            {"ref": "inc-meta", "dependsOn": ["inc-z"]},
        ],
        metadata_component={"bom-ref": "inc-meta", "type": "firmware",
                            "name": "initramfs", "version": "2.0"},
        **sbom_kwargs)
    if vex is ...:
        vex = vex_document([{
            "id": "CVE-2024-5",
            "source": {"name": "NVD",
                       "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-5"},
            "analysis": {"state": "resolved", "detail": "STATE: fixed\n"},
            "affects": [
                {"ref": f"urn:cdx:{INC_SERIAL}/1#inc-u"},
                {"ref": f"urn:cdx:{INC_SERIAL}/1#inc-z"},
            ],
        }])
    return {"name": "initramfs", "sbom": sbom, "vex": vex, "vex_error": None}


def test_included_image_becomes_a_firmware_component_on_the_root():
    sbom, _vex, _logs = render_docs(parent_facts(included_images=[included_image()]))

    firmware = component_by_name(sbom, "initramfs")
    assert firmware["type"] == "firmware"
    assert firmware["version"] == "2.0"
    assert firmware["scope"] == "required"
    assert firmware["bom-ref"] in root_entry(sbom)["dependsOn"]


def test_shared_cpe_components_stay_single_with_parent_identity():
    sbom, _vex, _logs = render_docs(parent_facts(included_images=[included_image()]))

    assert component_by_name(sbom, "zlib")["bom-ref"] == "ref-z"
    # parent "required" outranks the included "excluded"
    assert component_by_name(sbom, "zlib")["scope"] == "required"


def test_unique_components_join_with_required_scope():
    sbom, _vex, _logs = render_docs(parent_facts(included_images=[included_image()]))

    assert component_by_name(sbom, "busybox")["scope"] == "required"
    assert component_by_name(sbom, "busybox")["bom-ref"] == "inc-u"


def test_included_dependency_edges_are_remapped_to_parent_refs():
    sbom, _vex, _logs = render_docs(parent_facts(included_images=[included_image()]))

    zlib_entry = next(e for e in sbom["dependencies"] if e["ref"] == "ref-z")
    assert zlib_entry["dependsOn"] == ["inc-u"]

    firmware_ref = component_by_name(sbom, "initramfs")["bom-ref"]
    firmware_entry = next(e for e in sbom["dependencies"] if e["ref"] == firmware_ref)
    assert firmware_entry["dependsOn"] == ["ref-z"]


def test_included_vex_references_rewrite_to_the_parent_serial():
    sbom, vex, _logs = render_docs(parent_facts(included_images=[included_image()]))

    serial = sbom["serialNumber"].split("urn:uuid:")[-1]
    statement = next(v for v in vex["vulnerabilities"] if v["id"] == "CVE-2024-5")
    assert sorted(affect_refs(statement)) == sorted([
        f"urn:cdx:{serial}/1#inc-u",   # unique component keeps its ref
        f"urn:cdx:{serial}/1#ref-z",   # shared component resolves to the parent ref
    ])
    assert INC_SERIAL not in str(vex)


def test_included_vex_merges_affects_into_an_existing_statement():
    parent_vuln = vuln("CVE-2024-5", "ref-app")
    facts = parent_facts(included_images=[included_image()])
    facts["fragments"]["app"]["cves"] = [parent_vuln]
    sbom, vex, _logs = render_docs(facts)

    statements = [v for v in vex["vulnerabilities"] if v["id"] == "CVE-2024-5"]
    assert len(statements) == 1
    serial = sbom["serialNumber"].split("urn:uuid:")[-1]
    assert sorted(affect_refs(statements[0])) == sorted([
        f"urn:cdx:{serial}/1#ref-app",
        f"urn:cdx:{serial}/1#inc-u",
        f"urn:cdx:{serial}/1#ref-z",
    ])


def test_spec_version_mismatch_is_reported_but_merges():
    entry = included_image()
    entry["sbom"]["specVersion"] = "1.6"
    sbom, _vex, logs = render_docs(parent_facts(included_images=[entry]))

    assert any(level == "warn" and "differs from parent" in message
               for level, message in logs)
    assert component_by_name(sbom, "initramfs")


def test_missing_included_vex_skips_only_the_vex_merge():
    entry = included_image()
    entry["vex"] = None
    sbom, vex, _logs = render_docs(parent_facts(included_images=[entry]))

    assert component_by_name(sbom, "initramfs")
    assert vex["vulnerabilities"] == []


def test_unparseable_included_vex_is_warned_and_skipped():
    entry = included_image()
    entry["vex"] = None
    entry["vex_error"] = "Expecting value: line 1 column 1 (char 0)"
    _sbom, vex, logs = render_docs(parent_facts(included_images=[entry]))

    assert any(level == "warn" and "cannot parse VEX" in message
               for level, message in logs)
    assert vex["vulnerabilities"] == []
