"""Normalized-fact construction: component identity and VEX statements from
recipe CVE status. These facts are what do_populate_cyclonedx stores per
recipe; assertions target the fact content, not helper plumbing."""

import re

import meta_cyclonedx

from helpers import PLACEHOLDER


def test_one_identity_per_cve_product_alias():
    pkgs = meta_cyclonedx.component_identity("libfoo foo", "1.2", "pkg:yocto/foo@1.2")

    assert {p["name"] for p in pkgs} == {"libfoo", "foo"}
    assert {p["version"] for p in pkgs} == {"1.2"}
    assert len({p["bom-ref"] for p in pkgs}) == 2
    assert all(p["purl"] == "pkg:yocto/foo@1.2" for p in pkgs)


def test_vendor_qualifier_becomes_group_and_cpe_vendor():
    pkgs = meta_cyclonedx.component_identity("vendor:libfoo", "1.2", "pkg:yocto/x")

    assert pkgs[0]["name"] == "libfoo"
    assert pkgs[0]["group"] == "vendor"
    assert pkgs[0]["cpe"] == "cpe:2.3:*:vendor:libfoo:1.2:*:*:*:*:*:*:*"


def test_git_suffixes_and_empty_versions_stay_matchable():
    [pkg] = meta_cyclonedx.component_identity("app", "6.6+gitAUTOINC+abcdef", "p")
    assert pkg["version"] == "6.6"

    [pkg] = meta_cyclonedx.component_identity("app", "  ", "p")
    assert pkg["version"] == "unknown"
    assert ":unknown:" in pkg["cpe"]


def test_external_references_are_attached_when_supplied():
    refs = [{"type": "vcs", "url": "https://example.org/src.git@deadbeef"}]
    [pkg] = meta_cyclonedx.component_identity("app", "1", "p", external_references=refs)
    assert pkg["externalReferences"] == refs


def test_patched_status_becomes_resolved_statement():
    statements = []
    meta_cyclonedx.add_status_vex_statement(
        ("CVE-2025-52886", "Patched", "Fixed in 1.2.3", ""), statements,
        "ref-x", "myrecipe", PLACEHOLDER, add_timestamps=False)

    [statement] = statements
    assert statement["id"] == "CVE-2025-52886"
    assert statement["analysis"]["state"] == "resolved"
    assert statement["affects"] == [{"ref": f"urn:cdx:{PLACEHOLDER}/1#ref-x"}]
    assert statement["source"]["name"] == "NVD"


def test_ignored_status_becomes_not_affected_with_justification():
    statements = []
    meta_cyclonedx.add_status_vex_statement(
        ("CVE-2025-1", "Ignored", "Discarded reason", "upstream not affected"),
        statements, "ref-x", "myrecipe", PLACEHOLDER, add_timestamps=False)

    [statement] = statements
    assert statement["analysis"]["state"] == "not_affected"
    assert "JUSTIFICATION: upstream not affected" in statement["analysis"]["detail"]


def test_irrelevant_status_produces_no_statement():
    statements = []
    meta_cyclonedx.add_status_vex_statement(
        ("CVE-2025-2", "Unpatched", "Needs triage", ""), statements,
        "ref-x", "myrecipe", PLACEHOLDER, add_timestamps=False)

    assert statements == []


def test_patch_suffixes_collapse_into_one_statement_with_details():
    statements = []
    for cve_id in ("CVE-2025-52886-0001", "CVE-2025-52886-0002"):
        meta_cyclonedx.add_status_vex_statement(
            (cve_id, "Patched", "Backported patch", ""), statements,
            "ref-x", "myrecipe", PLACEHOLDER, add_timestamps=False)

    [statement] = statements
    assert statement["id"] == "CVE-2025-52886"
    assert "Patch file: CVE-2025-52886-0001" in statement["analysis"]["detail"]
    assert "Additional patch: CVE-2025-52886-0002" in statement["analysis"]["detail"]
    assert statement["affects"] == [{"ref": f"urn:cdx:{PLACEHOLDER}/1#ref-x"}]


def test_alias_components_attract_the_same_statement():
    statements = []
    for bom_ref in ("ref-a", "ref-b"):
        meta_cyclonedx.add_status_vex_statement(
            ("CVE-2025-3", "Patched", "Fixed", ""), statements,
            bom_ref, "myrecipe", PLACEHOLDER, add_timestamps=False)

    [statement] = statements
    assert statement["affects"] == [
        {"ref": f"urn:cdx:{PLACEHOLDER}/1#ref-a"},
        {"ref": f"urn:cdx:{PLACEHOLDER}/1#ref-b"},
    ]


def test_timestamps_follow_configuration():
    statements = []
    meta_cyclonedx.add_status_vex_statement(
        ("CVE-2025-4", "Patched", "Fixed", ""), statements,
        "ref-x", "myrecipe", PLACEHOLDER, add_timestamps=True)

    analysis = statements[0]["analysis"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T.*", analysis["firstIssued"])
    assert analysis["firstIssued"] == analysis["lastUpdated"]


def test_kernel_not_affected_statement_covers_all_kernel_components():
    statement = meta_cyclonedx.kernel_vex_statement(
        "CVE-2024-777", ["ref-k1", "ref-k2"], PLACEHOLDER, "file never compiled")

    assert statement["analysis"] == {
        "state": "not_affected",
        "justification": "code_not_present",
        "detail": "file never compiled",
    }
    assert statement["affects"] == [
        {"ref": f"urn:cdx:{PLACEHOLDER}/1#{r}"} for r in ("ref-k1", "ref-k2")]
