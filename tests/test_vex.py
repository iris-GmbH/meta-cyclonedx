"""VEX document behavior: reference resolution, coverage dedup, ordering."""

from helpers import (affect_refs, default_facts, dep, fragment, pkg, render_docs,
                     vuln, vuln_by_id)


def test_fragment_references_resolve_to_the_sbom_serial_and_bom_refs():
    facts = default_facts(fragments={
        "openssl": fragment(pkgs=[pkg("openssl", "3.2", "ref-o")],
                            cves=[vuln("CVE-2024-1234", "ref-o")]),
    })
    sbom, vex, _logs = render_docs(facts)

    serial = sbom["serialNumber"].split("urn:uuid:")[-1]
    statement = vuln_by_id(vex, "CVE-2024-1234")
    assert affect_refs(statement) == [f"urn:cdx:{serial}/1#ref-o"]


def test_no_placeholder_survives_into_the_vex():
    facts = default_facts(fragments={
        "openssl": fragment(pkgs=[pkg("openssl", "3.2", "ref-o")],
                            cves=[vuln("CVE-2024-1234", "ref-o")]),
    })
    _sbom, vex, _logs = render_docs(facts)

    assert "<SBOM_SERIAL>" not in str(vex)


def test_statements_beyond_the_last_component_are_dropped():
    facts = default_facts(fragments={
        "openssl": fragment(pkgs=[pkg("openssl", "3.2", "ref-o")],
                            cves=[vuln("CVE-2024-1", "ref-nonexistent")]),
    })
    _sbom, vex, _logs = render_docs(facts)

    assert vex["vulnerabilities"] == []


def test_duplicate_cve_across_recipes_sharing_a_cpe_is_stated_once():
    shared_cpe = "cpe:2.3:*:*:widget:1.0:*:*:*:*:*:*:*"
    facts = default_facts(fragments={
        "widget-a": fragment(pkgs=[pkg("widget", "1.0", "ref-a", cpe=shared_cpe)],
                             cves=[vuln("CVE-2024-9", "ref-a")]),
        "widget-b": fragment(pkgs=[pkg("widget", "1.0", "ref-b", cpe=shared_cpe)],
                             cves=[vuln("CVE-2024-9", "ref-b")]),
    })
    sbom, vex, _logs = render_docs(facts)

    statement = vuln_by_id(vex, "CVE-2024-9")
    serial = sbom["serialNumber"].split("urn:uuid:")[-1]
    # the dropped duplicate's reference resolves to the surviving component
    assert affect_refs(statement) == [f"urn:cdx:{serial}/1#ref-a"]


def test_vulnerabilities_are_ordered_by_identifier():
    facts = default_facts(fragments={
        "openssl": fragment(
            pkgs=[pkg("openssl", "3.2", "ref-o")],
            cves=[vuln("CVE-2024-2", "ref-o"), vuln("CVE-2023-1", "ref-o")]),
    })
    _sbom, vex, _logs = render_docs(facts)

    assert [v["id"] for v in vex["vulnerabilities"]] == ["CVE-2023-1", "CVE-2024-2"]


def test_independently_assessable_instances_keep_disjoint_statements():
    # Two recipes whose components share a CPE are NOT collapsed here (they
    # differ in name); each keeps its own statement of the same CVE.
    facts = default_facts(fragments={
        "a": fragment(pkgs=[pkg("dup", "1", "ref-1", cpe="cpe:2.3:*:*:dup:1:*:*:*:*:*:*:*")],
                      cves=[vuln("CVE-2024-1", "ref-1")]),
        "b": fragment(pkgs=[pkg("other", "1", "ref-2")],
                      cves=[vuln("CVE-2024-1", "ref-2")]),
    })
    sbom, vex, _logs = render_docs(facts)

    serial = sbom["serialNumber"].split("urn:uuid:")[-1]
    statements = [v for v in vex["vulnerabilities"] if v["id"] == "CVE-2024-1"]
    assert len(statements) == 2
    assert [affect_refs(s) for s in statements] == [
        [f"urn:cdx:{serial}/1#ref-1"], [f"urn:cdx:{serial}/1#ref-2"]]
