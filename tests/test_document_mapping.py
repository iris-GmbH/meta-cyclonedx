"""Document-level rendering behavior: headers, primary component, extensions."""

import re

import meta_cyclonedx

from helpers import TIMESTAMP, component_by_name, default_config, default_facts, render_docs


def test_sbom_describes_primary_component_and_build_lifecycle():
    sbom, _vex, _logs = render_docs(default_facts())

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.7"
    assert sbom["version"] == 1
    assert re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", sbom["serialNumber"])

    component = sbom["metadata"]["component"]
    assert component["type"] == "firmware"
    assert component["name"] == "core-image"
    assert component["version"] == "1.0"
    assert component["bom-ref"]

    assert sbom["metadata"]["timestamp"] == TIMESTAMP
    assert sbom["metadata"]["lifecycles"] == [{"phase": "build"}]
    assert [t["name"] for t in sbom["metadata"]["tools"]["components"]] == ["yocto"]


def test_vex_is_a_separate_document_without_components():
    sbom, vex, _logs = render_docs(default_facts())

    assert vex["bomFormat"] == "CycloneDX"
    assert vex["specVersion"] == sbom["specVersion"]
    assert vex["serialNumber"] != sbom["serialNumber"]
    assert re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", vex["serialNumber"])
    assert "components" not in vex
    assert "dependencies" not in vex
    assert vex["metadata"]["timestamp"] == TIMESTAMP


def test_primary_external_references_are_carried_into_metadata_component():
    refs = [{"type": "vcs", "url": "https://example.org/layers/meta.git@abc123"}]
    facts = default_facts(primary={"type": "firmware", "name": "img", "version": "1",
                                   "external_references": refs})
    sbom, _vex, _logs = render_docs(facts)

    assert sbom["metadata"]["component"]["externalReferences"] == refs


def test_primary_component_without_references_fact_carries_no_external_references():
    sbom, _vex, _logs = render_docs(default_facts())

    assert "externalReferences" not in sbom["metadata"]["component"]


def test_spec_17_citation_attributes_the_whole_document_to_the_tool():
    facts = default_facts(config=default_config(add_citation=True))
    sbom, vex, _logs = render_docs(facts)

    for doc in (sbom, vex):
        assert len(doc["citations"]) == 1
        citation = doc["citations"][0]
        assert citation["pointers"] == [""]
        assert citation["attributedTo"] in [
            t["bom-ref"] for t in doc["metadata"]["tools"]["components"]]
        assert citation["timestamp"] == doc["metadata"]["timestamp"]


def test_spec_17_tlp_marking_lands_in_distribution_constraints():
    facts = default_facts(config=default_config(add_citation=True, tlp_marking="AMBER"))
    sbom, vex, _logs = render_docs(facts)

    for doc in (sbom, vex):
        assert doc["metadata"]["distributionConstraints"]["tlp"] == "AMBER"


def test_unknown_tlp_marking_is_not_emitted():
    facts = default_facts(config=default_config(add_citation=False, tlp_marking="PURPLE"))
    sbom, _vex, _logs = render_docs(facts)

    assert "distributionConstraints" not in sbom["metadata"]


def test_spec_16_omits_citations_and_tlp():
    facts = default_facts(config=default_config(spec_version="1.6", add_citation=True,
                                                tlp_marking="CLEAR"))
    sbom, _vex, _logs = render_docs(facts)

    assert "citations" not in sbom
    assert "distributionConstraints" not in sbom["metadata"]


def test_config_validation_names_supported_values():
    assert meta_cyclonedx.config_errors("1.7", "firmware") is None

    error = meta_cyclonedx.config_errors("1.4", "firmware")
    assert "Unsupported CYCLONEDX_SPEC_VERSION: 1.4" in error
    assert "1.6" in error and "1.7" in error

    error = meta_cyclonedx.config_errors("1.7", "kitchen-appliance")
    assert "CYCLONEDX_IMAGE_TYPE" in error
    assert "firmware" in error
