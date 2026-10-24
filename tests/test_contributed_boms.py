"""Ecosystem BOM composition: pre-resolved fragments contributed by recipes."""

from helpers import default_facts, fragment, pkg, render_docs


def contributed(pkg_list, dep_entries, roots):
    return {
        "extra_components": pkg_list,
        "extra_dependencies": dep_entries,
        "extra_roots": roots,
    }


def test_contributed_components_and_edges_are_merged_verbatim():
    module_a = {"bom-ref": "cargo://a", "type": "library", "name": "serde",
                "version": "1.0", "purl": "pkg:cargo/serde@1.0"}
    module_b = {"bom-ref": "cargo://b", "type": "library", "name": "libc-crate",
                "version": "0.2", "purl": "pkg:cargo/libc@0.2"}
    facts = default_facts(fragments={
        "rust-app": fragment(
            pkgs=[pkg("rust-app", "1", "ref-r")],
            **contributed([module_a, module_b],
                          [{"ref": "cargo://a", "dependsOn": ["cargo://b"]}],
                          ["cargo://a"])),
    })
    sbom, _vex, _logs = render_docs(facts)

    refs = {c["bom-ref"] for c in sbom["components"]}
    assert {"cargo://a", "cargo://b"} <= refs
    entry = next(e for e in sbom["dependencies"] if e["ref"] == "cargo://a")
    assert entry["dependsOn"] == ["cargo://b"]


def test_contributed_tree_is_attached_to_the_owner_component():
    module = {"bom-ref": "go://dep", "type": "library", "name": "dep", "version": "1"}
    facts = default_facts(fragments={
        "go-app": fragment(
            pkgs=[pkg("go-app", "1", "ref-g")],
            **contributed([module],
                          [{"ref": "ref-g", "dependsOn": ["go://dep"]}],
                          ["go://dep"])),
    })
    sbom, _vex, _logs = render_docs(facts)

    owner = next(e for e in sbom["dependencies"] if e["ref"] == "ref-g")
    assert "go://dep" in owner["dependsOn"]


def test_contributed_root_is_still_attached_without_contributed_edges():
    module = {"bom-ref": "npm://x", "type": "library", "name": "x", "version": "1"}
    facts = default_facts(fragments={
        "node-app": fragment(
            pkgs=[pkg("node-app", "1", "ref-n")],
            **contributed([module], [], ["npm://x"])),
    })
    sbom, _vex, _logs = render_docs(facts)

    owner = next(e for e in sbom["dependencies"] if e["ref"] == "ref-n")
    assert owner["dependsOn"] == ["npm://x"]


def test_component_already_present_by_ref_is_not_contributed_twice():
    shared = {"bom-ref": "dup-ref", "type": "library", "name": "dup", "version": "1"}
    facts = default_facts(fragments={
        "a": fragment(pkgs=[pkg("dup", "1", "dup-ref")]),
        "b": fragment(pkgs=[pkg("carrier", "1", "ref-c")],
                      **contributed([shared], [], [])),
    })
    sbom, _vex, _logs = render_docs(facts)

    assert [c["bom-ref"] for c in sbom["components"]].count("dup-ref") == 1


def test_contributed_tree_without_owner_is_reported_not_attached():
    module = {"bom-ref": "orphan-root", "type": "library", "name": "m", "version": "1"}
    facts = default_facts(fragments={
        "carrier": fragment(pkgs=[], **contributed([module], [], ["orphan-root"])),
    })
    sbom, _vex, logs = render_docs(facts)

    # The tree still lands in the component list; only attachment needs an owner.
    assert "orphan-root" in {c["bom-ref"] for c in sbom["components"]}
    assert any("no component to attach" in message for _level, message in logs)
    assert "orphan-root" not in [d for e in sbom["dependencies"] for d in e["dependsOn"]]
