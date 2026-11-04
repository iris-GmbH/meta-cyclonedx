"""Dependency graph behavior: root node, token resolution, merging, pruning."""

from helpers import default_facts, dep, fragment, pkg, ref_of, render_docs, root_entry


def test_root_node_is_first_and_lists_directly_installed_components():
    facts = default_facts(fragments={
        "busybox": fragment(pkgs=[pkg("busybox", "1.36", "ref-b")]),
        "bash": fragment(pkgs=[pkg("bash", "5.2", "ref-s")]),
        "libextra": fragment(pkgs=[pkg("libextra", "1", "ref-x")]),
    }, image_install_recipes=["bash", "busybox"])
    sbom, _vex, _logs = render_docs(facts)

    root = root_entry(sbom)
    # Targets ride the components array's declaration (name/version) order,
    # not the bom-ref values, so regeneration cannot shuffle this array.
    assert root["dependsOn"] == ["ref-s", "ref-b"]
    assert "ref-x" not in root["dependsOn"]


def test_recipe_name_token_resolves_to_the_recipe_components():
    facts = default_facts(fragments={
        "app": fragment(pkgs=[pkg("app", "1", "ref-app")],
                        dependencies=[dep("ref-app", ["busybox"])]),
        "busybox": fragment(pkgs=[pkg("busybox", "1.36", "ref-b")]),
    })
    sbom, _vex, _logs = render_docs(facts)

    entry = next(e for e in sbom["dependencies"] if e["ref"] == "ref-app")
    assert entry["dependsOn"] == ["ref-b"]


def test_dependency_on_recipe_resolves_when_component_name_differs():
    # A recipe named binutils whose components are named libb (CVE_PRODUCT):
    # the dependency names the recipe, and reaches its component anyway.
    facts = default_facts(fragments={
        "app": fragment(pkgs=[pkg("app", "1", "ref-app")],
                        dependencies=[dep("ref-app", ["binutils"])]),
        "binutils": fragment(pkgs=[pkg("libb", "2.42", "ref-libb")]),
    })
    sbom, _vex, _logs = render_docs(facts)

    entry = next(e for e in sbom["dependencies"] if e["ref"] == "ref-app")
    assert entry["dependsOn"] == ["ref-libb"]


def test_dependency_token_reaches_every_alias_component_of_a_recipe():
    facts = default_facts(fragments={
        "alias-owner": fragment(
            pkgs=[pkg("alias-a", "1", "ref-a1"), pkg("alias-b", "1", "ref-a2")]),
        "consumer": fragment(pkgs=[pkg("consumer", "1", "ref-c")],
                             dependencies=[dep("ref-c", ["alias-owner"])]),
    })
    sbom, _vex, _logs = render_docs(facts)

    entry = next(e for e in sbom["dependencies"] if e["ref"] == "ref-c")
    assert sorted(entry["dependsOn"]) == ["ref-a1", "ref-a2"]


def test_dependency_on_a_recipe_outside_the_image_is_pruned():
    facts = default_facts(fragments={
        "app": fragment(pkgs=[pkg("app", "1", "ref-app")],
                        dependencies=[dep("ref-app", ["busybox", "ghost"])]),
        "busybox": fragment(pkgs=[pkg("busybox", "1.36", "ref-b")]),
    })
    sbom, _vex, logs = render_docs(facts)

    entry = next(e for e in sbom["dependencies"] if e["ref"] == "ref-app")
    assert entry["dependsOn"] == ["ref-b"]
    assert any("ghost" in message for _level, message in logs)


def test_self_dependency_is_dropped():
    facts = default_facts(fragments={
        "app": fragment(pkgs=[pkg("app", "1", "ref-app")],
                        dependencies=[dep("ref-app", ["app"])]),
    })
    sbom, _vex, _logs = render_docs(facts)

    assert "ref-app" not in [e["ref"] for e in sbom["dependencies"]
                             if e["ref"] != sbom["metadata"]["component"]["bom-ref"]]


def test_runtime_edges_are_merged_into_existing_recipe_edges():
    facts = default_facts(fragments={
        "app": fragment(pkgs=[pkg("app", "1", "ref-app")],
                        dependencies=[dep("ref-app", ["busybox"])]),
        "busybox": fragment(pkgs=[pkg("busybox", "1.36", "ref-b")]),
        "libc": fragment(pkgs=[pkg("libc", "2.40", "ref-libc")]),
    }, runtime_edges={"app": ["libc"]})
    sbom, _vex, _logs = render_docs(facts)

    entries = [e for e in sbom["dependencies"] if e["ref"] == "ref-app"]
    assert len(entries) == 1
    assert sorted(entries[0]["dependsOn"]) == ["ref-b", "ref-libc"]


def test_runtime_edges_alone_produce_dependency_entries():
    facts = default_facts(fragments={
        "app": fragment(pkgs=[pkg("app", "1", "ref-app")]),
        "libc": fragment(pkgs=[pkg("libc", "2.40", "ref-libc")]),
    }, runtime_edges={"app": ["libc"]})
    sbom, _vex, _logs = render_docs(facts)

    entry = next(e for e in sbom["dependencies"] if e["ref"] == "ref-app")
    assert entry["dependsOn"] == ["ref-libc"]


def test_fragments_without_edges_have_no_dependency_node():
    facts = default_facts(fragments={
        "busybox": fragment(pkgs=[pkg("busybox", "1.36", "ref-b")]),
    })
    sbom, _vex, _logs = render_docs(facts)

    refs = [e["ref"] for e in sbom["dependencies"]]
    assert refs == [sbom["metadata"]["component"]["bom-ref"]]


def test_dependency_component_refs_point_at_rendered_components():
    facts = default_facts(fragments={
        "app": fragment(pkgs=[pkg("app", "1", "ref-app")],
                        dependencies=[dep("ref-app", ["busybox"])]),
        "busybox": fragment(pkgs=[pkg("busybox", "1.36", "ref-b")]),
    })
    sbom, _vex, _logs = render_docs(facts)

    component_refs = {c["bom-ref"] for c in sbom["components"]}
    for entry in sbom["dependencies"]:
        assert entry["ref"] in component_refs | {sbom["metadata"]["component"]["bom-ref"]}
        assert set(entry["dependsOn"]) <= component_refs
