"""Component inventory behavior: inclusion, ordering, scope, CPE deduplication."""

from helpers import component_by_name, component_names, default_config, default_facts, dep, fragment, pkg, ref_of, render_docs


def test_all_recipe_components_appear_sorted_by_identity():
    facts = default_facts(fragments={
        "zlib": fragment(pkgs=[pkg("zlib", "1.3", "ref-z")]),
        "busybox": fragment(pkgs=[pkg("busybox", "1.36", "ref-b"),
                                  pkg("busybox", "1.30", "ref-b30")]),
        "app": fragment(pkgs=[pkg("app", "0.1", "ref-app")]),
    })
    sbom, _vex, _logs = render_docs(facts)

    assert component_names(sbom) == ["app", "busybox", "busybox", "zlib"]
    assert [c["version"] for c in sbom["components"][1:3]] == ["1.30", "1.36"]


def test_scope_marks_runtime_against_build_time_recipes():
    facts = default_facts(
        fragments={
            "busybox": fragment(pkgs=[pkg("busybox", "1.36", "ref-b")]),
            "cmake": fragment(pkgs=[pkg("cmake", "3.0", "ref-c")]),
        },
        runtime_recipes=["busybox"],
    )
    sbom, _vex, _logs = render_docs(facts)

    assert component_by_name(sbom, "busybox")["scope"] == "required"
    assert component_by_name(sbom, "cmake")["scope"] == "excluded"


def test_scope_assignment_can_be_disabled():
    facts = default_facts(config=default_config(add_component_scopes=False),
                          fragments={
                              "busybox": fragment(pkgs=[pkg("busybox", "1.36", "ref-b")]),
                              "cmake": fragment(pkgs=[pkg("cmake", "3.0", "ref-c")]),
                          },
                          runtime_recipes=["busybox"])
    sbom, _vex, _logs = render_docs(facts)

    assert all("scope" not in c for c in sbom["components"])


def test_recipes_sharing_a_cpe_collapse_to_one_component():
    shared_cpe = "cpe:2.3:*:*:widget:1.0:*:*:*:*:*:*:*"
    facts = default_facts(fragments={
        "widget-a": fragment(pkgs=[pkg("widget", "1.0", "ref-a", cpe=shared_cpe)]),
        "widget-b": fragment(pkgs=[pkg("widget", "1.0", "ref-b", cpe=shared_cpe)]),
    })
    sbom, _vex, logs = render_docs(facts)

    assert component_names(sbom).count("widget") == 1
    # first recipe (alphabetical) wins the surviving bom-ref
    assert ref_of(sbom, "widget") == "ref-a"


def test_dependency_on_a_dropped_duplicate_resolves_to_the_survivor():
    shared_cpe = "cpe:2.3:*:*:widget:1.0:*:*:*:*:*:*:*"
    facts = default_facts(fragments={
        "widget-a": fragment(pkgs=[pkg("widget", "1.0", "ref-a", cpe=shared_cpe)]),
        "widget-b": fragment(pkgs=[pkg("widget", "1.0", "ref-b", cpe=shared_cpe)]),
        "consumer": fragment(pkgs=[pkg("consumer", "1", "ref-c")],
                             dependencies=[dep("ref-c", ["widget-b"])]),
    })
    sbom, _vex, _logs = render_docs(facts)

    entry = next(e for e in sbom["dependencies"] if e["ref"] == "ref-c")
    assert entry["dependsOn"] == ["ref-a"]


def test_recipe_level_dedup_map_redirects_its_own_dependency_edge():
    facts = default_facts(fragments={
        "multi": fragment(
            pkgs=[pkg("multi", "1", "ref-main"), pkg("multi-alias", "1", "ref-dup")],
            dependencies=[dep("ref-dup", ["libc"])],
            dedup={"ref-dup": "ref-main"}),
        "libc": fragment(pkgs=[pkg("libc", "2.40", "ref-libc")]),
    })
    sbom, _vex, _logs = render_docs(facts)

    # The fragment owned its dependency entry under a dropped bom-ref; the
    # graph must expose it once, under the surviving ref.
    entries = [e for e in sbom["dependencies"] if e["ref"] == "ref-main"]
    assert len(entries) == 1
    assert entries[0]["dependsOn"] == ["ref-libc"]


def test_fragment_input_is_not_mutated():
    frag = fragment(pkgs=[pkg("busybox", "1.36", "ref-b")])
    facts = default_facts(fragments={"busybox": frag})
    render_docs(facts)

    assert "scope" not in frag["pkgs"][0]
