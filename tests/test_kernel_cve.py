# SPDX-License-Identifier: MIT
"""Kernel exclusions: ambiguous or incomplete evidence must retain the CVE."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import textwrap
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

import meta_cyclonedx
from meta_cyclonedx_kernel import SourcePaths, find_exclusions


@pytest.fixture
def kernel(tmp_path):
    source, build, db = [tmp_path / name for name in ("source", "build", "db")]
    for root in (source, build, db):
        root.mkdir()
    for name in ("present.c", "absent.c", "other.c", "header.h", "entry.S", "entry.s"):
        path = source / "drivers" / name
        path.parent.mkdir(exist_ok=True)
        path.touch()
    mapper = SourcePaths([str(source), str(build)], "linux-test-6.6.1", "/usr/src/kernel",
                         f"-fdebug-prefix-map={source}=/debug/source "
                         f"-ffile-prefix-map={build}=/debug/build")
    return SimpleNamespace(source=source, build=build, db=db, mapper=mapper,
                           compiled={"linux-test-6.6.1/drivers/present.c"},
                           matcher=SimpleNamespace(Version=str,
                                                   get_cpe_applicability=lambda record, version: (True,)),
                           logs=[])


def record(kernel, number=1, files=None):
    cve_id = f"CVE-2026-{number:04d}"
    data = {
        "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED"},
        "containers": {"cna": {
            "affected": [{"vendor": "Linux", "product": "Linux",
                          "programFiles": files if files is not None else ["drivers/absent.c"]}],
            "cpeApplicability": [{"nodes": [{"cpeMatch": [{
                "vulnerable": True, "versionStartIncluding": "6.6.0",
                "versionEndExcluding": "6.6.10",
            }]}]}],
        }},
    }
    (kernel.db / f"{cve_id}.json").write_text(json.dumps(data))
    return cve_id, data


def save(kernel, cve_id, data):
    (kernel.db / f"{cve_id}.json").write_text(json.dumps(data))


def exclusions(kernel, protected=(), version="6.6.1+git123"):
    return find_exclusions(kernel.db, kernel.compiled, kernel.mapper, version,
                           kernel.matcher, protected,
                           log=lambda *entry: kernel.logs.append(entry))


def test_present_absent_and_multiple_c_files(kernel):
    absent, _ = record(kernel)
    record(kernel, 2, ["drivers/present.c"])
    record(kernel, 3, ["drivers/absent.c", "drivers/present.c"])
    both_absent, _ = record(kernel, 4, ["drivers/absent.c", "drivers/other.c"])
    assert set(exclusions(kernel)) == {absent, both_absent}


@pytest.mark.parametrize("files", [
    [], ["drivers/header.h"], ["drivers/entry.S"], ["drivers/entry.s"],
    ["drivers/absent.c", "drivers/header.h"], ["drivers/unknown.c"],
    ["absent.c"], ["drivers/*.c"], ["drivers/../drivers/absent.c"],
    ["./drivers/absent.c"], ["drivers//absent.c"], ["drivers"],
    ["/usr/src/kernel/drivers/absent.c"], [None], "drivers/absent.c",
])
def test_unsupported_affected_paths_are_retained(kernel, files):
    record(kernel, files=files)
    assert exclusions(kernel) == {}


@pytest.mark.parametrize("path", [
    "drivers/present.c", "linux-test-6.6.1/drivers/present.c",
    "/usr/src/kernel/drivers/present.c", "/debug/source/drivers/present.c",
])
def test_known_source_prefixes(kernel, path):
    record(kernel, files=["drivers/present.c"])
    kernel.compiled = {path}
    assert exclusions(kernel) == {}
    assert kernel.logs == []


def test_absolute_source_and_generated_build_paths(kernel):
    generated = kernel.build / "generated.c"
    generated.touch()
    record(kernel, files=["generated.c"])
    for path in (str(generated), "/debug/build/generated.c", "linux-test-6.6.1/generated.c"):
        kernel.compiled = {str(kernel.source / "drivers/present.c"), path}
        assert exclusions(kernel) == {}
        assert kernel.logs == []
    kernel.compiled = {str(kernel.source / "drivers/present.c")}
    assert len(exclusions(kernel)) == 1


@pytest.mark.parametrize("compiled", [set(), {"unknown-prefix/drivers/present.c"},
                                       {"/unmapped/drivers/present.c"},
                                       {"linux-test-6.6.1/drivers/present.c", "/unmapped/file.h"}])
def test_empty_or_unmapped_debug_sources_disable_all_exclusions(kernel, compiled):
    record(kernel)
    kernel.compiled = compiled
    assert exclusions(kernel) == {}
    assert kernel.logs[0][0] == "warn"


def test_ambiguous_source_build_file_is_retained(kernel):
    (kernel.build / "drivers").mkdir()
    (kernel.build / "drivers/absent.c").touch()
    record(kernel)
    assert exclusions(kernel) == {}


def test_ambiguous_compiled_path_disables_all_exclusions(kernel):
    (kernel.build / "drivers").mkdir()
    (kernel.build / "drivers/present.c").touch()
    record(kernel)
    assert exclusions(kernel) == {}
    assert kernel.logs[0][0] == "warn"


def test_compiled_symlink_alias_keeps_original_affected(kernel):
    (kernel.source / "alias.c").symlink_to(kernel.source / "drivers/absent.c")
    kernel.compiled.add("linux-test-6.6.1/alias.c")
    record(kernel)
    assert exclusions(kernel) == {}


def test_multiple_affected_entries_require_complete_c_metadata(kernel):
    cve_id, data = record(kernel)
    data["containers"]["cna"]["affected"].append({"vendor": "Linux", "product": "Linux"})
    save(kernel, cve_id, data)
    assert exclusions(kernel) == {}


def test_adp_paths_are_not_overlooked(kernel):
    cve_id, data = record(kernel)
    data["containers"]["adp"] = [{"affected": [{
        "vendor": "Linux", "product": "Linux", "programFiles": ["drivers/header.h"]}]}]
    save(kernel, cve_id, data)
    assert exclusions(kernel) == {}


@pytest.mark.parametrize("state", ["REJECTED", "RESERVED", None])
def test_unpublished_or_unknown_metadata_retains_cve(kernel, state):
    cve_id, data = record(kernel)
    data["cveMetadata"]["state"] = state
    save(kernel, cve_id, data)
    assert exclusions(kernel) == {}


def test_malformed_or_duplicate_records_do_not_exclude(kernel):
    cve_id, data = record(kernel)
    (kernel.db / "CVE-2026-0002.json").write_text("not JSON")
    duplicate = kernel.db / "duplicate"
    duplicate.mkdir()
    (duplicate / f"{cve_id}.json").write_text(json.dumps(data))
    assert exclusions(kernel) == {}


def test_invalid_json_does_not_prevent_other_exclusions(kernel):
    valid_id, _ = record(kernel)
    (kernel.db / "CVE-2026-0002.json").write_text("not JSON")
    assert set(exclusions(kernel)) == {valid_id}
    assert "cannot read CVE record" in kernel.logs[0][1]


def test_path_mapping_errors_are_not_reported_as_bad_metadata(kernel):
    record(kernel)
    kernel.mapper.affected = Mock(side_effect=AttributeError("path mapping failed"))
    with pytest.raises(AttributeError, match="path mapping failed"):
        exclusions(kernel)
    assert kernel.logs == []


def test_invalid_version_metadata_does_not_prevent_other_exclusions(kernel):
    invalid_id, _ = record(kernel)
    valid_id, _ = record(kernel, 2)

    def match_version(data, version):
        if data["cveMetadata"]["cveId"] == invalid_id:
            raise ValueError("invalid version range")
        return (True,)

    kernel.matcher.get_cpe_applicability = match_version
    assert set(exclusions(kernel)) == {valid_id}
    assert "cannot match CVE version metadata" in kernel.logs[0][1]


@pytest.mark.parametrize("matched", [False, None])
def test_unaffected_or_unknown_versions_are_retained(kernel, matched):
    record(kernel)
    kernel.matcher.get_cpe_applicability = lambda record, version: (matched,)
    assert exclusions(kernel) == {}


def test_invalid_version_retains_assessments(kernel):
    record(kernel)
    kernel.matcher.Version = Mock(side_effect=ValueError)
    assert exclusions(kernel) == {}
    assert kernel.logs[0][0] == "warn"


def class_function(name, namespace):
    """Execute the production BitBake adapter without requiring BitBake."""
    path = Path(__file__).resolve().parents[1] / "classes/cyclonedx-export.bbclass"
    lines = path.read_text().splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.startswith(f"def {name}("))
    end = start + 1
    while end < len(lines) and (not lines[end].strip() or lines[end][0].isspace()):
        end += 1
    exec(compile("".join(lines[start:end]), str(path), "exec"), namespace)
    return namespace[name]


def test_provider_detection_includes_default_kernel_but_not_modules():
    detect = class_function("cyclonedx_is_kernel", {})
    assert detect(Mock(getVar=lambda name: "linux-test virtual/kernel"))
    assert not detect(Mock(getVar=lambda name: "kernel-module-foo"))


@pytest.mark.parametrize("enabled,provides", [("0", "virtual/kernel"),
                                             ("1", "kernel-module-foo")])
def test_disabled_or_non_kernel_filter_has_no_database_dependency(enabled, provides):
    namespace = {"os": os, "bb": Mock()}
    class_function("cyclonedx_is_kernel", namespace)
    configure = class_function("configure_kernel_cve_filter", namespace)
    values = {"CYCLONEDX_VEX_ADD_KERNEL_CVE": enabled, "PROVIDES": provides}
    d = Mock(getVar=values.get)
    configure(d)
    d.appendVarFlag.assert_not_called()
    namespace["bb"].fatal.assert_not_called()


def test_enabled_filter_requires_helper_and_only_depends_at_assessment(tmp_path):
    def fatal(message):
        raise RuntimeError(message)

    namespace = {"os": os, "bb": Mock()}
    namespace["bb"].fatal.side_effect = fatal
    class_function("cyclonedx_is_kernel", namespace)
    configure = class_function("configure_kernel_cve_filter", namespace)
    values = {"CYCLONEDX_VEX_ADD_KERNEL_CVE": "1", "PROVIDES": "virtual/kernel",
              "COREBASE": str(tmp_path), "CYCLONEDX_LAYERDIR": "/layer"}
    d = Mock(getVar=values.get)
    with pytest.raises(RuntimeError, match="requires an OE-Core revision"):
        configure(d)
    d.appendVarFlag.assert_not_called()
    script = tmp_path / "scripts/contrib/improve_kernel_cve_report.py"
    script.parent.mkdir(parents=True)
    script.touch()
    configure(d)
    assert d.appendVarFlag.call_args_list[0].args == (
        "do_populate_cyclonedx", "file-checksums",
        f" {script}:True /layer/lib/meta_cyclonedx_kernel.py:True")
    assert d.appendVarFlag.call_args_list[1].args == (
        "do_populate_cyclonedx", "depends", " cyclonedx-cvelist-native:do_populate_sysroot")
    d.appendVar.assert_not_called()  # No recipe-wide DEPENDS edge.


def test_recipe_collection_protects_patches_and_explicit_unpatched_ids(monkeypatch):
    oe = ModuleType("oe")
    oe.cve_check = ModuleType("oe.cve_check")
    oe.cve_check.get_patched_cves = lambda d: {
        "CVE-2026-0001-0001": {"abbrev-status": "Patched", "status": "fixed"},
        "CVE-2026-0002": {"abbrev-status": "Unpatched", "status": "unpatched"},
    }
    oe.purl = ModuleType("oe.purl")
    oe.purl.get_base_purl = lambda d: "pkg:yocto/linux@6.6.1"
    for name, module in (("oe", oe), ("oe.cve_check", oe.cve_check), ("oe.purl", oe.purl)):
        monkeypatch.setitem(sys.modules, name, module)
    values = {"PN": "linux-test", "BPN": "linux-test", "CVE_PRODUCT": "linux linux-alias",
              "CVE_VERSION": "6.6.1", "PROVIDES": "linux-test virtual/kernel",
              "CYCLONEDX_VEX_ADD_KERNEL_CVE": "1", "CYCLONEDX_PNDATA_WORKDIR": "/pn",
              "CYCLONEDX_SBOM_SERIAL_PLACEHOLDER": "<SBOM_SERIAL>"}
    d = Mock(getVar=values.get, getVarFlags=lambda name: {"CVE-2026-0003": "unpatched"})
    namespace = {
        "os": os, "bb": Mock(), "_cyclonedx_log": lambda *args: None,
        "_cyclonedx_renderer": lambda d: meta_cyclonedx,
        "get_custom_properties": lambda d: None, "get_recipe_dependencies": lambda d: [],
        "add_kernel_cve_exclusions": Mock(), "write_json": Mock(),
    }
    class_function("cyclonedx_is_kernel", namespace)
    path = Path(__file__).resolve().parents[1] / "classes/cyclonedx-export.bbclass"
    text = path.read_text().split("python do_populate_cyclonedx() {\n", 1)[1].split("\n}", 1)[0]
    exec("def collect(d):\n" + textwrap.indent(textwrap.dedent(text), "    "), namespace)
    namespace["collect"](d)
    args = namespace["add_kernel_cve_exclusions"].call_args.args
    assert args[4] == {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}
    assert len(args[2]) == 2  # Both vulnerability-correlation aliases.
    cves = namespace["write_json"].call_args.args[1]["cves"]
    assert len(cves) == 1
    assert cves[0]["id"] == "CVE-2026-0001"
    assert len(cves[0]["affects"]) == 2


@pytest.fixture
def adapter(kernel, tmp_path, monkeypatch):
    # Stub only the version API at the OE boundary; run the production filter,
    # adapter and renderer, including dynamically loading the source module.
    corebase = tmp_path / "core"
    contrib = corebase / "scripts/contrib"
    contrib.mkdir(parents=True)
    (contrib / "improve_kernel_cve_report.py").write_text(
        "Version = str\ndef get_cpe_applicability(record, version):\n    return (True,)\n")
    (kernel.build / ".config").write_text("CONFIG_DEBUG_INFO=y\nCONFIG_DEBUG_INFO_DWARF4=y\n")
    values = {
        "COREBASE": str(corebase), "CYCLONEDX_LAYERDIR": str(Path(__file__).resolve().parents[1]),
        "S": str(kernel.source), "B": str(kernel.build), "BP": "linux-test-6.6.1",
        "KERNEL_SRC_PATH": "/usr/src/kernel", "CYCLONEDX_KERNEL_CVE_DB_DIR": str(kernel.db),
        "CYCLONEDX_SBOM_SERIAL_PLACEHOLDER": "<SBOM_SERIAL>",
    }
    oe = ModuleType("oe")
    oe.package = ModuleType("oe.package")
    reader = Mock(return_value={"boot/vmlinux-6.6.1": list(kernel.compiled)})
    oe.package.read_debugsources_info = reader
    monkeypatch.setitem(sys.modules, "oe", oe)
    monkeypatch.setitem(sys.modules, "oe.package", oe.package)
    bb = Mock()

    def fatal(message):
        raise RuntimeError(message)

    bb.fatal.side_effect = fatal
    namespace = {"os": os, "bb": bb,
                 "_cyclonedx_log": lambda *entry: kernel.logs.append(entry),
                 "_cyclonedx_renderer": lambda d: meta_cyclonedx}
    class_function("kernel_cve_filter_prerequisite_error", namespace)
    class_function("get_kernel_compiled_sources", namespace)
    add = class_function("add_kernel_cve_exclusions", namespace)
    return SimpleNamespace(add=add, values=values, d=Mock(getVar=values.get),
                           bb=bb, reader=reader,
                           script=contrib / "improve_kernel_cve_report.py")


def test_adapter_preserves_existing_statements_and_all_component_references(kernel, adapter):
    existing_id, _ = record(kernel, 1)
    unpatched_id, _ = record(kernel, 2)
    new_id, _ = record(kernel, 3)
    original = {"id": existing_id, "analysis": {"state": "resolved"}}
    cves = [copy.deepcopy(original)]
    packages = [{"bom-ref": "kernel"}, {"bom-ref": "alias"}, {"bom-ref": "kernel"}]
    adapter.add(adapter.d, "6.6.1", packages, cves, {unpatched_id})
    assert cves[0] == original
    assert [cve["id"] for cve in cves] == [existing_id, new_id]
    assert cves[1]["analysis"]["state"] == "not_affected"
    assert cves[1]["analysis"]["justification"] == "code_not_present"
    assert cves[1]["affects"] == [
        {"ref": "urn:cdx:<SBOM_SERIAL>/1#kernel"},
        {"ref": "urn:cdx:<SBOM_SERIAL>/1#alias"},
    ]
    adapter.add(adapter.d, "6.6.1", packages, cves, {unpatched_id})
    assert len(cves) == 2


@pytest.mark.parametrize("setting,value,config,diagnostic", [
    ("INHIBIT_PACKAGE_DEBUG_SPLIT", "1", "CONFIG_DEBUG_INFO=y\n", "INHIBIT_PACKAGE_DEBUG_SPLIT"),
    ("PACKAGE_DEBUG_SPLIT_STYLE", "debug-without-src", "CONFIG_DEBUG_INFO=y\n", "debug-with-srcpkg"),
    (None, None, "# CONFIG_DEBUG_INFO is not set\n", "enable CONFIG_DEBUG_INFO"),
    (None, None, "CONFIG_DEBUG_INFO=y\nCONFIG_DEBUG_INFO_SPLIT=y\n", "disable CONFIG_DEBUG_INFO_SPLIT"),
    (None, None, None, "cannot read kernel configuration"),
])
def test_bad_prerequisites_warn_and_preserve_assessments(kernel, adapter, setting, value, config, diagnostic):
    if setting:
        adapter.values[setting] = value
    config_path = kernel.build / ".config"
    if config is None:
        config_path.unlink()
    else:
        config_path.write_text(config)
    cve_id, _ = record(kernel)
    original = [{"id": cve_id, "analysis": {"state": "in_triage"}}]
    cves = copy.deepcopy(original)
    adapter.add(adapter.d, "6.6.1", [{"bom-ref": "kernel"}], cves, set())
    assert cves == original
    assert diagnostic in adapter.bb.warn.call_args.args[0]
    assert "leaving CVE assessments unchanged" in adapter.bb.warn.call_args.args[0]
    adapter.reader.assert_not_called()


@pytest.mark.parametrize("source_info,diagnostic", [
    ({"lib/modules/6.6/kernel/a.ko": ["linux-test-6.6.1/drivers/present.c"]}, "packaged vmlinux"),
    ({"boot/vmlinux-6.6.1": [],
      "lib/modules/6.6/kernel/a.ko": ["linux-test-6.6.1/drivers/present.c"]}, "packaged vmlinux"),
    ({"boot/vmlinux-6.6.1": ["linux-test-6.6.1/drivers/present.c"],
      "lib/modules/6.6/kernel/a.ko": []}, "no debug sources for module"),
])
def test_detectable_partial_debug_data_prevents_exclusions(kernel, adapter, source_info, diagnostic):
    record(kernel)
    adapter.reader.return_value = source_info
    cves = []
    adapter.add(adapter.d, "6.6.1", [{"bom-ref": "kernel"}], cves, set())
    assert cves == []
    assert diagnostic in adapter.bb.warn.call_args.args[0]


def test_empty_packaging_data_warns_once_and_leaves_assessments_unchanged(kernel, adapter):
    record(kernel)
    adapter.reader.return_value = None
    cves = []
    adapter.add(adapter.d, "6.6.1", [{"bom-ref": "kernel"}], cves, set())
    assert cves == []
    assert len(kernel.logs) == 1
    assert kernel.logs[0][0] == "warn"
    assert "no compiled-source debug information" in kernel.logs[0][1]


def test_nul_separator_entries_do_not_disable_filtering(kernel, adapter):
    record(kernel)
    adapter.reader.return_value = {
        "boot/vmlinux-6.6.1": ["linux-test-6.6.1/drivers/present.c", ""],
        "lib/modules/6.6/kernel/a.ko": ["linux-test-6.6.1/drivers/present.c", ""],
    }
    cves = []
    adapter.add(adapter.d, "6.6.1", [{"bom-ref": "kernel"}], cves, set())
    assert len(cves) == 1
    adapter.bb.warn.assert_not_called()
    assert kernel.logs == []


@pytest.mark.parametrize("binary", ["boot/vmlinux-6.6.1", "lib/modules/6.6/kernel/a.ko"])
def test_separator_alone_is_not_debug_source_evidence(kernel, adapter, binary):
    record(kernel)
    adapter.reader.return_value[binary] = [""]
    cves = []
    adapter.add(adapter.d, "6.6.1", [{"bom-ref": "kernel"}], cves, set())
    assert cves == []
    assert "no debug sources" in adapter.bb.warn.call_args.args[0]


def test_dwarf5_and_compression_are_not_rejected_if_sources_are_available(kernel, adapter):
    record(kernel)
    (kernel.build / ".config").write_text(
        "CONFIG_DEBUG_INFO=y\nCONFIG_DEBUG_INFO_DWARF5=y\nCONFIG_DEBUG_INFO_COMPRESSED_ZSTD=y\n")
    adapter.reader.return_value["lib/modules/6.6/kernel/a.ko"] = list(kernel.compiled)
    cves = []
    adapter.add(adapter.d, "6.6.1", [{"bom-ref": "kernel"}], cves, set())
    assert len(cves) == 1
    adapter.bb.warn.assert_not_called()


def test_missing_matcher_dependency_has_actionable_error(kernel, adapter):
    adapter.script.write_text("raise ModuleNotFoundError('No module named packaging')\n")
    with pytest.raises(RuntimeError, match="including Python packaging"):
        adapter.add(adapter.d, "6.6.1", [{"bom-ref": "kernel"}], [], set())


def test_invalid_prefix_map_warns_and_does_not_exclude(kernel, adapter):
    record(kernel)
    adapter.values["DEBUG_PREFIX_MAP"] = '"unterminated'
    cves = []
    adapter.add(adapter.d, "6.6.1", [{"bom-ref": "kernel"}], cves, set())
    assert cves == []
    assert "leaving CVE assessments unchanged" in adapter.bb.warn.call_args.args[0]


def test_known_sysroot_header_does_not_disable_kernel_exclusions(kernel, adapter, tmp_path):
    sysroot = tmp_path / 'recipe-sysroot-native'
    header = sysroot / 'usr/lib/gcc/include/arm_neon.h'
    header.parent.mkdir(parents=True)
    header.touch()
    adapter.values['RECIPE_SYSROOT_NATIVE'] = str(sysroot)
    adapter.reader.return_value['boot/vmlinux-6.6.1'].append('/usr/lib/gcc/include/arm_neon.h')
    cve_id, _ = record(kernel)
    cves = []
    adapter.add(adapter.d, '6.6.1', [{'bom-ref': 'kernel'}], cves, set())
    assert [cve['id'] for cve in cves] == [cve_id]
    assert kernel.logs == []


@pytest.mark.parametrize('filename', ['missing.h', 'external.c'])
def test_missing_header_or_external_c_source_still_disables_exclusions(kernel, adapter, tmp_path, filename):
    sysroot = tmp_path / 'recipe-sysroot-native'
    (sysroot / 'usr/include').mkdir(parents=True)
    (sysroot / 'usr/include/external.c').touch()
    adapter.values['RECIPE_SYSROOT_NATIVE'] = str(sysroot)
    adapter.reader.return_value['boot/vmlinux-6.6.1'].append('/usr/include/' + filename)
    record(kernel)
    cves = []
    adapter.add(adapter.d, '6.6.1', [{'bom-ref': 'kernel'}], cves, set())
    assert cves == []
    assert 'unmapped or ambiguous debug source' in kernel.logs[0][1]


def test_ambiguous_sysroot_headers_still_disable_exclusions(kernel, adapter, tmp_path):
    for variable in ('RECIPE_SYSROOT', 'RECIPE_SYSROOT_NATIVE'):
        sysroot = tmp_path / variable
        header = sysroot / 'usr/include/external.h'
        header.parent.mkdir(parents=True)
        header.touch()
        adapter.values[variable] = str(sysroot)
    adapter.reader.return_value['boot/vmlinux-6.6.1'].append('/usr/include/external.h')
    record(kernel)
    cves = []
    adapter.add(adapter.d, '6.6.1', [{'bom-ref': 'kernel'}], cves, set())
    assert cves == []
    assert 'unmapped or ambiguous debug source' in kernel.logs[0][1]


def test_sysroot_header_alias_preserves_compiled_physical_file(kernel, tmp_path):
    sysroot = tmp_path / 'recipe-sysroot-native'
    header = sysroot / 'usr/include/external.h'
    header.parent.mkdir(parents=True)
    header.symlink_to(kernel.source / 'drivers/absent.c')
    kernel.mapper = SourcePaths([str(kernel.source), str(kernel.build)],
                              'linux-test-6.6.1', '/usr/src/kernel',
                              external_header_roots=[str(sysroot)])
    record(kernel)
    kernel.compiled = {'/usr/include/external.h'}
    assert exclusions(kernel) == {}


def test_real_oe_core_version_matching(kernel):
    corebase = os.environ.get("COREBASE")
    if not corebase:
        pytest.skip("Set COREBASE to test the installed OE-Core version matcher")
    pytest.importorskip("packaging.version")
    path = Path(corebase) / "scripts/contrib/improve_kernel_cve_report.py"
    spec = importlib.util.spec_from_file_location("improve_kernel_cve_report", path)
    kernel.matcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kernel.matcher)
    record(kernel)
    assert len(exclusions(kernel, version="6.6.1+git123")) == 1
    assert exclusions(kernel, version="6.6.10") == {}
    assert exclusions(kernel, version="6.5.0") == {}
    cve_id, data = record(kernel)
    del data["containers"]["cna"]["cpeApplicability"]
    save(kernel, cve_id, data)
    assert exclusions(kernel) == {}

    # A broad synthetic range used by the real-build fixture must also match
    # newer kernels through OE's matcher (whose internal sentinel is 5000).
    cve_id, data = record(kernel)
    match = data["containers"]["cna"]["cpeApplicability"][0]["nodes"][0]["cpeMatch"][0]
    match["versionEndExcluding"] = "99.0.0"
    save(kernel, cve_id, data)
    assert len(exclusions(kernel, version="7.2.8")) == 1
