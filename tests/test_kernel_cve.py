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
