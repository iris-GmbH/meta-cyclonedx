# SPDX-License-Identifier: MIT
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"
SRC_URI += "file://kernel-cve.cfg file://kernel-cve-fixture.patch"

# Use real recipe decisions and patch detection, not a mocked VEX producer.
CVE_STATUS[CVE-2099-0007] = "unpatched: synthetic acceptance case"
CVE_STATUS[CVE-2099-0009] = "ignored: synthetic acceptance decision"

# This evidence travels with the real kernel's CycloneDX sstate output. It
# records packaging facts without using the filter's path-matching helpers.
python do_populate_cyclonedx:append() {
    import json
    import oe.package
    from pathlib import Path

    source_info = oe.package.read_debugsources_info(d) or {}
    vmlinux = [sources for binary, sources in source_info.items()
               if os.path.basename(binary).startswith('vmlinux')]
    dummy = [sources for binary, sources in source_info.items()
             if os.path.basename(binary) == 'dummy.ko']
    def mentions(source_lists, path):
        return any(src == path or src.endswith('/' + path)
                   for sources in source_lists for src in sources)
    config = Path(d.getVar('B'), '.config').read_text().splitlines()
    taskdeps = d.getVar('BB_TASKDEPDATA', False) or {}
    evidence = {
        'debug_info': 'CONFIG_DEBUG_INFO=y' in config,
        'dummy_module': 'CONFIG_DUMMY=m' in config,
        'vmlinux_records': len(vmlinux),
        'main_source_present': mentions(vmlinux, 'init/main.c'),
        'dummy_records': len(dummy),
        'dummy_source_present': mentions(dummy, 'drivers/net/dummy.c'),
        'fixture_sources_exist': all(Path(d.getVar('S'), 'drivers/cyclonedx-test', name).is_file()
                                     for name in ('absent.c', 'absent.h', 'absent.S')),
        'database_in_graph': any(dep[0] == 'cyclonedx-cvelist-native' for dep in taskdeps.values()),
        'database_revision': d.getVar('CYCLONEDX_KERNEL_CVE_DB_SRCREV'),
    }
    Path(d.getVar('CYCLONEDX_PNDATA_WORKDIR'), 'linux-yocto.kernel-cve-evidence.json').write_text(json.dumps(evidence))
}
do_populate_cyclonedx[vardepsexclude] += "BB_TASKDEPDATA"
