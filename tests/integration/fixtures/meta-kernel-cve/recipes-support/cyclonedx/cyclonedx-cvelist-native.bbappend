# SPDX-License-Identifier: MIT
# Exercise the production native recipe/sysroot dependency without fetching
# the full upstream CVE database. Only this test configuration sees the append.
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"
SRC_URI = "file://cases.json"
S = "${@d.getVar('UNPACKDIR') or d.getVar('WORKDIR')}"

python do_install() {
    import json
    from pathlib import Path

    unpackdir = d.getVar('UNPACKDIR') or d.getVar('WORKDIR')
    cases = json.loads(Path(unpackdir, 'cases.json').read_text())
    destination = Path(d.getVar('D') + d.getVar('datadir'), 'cyclonedx/cvelist')
    destination.mkdir(parents=True, exist_ok=True)
    revision = d.getVar('CYCLONEDX_KERNEL_CVE_DB_SRCREV')
    for cve_id, files in cases.items():
        if cve_id == 'CVE-2099-0011' and revision.endswith('1'):
            continue
        affected = {'vendor': 'Linux', 'product': 'Linux'}
        if files is not None:
            affected['programFiles'] = files
        record = {
            'cveMetadata': {'cveId': cve_id, 'state': 'PUBLISHED'},
            'containers': {'cna': {
                'descriptions': [{'lang': 'en', 'value': 'Synthetic meta-cyclonedx acceptance case'}],
                'affected': [affected],
                'cpeApplicability': [{'nodes': [{'cpeMatch': [{
                    'criteria': 'cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*',
                    'vulnerable': True, 'versionStartIncluding': '0.0.0',
                    'versionEndExcluding': '99.0.0',
                }]}]}],
            }},
        }
        (destination / (cve_id + '.json')).write_text(json.dumps(record))
}
