# SPDX-License-Identifier: MIT
SUMMARY = "CVE records for CycloneDX kernel configuration analysis"
HOMEPAGE = "https://github.com/CVEProject/cvelistV5"
LICENSE = "CVE-TOU"
LIC_FILES_CHKSUM = "file://README.md;beginline=31;endline=31;md5=8aaff1c34f4c952283c4088b40b9ad31"
NO_GENERIC_LICENSE[CVE-TOU] = "README.md"

inherit native

INHIBIT_DEFAULT_DEPS = "1"
require conf/cyclonedx-kernel-cve.inc
SRCREV = "${CYCLONEDX_KERNEL_CVE_DB_SRCREV}"
SRC_URI = "git://github.com/CVEProject/cvelistV5.git;branch=main;protocol=https;destsuffix=git"
BB_GIT_SHALLOW = "1"
# UNPACKDIR was split from WORKDIR after scarthgap.
S = "${@d.getVar('UNPACKDIR') or d.getVar('WORKDIR')}/git"

do_configure[noexec] = "1"
do_compile[noexec] = "1"

do_install() {
    install -d ${D}${datadir}/cyclonedx/cvelist
    cp -R --no-preserve=ownership ${S}/cves/. ${D}${datadir}/cyclonedx/cvelist/
}
