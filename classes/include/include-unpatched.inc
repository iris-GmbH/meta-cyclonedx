# SPDX-License-Identifier: MIT

do_cyclonedx_package_collect[depends] += "${PN}:do_cve_check"
do_cyclonedx_package_collect[nostamp] = "1"
