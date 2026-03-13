# SPDX-License-Identifier: MIT

do_populate_cyclonedx[depends] += "${PN}:do_cve_check"
do_populate_cyclonedx[nostamp] = "1"
