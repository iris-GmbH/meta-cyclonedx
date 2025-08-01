# SPDX-License-Identifier: MIT
# Copyright 2022 BG Networks, Inc.
# Copyright (C) 2024 Savoir-faire Linux Inc. (<www.savoirfairelinux.com>).

# The product name that the CVE database uses.  Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"

CYCLONEDX_EXPORT_DIR ??= "${DEPLOY_DIR}/cyclonedx-export"
CYCLONEDX_EXPORT_SBOM ??= "${CYCLONEDX_EXPORT_DIR}/bom.json"
CYCLONEDX_EXPORT_VEX ??= "${CYCLONEDX_EXPORT_DIR}/vex.json"
CYCLONEDX_EXPORT_TMP ??= "${TMPDIR}/cyclonedx-export"
CYCLONEDX_EXPORT_LOCK ??= "${CYCLONEDX_EXPORT_TMP}/bom.lock"

python do_cyclonedx_init() {
    import uuid
    from datetime import datetime, timezone

    timestamp = datetime.now(timezone.utc).isoformat()
    sbom_dir = d.getVar("CYCLONEDX_EXPORT_DIR")
    bb.debug(2, "Creating cyclonedx directory: %s" % sbom_dir)
    bb.utils.mkdirhier(sbom_dir)

    # Generate unique serial numbers for sbom and vex document
    sbom_serial_number = str(uuid.uuid4())
    vex_serial_number = str(uuid.uuid4())

    bb.debug(2, f"Creating empty sbom file with serial number {sbom_serial_number}")
    write_json(d.getVar("CYCLONEDX_EXPORT_SBOM"), {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{sbom_serial_number}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"name": "yocto"}]
        },
        "components": []
    })

    bb.debug(2, f"Creating empty vex file with serial number {vex_serial_number}")
    write_json(d.getVar("CYCLONEDX_EXPORT_VEX"), {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{vex_serial_number}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"name": "yocto"}]
        },
        "vulnerabilities": []
    })
}
addhandler do_cyclonedx_init
do_cyclonedx_init[eventmask] = "bb.event.BuildStarted"

python do_cyclonedx_package_collect() {
    import oe.cve_check

    # ignore non-target packages
    for ignored_suffix in (d.getVar("SPECIAL_PKGSUFFIX") or "").split():
        if d.getVar("PN").endswith(ignored_suffix):
            return

    # load the bom
    name = d.getVar("CVE_PRODUCT")
    version = d.getVar("CVE_VERSION")
    sbom = read_json(d.getVar("CYCLONEDX_EXPORT_SBOM"))
    # extract the sbom serial number without "urn:uuid:" prefix
    # (avoid using builtin str.removeprefix function as Python >= 3.9 required)
    sbom_serial_number = sbom["serialNumber"][len("urn:uuid:"):]
    vex = read_json(d.getVar("CYCLONEDX_EXPORT_VEX"))

    dependencies = []
    bom_ref_map = {comp["name"]: comp["bom-ref"] for comp in sbom["components"] if "bom-ref" in comp}
    existing_components_by_cpe = {c.get("cpe"): c for c in sbom["components"] if "cpe" in c}

    for pkg in generate_packages_list(name, version):
        if not pkg["cpe"] in existing_components_by_cpe:
            sbom["components"].append(pkg)
            bom_ref = pkg["bom-ref"]
            bom_ref_map[pkg["name"]] = bom_ref

            # Add CVEs
            for patched_cve in oe.cve_check.get_patched_cves(d):
                bb.debug(2, f"Found patch for CVE {patched_cve} in {name}@{version}")
                vex["vulnerabilities"].append({
                    "id": patched_cve,
                    # vex documents require a valid source, see https://github.com/DependencyTrack/dependency-track/issues/2977
                    # this should always be NVD for yocto CVEs.
                    "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{patched_cve}"},
                    "analysis": {"state": "resolved"},
                    # Hint: Component specific resolving seems not to work at the moment when using DependencyTrack
                    # resolution will of CVE will be applied to all components within the project that contain the CVE
                    "affects": [{"ref": f"urn:cdx:{sbom_serial_number}/1#{bom_ref}"}]
                })

            # populate vex file with ignored CVEs defined in CVE_CHECK_IGNORE
            cve_check_ignore = d.getVar("CVE_CHECK_IGNORE")
            if cve_check_ignore is not None:
                for ignored_cve in cve_check_ignore.split():
                    bb.debug(2, f"Found ignore statement for CVE {ignored_cve} in {name}@{version}")
                    vex["vulnerabilities"].append({
                        "id": ignored_cve,
                        # vex documents require a valid source, see https://github.com/DependencyTrack/dependency-track/issues/2977
                        # this should always be NVD for yocto CVEs.
                        "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{ignored_cve}"},
                        # setting not-affected state for ignored CVEs
                        "analysis": {"state": "not_affected"},
                        # Hint: Component specific resolving seems not to work at the moment when using DependencyTrack
                        # resolution will of CVE will be applied to all components within the project that contain the CVE
                        "affects": [{"ref": f"urn:cdx:{sbom_serial_number}/1#{bom_ref}"}]
                    })

            # Add dependencies
            dep_entry = {
                "ref": bom_ref,
                "dependsOn": []
            }

            for dep_name in (d.getVar("DEPENDS") or "").split():
                dep_name = dep_name.strip().split()[0]
                dep_ref = bom_ref_map.get(dep_name)
                if not dep_ref:
                    dep_ref = f"{dep_name}-unknown"
                    bom_ref_map[dep_name] = dep_ref
                    sbom["components"].append({
                        "name": dep_name,
                        "version": "unknown",
                        "type": "library",
                        "bom-ref": dep_ref
                    })

                dep_entry["dependsOn"].append(dep_ref)

            if dep_entry["dependsOn"]:
                dependencies.append(dep_entry)

    if dependencies:
        sbom["dependencies"] = sbom.get("dependencies", []) + dependencies

    # write it back to the deploy directory
    write_json(d.getVar("CYCLONEDX_EXPORT_SBOM"), sbom)
    write_json(d.getVar("CYCLONEDX_EXPORT_VEX"), vex)
}

addtask do_cyclonedx_package_collect before do_build
do_cyclonedx_package_collect[nostamp] = "1"
do_cyclonedx_package_collect[lockfiles] += "${CYCLONEDX_EXPORT_LOCK}"
do_rootfs[recrdeptask] += "do_cyclonedx_package_collect"

def read_json(path):
    import json
    from pathlib import Path
    return json.loads(Path(path).read_text())

def write_json(path, content):
    import json
    from pathlib import Path
    Path(path).write_text(
        json.dumps(content, indent=2)
    )

def generate_packages_list(products_names, version):
    """
    Get a list of products and generate CPE and PURL identifiers for each of them.
    """
    import uuid

    packages = []

    # keep only the short version which can be matched against vulnerabilities databases
    version = version.split("+git")[0]

    # some packages have alternative names, so we split CVE_PRODUCT
    for product in products_names.split():
        # CVE_PRODUCT in recipes may include vendor information for CPE identifiers. If not,
        # use wildcard for vendor.
        if ":" in product:
            vendor, product = product.split(":", 1)
        else:
            vendor = ""

        pkg = {
            "name": product,
            "version": version,
            "type": "library",
            "cpe": 'cpe:2.3:*:{}:{}:{}:*:*:*:*:*:*:*'.format(vendor or "*", product, version),
            "purl": 'pkg:generic/{}{}@{}'.format(f"{vendor}/" if vendor else '', product, version),
            "bom-ref": str(uuid.uuid4())
        }
        if vendor != "":
            pkg["group"] = vendor
        packages.append(pkg)
    return packages
