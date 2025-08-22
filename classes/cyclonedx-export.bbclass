# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2022 BG Networks, Inc.
# SPDX-FileCopyrightText: Copyright (C) 2024 Savoir-faire Linux Inc. (<www.savoirfairelinux.com>).
# SPDX-FileCopyrightText: Copyright (C) 2024 iris-GmbH infrared & intelligent sensors.
# SPDX-FileCopyrightText: Copyright (C) 2025 balena, inc.

# The product name that the CVE database uses.  Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"

CYCLONEDX_RUNTIME_PACKAGES_ONLY ??= "1"

CYCLONEDX_EXPORT_DIR ??= "${DEPLOY_DIR}/cyclonedx-export/${PN}"
CYCLONEDX_EXPORT_SBOM ??= "${CYCLONEDX_EXPORT_DIR}/bom.json"
CYCLONEDX_EXPORT_VEX ??= "${CYCLONEDX_EXPORT_DIR}/vex.json"
CYCLONEDX_TMP_WORK_DIR ??= "${WORKDIR}/cyclonedx"
CYCLONEDX_TMP_PN_LIST = "${CYCLONEDX_TMP_WORK_DIR}/pn-list.json"
CYCLONEDX_WORK_DIR_ROOT ??= "${TMPDIR}/cyclonedx"
CYCLONEDX_WORK_DIR = "${CYCLONEDX_WORK_DIR_ROOT}/${PN}"
CYCLONEDX_WORK_DIR_PN_LIST = "${CYCLONEDX_WORK_DIR}/pn-list.json"

# We need to add the sbom serial number to the list of vulnerabilites for each recipe but
# don't know it until after we generate the sbom export header file
CYCLONEDX_SBOM_SERIAL_PLACEHOLDER = "<SBOM_SERIAL>"

# resolve CVE_CHECK_IGNORE and CVE_STATUS_GROUPS,
# taken from https://git.yoctoproject.org/poky/commit/meta/classes/cve-check.bbclass?id=be9883a92bad0fe4c1e9c7302c93dea4ac680f8c
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright OpenEmbedded Contributors
python () {
    # Fallback all CVEs from CVE_CHECK_IGNORE to CVE_STATUS
    cve_check_ignore = d.getVar("CVE_CHECK_IGNORE")
    if cve_check_ignore:
        bb.warn("CVE_CHECK_IGNORE is deprecated in favor of CVE_STATUS")
        for cve in (d.getVar("CVE_CHECK_IGNORE") or "").split():
            d.setVarFlag("CVE_STATUS", cve, "ignored")

    # Process CVE_STATUS_GROUPS to set multiple statuses and optional detail or description at once
    for cve_status_group in (d.getVar("CVE_STATUS_GROUPS") or "").split():
        cve_group = d.getVar(cve_status_group)
        if cve_group is not None:
            for cve in cve_group.split():
                d.setVarFlag("CVE_STATUS", cve, d.getVarFlag(cve_status_group, "status"))
        else:
            bb.warn("CVE_STATUS_GROUPS contains undefined variable %s" % cve_status_group)
}

# Clean out work folder to avoid leftovers from previous builds when including build-time package
# information and a recipe was removed from the dependency list. (CYCLONEDX_RUNTIME_PACKAGES_ONLY set to 0)
python clean_cyclonedx_work_folder() {
    bb.note(f"Cleaning cyclonedx work folder {d.getVar('CYCLONEDX_WORK_DIR_ROOT')}")
}
clean_cyclonedx_work_folder[cleandirs] = "${CYCLONEDX_WORK_DIR_ROOT}"
addhandler clean_cyclonedx_work_folder
clean_cyclonedx_work_folder[eventmask] = "bb.event.BuildStarted"

python do_cyclonedx_package_collect() {
    """
    Collect package information and CVE data from all packages built for the target architecture.
    """
    from oe.cve_check import get_patched_cves

    pn = d.getVar("PN")

    # ignore non-target packages
    for ignored_suffix in (d.getVar("SPECIAL_PKGSUFFIX") or "").split():
        if pn.endswith(ignored_suffix):
            return

    # get all CVE product names and version from the recipe
    name = d.getVar("CVE_PRODUCT")
    version = d.getVar("CVE_VERSION")

    # We create and populate a per-recipe partial sbom which will be added to the sstate cache
    pn_list = {}
    pn_list["pkgs"] = []
    cves = []
    # append all defined package names for recipe to pn_list pkgs
    for pkg in generate_packages_list(name, version):
        if not next((c for c in pn_list["pkgs"] if c["cpe"] == pkg["cpe"]), None):
            pn_list["pkgs"].append(pkg)
            bom_ref = pkg["bom-ref"]

            # append any CVEs either patched or taken from CVE_STATUS
            for cve_id, cve_info in get_patched_cves(d).items():
                cve = (
                    cve_id,
                    cve_info["abbrev-status"],
                    cve_info["status"],
                    cve_info.get("justification", "")
                )
                append_to_vex(d, cve, cves, bom_ref)

    # append any cve status within recipe to pn_list cves
    pn_list["cves"] = cves

    # Add dependencies
    dependencies = []

    for comp in pn_list["pkgs"]:
        main_ref = comp.get("bom-ref")
        if not main_ref:
            continue

        dep_entry = {
            "ref": main_ref,
            "dependsOn": []
        }

        for dep_name in get_recipe_dependencies(d):
            dep_entry["dependsOn"].append(dep_name)

        if dep_entry["dependsOn"]:
            dependencies.append(dep_entry)

    pn_list["dependencies"] = dependencies

    # write partial sbom to the recipes work folder
    write_json(d.getVar("CYCLONEDX_TMP_PN_LIST"), pn_list)
}

addtask do_cyclonedx_package_collect before do_build
do_cyclonedx_package_collect[cleandirs] = "${CYCLONEDX_TMP_WORK_DIR}"

# Utilizing shared state for output caching
# see https://docs.yoctoproject.org/overview-manual/concepts.html#shared-state
SSTATETASKS += "do_populate_cyclonedx"
do_populate_cyclonedx() {
    bbnote "Deploying intermediate product name list files from ${CYCLONEDX_TMP_WORK_DIR} to ${CYCLONEDX_WORK_DIR}"
}
python do_populate_cyclonedx_setscene() {
    sstate_setscene(d)
}

do_populate_cyclonedx[cleandirs] = "${CYCLONEDX_WORK_DIR}"
do_populate_cyclonedx[sstate-inputdirs] = "${CYCLONEDX_TMP_WORK_DIR}"
do_populate_cyclonedx[sstate-outputdirs] = "${CYCLONEDX_WORK_DIR}"
addtask do_populate_cyclonedx_setscene
addtask do_populate_cyclonedx after do_cyclonedx_package_collect
do_rootfs[recrdeptask] += "do_populate_cyclonedx"

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


def get_recipe_dependencies(d):
    """ 
    Return recipe names which depend on the current one.
    Combines DEPENDS and RDEPENDS if CYCLONEDX_RUNTIME_PACKAGES_ONLY is set to 0.
    """
    runtime_only = d.getVar("CYCLONEDX_RUNTIME_PACKAGES_ONLY") == "1"
    pn = d.getVar("PN")
    runtime_deps = (d.getVar("RDEPENDS:" + pn) or "").split()
    ignored_suffixes = set((d.getVar("SPECIAL_PKGSUFFIX") or "").split())

    if runtime_only:
        deps = runtime_deps
    else:
        build_deps = (d.getVar("DEPENDS") or "").split()
        deps = build_deps + runtime_deps

    # Resolves virtual/* dependencies to their preferred providers.
    resolved_deps = set()
    for dep in deps:
        dep = dep.strip()
        if not dep:
            continue
        # If package is virtual, we retrieve his provider
        if dep.startswith("virtual/"):
            if runtime_only:
                dep = d.getVar("PREFERRED_RPROVIDER_" + dep) or d.getVar("PREFERRED_PROVIDER_" + dep) or dep
            else:
                dep = d.getVar("PREFERRED_PROVIDER_" + dep) or dep
        # ignore non-target packages
        if any(dep.endswith(suffix) for suffix in ignored_suffixes):
            continue
        
        resolved_deps.add(dep)

    return list(resolved_deps)

def resolve_dependency_ref(depends, bom_ref_map, alias_map):
    """
    Replace dependency name by his bom-ref attribute
    """
    import re 

    # Direct
    if depends in bom_ref_map:
        return bom_ref_map[depends]["bom-ref"]
    
    # By Alias
    if depends in alias_map:
        real_name = alias_map[depends]
        if real_name in bom_ref_map:
            return bom_ref_map[real_name]["bom-ref"]
    
    # Clean and resolve
    sanitized_name = re.sub(r"[0-9\- .]", "", depends)
    if sanitized_name in bom_ref_map:
        return bom_ref_map[sanitized_name]["bom-ref"]
    
    # Return None if no solution found
    return None

def generate_packages_list(products_names, version):
    """
    Get a list of products and generate CPE and PURL identifiers for each of them.
    """
    import uuid

    packages = []

    # keep only the short version which can be matched against vulnerabilities databases
    version = version.split("+git")[0]

    # some packages have alternative names, so we split CVE_PRODUCT
    # convert to set to avoid duplicates
    for product in set(products_names.split()):
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

def append_to_vex(d, cve, cves, bom_ref):
    """
    Collect CVE status information from within open embedded recipes and append to add to cve dictionary.
    This could be backported, patched or ignored CVEs.
    """
    cve_id, abbrev_status, status, justification = cve

    # Currently, only "Patched" and "Ignored" status are relevant to us.
    # See https://docs.yoctoproject.org/singleindex.html#term-CVE_CHECK_STATUSMAP for possible statuses.
    if abbrev_status == "Patched":
        bb.debug(2, f"Found patch for {cve_id} in {d.getVar('BPN')}")
        vex_state = "resolved"
    elif abbrev_status == "Ignored":
        bb.debug(2, f"Found ignore statement for {cve_id} in {d.getVar('BPN')}")
        vex_state = "not_affected"
    else:
        bb.debug(2, f"Found unknown or irrelevant CVE status {abbrev_status} for {cve_id} in {d.getVar('BPN')}. Skipping...")
        return

    detail_string = ""
    detail_string += f"STATE: {status}\n"
    if justification:
        detail_string += f"JUSTIFICATION: {justification}\n"

    cves.append({
        "id": cve_id,
        # vex documents require a valid source, see https://github.com/DependencyTrack/dependency-track/issues/2977
        # this should always be NVD for yocto CVEs.
        "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
        "analysis": {
            "state": vex_state,
            "detail": detail_string,
        },
        "affects": [{"ref": f"urn:cdx:{d.getVar('CYCLONEDX_SBOM_SERIAL_PLACEHOLDER')}/1#{bom_ref}"}]
    })
    return

python do_deploy_cyclonedx() {
    """
    Select CVE and package information and runtime packages and output them into a single export file.
    """
    from oe.rootfs import image_list_installed_packages
    import uuid
    from datetime import datetime, timezone
    import os

    timestamp = datetime.now(timezone.utc).isoformat()

    # Generate unique serial numbers for sbom and vex document
    sbom_serial_number = str(uuid.uuid4())
    vex_serial_number = str(uuid.uuid4())

    cyclonedx_work_dir_root = d.getVar("CYCLONEDX_WORK_DIR_ROOT")

    # Generate sbom document header
    bb.debug(2, f"Creating empty temporary sbom file with serial number {sbom_serial_number}")
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{sbom_serial_number}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"name": "yocto"}]
        },
        "components": [],
        "dependencies": []
    }

    # Generate vex document header
    bb.debug(2, f"Creating empty temporary vex file with serial number {sbom_serial_number}")
    vex = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{vex_serial_number}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"name": "yocto"}]
        },
        "vulnerabilities": []
    }

    # taken from https://github.com/yoctoproject/poky/blob/fec201518be3c35a9359ec8c37675a33e458b92d/meta/classes/cve-check.bbclass
    # SPDX-License-Identifier: MIT
    # SPDX-FileCopyrightText: Copyright OpenEmbedded Contributors
    # Collect sbom data from runtime packages

    recipes = set()
    if d.getVar('CYCLONEDX_RUNTIME_PACKAGES_ONLY') == "1":
        for pkg in list(image_list_installed_packages(d)):
            pkg_info = os.path.join(d.getVar('PKGDATA_DIR'),
                                    'runtime-reverse', pkg)
            pkg_data = oe.packagedata.read_pkgdatafile(pkg_info)
            recipes.add(pkg_data["PN"])
    else:
        recipes = {pn for pn in os.listdir(cyclonedx_work_dir_root) if os.path.isdir(os.path.join(cyclonedx_work_dir_root, pn))}

    save_pn = d.getVar("PN")

    # Create a bom_ref_map for dependencies sanitarization
    # And an alias_map to retrieve real pkg name
    bom_ref_map = {}
    alias_map = {}

    # first loop to fill the dictionary
    for pkg in recipes:
        # To be able to use the CYCLONEDX_WORK_DIR_PN_LIST variable we have to evaluate
        # it with the different PN names set each time.
        d.setVar("PN", pkg)

        pn_list_filepath = d.getVar("CYCLONEDX_WORK_DIR_PN_LIST")

        if not os.path.exists(pn_list_filepath):
            continue

        pn_list = read_json(pn_list_filepath)
        for pn_pkg in pn_list["pkgs"]:
            bom_ref_map[pn_pkg["name"]]=pn_pkg
            alias_map[d.getVar("PN")]=pn_pkg["name"]

    for pkg in recipes:
        # To be able to use the CYCLONEDX_WORK_DIR_PN_LIST variable we have to evaluate
        # it with the different PN names set each time.
        d.setVar("PN", pkg)

        pn_list_filepath = d.getVar("CYCLONEDX_WORK_DIR_PN_LIST")

        if not os.path.exists(pn_list_filepath):
            continue

        pn_list = read_json(pn_list_filepath)

        for pn_pkg in pn_list["pkgs"]:
            # Avoid multiple pkgs referencing the same cpe
            for sbom_pkg in sbom["components"]:
                if pn_pkg["cpe"] == sbom_pkg["cpe"]:
                    break
            else:
                sbom["components"].append(pn_pkg)
        for pn_cve in pn_list["cves"]:
            pn_cve["affects"][0]["ref"] = pn_cve["affects"][0]["ref"].replace(
                d.getVar('CYCLONEDX_SBOM_SERIAL_PLACEHOLDER'), sbom_serial_number)
            vex["vulnerabilities"].append(pn_cve)

        # Add dependencies
        if deps := pn_list.get("dependencies"):
            pn_list["dependencies"] = []
            
            for dep_entry in deps:
                resolved_depends = []
                
                for depends in dep_entry["dependsOn"]:
                    if resolved_ref := resolve_dependency_ref(depends, bom_ref_map, alias_map):
                        if resolved_ref not in resolved_depends:
                            resolved_depends.append(resolved_ref)
                            
                            # Add component to isolate file
                            if ((depends in alias_map) and (alias_map[depends] in bom_ref_map)):
                                comp = bom_ref_map[alias_map[depends]] 
                                if comp not in pn_list["pkgs"] :
                                    pn_list["pkgs"].append(comp)
                
                updated_entry = {"ref": dep_entry["ref"], "dependsOn": resolved_depends}
                pn_list["dependencies"].append(updated_entry)
                
                if updated_entry not in sbom["dependencies"]:
                    sbom["dependencies"].append(updated_entry)
            
            write_json(pn_list_filepath, pn_list)

    d.setVar("PN", save_pn)

    write_json(d.getVar("CYCLONEDX_EXPORT_SBOM"), sbom)
    write_json(d.getVar("CYCLONEDX_EXPORT_VEX"), vex)
}
do_deploy_cyclonedx[cleandirs] = "${CYCLONEDX_EXPORT_DIR}"

# We use ROOTFS_POSTUNINSTALL_COMMAND to make sure this function runs exactly once
# after the build process has been completed
# see https://docs.yoctoproject.org/ref-manual/variables.html#term-ROOTFS_POSTUNINSTALL_COMMAND
ROOTFS_POSTUNINSTALL_COMMAND =+ "do_deploy_cyclonedx; "
