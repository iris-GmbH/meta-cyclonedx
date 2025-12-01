# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2022 BG Networks, Inc.
# SPDX-FileCopyrightText: Copyright (C) 2024 Savoir-faire Linux Inc. (<www.savoirfairelinux.com>).
# SPDX-FileCopyrightText: Copyright (C) 2024 iris-GmbH infrared & intelligent sensors.
# SPDX-FileCopyrightText: Copyright (C) 2025 balena, inc.

# The product name that the CVE database uses.  Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"

# CycloneDX specification version to generate
# Options: "1.4", "1.6", "1.7"
# Version 1.4: Legacy format for compatibility with older tools
# Version 1.6: Modern format with enhanced features (default)
# Version 1.7: Latest version with advanced cryptography, IP transparency, and citations
CYCLONEDX_SPEC_VERSION ??= "1.6"

# Component scope support
# When enabled, components are marked as "required" (runtime) or "optional" (build-time)
# Set to "0" to disable (e.g., for certain SBOM profiles or tool compatibility)
# Available in both CycloneDX 1.4 and 1.6
CYCLONEDX_ADD_COMPONENT_SCOPES ??= "1"

# Vulnerability analysis timestamps
# When enabled, adds firstIssued and lastUpdated timestamps to vulnerability analysis
# Set to "0" to disable for minimal VEX documents
# Available in CycloneDX 1.6
CYCLONEDX_ADD_VULN_TIMESTAMPS ??= "1"

CYCLONEDX_RUNTIME_PACKAGES_ONLY ??= "1"

# Add component licenses (as specified within the recipe) to the SBOM
CYCLONEDX_ADD_COMPONENT_LICENSES ??= "1"

# Optionally, split simple license expressions (only containing "AND") into multiple licenses.
CYCLONEDX_SPLIT_LICENSE_EXPRESSIONS ??= "1"

# Add license expression details for custom licenses (CycloneDX 1.7)
# When enabled, includes license text for LicenseRef-* identifiers
CYCLONEDX_ADD_LICENSE_DETAILS ??= "1"

# Add citation for SBOM generator (CycloneDX 1.7)
# Tracks data provenance - who created the SBOM
CYCLONEDX_ADD_CITATION ??= "1"

# Set Traffic Light Protocol marking for SBOM distribution (CycloneDX 1.7)
# Options: "CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED", or "" to disable
# See: https://www.cisa.gov/tlp
CYCLONEDX_TLP_MARKING ??= ""

CYCLONEDX_EXPORT_DIR ??= "${DEPLOY_DIR}/cyclonedx-export/${PN}"
CYCLONEDX_EXPORT_DIR ??= "${DEPLOY_DIR}/cyclonedx-export/${IMAGE_BASENAME}"
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

    # Validate CycloneDX specification version
    spec_version = d.getVar("CYCLONEDX_SPEC_VERSION")
    if spec_version not in ["1.4", "1.6", "1.7"]:
        bb.fatal(f"Unsupported CYCLONEDX_SPEC_VERSION: {spec_version}. Supported versions: 1.4, 1.6, 1.7")
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

    # Track duplicate bom-refs that map to the same CPE
    # This prevents self-dependencies when multiple packages share the same CPE
    bom_ref_dedup_map = {}

    # append all defined package names for recipe to pn_list pkgs
    for pkg in generate_packages_list(name, version):
        # Check if we already have a package with this CPE
        existing_pkg = next((c for c in pn_list["pkgs"] if c["cpe"] == pkg["cpe"]), None)
        if existing_pkg:
            # Map this bom-ref to the existing (canonical) bom-ref
            bom_ref_dedup_map[pkg["bom-ref"]] = existing_pkg["bom-ref"]
            continue

        if d.getVar("CYCLONEDX_ADD_COMPONENT_LICENSES") == "1":
            bb.debug(2, f"Resolving licenses for {pkg['name']}")
            licenses = resolve_license_data(d)
            if len(licenses) != 0:
                pkg["licenses"] = licenses
            else:
                bb.warn(f"LICENSE variable not set for package {pn}")

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

    # Store the deduplication map for use during deployment
    pn_list["bom_ref_dedup_map"] = bom_ref_dedup_map

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

def convert_to_spdx_license(d, spdx_license_ids):
    """
    Converts an OE license (expression) (see: https://docs.yoctoproject.org/singleindex.html#term-LICENSE)
    to a valid SPDX license (expression) (for the latter see: https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/)
    """

    oe_license_exp = d.getVar("LICENSE")

    oe_licenses_split = oe_license_exp \
        .replace("(", " ( ") \
        .replace(")", " ) ") \
        .replace("&", " & ") \
        .replace("|", " | ") \
        .split()

    for i in range(len(oe_licenses_split)):
        elem = oe_licenses_split[i]
        if elem in ["(", ")"]:
            continue
        elif elem == "&":
            oe_licenses_split[i] = " AND "
        elif elem == "|":
            oe_licenses_split[i] = " OR "
        else:
            elem = d.getVarFlag("SPDXLICENSEMAP", elem) or elem
            if elem not in spdx_license_ids:
                elem = f"LicenseRef-{elem}"
            oe_licenses_split[i] = elem

    return "".join(oe_licenses_split)

def remove_prefix(text, prefix):
    """
    If the string starts with the prefix string, return string[len(prefix):].
    Otherwise, return a copy of the original string.
    Built-in method only available starting Python 3.9
    """
    if text.startswith(prefix):
        return text[len(prefix):]
    return text

def get_license_text(d, license_name):
    """
    Attempt to read license text from common Yocto locations.
    Returns license text content or None if not found.
    """
    import os

    pn = d.getVar("PN")
    common_lic_dir = d.getVar('COMMON_LICENSE_DIR')

    # Try common license directory first (e.g., /meta/files/common-licenses/)
    if common_lic_dir:
        license_path = os.path.join(common_lic_dir, license_name)
        if os.path.exists(license_path):
            try:
                with open(license_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Limit size to avoid huge files
                    if len(content) > 65535:
                        content = content[:65535] + "\n... [truncated]"
                    bb.debug(2, f"Found license text for {license_name} in common licenses")
                    return content
            except Exception as e:
                bb.debug(2, f"Could not read license file {license_path}: {e}")

    # Try to find from LIC_FILES_CHKSUM
    lic_files = d.getVar('LIC_FILES_CHKSUM') or ""
    for entry in lic_files.split():
        if 'file://' in entry:
            # Extract file path from file://path;md5=...
            file_part = entry.split(';')[0].replace('file://', '')
            if license_name.lower() in file_part.lower() or 'license' in file_part.lower() or 'copying' in file_part.lower():
                s_dir = d.getVar('S')
                if s_dir:
                    license_path = os.path.join(s_dir, file_part)
                    if os.path.exists(license_path):
                        try:
                            with open(license_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                if len(content) > 65535:
                                    content = content[:65535] + "\n... [truncated]"
                                bb.debug(2, f"Found license text for {license_name} in {license_path}")
                                return content
                        except Exception as e:
                            bb.debug(2, f"Could not read license file {license_path}: {e}")

    bb.debug(2, f"No license text found for {license_name}")
    return None

def extract_license_details(d, expression):
    """
    Extract license details including text for custom licenses in expression.
    Returns expressionDetails array for CycloneDX 1.7
    """
    import re
    details = []

    # Find all LicenseRef-* identifiers in the expression
    custom_licenses = re.findall(r'LicenseRef-[\w.-]+', expression)

    for license_ref in set(custom_licenses):
        raw_license = license_ref.replace("LicenseRef-", "")

        # Try to get license text from Yocto locations
        license_text = get_license_text(d, raw_license)

        detail = {
            "licenseIdentifier": license_ref,
        }

        if license_text:
            detail["text"] = {
                "contentType": "text/plain",
                "content": license_text
            }

        details.append(detail)

    return details if details else None

def resolve_license_data(d):
    """
    Resolves a given recipe LICENSE (see: https://docs.yoctoproject.org/singleindex.html#term-LICENSE)
    for use in CycloneDX
    """
    # load spdx license identifiers for the appropriate CycloneDX spec version
    spec_version = d.getVar('CYCLONEDX_SPEC_VERSION') or "1.6"
    layerdir = d.getVar("CYCLONEDX_LAYERDIR")
    pn = d.getVar("PN")
    licenses_file_path = f"{layerdir}/meta/files/spdx-license-list-data/licenses-{spec_version}.json"
    bb.debug(2, f"Loading SPDX licenses from {licenses_file_path}")
    licenses_json = read_json(licenses_file_path)
    spdx_license_ids = [l["licenseId"] for l in licenses_json["licenses"]]
    split_expressions = d.getVar('CYCLONEDX_SPLIT_LICENSE_EXPRESSIONS')

    licenses = convert_to_spdx_license(d, spdx_license_ids)
    add_license_details = d.getVar('CYCLONEDX_ADD_LICENSE_DETAILS')

    license_info = []
    # Check if the license is a complex expression
    if "(" in licenses or ")" in licenses or " OR " in licenses or (split_expressions != "1" and " AND " in licenses):
        bb.debug(2, f"Adding {licenses} as expression.")
        entry = {"expression": licenses}
        if spec_version != "1.4":
            entry["acknowledgement"] = "declared"

        # Add expressionDetails for CycloneDX 1.7 if enabled
        if spec_version == "1.7" and add_license_details == "1":
            details = extract_license_details(d, licenses)
            if details:
                entry["expressionDetails"] = details
                bb.debug(2, f"Added expressionDetails with {len(details)} custom license(s)")

        license_info.append(entry)
        return license_info

    # otherwise this is a single license entry or consists only of "AND" connections
    # which we can split this into multiple license entries (if feature enabled)
    for license in licenses.split(" AND "):
        if license in spdx_license_ids:
            bb.debug(2, f"Adding {license} as known SPDX license.")
            license_info.append({"license": {"id": license}})
        else:
            raw_license = remove_prefix(license, "LicenseRef-")
            bb.debug(2, f"Unknown license {raw_license}. Using raw name.")
            license_info.append({"license": {"name": raw_license}})

        if spec_version != "1.4":
            license_info[-1]["license"]["acknowledgement"] = "declared"

    return license_info

def create_tools_metadata(d):
    """
    Create tools metadata in the format appropriate for the CycloneDX spec version.

    Version 1.4: Array format [{"name": "yocto"}]
    Version 1.6+: Object format {"components": [{"type": "application", "name": "yocto", ...}]}
    """
    import uuid

    spec_version = d.getVar('CYCLONEDX_SPEC_VERSION') or "1.6"

    if spec_version == "1.4":
        # Legacy array format
        return [{"name": "yocto"}]
    else:
        # Modern object format (1.6+)
        return {
            "components": [
                {
                    "type": "application",
                    "name": "yocto",
                    "bom-ref": str(uuid.uuid4())
                }
            ]
        }

def create_citations(d):
    """
    Create citations array for CycloneDX 1.7 to document SBOM provenance.
    Citations track the source and generation methodology.
    """
    citations = []

    # Add citation for meta-cyclonedx layer as the source
    citation = {
        "description": "Generated by meta-cyclonedx layer for Yocto Project"
    }

    # Add layer repository URL if available
    layerdir = d.getVar("CYCLONEDX_LAYERDIR")
    if layerdir:
        citation["url"] = "https://github.com/iris-GmbH/meta-cyclonedx"

    citations.append(citation)

    return citations

def add_metadata_extensions(d, metadata):
    """
    Add optional CycloneDX 1.7+ metadata extensions like citations and TLP marking.
    Modifies metadata dict in place.
    """
    spec_version = d.getVar('CYCLONEDX_SPEC_VERSION') or "1.6"

    if spec_version != "1.7":
        return

    # Add citations if enabled
    add_citation = d.getVar('CYCLONEDX_ADD_CITATION')
    if add_citation == "1":
        citations = create_citations(d)
        if citations:
            metadata["citations"] = citations
            bb.debug(2, "Added citations to SBOM metadata")

    # Add TLP marking if specified
    tlp_marking = d.getVar('CYCLONEDX_TLP_MARKING')
    if tlp_marking and tlp_marking in ["CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"]:
        if "distribution" not in metadata:
            metadata["distribution"] = {}
        metadata["distribution"]["tlp"] = tlp_marking
        bb.debug(2, f"Added TLP marking: {tlp_marking}")

def get_recipe_dependencies(d):
    """
    Return recipe names which depend on the current one.
    """
    pn = d.getVar("PN")
    runtime_deps = (d.getVar("RDEPENDS:" + pn) or "").split()
    build_deps = (d.getVar("DEPENDS") or "").split()
    deps = build_deps + runtime_deps
    ignored_suffixes = set((d.getVar("SPECIAL_PKGSUFFIX") or "").split())
    # Resolves virtual/* dependencies to their preferred providers.
    resolved_deps = set()
    for dep in deps:
        dep = dep.strip()
        if not dep:
            continue
        # If package is virtual, we retrieve his provider
        if dep.startswith("virtual/"):
            dep = d.getVar("PREFERRED_RPROVIDER_" + dep) or d.getVar("PREFERRED_PROVIDER_" + dep) or dep
        # ignore non-target packages
        if any(dep.endswith(suffix) for suffix in ignored_suffixes):
            continue

        resolved_deps.add(dep)
    return list(resolved_deps)

def resolve_dependency_ref(depends, bom_ref_map, alias_map):
    """
    Replace dependency name by his bom-ref attribute
    """

    # Direct
    if depends in bom_ref_map:
        return bom_ref_map[depends]["bom-ref"]

    # By Alias
    if depends in alias_map:
        real_name = alias_map[depends]
        if real_name in bom_ref_map:
            return bom_ref_map[real_name]["bom-ref"]

    # If depends is already a bom-ref
    for comp in bom_ref_map.values():
        if depends == comp["bom-ref"]:
            return depends

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

    # Ensure version is never empty (required by some SBOM profiles)
    if not version or version.strip() == "":
        version = "unknown"

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

def normalize_cve_id(cve_id):
    """
    Normalize CVE ID by removing patch file suffixes.

    Yocto recipes often use multiple patches for the same CVE with suffixes like:
    - CVE-2025-52886-0001.patch
    - CVE-2025-52886-0002.patch

    This function strips the numeric suffix to get the canonical CVE ID.
    """
    import re
    # Match CVE-YYYY-NNNNN format, optionally followed by -NNNN suffix
    match = re.match(r'(CVE-\d{4}-\d+)(?:-\d+)?', cve_id)
    if match:
        return match.group(1)
    return cve_id

def append_to_vex(d, cve, cves, bom_ref):
    """
    Collect CVE status information from within open embedded recipes and append to add to cve dictionary.
    This could be backported, patched or ignored CVEs.
    """
    from datetime import datetime, timezone

    cve_id, abbrev_status, status, justification = cve

    # Normalize CVE ID to remove patch file suffixes (e.g., CVE-2025-52886-0001 -> CVE-2025-52886)
    normalized_cve_id = normalize_cve_id(cve_id)

    # Currently, only "Patched" and "Ignored" status are relevant to us.
    # See https://docs.yoctoproject.org/singleindex.html#term-CVE_CHECK_STATUSMAP for possible statuses.
    if abbrev_status == "Patched":
        bb.debug(2, f"Found patch for {normalized_cve_id} in {d.getVar('BPN')}")
        vex_state = "resolved"
    elif abbrev_status == "Ignored":
        bb.debug(2, f"Found ignore statement for {normalized_cve_id} in {d.getVar('BPN')}")
        vex_state = "not_affected"
    else:
        bb.debug(2, f"Found unknown or irrelevant CVE status {abbrev_status} for {normalized_cve_id} in {d.getVar('BPN')}. Skipping...")
        return

    # Check if this CVE already exists in the list (avoid duplicates from multiple patches)
    for existing_cve in cves:
        if existing_cve["id"] == normalized_cve_id:
            # CVE already recorded, just update the detail to mention this patch too
            if cve_id != normalized_cve_id:  # Only if there was a suffix
                existing_cve["analysis"]["detail"] += f"Additional patch: {cve_id}\n"
            bb.debug(2, f"CVE {normalized_cve_id} already recorded, updated details")
            return

    detail_string = ""
    detail_string += f"STATE: {status}\n"
    if justification:
        detail_string += f"JUSTIFICATION: {justification}\n"
    # Mention original patch filename if it had a suffix
    if cve_id != normalized_cve_id:
        detail_string += f"Patch file: {cve_id}\n"

    # Build analysis object
    analysis = {
        "state": vex_state,
        "detail": detail_string
    }

    # Add timestamps for CycloneDX 1.6+ when enabled
    # This provides better tracking of when vulnerabilities were identified and updated
    spec_version = d.getVar('CYCLONEDX_SPEC_VERSION') or "1.6"
    add_timestamps = d.getVar('CYCLONEDX_ADD_VULN_TIMESTAMPS') == "1"
    if spec_version in ["1.6", "1.7"] and add_timestamps:
        timestamp = datetime.now(timezone.utc).isoformat()
        analysis["firstIssued"] = timestamp
        analysis["lastUpdated"] = timestamp

    cves.append({
        "id": normalized_cve_id,
        # vex documents require a valid source, see https://github.com/DependencyTrack/dependency-track/issues/2977
        # this should always be NVD for yocto CVEs.
        "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{normalized_cve_id}"},
        "analysis": analysis,
        "affects": [{"ref": f"urn:cdx:{d.getVar('CYCLONEDX_SBOM_SERIAL_PLACEHOLDER')}/1#{bom_ref}"}]
    })
    return

python do_deploy_cyclonedx() {
    """
    Select CVE and package information and runtime packages and output them
    into a single export file.
    """
    from oe.rootfs import image_list_installed_packages
    import uuid
    from datetime import datetime, timezone
    import os

    timestamp = datetime.now(timezone.utc).isoformat()

    # Generate unique serial numbers for sbom and vex document
    sbom_serial_number = str(uuid.uuid4())
    vex_serial_number = str(uuid.uuid4())

    # Get configured spec version
    spec_version = d.getVar('CYCLONEDX_SPEC_VERSION') or "1.6"

    cyclonedx_work_dir_root = d.getVar("CYCLONEDX_WORK_DIR_ROOT")

    # Generate sbom document header
    bb.debug(2, f"Creating empty temporary sbom file with serial number {sbom_serial_number}")
    sbom_metadata = {
        "timestamp": timestamp,
        "tools": create_tools_metadata(d)
    }
    add_metadata_extensions(d, sbom_metadata)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": f"urn:uuid:{sbom_serial_number}",
        "version": 1,
        "metadata": sbom_metadata,
        "components": [],
        "dependencies": []
    }

    # Generate vex document header
    bb.debug(2, f"Creating empty temporary vex file with serial number {sbom_serial_number}")
    vex_metadata = {
        "timestamp": timestamp,
        "tools": create_tools_metadata(d)
    }
    add_metadata_extensions(d, vex_metadata)

    vex = {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": f"urn:uuid:{vex_serial_number}",
        "version": 1,
        "metadata": vex_metadata,
        "vulnerabilities": []
    }

    # taken from https://github.com/yoctoproject/poky/blob/fec201518be3c35a9359ec8c37675a33e458b92d/meta/classes/cve-check.bbclass
    # SPDX-License-Identifier: MIT
    # SPDX-FileCopyrightText: Copyright OpenEmbedded Contributors
    # Collect sbom data from runtime packages

    # Determine runtime packages for scope assignment
    runtime_recipes = set()
    for pkg in list(image_list_installed_packages(d)):
        pkg_info = os.path.join(d.getVar('PKGDATA_DIR'),
                                'runtime-reverse', pkg)
        pkg_data = oe.packagedata.read_pkgdatafile(pkg_info)
        runtime_recipes.add(pkg_data["PN"])

    # Determine which recipes to include
    recipes = set()
    if d.getVar('CYCLONEDX_RUNTIME_PACKAGES_ONLY') == "1":
        recipes = runtime_recipes
    else:
        all_available = {pn for pn in os.listdir(cyclonedx_work_dir_root)
                        if os.path.isdir(os.path.join(cyclonedx_work_dir_root, pn))}
        recipes = all_available

    save_pn = d.getVar("PN")

    # Create a bom_ref_map for dependencies sanitarization
    # And an alias_map to retrieve real pkg name
    bom_ref_map = {}
    alias_map = {}
    # Global deduplication map that tracks all duplicate bom-refs across all recipes
    global_bom_ref_dedup_map = {}

    image_recipe_names = set()
    # first loop to fill the dictionary
    for pkg in recipes:
        # To be able to use the CYCLONEDX_WORK_DIR_PN_LIST variable we have to evaluate
        # it with the different PN names set each time.
        d.setVar("PN", pkg)

        pn_list_filepath = d.getVar("CYCLONEDX_WORK_DIR_PN_LIST")

        if not os.path.exists(pn_list_filepath):
            continue

        pn_list = read_json(pn_list_filepath)
        image_recipe_names.add(pkg)
        # Merge recipe-level deduplication map into global map
        if "bom_ref_dedup_map" in pn_list:
            global_bom_ref_dedup_map.update(pn_list["bom_ref_dedup_map"])

        for pn_pkg in pn_list["pkgs"]:
            bom_ref_map[pn_pkg["name"]] = pn_pkg
            # Map recipe name to its main package
            if pn_pkg["name"] == pkg:
                alias_map[pkg] = pkg

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
            if any(sbom_pkg["cpe"] == pn_pkg["cpe"] for sbom_pkg in sbom["components"]):
                continue

            # Add scope field to indicate runtime vs build-time component
            # Can be disabled for certain SBOM profiles or tool compatibility
            if d.getVar('CYCLONEDX_ADD_COMPONENT_SCOPES') == "1":
                pn_pkg["scope"] = "required" if pkg in runtime_recipes else "optional"

            sbom["components"].append(pn_pkg)
        for pn_cve in pn_list["cves"]:
            # Don't replace serial number yet - it will be done after all CVEs are collected
            # This fixes multi-output builds where shared components would get the wrong serial
            vex["vulnerabilities"].append(pn_cve)

        # Add dependencies
    for pkg in recipes:
        d.setVar("PN", pkg)
        pn_list_filepath = d.getVar("CYCLONEDX_WORK_DIR_PN_LIST")

        if not os.path.exists(pn_list_filepath):
            continue

        pn_list = read_json(pn_list_filepath)
        deps = pn_list.get("dependencies")

        if not deps:
            continue

        for dep_entry in deps:
            component_ref = dep_entry["ref"]
            if component_ref in global_bom_ref_dedup_map:
                component_ref = global_bom_ref_dedup_map[component_ref]

            # Skip if component doesn't exist in SBOM
            if not any(comp["bom-ref"] == component_ref for comp in sbom["components"]):
                continue

            resolved_depends = []

            for depends in dep_entry["dependsOn"]:
                if depends not in image_recipe_names:
                    bb.debug(2, f"Skipping dependency {depends} - not in this image")
                    continue

                resolved_ref = resolve_dependency_ref(depends, bom_ref_map, alias_map)
                if not resolved_ref:
                    continue

                if resolved_ref in global_bom_ref_dedup_map:
                    resolved_ref = global_bom_ref_dedup_map[resolved_ref]

                if resolved_ref == component_ref:
                    continue

                # Verify that the component exists in the SBOM
                # If it was filtered out by CPE deduplication, skip this dependency entry
                if not any(comp["bom-ref"] == resolved_ref for comp in sbom["components"]):
                    continue

                if resolved_ref not in resolved_depends:
                    resolved_depends.append(resolved_ref)

            if resolved_depends:
                updated_entry = {"ref": component_ref, "dependsOn": resolved_depends}
                if updated_entry not in sbom["dependencies"]:
                    sbom["dependencies"].append(updated_entry)

    d.setVar("PN", save_pn)

    # Replace SBOM serial placeholder in VEX vulnerabilities
    # This must be done after all vulnerabilities are collected to ensure each image
    # gets its own SBOM serial number in multi-output builds (e.g., rootfs + initramfs)
    for vuln in vex["vulnerabilities"]:
        for affect in vuln.get("affects", []):
            if "ref" in affect:
                affect["ref"] = affect["ref"].replace(
                    d.getVar('CYCLONEDX_SBOM_SERIAL_PLACEHOLDER'), sbom_serial_number)

    write_json(d.getVar("CYCLONEDX_EXPORT_SBOM"), sbom)
    write_json(d.getVar("CYCLONEDX_EXPORT_VEX"), vex)
}
do_deploy_cyclonedx[cleandirs] = "${CYCLONEDX_EXPORT_DIR}"

# We use ROOTFS_POSTUNINSTALL_COMMAND to make sure this function runs exactly once
# after the build process has been completed
# see https://docs.yoctoproject.org/ref-manual/variables.html#term-ROOTFS_POSTUNINSTALL_COMMAND
ROOTFS_POSTUNINSTALL_COMMAND =+ "do_deploy_cyclonedx; "
