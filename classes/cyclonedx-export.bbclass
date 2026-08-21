# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2022 BG Networks, Inc.
# SPDX-FileCopyrightText: Copyright (C) 2024 Savoir-faire Linux Inc. (<www.savoirfairelinux.com>).
# SPDX-FileCopyrightText: Copyright (C) 2024 iris-GmbH infrared & intelligent sensors.
# SPDX-FileCopyrightText: Copyright (C) 2025 balena, inc.

# The product name that the CVE database uses.  Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"

# Defines SBOM_CVE_CHECK_DEPLOY_DB_DIR, used by the kernel CVE filtering below
# to find the cvelist database deployed by sbom-cve-check-update-cvelist-native.
require conf/sbom-cve-check-config.inc

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

# State to assign to unpatched vulnerabilities.
# Can be empty to omit the state field.
CYCLONEDX_UNPATCHED_VULNS_STATE ??= "in_triage"

# Add "not_affected" VEX entries for kernel CVEs whose affected files were
# never compiled (based on the actual compiled sources, read from
# debugsources info produced by do_package).
# Only applies to whichever recipe provides virtual/kernel.
CYCLONEDX_VEX_ADD_KERNEL_CVE ??= "0"

# Keep the kernel CVE database fresh instead of pinned to the recipe's
# default SRCREV. Also drop the recipe's own "tag=" pin from SRC_URI (as
# oe-core's own sbom-cve-check fragment does): with AUTOREV in effect,
# leaving the fixed tag= in place makes the git fetcher reject the AUTOREV
# revision for not matching what that tag resolves to.
SRCREV:pn-sbom-cve-check-update-cvelist-native = "${AUTOREV}"
SRC_URI:pn-sbom-cve-check-update-cvelist-native = "git://github.com/CVEProject/cvelistV5.git;branch=main;protocol=https;destsuffix="

CYCLONEDX_RUNTIME_PACKAGES_ONLY ??= "1"

# Version string for metadata.component in the CycloneDX SBOM.
CYCLONEDX_IMAGE_VERSION ??= "${DISTRO_VERSION}${IMAGE_VERSION_SUFFIX}"

# Space-separated list of recipe names to include in the SBOM regardless of
# whether they produce rootfs packages. Use this for components that are
# embedded directly into the image (e.g. OP-TEE inside a fitImage).
CYCLONEDX_EXTRA_RUNTIME_RECIPES ??= ""

# Space-separated list of CycloneDX documents produced by the recipe itself, for
# language ecosystems that resolve their own dependency tree (cargo, npm, go).
# Their components and dependency edges are merged into the image BOM verbatim.
CYCLONEDX_EXTRA_BOM_FILES ??= ""

# Whether to fail the build if a specified CycloneDX document does not exists or
# cannot be parsed. Set to "0" to emit a warning instead.
CYCLONEDX_EXTRA_BOM_FILES_FAIL_ON_BROKEN_BOM_FILES ??= "1"

# Space-separated list of image recipe names whose completed SBOMs are merged into this image's SBOM+VEX.
CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES ??= ""

# Add component licenses (as specified within the recipe) to the SBOM
CYCLONEDX_ADD_COMPONENT_LICENSES ??= "1"

# Space-separated list of "name=value" pairs to attach to this recipe's
# components as a CycloneDX properties array (e.g. downstream/vendor tagging
# such as `seco:modified=true`). Empty by default (no properties added).
# NOTE: this must be a plain string value, not a bitbake variable flag —
# flag names cannot contain ":" (see bitbake's ConfHandler flag regex), so
# CYCLONEDX_COMPONENT_PROPERTIES[foo:bar] = "..." is invalid syntax and will
# fail to parse.
CYCLONEDX_COMPONENT_PROPERTIES ??= ""

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

CYCLONEDX_TMP_EXPORT_DIR = "${WORKDIR}/cyclonedx-export"
CYCLONEDX_EXPORT_DIR ??= "${DEPLOY_DIR_IMAGE}"
# Try to set meaningful default filenames for both image and non-image recipes
CYCLONEDX_EXPORT_BASENAME ?= "${@d.getVar('IMAGE_NAME') or d.getVar('IMAGE_BASENAME') or d.getVar('PN')}.cyclonedx"
CYCLONEDX_EXPORT_SBOM ??= "${CYCLONEDX_EXPORT_BASENAME}.bom.json"
CYCLONEDX_EXPORT_VEX ??= "${CYCLONEDX_EXPORT_BASENAME}.vex.json"
# Create symlinks for image recipes similar to the image files by default
IMAGE_LINK_NAME ??= ""
CYCLONEDX_EXPORT_SBOM_LINK ??= "${@'${IMAGE_LINK_NAME}.cyclonedx.bom.json' if d.getVar('IMAGE_LINK_NAME') else ''}"
CYCLONEDX_EXPORT_VEX_LINK ??= "${@'${IMAGE_LINK_NAME}.cyclonedx.vex.json' if d.getVar('IMAGE_LINK_NAME') else ''}"
CYCLONEDX_PNDATA_WORKDIR = "${WORKDIR}/cyclonedx"
CYCLONEDX_PNDATA = "${TMPDIR}/cyclonedx/pn"
CYCLONEDX_BUILDTIME_DIR = "${TMPDIR}/cyclonedx/buildtime"

# We need to add the sbom serial number to the list of vulnerabilites for each recipe but
# don't know it until after we generate the sbom export header file
CYCLONEDX_SBOM_SERIAL_PLACEHOLDER = "<SBOM_SERIAL>"

python () {
    from oe.cve_check import extend_cve_status

    # resolve CVE_CHECK_IGNORE and CVE_STATUS_GROUPS
    extend_cve_status(d)

    # Validate CycloneDX specification version
    spec_version = d.getVar("CYCLONEDX_SPEC_VERSION")
    if spec_version not in ["1.4", "1.6", "1.7"]:
        bb.fatal(f"Unsupported CYCLONEDX_SPEC_VERSION: {spec_version}. Supported versions: 1.4, 1.6, 1.7")

    if d.getVar("CYCLONEDX_INCLUDE_UNPATCHED_VULNS") == "1":
        bb.warn(f"meta-cyclonedx: Option CYCLONEDX_INCLUDE_UNPATCHED_VULNS has been removed post-Wrynose")
}

python () {
    if d.getVar('CYCLONEDX_VEX_ADD_KERNEL_CVE') != '1':
        return
    if d.getVar('PN') != d.getVar('PREFERRED_PROVIDER_virtual/kernel'):
        return
    d.appendVarFlag('do_populate_cyclonedx', 'depends',
                     ' sbom-cve-check-update-cvelist-native:do_patch')
}

# Clean out buildtime dir to prepare for creating complete list of build-time package information
python clean_buildtime_dir() {
    if bb.utils.to_boolean(d.getVar("CYCLONEDX_RUNTIME_PACKAGES_ONLY")):
        return
    cyclonedx_buildtime_dir = d.getVar('CYCLONEDX_BUILDTIME_DIR')
    bb.debug(1, f"Cleaning cyclonedx buildtime dir {cyclonedx_buildtime_dir}")
    if os.path.exists(cyclonedx_buildtime_dir):
        import shutil
        shutil.rmtree(cyclonedx_buildtime_dir)
    bb.utils.mkdirhier(cyclonedx_buildtime_dir)
}
addhandler clean_buildtime_dir
clean_buildtime_dir[eventmask] = "bb.event.BuildStarted"

python do_populate_cyclonedx() {
    """
    Collect package information and CVE data from all packages built for the target architecture.
    """
    from oe.cve_check import get_patched_cves
    from pathlib import Path

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
    for pkg in generate_packages_list(d, name, version):
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

        custom_properties = get_custom_properties(d)
        if custom_properties:
            pkg["properties"] = custom_properties

        pn_list["pkgs"].append(pkg)
        bom_ref = pkg["bom-ref"]

        # append any CVEs either patched or taken from CVE_STATUS
        patched_cves = get_patched_cves(d)
        for cve_id, cve_info in patched_cves.items():
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

    # Fold in CycloneDX documents produced by the recipe itself (cargo, npm, go,
    # ...). They are stored aside from "pkgs"/"dependencies" because they are
    # already fully resolved and must bypass the CPE deduplication and the
    # recipe-name dependency remapping that export_cyclonedx() applies to
    # Yocto-derived components.
    extra_components = []
    extra_dependencies = []
    extra_roots = []
    for bom_path in (d.getVar("CYCLONEDX_EXTRA_BOM_FILES") or "").split():
        if not os.path.exists(bom_path):
            if d.getVar("CYCLONEDX_EXTRA_BOM_FILES_FAIL_ON_BROKEN_BOM_FILES") == "0":
                bb.warn(f"CYCLONEDX_EXTRA_BOM_FILES: {pn}: no such file, skipping: {bom_path}")
                continue
            else:
                bb.fatal(f"CYCLONEDX_EXTRA_BOM_FILES: {pn}: no such file: {bom_path}")
        try:
            extra_bom = read_json(bom_path)
        except Exception as e:
            if d.getVar("CYCLONEDX_EXTRA_BOM_FILES_FAIL_ON_BROKEN_BOM_FILES") == "0":
                bb.warn(f"CYCLONEDX_EXTRA_BOM_FILES: {pn}: cannot parse {bom_path}, skipping: {e}")
                continue
            else:
                bb.fatal(f"CYCLONEDX_EXTRA_BOM_FILES: {pn}: cannot parse {bom_path}: {e}")
        components = extra_bom.get("components") or []
        # The document's own root -- metadata.component, i.e. the module the
        # recipe builds -- is by convention not repeated in "components", yet
        # the dependency edges reference it. Carry it over explicitly, or the
        # merged tree hangs off a bom-ref that resolves to nothing, and remember
        # it so export_cyclonedx() can attach the tree to the recipe.
        root = (extra_bom.get("metadata") or {}).get("component") or {}
        if root.get("bom-ref"):
            components = components + [root]
            extra_roots.append(root["bom-ref"])
        extra_components.extend(components)
        extra_dependencies.extend(extra_bom.get("dependencies") or [])
        bb.debug(1, f"CYCLONEDX_EXTRA_BOM_FILES: {pn}: merged {len(components)} "
                    f"components from {bom_path}")
    if extra_components:
        pn_list["extra_components"] = extra_components
    if extra_dependencies:
        pn_list["extra_dependencies"] = extra_dependencies
    if extra_roots:
        pn_list["extra_roots"] = extra_roots

    # Add "not_affected" VEX entries for kernel CVEs whose affected files were
    # never compiled, based on the sources actually compiled for this kernel
    # (only applies to whichever recipe provides virtual/kernel).
    if (d.getVar('CYCLONEDX_VEX_ADD_KERNEL_CVE') == '1'
            and pn == d.getVar('PREFERRED_PROVIDER_virtual/kernel')):
        # NOTE: "os" is intentionally not imported here. This function relies
        # on the "os" bitbake injects globally without importing it itself
        # (see the os.path.join() call above); shadowing it with a local
        # import would make Python treat "os" as local to the whole function
        # and break that earlier call with an UnboundLocalError.
        import importlib.util
        import oe.spdx_common

        # Reuse oe-core's own CVE-vs-compiled-files matching logic instead
        # of duplicating its CPE/version-range parsing.
        script = os.path.join(d.getVar('COREBASE'), 'scripts', 'contrib',
                               'improve_kernel_cve_report.py')
        spec = importlib.util.spec_from_file_location('improve_kernel_cve_report', script)
        ikcr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ikcr)

        # get_compiled_sources() returns kernel paths prefixed with "${BP}/"
        # (see save_debugsources_info() in oe/package.py); strip that first
        # path component to match the plain kernel-relative paths used by
        # CVE records' "programFiles" -- same normalization
        # improve_kernel_cve_report.py itself applies in
        # read_spdx3()/read_debugsources().
        compiled_files_raw, _ = oe.spdx_common.get_compiled_sources(d)
        compiled_files = {src[src.find('/') + 1:] for src in compiled_files_raw}
        datadir = d.expand('${SBOM_CVE_CHECK_DEPLOY_DB_DIR}/cvelist')
        # Same version normalization used above for this same recipe's SBOM
        # component.
        pv = ikcr.Version(version.split('+git')[0])

        kernel_cves = ikcr.get_kernel_cves(datadir, compiled_files, pv)

        existing_ids = {c['id'] for c in cves}
        bom_refs = [pkg['bom-ref'] for pkg in pn_list['pkgs']]
        placeholder = d.getVar('CYCLONEDX_SBOM_SERIAL_PLACEHOLDER')

        added = 0
        for cve_id, entry in kernel_cves.items():
            if entry.get('status') != 'Ignored' or entry.get('detail') != 'not-applicable-config':
                continue
            if cve_id in existing_ids:
                continue
            cves.append({
                'id': cve_id,
                'source': {'name': 'NVD', 'url': f'https://nvd.nist.gov/vuln/detail/{cve_id}'},
                'analysis': {
                    'state': 'not_affected',
                    'justification': 'code_not_present',
                    'detail': entry.get('description', ''),
                },
                'affects': [{'ref': f"urn:cdx:{placeholder}/1#{ref}"} for ref in bom_refs],
            })
            added += 1
        bb.note(f"cyclonedx-export: added {added} not_affected kernel CVE entries")


    # write partial sbom to the recipes work folder
    write_json(os.path.join(d.getVar("CYCLONEDX_PNDATA_WORKDIR"), f"{pn}.json"), pn_list)

    if not bb.utils.to_boolean(d.getVar("CYCLONEDX_RUNTIME_PACKAGES_ONLY")):
        Path(os.path.join(d.getVar("CYCLONEDX_BUILDTIME_DIR"), pn)).touch()
}

addtask do_populate_cyclonedx before do_build after do_package do_packagedata
do_populate_cyclonedx[cleandirs] = "${CYCLONEDX_PNDATA_WORKDIR}"
do_populate_cyclonedx[vardeps] += "CVE_STATUS"
SSTATETASKS += "do_populate_cyclonedx"
do_populate_cyclonedx[sstate-inputdirs] = "${CYCLONEDX_PNDATA_WORKDIR}"
do_populate_cyclonedx[sstate-outputdirs] = "${CYCLONEDX_PNDATA}/${SSTATE_PKGARCH}"
do_populate_cyclonedx[vardeps] += "CYCLONEDX_PNDATA"
do_populate_cyclonedx[vardeps] += "CYCLONEDX_COMPONENT_PROPERTIES"
do_populate_cyclonedx[vardeps] += "CYCLONEDX_EXTRA_BOM_FILES"
do_populate_cyclonedx[vardeps] += "CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES"

python do_populate_cyclonedx_setscene() {
    sstate_setscene(d)
}
addtask do_populate_cyclonedx_setscene

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

def get_custom_properties(d):
    """
    Parse CYCLONEDX_COMPONENT_PROPERTIES ("name=value" entries, space separated)
    into a CycloneDX properties array: [{"name": ..., "value": ...}, ...].

    Malformed entries (missing "=") are skipped with a warning rather than
    failing the build, since a typo here shouldn't break SBOM generation.
    """
    properties = []
    for entry in (d.getVar("CYCLONEDX_COMPONENT_PROPERTIES") or "").split():
        name, sep, value = entry.partition("=")
        if not sep:
            bb.warn(f"Ignoring malformed CYCLONEDX_COMPONENT_PROPERTIES entry (expected name=value): {entry}")
            continue
        properties.append({"name": name, "value": value})
    return properties

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

def generate_packages_list(d, products_names, version):
    """
    Get a list of products and generate CPE and PURL identifiers for each of them.
    """
    import uuid
    from oe.purl import get_base_purl

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

        spdx_purls = (d.getVar("SPDX_PACKAGE_URLS") or "").split()
        purl = spdx_purls[0] if spdx_purls else get_base_purl(d)

        pkg = {
            "name": product,
            "version": version,
            "type": "library",
            "cpe": 'cpe:2.3:*:{}:{}:{}:*:*:*:*:*:*:*'.format(vendor or "*", product, version),
            "purl": purl,
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
            # record additional bom reference if unique
            if not any(existing_bom_ref["ref"].endswith(bom_ref)
                    for existing_bom_ref in existing_cve["affects"]):
                existing_cve["affects"].append({"ref": f"urn:cdx:{d.getVar('CYCLONEDX_SBOM_SERIAL_PLACEHOLDER')}/1#{bom_ref}"})
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
        "detail": detail_string
    }
    if vex_state:
        analysis["state"] = vex_state

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

def list_runtime_recipes(d):
    depends = (d.getVar("CYCLONEDX_EXPORT_DEPENDS") or "").split()
    if depends:
        return list_runtime_recipes_from_depends(d, depends)
    else:
        return list_runtime_recipes_from_packages(d)

def list_runtime_recipes_from_packages(d):
    from oe.rootfs import image_list_installed_packages
    runtime_recipes = set()
    for pkg in list(image_list_installed_packages(d)):
        pkg_info = os.path.join(d.getVar('PKGDATA_DIR'),
                                'runtime-reverse', pkg)
        pkg_data = oe.packagedata.read_pkgdatafile(pkg_info)
        runtime_recipes.add(pkg_data["PN"])
    return runtime_recipes

def list_image_install_recipes(d):
    """
    Return recipe names for packages explicitly requested for the image.

    PACKAGE_INSTALL is the authoritative list handed to the package manager and
    normally expands IMAGE_INSTALL, but initramfs and other minimal images set it
    directly and leave IMAGE_INSTALL empty, so both are considered.
    """
    image_install = (d.expand(d.getVar("PACKAGE_INSTALL") or "").split()
                     + d.expand(d.getVar("IMAGE_INSTALL") or "").split())
    recipes = set()

    def resolve_and_record(pkg_token):
        recipe = _resolve_runtime_token_to_recipe(d, pkg_token)
        if recipe:
            recipes.add(recipe)
        return recipe

    seen_tokens = set()
    for token in image_install:
        if not token or token in seen_tokens:
            continue
        seen_tokens.add(token)

        root_recipe = resolve_and_record(token)
        if not root_recipe:
            bb.debug(2, f"Could not map requested package '{token}' to a recipe token")
            continue

        # If the request is a packagegroup, treat packages brought in by
        # that packagegroup as direct image-install components too.
        if root_recipe.startswith("packagegroup-"):
            queue = [token]
            seen_pkg_tokens = set()

            while queue:
                current_pkg_token = queue.pop(0)
                if current_pkg_token in seen_pkg_tokens:
                    continue
                seen_pkg_tokens.add(current_pkg_token)

                for dep_pkg in _read_runtime_package_rdepends(d, current_pkg_token):
                    dep_recipe = resolve_and_record(dep_pkg)
                    if dep_recipe and dep_recipe.startswith("packagegroup-") and dep_pkg not in seen_pkg_tokens:
                        queue.append(dep_pkg)

    return recipes

def _resolve_runtime_token_to_recipe(d, token):
    """
    Resolve a package/runtime token (or virtual/* token) to recipe PN.
    """
    pkg_info = os.path.join(d.getVar('PKGDATA_DIR'), 'runtime-reverse', token)
    if os.path.exists(pkg_info):
        pkg_data = oe.packagedata.read_pkgdatafile(pkg_info)
        return pkg_data.get("PN")

    if token.startswith("virtual/"):
        return d.getVar("PREFERRED_RPROVIDER_" + token) or d.getVar("PREFERRED_PROVIDER_" + token)

    return None

def _read_runtime_package_rdepends(d, pkg):
    """
    Read runtime dependencies of a package token from pkgdata/runtime.
    """
    pkg_runtime_info = os.path.join(d.getVar('PKGDATA_DIR'), 'runtime', pkg)
    if not os.path.exists(pkg_runtime_info):
        return []

    pkg_data = oe.packagedata.read_pkgdatafile(pkg_runtime_info)
    # pkgdata stores package-scoped dependency keys (e.g. RDEPENDS:busybox).
    # Fall back to plain RDEPENDS for compatibility with possible format changes.
    raw_rdepends = pkg_data.get(f"RDEPENDS:{pkg}") or pkg_data.get("RDEPENDS") or ""

    # pkgdata may include version constraints and alternation markers.
    # Keep the plain dependency tokens only.
    deps = []
    for dep in raw_rdepends.replace("|", " ").split():
        if dep in ["(", ")", "=", ">=", "<=", ">", "<", "|"]:
            continue
        dep = dep.split("(", 1)[0].strip()
        if dep:
            deps.append(dep)
    return deps

def list_runtime_recipes_from_depends(d, depends):
    runtime_recipes = set()
    ignored_suffixes = d.getVar("SPECIAL_PKGSUFFIX", "").split()
    def runtime_recipe(dependency):
        for ignored_suffix in ignored_suffixes:
            if dependency.endswith(ignored_suffix):
                return None
        return d.getVar(f"PREFERRED_PROVIDER_{dependency}") or dependency
    for dependency in depends:
        recipe = runtime_recipe(dependency)
        if recipe:
            runtime_recipes.add(recipe)
    return runtime_recipes

def highest_priority_scope(*scopes):
    """
    Return the most significant of the given CycloneDX scopes, ordered
    required > optional > excluded. Unknown or missing values are ignored,
    and None is returned when no scope is known.
    """
    priority = ["required", "optional", "excluded"]
    known = [scope for scope in scopes if scope in priority]
    if not known:
        return None
    return min(known, key=priority.index)

def resolve_extra_image_sbom_paths(d):
    # Paths follow IMAGE_LINK_NAME convention; all images share CYCLONEDX_EXPORT_DIR = DEPLOY_DIR_IMAGE.
    export_dir = d.getVar("CYCLONEDX_EXPORT_DIR")
    machine = d.getVar("MACHINE")
    current_pn = d.getVar("PN")
    results = []
    for img_name in (d.getVar("CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES") or "").split():
        if img_name == current_pn:
            bb.warn(f"CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES: skipping self-reference '{img_name}'")
            continue
        link_basename = f"{img_name}-{machine}"
        results.append((
            img_name,
            os.path.join(export_dir, f"{link_basename}.cyclonedx.bom.json"),
            os.path.join(export_dir, f"{link_basename}.cyclonedx.vex.json"),
        ))
    return results

def export_cyclonedx(d):
    """
    Select CVE and package information and runtime packages and output them
    into a single export file.
    """
    import uuid
    from datetime import datetime, timezone
    import os
    from pathlib import Path
    import copy

    timestamp = datetime.now(timezone.utc).isoformat()

    image_name = d.getVar("IMAGE_BASENAME") or d.getVar("PN") or "image"
    image_version = d.getVar("CYCLONEDX_IMAGE_VERSION") or "unknown"
    metadata_component_ref = str(uuid.uuid4())

    # Generate unique serial numbers for sbom and vex document
    sbom_serial_number = str(uuid.uuid4())
    vex_serial_number = str(uuid.uuid4())

    # Get configured spec version
    spec_version = d.getVar('CYCLONEDX_SPEC_VERSION') or "1.6"

    cyclonedx_buildtime_dir = d.getVar("CYCLONEDX_BUILDTIME_DIR")

    # Generate sbom document header
    bb.debug(2, f"Creating empty temporary sbom file with serial number {sbom_serial_number}")
    sbom_metadata = {
        "timestamp": timestamp,
        "tools": create_tools_metadata(d)
    }
    add_metadata_extensions(d, sbom_metadata)
    sbom_metadata["component"] = {
        "type": "firmware",
        "name": image_name,
        "version": image_version,
        "bom-ref": metadata_component_ref
    }

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": f"urn:uuid:{sbom_serial_number}",
        "version": 1,
        "metadata": sbom_metadata,
        "components": [],
        "dependencies": []
    }

    # Only supported from CycloneDX 1.5.
    if spec_version != "1.4":
        sbom["metadata"]["lifecycles"] = [
            {"phase": "build"}
        ]

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
    runtime_recipes = list_runtime_recipes(d)

    # Determine recipes explicitly requested by the image author.
    image_install_recipes = list_image_install_recipes(d)

    # Determine which recipes to include
    recipes = set()
    if d.getVar('CYCLONEDX_RUNTIME_PACKAGES_ONLY') == "1":
        recipes = runtime_recipes
    else:
        all_available = {pn for pn in os.listdir(cyclonedx_buildtime_dir)
                        if os.path.exists(os.path.join(cyclonedx_buildtime_dir, pn))}
        recipes = all_available.union(runtime_recipes)

    # Always include explicitly requested recipes (e.g. optee-os embedded in fitImage)
    # Resolve virtual/* entries via PREFERRED_PROVIDER_*
    extra_recipes = set()

    for recipe in (d.getVar('CYCLONEDX_EXTRA_RUNTIME_RECIPES') or '').split():
        if recipe.startswith("virtual/"):
            resolved = (d.getVar("PREFERRED_RPROVIDER_" + recipe)
                        or d.getVar("PREFERRED_PROVIDER_" + recipe))
            if not resolved:
                bb.warn(f"CYCLONEDX_EXTRA_RUNTIME_RECIPES: no provider for {recipe}, skipping")
                continue
            bb.debug(2, f"CYCLONEDX_EXTRA_RUNTIME_RECIPES: resolved {recipe} -> {resolved}")
            recipe = resolved
        extra_recipes.add(recipe)
    recipes = recipes.union(extra_recipes)

    # Treat extra runtime recipes as direct image-install intent.
    image_install_recipes = image_install_recipes.union(extra_recipes)

    # Track direct-install components without persisting debug properties in output.
    directly_installed_component_refs = set()

    # Create a bom_ref_map for dependencies sanitarization
    # And an alias_map to retrieve real pkg name
    bom_ref_map = {}
    alias_map = {}
    # Global deduplication map that tracks all duplicate bom-refs across all recipes
    global_bom_ref_dedup_map = {}

    image_recipe_names = set()
    pn_lists = {}
    pkgarchs = d.getVar("SSTATE_ARCHS").split()
    pkgarchs.reverse()
    # first loop to fill the dictionary
    for pkg in recipes:
        for pkgarch in pkgarchs:
            pn_list_filepath = os.path.join(d.getVar("CYCLONEDX_PNDATA"),
                                            pkgarch, f"{pkg}.json")
            if os.path.exists(pn_list_filepath):
                break
        if not os.path.exists(pn_list_filepath):
            bb.error(f"CycloneDX PN file not found: {pkg}.json")
            continue
        pn_lists[pkg] = read_json(pn_list_filepath)
        pn_list = copy.deepcopy(pn_lists[pkg])

        image_recipe_names.add(pkg)
        # Merge recipe-level deduplication map into global map
        if "bom_ref_dedup_map" in pn_list:
            global_bom_ref_dedup_map.update(pn_list["bom_ref_dedup_map"])

        for pn_pkg in pn_list["pkgs"]:
            bom_ref_map[pn_pkg["name"]] = pn_pkg
            # Map recipe name to its primary component name.
            # Handles cases where recipe name differs from CVE_PRODUCT/BPN,
            # e.g. recipe "sqlite3" produces component "sqlite".
            # Only map once, to the first/primary package.
            if pkg not in alias_map:
                alias_map[pkg] = pn_pkg["name"]

    for pkg in recipes:
        pn_list = copy.deepcopy(pn_lists[pkg])

        for pn_pkg in pn_list["pkgs"]:
            # Avoid multiple pkgs referencing the same cpe
            existing_component = next((sbom_pkg for sbom_pkg in sbom["components"]
                                       if sbom_pkg["cpe"] == pn_pkg["cpe"]), None)
            if existing_component:
                if pkg in image_install_recipes:
                    existing_ref = existing_component.get("bom-ref")
                    if existing_ref:
                        directly_installed_component_refs.add(existing_ref)
                continue

            # Add scope field to indicate runtime vs build-time component
            # Can be disabled for certain SBOM profiles or tool compatibility
            if d.getVar('CYCLONEDX_ADD_COMPONENT_SCOPES') == "1":
                pn_pkg["scope"] = "required" if pkg in runtime_recipes or pkg in extra_recipes else "excluded"

            if pkg in image_install_recipes:
                directly_installed_component_refs.add(pn_pkg["bom-ref"])

            sbom["components"].append(pn_pkg)
        for pn_cve in pn_list["cves"]:
            # Don't replace serial number yet - it will be done after all CVEs are collected
            # This fixes multi-output builds where shared components would get the wrong serial
            vex["vulnerabilities"].append(pn_cve)

    # Sort components by name for a stable, human-readable order.
    # "recipes" is a set, so insertion order above is non-deterministic across builds.
    sbom["components"].sort(key=lambda c: (c["name"], c["version"]))

    # Add dependencies
    for pkg in recipes:
        pn_list = copy.deepcopy(pn_lists[pkg])

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

    # Fold in pre-resolved CycloneDX fragments contributed by recipes.
    #
    # Language ecosystems that resolve their own dependency trees (cargo, npm,
    # go, ...) are invisible to Yocto's package model: the image BOM lists the
    # recipe that builds the binary, but not the hundreds of modules linked into
    # it. Such a recipe can generate a CycloneDX document at build time and
    # attach it to its own pn fragment under "extra_components" /
    # "extra_dependencies", and it is merged into the image BOM here.
    #
    # These entries already carry their own bom-refs, purls and dependency
    # edges, so they are appended verbatim: the CPE deduplication and the
    # recipe-name dependency remapping above apply to components derived from
    # Yocto packages and would corrupt an externally resolved tree.
    extra_seen_refs = {c["bom-ref"] for c in sbom["components"] if c.get("bom-ref")}
    for pkg in recipes:
        pn_list = pn_lists.get(pkg)
        if not pn_list:
            continue
        for component in pn_list.get("extra_components", []):
            ref = component.get("bom-ref") or component.get("purl")
            if ref:
                if ref in extra_seen_refs:
                    continue
                extra_seen_refs.add(ref)
            sbom["components"].append(component)
        for dep_entry in pn_list.get("extra_dependencies", []):
            if dep_entry not in sbom["dependencies"]:
                sbom["dependencies"].append(dep_entry)

        # Attach each contributed tree to the recipe that produced it, so the
        # modules are attributable to the binary they are linked into instead of
        # floating unreferenced at the top level of the BOM.
        extra_roots = pn_list.get("extra_roots") or []
        if not extra_roots:
            continue
        owner_name = alias_map.get(pkg)
        owner = bom_ref_map.get(owner_name) if owner_name else None
        owner_ref = owner.get("bom-ref") if owner else None
        if owner_ref in global_bom_ref_dedup_map:
            owner_ref = global_bom_ref_dedup_map[owner_ref]
        if not owner_ref or not any(c.get("bom-ref") == owner_ref for c in sbom["components"]):
            bb.debug(1, f"CYCLONEDX_EXTRA_BOM_FILES: {pkg}: no component to attach "
                        f"{len(extra_roots)} contributed tree(s) to")
            continue
        owner_entry = next((x for x in sbom["dependencies"] if x["ref"] == owner_ref), None)
        if owner_entry is None:
            owner_entry = {"ref": owner_ref, "dependsOn": []}
            sbom["dependencies"].append(owner_entry)
        for root_ref in extra_roots:
            if root_ref in extra_seen_refs and root_ref not in owner_entry["dependsOn"]:
                owner_entry["dependsOn"].append(root_ref)

    # Fold in complete SBOMs from other images listed in CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES.
    # Components shared by CPE are deduplicated (parent wins); unique components are added with scope "required".
    extra_seen_image_refs = {c["bom-ref"] for c in sbom["components"] if c.get("bom-ref")}
    for img_name, img_sbom_path, img_vex_path in resolve_extra_image_sbom_paths(d):
        if not os.path.exists(img_sbom_path):
            bb.warn(f"CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES: SBOM not found for {img_name}: {img_sbom_path}")
            continue
        try:
            img_sbom_data = read_json(img_sbom_path)
        except Exception as e:
            bb.warn(f"CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES: cannot parse SBOM for {img_name}: {e}")
            continue

        img_spec = img_sbom_data.get("specVersion")
        if img_spec and img_spec != spec_version:
            bb.warn(f"CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES: {img_name} specVersion {img_spec} "
                    f"differs from parent {spec_version}; merging anyway")

        # The UUID portion of the included SBOM's serialNumber appears verbatim in its VEX affects refs.
        included_serial = remove_prefix(img_sbom_data.get("serialNumber") or "", "urn:uuid:")

        # Map included bom-refs to parent bom-refs for components that share the same CPE.
        included_bom_ref_remap = {}
        for inc_comp in img_sbom_data.get("components") or []:
            inc_cpe = inc_comp.get("cpe")
            inc_ref = inc_comp.get("bom-ref")
            if not inc_ref or not inc_cpe:
                continue
            existing = next(
                (c for c in sbom["components"] if c.get("cpe") == inc_cpe), None
            )
            if existing:
                included_bom_ref_remap[inc_ref] = existing["bom-ref"]
                if d.getVar("CYCLONEDX_ADD_COMPONENT_SCOPES") == "1":
                    merged_scope = highest_priority_scope(existing.get("scope"), inc_comp.get("scope"))
                    if merged_scope:
                        existing["scope"] = merged_scope

        # Add components unique to the included image (no CPE match in the parent SBOM).
        for inc_comp in img_sbom_data.get("components") or []:
            inc_ref = inc_comp.get("bom-ref")
            if inc_ref and inc_ref in included_bom_ref_remap:
                continue
            if inc_ref and inc_ref in extra_seen_image_refs:
                continue
            if d.getVar("CYCLONEDX_ADD_COMPONENT_SCOPES") == "1" and "scope" not in inc_comp:
                inc_comp = dict(inc_comp)
                inc_comp["scope"] = "required"
            sbom["components"].append(inc_comp)
            if inc_ref:
                extra_seen_image_refs.add(inc_ref)

        # Represent the included image itself as a firmware component in the parent SBOM.
        inc_metadata_comp = (img_sbom_data.get("metadata") or {}).get("component") or {}
        img_firmware_ref = str(uuid.uuid4())
        img_firmware_comp = {
            "type": "firmware",
            "name": img_name,
            "version": inc_metadata_comp.get("version") or "unknown",
            "bom-ref": img_firmware_ref,
        }
        if d.getVar("CYCLONEDX_ADD_COMPONENT_SCOPES") == "1":
            img_firmware_comp["scope"] = "required"
        sbom["components"].append(img_firmware_comp)
        extra_seen_image_refs.add(img_firmware_ref)
        # The embedded image is a direct child of the parent image in the dependency tree.
        directly_installed_component_refs.add(img_firmware_ref)

        inc_metadata_ref = inc_metadata_comp.get("bom-ref")
        if inc_metadata_ref:
            included_bom_ref_remap[inc_metadata_ref] = img_firmware_ref

        def remap_ref(ref, _remap=included_bom_ref_remap):
            return _remap.get(ref, ref)

        # Add dependency edges from the included SBOM, remapping shared bom-refs.
        # Merge into an existing dep entry when the ref is already present in the parent.
        for dep_entry in img_sbom_data.get("dependencies") or []:
            r_ref = remap_ref(dep_entry.get("ref", ""))
            if not r_ref or not any(c.get("bom-ref") == r_ref for c in sbom["components"]):
                continue
            r_depends = []
            for dr in dep_entry.get("dependsOn") or []:
                rdr = remap_ref(dr)
                if rdr == r_ref:
                    continue
                if not any(c.get("bom-ref") == rdr for c in sbom["components"]):
                    continue
                if rdr not in r_depends:
                    r_depends.append(rdr)
            if not r_depends:
                continue
            existing_entry = next((x for x in sbom["dependencies"] if x["ref"] == r_ref), None)
            if existing_entry:
                for rdr in r_depends:
                    if rdr not in existing_entry["dependsOn"]:
                        existing_entry["dependsOn"].append(rdr)
            else:
                sbom["dependencies"].append({"ref": r_ref, "dependsOn": r_depends})

        bb.debug(1, f"CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES: merged {img_name} "
                    f"({len(img_sbom_data.get('components') or [])} components)")

        # Merge VEX vulnerabilities: remap included SBOM serial and shared bom-refs, avoid CVE ID duplicates.
        if not os.path.exists(img_vex_path):
            bb.debug(1, f"CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES: no VEX for {img_name}: {img_vex_path}")
            continue
        try:
            img_vex_data = read_json(img_vex_path)
        except Exception as e:
            bb.warn(f"CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES: cannot parse VEX for {img_name}: {e}")
            continue

        for inc_vuln in img_vex_data.get("vulnerabilities") or []:
            cve_id = inc_vuln.get("id")
            if not cve_id:
                continue
            remapped_affects = []
            for affect in inc_vuln.get("affects") or []:
                ref = affect.get("ref", "")
                if included_serial and included_serial in ref:
                    ref = ref.replace(included_serial, sbom_serial_number)
                if "#" in ref:
                    prefix, bom_ref_part = ref.rsplit("#", 1)
                    ref = f"{prefix}#{remap_ref(bom_ref_part)}"
                bom_ref_in_ref = ref.rsplit("#", 1)[-1] if "#" in ref else ""
                if bom_ref_in_ref and not any(
                    c.get("bom-ref") == bom_ref_in_ref for c in sbom["components"]
                ):
                    continue
                remapped_affects.append({"ref": ref})
            if not remapped_affects:
                continue
            existing_vuln = next(
                (v for v in vex["vulnerabilities"] if v.get("id") == cve_id), None
            )
            if existing_vuln:
                for a in remapped_affects:
                    if a not in existing_vuln["affects"]:
                        existing_vuln["affects"].append(a)
            else:
                merged_vuln = dict(inc_vuln)
                merged_vuln["affects"] = remapped_affects
                vex["vulnerabilities"].append(merged_vuln)

    # Add a root dependency node as the first entry.
    # It references metadata.component and points to all directly installed components.
    directly_installed_refs = sorted(directly_installed_component_refs)

    root_dep_entry = {
        "ref": metadata_component_ref,
        "dependsOn": directly_installed_refs
    }
    sbom["dependencies"].insert(0, root_dep_entry)

    # Replace SBOM serial placeholder in VEX vulnerabilities
    # This must be done after all vulnerabilities are collected to ensure each image
    # gets its own SBOM serial number in multi-output builds (e.g., rootfs + initramfs)
    for vuln in vex["vulnerabilities"]:
        affects = []
        for affect in vuln.get("affects", []):
            if "ref" in affect:
                affect["ref"] = affect["ref"].replace(
                    d.getVar('CYCLONEDX_SBOM_SERIAL_PLACEHOLDER'), sbom_serial_number)
            # Refs merged from another image only become comparable to this
            # document's own, still-templated refs once the serial is substituted.
            if affect not in affects:
                affects.append(affect)
        vuln["affects"] = affects

    # Sort vulnerabilities by CVE id for a stable, human-readable order.
    vex["vulnerabilities"].sort(key=lambda v: v["id"])

    export_dir = d.getVar("CYCLONEDX_EXPORT_DIR")
    tmp_export_dir = d.getVar("CYCLONEDX_TMP_EXPORT_DIR")
    if os.path.exists(tmp_export_dir):
        import shutil
        shutil.rmtree(tmp_export_dir)
    bb.utils.mkdirhier(tmp_export_dir)

    def get_cyclonedx_export_path(path_variable_name, required=False):
        path = d.getVar(path_variable_name)
        if not path:
            if required:
                bb.error(f"{path_variable_name} must be set")
            else:
                return path
        if os.path.isabs(path):
            if not path.startswith(export_dir):
                bb.error(path_variable_name + " must be a relative path or start with ${CYCLONEDX_EXPORT_DIR}")
            else:
                path = Path(path).relative_to(export_dir)
        path = os.path.join(tmp_export_dir, path)
        bb.utils.mkdirhier(os.path.dirname(path))
        return path

    export_sbom = get_cyclonedx_export_path("CYCLONEDX_EXPORT_SBOM", required=True)
    export_vex = get_cyclonedx_export_path("CYCLONEDX_EXPORT_VEX", required=True)

    write_json(export_sbom, sbom)
    write_json(export_vex, vex)

    def make_deploy_symlink(target, link_name):
        if link_name and target != link_name:
            target = Path(target).relative_to(os.path.dirname(link_name))
            os.symlink(target, link_name)
    make_deploy_symlink(export_sbom, get_cyclonedx_export_path("CYCLONEDX_EXPORT_SBOM_LINK"))
    make_deploy_symlink(export_vex, get_cyclonedx_export_path("CYCLONEDX_EXPORT_VEX_LINK"))

python do_export_cyclonedx() {
    export_cyclonedx(d)
}

# We use ROOTFS_POSTUNINSTALL_COMMAND to make sure this function runs exactly once
# after the build process has been completed
# see https://docs.yoctoproject.org/ref-manual/variables.html#term-ROOTFS_POSTUNINSTALL_COMMAND
ROOTFS_POSTUNINSTALL_COMMAND =+ "do_export_cyclonedx; "

SSTATETASKS += "do_deploy_cyclonedx"
do_deploy_cyclonedx[sstate-inputdirs] = "${CYCLONEDX_TMP_EXPORT_DIR}"
do_deploy_cyclonedx[sstate-outputdirs] = "${CYCLONEDX_EXPORT_DIR}"
do_deploy_cyclonedx[vardeps] += "CYCLONEDX_EXPORT_DIR"
# Link names are stable (no timestamp) so they can safely invalidate sstate without churn.
do_deploy_cyclonedx[vardeps] += "CYCLONEDX_EXPORT_SBOM_LINK"
do_deploy_cyclonedx[vardeps] += "CYCLONEDX_EXPORT_VEX_LINK"
python do_deploy_cyclonedx_setscene() {
    sstate_setscene(d)
}
addtask do_deploy_cyclonedx_setscene
python do_deploy_cyclonedx() {
    if bb.data.inherits_class("image", d):
       bb.note("Deploying CycloneDX SBOM and VEX files generated by do_rootfs")
       return
    else:
       export_cyclonedx(d)
}
python () {
    if bb.data.inherits_class("image", d):
        bb.build.addtask("do_deploy_cyclonedx", "do_image_complete", "do_rootfs", d)
        pn = d.getVar("PN")
        for img in (d.getVar("CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES") or "").split():
            if img != pn:
                d.appendVarFlag("do_rootfs", "depends", f" {img}:do_deploy_cyclonedx")
}
