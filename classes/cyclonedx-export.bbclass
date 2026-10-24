# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2022 BG Networks, Inc.
# SPDX-FileCopyrightText: Copyright (C) 2024 Savoir-faire Linux Inc. (<www.savoirfairelinux.com>).
# SPDX-FileCopyrightText: Copyright (C) 2026 iris-GmbH infrared & intelligent sensors.

# The product name that the CVE database uses.  Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"

# Defines SBOM_CVE_CHECK_DEPLOY_DB_DIR, used by the kernel CVE filtering below
# to find the cvelist database deployed by sbom-cve-check-update-cvelist-native.
require conf/sbom-cve-check-config.inc

# CycloneDX specification version to generate
# Options: "1.6", "1.7"
# Version 1.6: Modern format with enhanced features
# Version 1.7: Latest version with advanced cryptography, IP transparency, and citations (default)
CYCLONEDX_SPEC_VERSION ??= "1.7"

# Component scope support
# When enabled, components are marked as "required" (runtime) or "optional" (build-time)
# Set to "0" to disable (e.g., for certain SBOM profiles or tool compatibility)
# Available in CycloneDX 1.6 and 1.7
CYCLONEDX_ADD_COMPONENT_SCOPES ??= "1"

# Vulnerability analysis timestamps
# When enabled, adds firstIssued and lastUpdated timestamps to vulnerability analysis
# Set to "0" to disable for minimal VEX documents
# Available in CycloneDX 1.6 and 1.7
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

# Name string for metadata.component in the CycloneDX SBOM.
CYCLONEDX_IMAGE_NAME ??= "${IMAGE_BASENAME}"

# Type string for metadata.component in the CycloneDX SBOM.
CYCLONEDX_IMAGE_TYPE ??= "firmware"

# Version string for metadata.component in the CycloneDX SBOM.
CYCLONEDX_IMAGE_VERSION ??= "${DISTRO_VERSION}${IMAGE_VERSION_SUFFIX}"

# Add layer sources as external references to metadata.component in the
# CycloneDX SBOM.
CYCLONEDX_ADD_LAYER_REFERENCES ??= "1"

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

# Add component sources (as specified with SRC_URI within the recipe) as
# external references to the SBOM.
CYCLONEDX_ADD_COMPONENT_SOURCE_REFERENCES ??= "0"

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
# Options: "CLEAR", "GREEN", "AMBER", "AMBER_AND_STRICT", "RED", or "" to disable
# See: https://www.first.org/tlp/
CYCLONEDX_TLP_MARKING ??= ""

CYCLONEDX_TMP_EXPORT_DIR = "${WORKDIR}/cyclonedx-export"
CYCLONEDX_EXPORT_DIR ??= "${DEPLOY_DIR_IMAGE}"
# Try to set meaningful default filenames for both image and non-image recipes
CYCLONEDX_EXPORT_BASENAME ?= "${@d.getVar('IMAGE_NAME') or d.getVar('IMAGE_BASENAME') or d.getVar('PN')}.cyclonedx"
CYCLONEDX_EXPORT_SBOM ??= "${CYCLONEDX_EXPORT_BASENAME}.bom.json"
CYCLONEDX_EXPORT_VEX ??= "${CYCLONEDX_EXPORT_BASENAME}.vex.json"
CYCLONEDX_EXPORT_SBOM_CVE_CHECK_VEX ??= "${CYCLONEDX_EXPORT_BASENAME}.sbom-cve-check.vex.json"
# Create symlinks for image recipes similar to the image files by default.
IMAGE_LINK_NAME ??= ""
CYCLONEDX_EXPORT_SBOM_LINK ??= "${@'${IMAGE_LINK_NAME}.cyclonedx.bom.json' if d.getVar('IMAGE_LINK_NAME') else ''}"
CYCLONEDX_EXPORT_VEX_LINK ??= "${@'${IMAGE_LINK_NAME}.cyclonedx.vex.json' if d.getVar('IMAGE_LINK_NAME') else ''}"
CYCLONEDX_PNDATA_WORKDIR = "${WORKDIR}/cyclonedx"
CYCLONEDX_PNDATA = "${TMPDIR}/cyclonedx/pn"
CYCLONEDX_IMAGEDATA_WORKDIR = "${WORKDIR}/cyclonedx-image"
# Multiconfigs may share TMPDIR while producing different variants of one image.
CYCLONEDX_IMAGEDATA = "${TMPDIR}/cyclonedx/image/${BB_CURRENT_MC}"
CYCLONEDX_SBOM_CVE_CHECK_DEPLOYDIR = "${WORKDIR}/cyclonedx-sbom-cve-check"
CYCLONEDX_SBOM_CVE_CHECK_IMAGEDATA_WORKDIR = "${WORKDIR}/cyclonedx-sbom-cve-check-image"

# We need to add the sbom serial number to the list of vulnerabilites for each recipe but
# don't know it until after we generate the sbom export header file
CYCLONEDX_SBOM_SERIAL_PLACEHOLDER = "<SBOM_SERIAL>"

def _cyclonedx_renderer(d):
    """
    Return the layer's document renderer module.

    Task code runs in a bitbake-worker whose module search path does not
    include the layer's lib directory, so the module is loaded by path and
    cached in sys.modules for the lifetime of the process. All document
    semantics (identity, graph construction, document mapping, validation,
    rendering) live there; this class only collects facts, orders tasks and
    deploys output.
    """
    import importlib.util
    import sys

    name = "meta_cyclonedx"
    module = sys.modules.get(name)
    if module is None:
        path = os.path.join(d.getVar("CYCLONEDX_LAYERDIR"), "lib", "meta_cyclonedx.py")
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module

def _cyclonedx_log(level, message):
    """
    Route renderer diagnostics into the build log. The renderer reports a
    severity (an int debug level or "warn", "error", "note") and stays
    independent of BitBake's messaging itself.
    """
    if level == "warn":
        bb.warn(message)
    elif level == "error":
        bb.error(message)
    elif level == "note":
        bb.note(message)
    else:
        bb.debug(level, message)

python () {
    from oe.cve_check import extend_cve_status

    # resolve CVE_CHECK_IGNORE and CVE_STATUS_GROUPS
    extend_cve_status(d)

    # Validate renderer-relevant configuration; the supported CycloneDX
    # versions and image types are owned by the renderer.
    error = _cyclonedx_renderer(d).config_errors(
        d.getVar("CYCLONEDX_SPEC_VERSION"), d.getVar("CYCLONEDX_IMAGE_TYPE"))
    if error:
        bb.fatal(error)
}

python () {
    if d.getVar('CYCLONEDX_VEX_ADD_KERNEL_CVE') != '1':
        return
    if d.getVar('PN') != d.getVar('PREFERRED_PROVIDER_virtual/kernel'):
        return
    d.appendVarFlag('do_populate_cyclonedx', 'depends',
                     ' sbom-cve-check-update-cvelist-native:do_patch')
}

python do_populate_cyclonedx() {
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

    # The renderer owns component identity. The package URL and any
    # SRC_URI external references are artifact facts collected here.
    renderer = _cyclonedx_renderer(d)
    import oe.purl
    spdx_purls = (d.getVar("SPDX_PACKAGE_URLS") or "").split()
    purl = spdx_purls[0] if spdx_purls else oe.purl.get_base_purl(d)
    references = (generate_source_references(d)
                  if d.getVar("CYCLONEDX_ADD_COMPONENT_SOURCE_REFERENCES") == "1" else None)

    # append all defined package names for recipe to pn_list pkgs
    for pkg in renderer.component_identity(name, version, purl, references):
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
            renderer.add_status_vex_statement(
                cve, cves, bom_ref, d.getVar("BPN"),
                d.getVar('CYCLONEDX_SBOM_SERIAL_PLACEHOLDER'),
                d.getVar('CYCLONEDX_ADD_VULN_TIMESTAMPS') == "1",
                log=_cyclonedx_log)

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
    # recipe-name dependency remapping that the renderer applies to
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
        # it so the renderer can attach the tree to the recipe.
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
            cves.append(renderer.kernel_vex_statement(
                cve_id, bom_refs, placeholder, entry.get('description', '')))
            added += 1
        bb.note(f"cyclonedx-export: added {added} not_affected kernel CVE entries")


    # write partial sbom to the recipes work folder
    write_json(os.path.join(d.getVar("CYCLONEDX_PNDATA_WORKDIR"), f"{pn}.json"), pn_list)
}

def list_buildtime_recipes(d):
    """
    Return every recipe (PN) whose do_populate_cyclonedx task is part of the
    build dependency closure of the currently running task.

    This is derived from BB_TASKDEPDATA, do_rootfs recursively depends on do_populate_cyclonedx
    for its whole dependency tree (see do_rootfs[recrdeptask] below), so the task dependency
    data is an authoritative, complete list of build-time recipes.
    """
    taskdepdata = d.getVar("BB_TASKDEPDATA", False)
    if not taskdepdata:
        bb.warn("BB_TASKDEPDATA is unavailable; build-time packages may be "
                "missing from the CycloneDX SBOM")
        return set()

    ignored_suffixes = (d.getVar("SPECIAL_PKGSUFFIX") or "").split()
    recipes = set()
    for dep in taskdepdata.values():
        pn, taskname = dep[0], dep[1]
        if taskname != "do_populate_cyclonedx":
            continue
        # Mirror the filtering done by do_populate_cyclonedx itself: non-target
        # recipes (native, cross, ...) return early and write no pn data file.
        if any(pn.endswith(suffix) for suffix in ignored_suffixes):
            continue
        recipes.add(pn)
    return recipes

list_buildtime_recipes[vardepsexclude] += "BB_TASKDEPDATA"

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
    spec_version = d.getVar('CYCLONEDX_SPEC_VERSION')
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

def redact_credentials(text):
    """
    Mask the user:password component of any url in a message, so that
    credentials from SRC_URI or a git remote never reach the build logs.
    """
    import re

    return re.sub(r"([a-zA-Z][a-zA-Z0-9+.\-]*)://[^/?#@:\s]+(:[^/?#@:\s]*)?@",
                  r"\1://***@", str(text))

def strip_credentials(url):
    """
    Return a url with any user:password userinfo component removed.

    Credentials from SRC_URI or a layer git remote must never be published in
    the SBOM. Unlike redact_credentials(), this leaves a valid, portable url
    that consumers can clone with their own credentials.
    """
    import re
    import urllib.parse

    try:
        scheme, netloc, path, query, fragment = urllib.parse.urlsplit(url)
    except ValueError:
        return re.sub(r"://[^/?#@]*@", "://", str(url))
    if "@" not in netloc:
        return url
    return urllib.parse.urlunsplit((scheme, netloc.partition("@")[2], path, query, fragment))

def generate_layer_references(d):
    """
    Get a list of externalReferences for the layers
    """
    import oe.buildcfg

    spec_version = d.getVar('CYCLONEDX_SPEC_VERSION')

    references = []
    layers = oe.buildcfg.get_layer_revisions(d)
    for (path, name, branch, rev, ismodified) in layers:
        try:
            repo_path = oe.buildcfg.get_metadata_git_toplevel(path)
            if not repo_path:
                bb.warn(f"cyclonedx-export: layer {name} is not part of a git repository, skipping its external reference")
                continue
            remotes = oe.buildcfg.get_metadata_git_remotes(repo_path)
            if not remotes:
                bb.warn(f"cyclonedx-export: layer {name} has no git remotes, skipping its external reference")
                continue
            remote_url = oe.buildcfg.get_metadata_git_remote_url(repo_path, remotes[0])
        except (IndexError, OSError) as e:
            bb.warn(f"cyclonedx-export: cannot resolve the remote url of layer {name}, skipping its external reference: {redact_credentials(e)}")
            continue

        # Only layers with a resolvable remote url get a reference.
        if not remote_url:
            bb.warn(f"cyclonedx-export: layer {name} has no resolvable remote url, skipping its external reference")
            continue

        # Credentials in a remote url are not publishable; keep the host/path.
        public_remote_url = strip_credentials(remote_url)
        if public_remote_url != remote_url:
            bb.warn(f"cyclonedx-export: stripped credentials from the remote url of layer {name}")

        reference = {
            "url": f"{public_remote_url}@{rev}{ismodified}",
            "type": "vcs",
            "comment": f"Yocto metadata layer {name}"
        }
        if spec_version == "1.7":
            reference["properties"] = [
                {
                    "name": "yocto:layer:name",
                    "value": name
                },
                {
                    "name": "yocto:layer:remote_url",
                    "value": public_remote_url
                },
                {
                    "name": "yocto:layer:rev",
                    "value": rev
                },
                {
                    "name": "yocto:layer:is_modified",
                    "value": "true" if ismodified else "false"
                }
            ]
        references.append(reference)
    return references

def find_local_source_layer(d, local_path):
    """
    Find the configured Yocto layer containing a resolved local source.
    """
    import os

    source_path = os.path.realpath(local_path)
    match = None
    for layer_path in (d.getVar("BBLAYERS") or "").split():
        layer_root = os.path.realpath(layer_path)
        try:
            relative_path = os.path.relpath(source_path, layer_root)
        except ValueError:
            continue
        if relative_path == os.pardir or relative_path.startswith(os.pardir + os.sep):
            continue
        if match is None or len(layer_root) > len(match[0]):
            match = (
                layer_root,
                os.path.basename(os.path.normpath(layer_path)),
                relative_path
            )

    if match is None:
        return None
    return {
        "name": match[1],
        "path": match[2].replace(os.sep, "/")
    }

def generate_source_references(d):
    """
    Get a list of externalReferences that has been generated from the SRC_URI
    """
    import os
    import urllib.parse
    import bb.fetch2
    import bb.utils

    spec_version = d.getVar('CYCLONEDX_SPEC_VERSION')

    references = []
    checksum_alg_map = {
        "md5": "MD5",
        "sha256": "SHA-256",
        "sha1": "SHA-1",
        "sha384": "SHA-384",
        "sha512": "SHA-512"
    }
    # Supported VCS fetchers.
    vcs_fetcher_types = {
        "ccrc", "git", "gitannex", "gitsm", "hg", "p4", "repo", "svn"
    }
    # Building the fetcher data resolves revisions (e.g. AUTOREV or branch
    # names for git urls). Keep this offline so SBOM generation never touches
    # the network, and skip urls that cannot be resolved without it.
    no_network = d.getVar("BB_NO_NETWORK")
    d.setVar("BB_NO_NETWORK", "1")
    try:
        for url in (d.getVar("SRC_URI") or "").split():
            # SRC_URI may embed credentials: log them masked, publish them stripped.
            safe_url = redact_credentials(url)
            public_url = strip_credentials(url)
            if url != public_url:
                bb.warn(f"cyclonedx-export: stripped credentials from SRC_URI entry {safe_url} in its external reference")
            try:
                fetcher = bb.fetch2.Fetch([url], d)
                url_data = fetcher.ud[url]
            except bb.fetch2.NetworkAccess:
                bb.warn(f"cyclonedx-export: cannot resolve SRC_URI entry {safe_url} without network access, skipping its external reference")
                continue

            revision = None
            local_layer = None
            property_source_uri = public_url
            if url_data.type == "file":
                try:
                    local_path = fetcher.localpath(url)
                except (IndexError, OSError) as e:
                    bb.warn(f"cyclonedx-export: cannot resolve local SRC_URI entry {safe_url}, skipping its external reference: {redact_credentials(e)}")
                    continue
                if not local_path or not os.path.exists(local_path):
                    bb.warn(f"cyclonedx-export: local SRC_URI entry {safe_url} does not resolve to an existing path, skipping its external reference")
                    continue

                local_layer = find_local_source_layer(d, local_path)
                if local_layer is None:
                    bb.warn(f"cyclonedx-export: local SRC_URI entry {safe_url} is outside the configured layers, skipping its external reference")
                    continue

                reference = {
                    "url": "file:" + urllib.parse.quote(
                        f"{local_layer['name']}/{local_layer['path']}"
                    ),
                    "type": "other",
                    "comment": f"Yocto-local build input from layer {local_layer['name']}"
                }
                # Never expose an absolute build-host path in SBOM properties.
                if os.path.isabs(getattr(url_data, "basepath", "")):
                    property_source_uri = reference["url"]
                if os.path.isfile(local_path):
                    reference["hashes"] = [{
                        "alg": "SHA-512",
                        "content": bb.utils.sha512_file(local_path)
                    }]
            elif getattr(url_data, "proto", None) == "file":
                # Local VCS repositories do not provide portable references.
                bb.warn(f"cyclonedx-export: local VCS SRC_URI entry {safe_url} does not provide a portable reference, skipping its external reference")
                continue
            else:
                reference = {
                    "url": public_url,
                    "type": "vcs" if url_data.type in vcs_fetcher_types else "distribution"
                }
                revision = getattr(url_data, "revision", None)
                if revision:
                    reference["url"] += f"@{revision}"
                for checksum_id in checksum_alg_map:
                    checksum = getattr(url_data, "%s_expected" % checksum_id, None)
                    if checksum:
                        reference.setdefault("hashes", [])
                        reference["hashes"].append({
                            "alg": checksum_alg_map[checksum_id],
                            "content": checksum
                        })

            if spec_version == "1.7":
                reference.setdefault("properties", [])
                reference["properties"].append({
                    "name": "yocto:src_uri",
                    "value": property_source_uri
                })
                parm = getattr(url_data, "parm", None)
                if parm:
                    for key in parm:
                        reference["properties"].append({
                            "name": "yocto:src_uri:" + key,
                            "value": parm[key]
                        })
                if local_layer:
                    reference["properties"].extend([
                        {
                            "name": "yocto:layer:name",
                            "value": local_layer["name"]
                        },
                        {
                            "name": "yocto:layer:path",
                            "value": local_layer["path"]
                        }
                    ])
                if revision:
                    reference["properties"].append({
                        "name": "yocto:srcrev",
                        "value": revision
                    })
            references.append(reference)
    finally:
        if no_network is None:
            d.delVar("BB_NO_NETWORK")
        else:
            d.setVar("BB_NO_NETWORK", no_network)
    return references

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

                for dep_pkg in _read_runtime_package_deps(d, current_pkg_token):
                    dep_recipe = resolve_and_record(dep_pkg)
                    if dep_recipe and dep_recipe.startswith("packagegroup-") and dep_pkg not in seen_pkg_tokens:
                        queue.append(dep_pkg)

    return recipes

def build_runtime_dependency_edges(d):
    """
    Build recipe -> recipes runtime edges from the pkgdata of the packages that
    are actually installed in the image.

    Unlike the recipe's parse-time RDEPENDS:${PN}, pkgdata also carries
    RRECOMMENDS, the dependencies of every other package a recipe produces and
    the shared library dependencies generated during do_package.
    """
    from oe.rootfs import image_list_installed_packages

    # runtime-reverse only indexes package names, so collect the RPROVIDES of
    # the installed packages to be able to resolve virtual dependencies too.
    providers = {}
    installed_recipes = {}
    for pkg in list(image_list_installed_packages(d)):
        pkg_file = _pkgdata_runtime_file(d, pkg)
        if not pkg_file:
            continue
        pkg_data = oe.packagedata.read_pkgdatafile(pkg_file)
        recipe = pkg_data.get("PN")
        if not recipe:
            continue
        installed_recipes[pkg] = recipe
        providers[pkg] = recipe
        for name, value in pkg_data.items():
            if name == "RPROVIDES" or name.startswith("RPROVIDES:"):
                for token in _split_dep_tokens(value):
                    providers.setdefault(token, recipe)

    edges = {}
    for pkg, recipe in installed_recipes.items():
        for dep in _read_runtime_package_deps(d, pkg, ("RDEPENDS", "RRECOMMENDS")):
            dep_recipe = providers.get(dep) or _resolve_runtime_token_to_recipe(d, dep)
            if not dep_recipe or dep_recipe == recipe:
                continue
            edges.setdefault(recipe, set()).add(dep_recipe)
    return edges

def _pkgdata_runtime_file(d, token):
    """
    Locate the pkgdata file for a runtime token.

    runtime-reverse/ is keyed by the final package name and by RPROVIDES, while
    runtime/ is keyed by the pre-rename package name used inside RDEPENDS.
    """
    pkgdata_dir = d.getVar('PKGDATA_DIR')
    for subdir in ('runtime-reverse', 'runtime'):
        path = os.path.join(pkgdata_dir, subdir, token)
        if os.path.exists(path):
            return path
    return None

def _resolve_runtime_token_to_recipe(d, token):
    """
    Resolve a package/runtime token (or virtual/* token) to recipe PN.
    """
    pkg_info = _pkgdata_runtime_file(d, token)
    if pkg_info:
        pkg_data = oe.packagedata.read_pkgdatafile(pkg_info)
        return pkg_data.get("PN")

    if token.startswith("virtual/"):
        return d.getVar("PREFERRED_RPROVIDER_" + token) or d.getVar("PREFERRED_PROVIDER_" + token)

    return None

def _split_dep_tokens(value):
    """
    Strip version constraints and alternation markers from a pkgdata dependency
    value and return the plain tokens.
    """
    import re

    return re.sub(r"\([^)]*\)", " ", value).replace("|", " ").split()

def _read_runtime_package_deps(d, pkg, keys=("RDEPENDS",)):
    """
    Read runtime dependency tokens of a package from pkgdata.
    """
    pkg_runtime_info = _pkgdata_runtime_file(d, pkg)
    if not pkg_runtime_info:
        return []

    pkg_data = oe.packagedata.read_pkgdatafile(pkg_runtime_info)

    deps = []
    for key in keys:
        # Dependency keys are package-scoped (e.g. RDEPENDS:busybox) and the
        # scope may differ from the token used to look the file up.
        for name, value in pkg_data.items():
            if name != key and not name.startswith(key + ":"):
                continue
            for dep in _split_dep_tokens(value):
                if dep not in deps:
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

def resolve_extra_image_sbom_paths(d):
    import os

    # Read the producer's sstate-managed documents, not filenames reconstructed
    # using this image's suffix, timestamp, export directory or link settings.
    current_pn = d.getVar("PN")
    imagedata_root = d.getVar("CYCLONEDX_IMAGEDATA")
    pkgarchs = list(reversed(d.getVar("SSTATE_ARCHS").split()))
    results = []
    for img_name in (d.getVar("CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES") or "").split():
        if img_name == current_pn:
            bb.warn(f"CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES: skipping self-reference '{img_name}'")
            continue
        for pkgarch in pkgarchs:
            imagedata_dir = os.path.join(imagedata_root, pkgarch, img_name)
            manifest_path = os.path.join(imagedata_dir, "manifest.json")
            if os.path.exists(manifest_path):
                manifest = read_json(manifest_path)
                results.append((img_name,
                                os.path.join(imagedata_dir, manifest["sbom"]),
                                os.path.join(imagedata_dir, manifest["vex"])))
                break
        else:
            bb.warn(f"CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES: image data not found for {img_name}")
    return results

def write_cyclonedx_image_data(d, sbom, vex):
    import os
    import shutil

    imagedata_dir = d.getVar("CYCLONEDX_IMAGEDATA_WORKDIR")
    if os.path.exists(imagedata_dir):
        shutil.rmtree(imagedata_dir)
    bb.utils.mkdirhier(imagedata_dir)
    write_json(os.path.join(imagedata_dir, "bom.json"), sbom)
    write_json(os.path.join(imagedata_dir, "vex.json"), vex)
    # The checked VEX has a separate sstate owner. The manifest selects it
    # explicitly so disabling sbom-cve-check cannot pick up a stale result.
    write_json(os.path.join(imagedata_dir, "manifest.json"), {
        "sbom": "bom.json",
        "vex": "sbom-cve-check/vex.json" if cyclonedx_sbom_cve_check_enabled(d) else "vex.json",
    })

def export_cyclonedx(d):
    """
    Collect normalized build facts and artifact facts, hand them to the
    renderer and deploy the SBOM and VEX documents it returns.
    """
    import os
    from pathlib import Path
    from datetime import datetime, timezone

    timestamp = datetime.now(timezone.utc).isoformat()


    # taken from https://github.com/yoctoproject/poky/blob/fec201518be3c35a9359ec8c37675a33e458b92d/meta/classes/cve-check.bbclass
    # SPDX-License-Identifier: MIT
    # SPDX-FileCopyrightText: Copyright OpenEmbedded Contributors
    # Determine runtime packages for scope assignment
    runtime_recipes = list_runtime_recipes(d)

    # Determine recipes explicitly requested by the image author.
    image_install_recipes = list_image_install_recipes(d)

    # Determine which recipes to include
    recipes = set()
    if d.getVar('CYCLONEDX_RUNTIME_PACKAGES_ONLY') == "1":
        recipes = set(runtime_recipes)
    else:
        recipes = list_buildtime_recipes(d).union(runtime_recipes)

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

    # Extra runtime recipes are runtime content and direct image-install intent.
    runtime_recipes = set(runtime_recipes) | extra_recipes
    image_install_recipes = set(image_install_recipes).union(extra_recipes)

    # Load the per-recipe facts written by do_populate_cyclonedx. They are
    # plain JSON fragments; the renderer never sees the data store.
    fragments = {}
    pkgarchs = d.getVar("SSTATE_ARCHS").split()
    pkgarchs.reverse()
    for pkg in sorted(recipes):
        for pkgarch in pkgarchs:
            pn_list_filepath = os.path.join(d.getVar("CYCLONEDX_PNDATA"),
                                            pkgarch, f"{pkg}.json")
            if os.path.exists(pn_list_filepath):
                break
        if not os.path.exists(pn_list_filepath):
            bb.error(f"CycloneDX PN file not found: {pkg}.json")
            continue
        fragments[pkg] = read_json(pn_list_filepath)

    # Runtime edges derived from pkgdata cover RRECOMMENDS, per-package
    # RDEPENDS and generated shlib dependencies, which the recipe metadata
    # alone misses. With configured export dependencies the caller has
    # resolved them instead.
    runtime_edges = {}
    if not (d.getVar("CYCLONEDX_EXPORT_DEPENDS") or "").split():
        runtime_edges = build_runtime_dependency_edges(d)

    primary = {
        "type": d.getVar("CYCLONEDX_IMAGE_TYPE") or "firmware",
        "name": d.getVar("CYCLONEDX_IMAGE_NAME") or d.getVar("PN") or "image",
        "version": d.getVar("CYCLONEDX_IMAGE_VERSION") or "unknown",
    }
    if d.getVar("CYCLONEDX_ADD_LAYER_REFERENCES") == "1":
        primary["external_references"] = generate_layer_references(d)

    # The completed documents of embedded images are build artifacts; read
    # them here and hand the renderer their contents only.
    included_images = []
    for img_name, img_sbom_path, img_vex_path in resolve_extra_image_sbom_paths(d):
        if not os.path.exists(img_sbom_path):
            bb.warn(f"CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES: SBOM not found for {img_name}: {img_sbom_path}")
            continue
        try:
            img_sbom_data = read_json(img_sbom_path)
        except Exception as e:
            bb.warn(f"CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES: cannot parse SBOM for {img_name}: {e}")
            continue
        img_vex_data = None
        img_vex_error = None
        if os.path.exists(img_vex_path):
            try:
                img_vex_data = read_json(img_vex_path)
            except Exception as e:
                img_vex_error = str(e)
        included_images.append({"name": img_name, "sbom": img_sbom_data,
                                "vex": img_vex_data, "vex_error": img_vex_error})

    docs = _cyclonedx_renderer(d).render({
        "config": {
            "spec_version": d.getVar('CYCLONEDX_SPEC_VERSION'),
            "add_component_scopes": d.getVar('CYCLONEDX_ADD_COMPONENT_SCOPES') == "1",
            "add_citation": d.getVar('CYCLONEDX_ADD_CITATION') == "1",
            "tlp_marking": d.getVar('CYCLONEDX_TLP_MARKING'),
            "add_vuln_timestamps": d.getVar('CYCLONEDX_ADD_VULN_TIMESTAMPS') == "1",
            "sbom_serial_placeholder": d.getVar('CYCLONEDX_SBOM_SERIAL_PLACEHOLDER'),
        },
        "timestamp": timestamp,
        "log": _cyclonedx_log,
        "primary": primary,
        "fragments": fragments,
        "runtime_recipes": sorted(runtime_recipes),
        "image_install_recipes": sorted(image_install_recipes),
        "runtime_edges": {pkg: sorted(deps) for pkg, deps in runtime_edges.items()},
        "included_images": included_images,
    })
    sbom = docs["sbom"]
    vex = docs["vex"]

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
    write_cyclonedx_image_data(d, sbom, vex)

    def make_deploy_symlink(target, link_name):
        if link_name and target != link_name:
            target = Path(target).relative_to(os.path.dirname(link_name))
            os.symlink(target, link_name)
    make_deploy_symlink(export_sbom, get_cyclonedx_export_path("CYCLONEDX_EXPORT_SBOM_LINK"))
    if not cyclonedx_sbom_cve_check_enabled(d):
        make_deploy_symlink(export_vex, get_cyclonedx_export_path("CYCLONEDX_EXPORT_VEX_LINK"))

python do_export_cyclonedx() {
    export_cyclonedx(d)
}

# We use ROOTFS_POSTUNINSTALL_COMMAND to make sure this function runs exactly once
# after the build process has been completed
# see https://docs.yoctoproject.org/ref-manual/variables.html#term-ROOTFS_POSTUNINSTALL_COMMAND
ROOTFS_POSTUNINSTALL_COMMAND =+ "do_export_cyclonedx"
# Looked up through a variable name argument, invisible to the signature
export_cyclonedx[vardeps] += "CYCLONEDX_EXPORT_SBOM CYCLONEDX_EXPORT_VEX \
    CYCLONEDX_EXPORT_SBOM_LINK CYCLONEDX_EXPORT_VEX_LINK"

SSTATETASKS += "do_deploy_cyclonedx"
do_deploy_cyclonedx[sstate-inputdirs] = "${CYCLONEDX_TMP_EXPORT_DIR} ${CYCLONEDX_IMAGEDATA_WORKDIR}"
do_deploy_cyclonedx[sstate-outputdirs] = "${CYCLONEDX_EXPORT_DIR} ${CYCLONEDX_IMAGEDATA}/${SSTATE_PKGARCH}/${PN}"
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
# Synchronize consumers with the final document producer, including its setscene
# task. This task has no output of its own.
do_cyclonedx_complete[noexec] = "1"
python () {
    if bb.data.inherits_class("image", d):
        bb.build.addtask("do_deploy_cyclonedx", "do_image_complete", "do_rootfs", d)
        complete_after = "do_deploy_cyclonedx"
        if cyclonedx_sbom_cve_check_enabled(d):
            complete_after = "do_cyclonedx_sbom_cve_check"
            bb.build.addtask("do_cyclonedx_sbom_cve_check", "do_build", "do_sbom_cve_check do_deploy_cyclonedx", d)
        elif d.getVar("CYCLONEDX_INCLUDE_UNPATCHED_VULNS") == "1":
            bb.warn(f"meta-cyclonedx: CYCLONEDX_INCLUDE_UNPATCHED_VULNS needs the sbom-cve-check class for {d.getVar('PN')}")
        bb.build.addtask("do_cyclonedx_complete", "do_build", complete_after, d)
        pn = d.getVar("PN")
        for img in (d.getVar("CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES") or "").split():
            if img != pn:
                d.appendVarFlag("do_rootfs", "depends", f" {img}:do_cyclonedx_complete")
}

def cyclonedx_sbom_cve_check_enabled(d):
    return bb.data.inherits_class("image", d) and bb.data.inherits_class("sbom-cve-check", d)


python do_cyclonedx_sbom_cve_check() {
    imagedata_dir = os.path.join(d.getVar("CYCLONEDX_IMAGEDATA"), d.getVar("SSTATE_PKGARCH"), d.getVar("PN"))
    sbom = read_json(os.path.join(imagedata_dir, "bom.json"))
    vex = read_json(os.path.join(imagedata_dir, "vex.json"))

    # Restored from sstate, the report keeps the IMAGE_NAME of an older build
    report_ext = d.getVarFlag("SBOM_CVE_CHECK_EXPORT_CVECHECK", "ext")
    image_link_name = d.getVar("IMAGE_LINK_NAME") or d.getVar("IMAGE_NAME")
    report = read_json(os.path.join(d.getVar("DEPLOY_DIR_IMAGE"), image_link_name + report_ext))

    added = _cyclonedx_renderer(d).merge_sbom_cve_check(sbom, vex, report, {
        "spec_version": d.getVar("CYCLONEDX_SPEC_VERSION"),
        "add_vuln_timestamps": d.getVar("CYCLONEDX_ADD_VULN_TIMESTAMPS") == "1",
        "include_unpatched_vulns": d.getVar("CYCLONEDX_INCLUDE_UNPATCHED_VULNS") == "1",
        "unpatched_vulns_state": d.getVar("CYCLONEDX_UNPATCHED_VULNS_STATE"),
    }, log=_cyclonedx_log)
    bb.note(f"Added {added} sbom-cve-check statements to the CycloneDX VEX")

    deploy_dir = d.getVar("CYCLONEDX_SBOM_CVE_CHECK_DEPLOYDIR")
    export_vex = os.path.join(deploy_dir, d.getVar("CYCLONEDX_EXPORT_SBOM_CVE_CHECK_VEX"))
    bb.utils.mkdirhier(os.path.dirname(export_vex))
    write_json(export_vex, vex)

    imagedata_dir = d.getVar("CYCLONEDX_SBOM_CVE_CHECK_IMAGEDATA_WORKDIR")
    bb.utils.mkdirhier(imagedata_dir)
    write_json(os.path.join(imagedata_dir, "vex.json"), vex)

    link = d.getVar("CYCLONEDX_EXPORT_VEX_LINK")
    if link:
        if os.path.isabs(link):
            link = os.path.relpath(link, d.getVar("CYCLONEDX_EXPORT_DIR"))
        link = os.path.join(deploy_dir, link)
        bb.utils.mkdirhier(os.path.dirname(link))
        os.symlink(os.path.relpath(export_vex, os.path.dirname(link)), link)
}

SSTATETASKS += "do_cyclonedx_sbom_cve_check"
do_cyclonedx_sbom_cve_check[cleandirs] = "${CYCLONEDX_SBOM_CVE_CHECK_DEPLOYDIR} ${CYCLONEDX_SBOM_CVE_CHECK_IMAGEDATA_WORKDIR}"
do_cyclonedx_sbom_cve_check[sstate-inputdirs] = "${CYCLONEDX_SBOM_CVE_CHECK_DEPLOYDIR} ${CYCLONEDX_SBOM_CVE_CHECK_IMAGEDATA_WORKDIR}"
do_cyclonedx_sbom_cve_check[sstate-outputdirs] = "${CYCLONEDX_EXPORT_DIR} ${CYCLONEDX_IMAGEDATA}/${SSTATE_PKGARCH}/${PN}/sbom-cve-check"
# The renderer module produces the documents; keep its contents in the
# task signatures of every task that executes it. BitBake encodes
# file-checksums entries as `path:exists` (cf. oe-core's SPDX3_DEP_FILES);
# the module is tracked in the layer, so it exists in every build.
do_populate_cyclonedx[file-checksums] += "${CYCLONEDX_LAYERDIR}/lib/meta_cyclonedx.py:True"
do_rootfs[file-checksums] += "${CYCLONEDX_LAYERDIR}/lib/meta_cyclonedx.py:True"
do_deploy_cyclonedx[file-checksums] += "${CYCLONEDX_LAYERDIR}/lib/meta_cyclonedx.py:True"
do_cyclonedx_sbom_cve_check[file-checksums] += "${CYCLONEDX_LAYERDIR}/lib/meta_cyclonedx.py:True"
python do_cyclonedx_sbom_cve_check_setscene() {
    sstate_setscene(d)
}
addtask do_cyclonedx_sbom_cve_check_setscene
