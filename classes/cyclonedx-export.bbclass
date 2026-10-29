# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2022 BG Networks, Inc.
# SPDX-FileCopyrightText: Copyright (C) 2024 Savoir-faire Linux Inc. (<www.savoirfairelinux.com>).
# SPDX-FileCopyrightText: Copyright (C) 2026 iris-GmbH infrared & intelligent sensors.

# The product name that the CVE database uses.  Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"

# CycloneDX specification version to generate
# Options: "1.6", "1.7"
# Version 1.6: Modern format with enhanced features (default)
# Version 1.7: Latest version with advanced cryptography, IP transparency, and citations
CYCLONEDX_SPEC_VERSION ??= "1.6"

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

# Include unpatched vulnerabilities in VEX.
# If enabled, the cve-check class is inherited to query the NVD.
# Note that querying the NVD happens at the time of running the
# task, which currently requires rootfs generation. You may
# want to use external tools for regular analysis.
CYCLONEDX_INCLUDE_UNPATCHED_VULNS ??= "0"

# State to assign to unpatched vulnerabilities.
# Can be empty to omit the state field.
CYCLONEDX_UNPATCHED_VULNS_STATE ??= "in_triage"

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

CYCLONEDX_TMP_EXPORT_DIR = "${WORKDIR}/cyclonedx-export"
CYCLONEDX_EXPORT_DIR ??= "${DEPLOY_DIR}/cyclonedx-export"
CYCLONEDX_EXPORT_SBOM ??= "${CYCLONEDX_EXPORT_DIR}/bom.json"
CYCLONEDX_EXPORT_VEX ??= "${CYCLONEDX_EXPORT_DIR}/vex.json"
CYCLONEDX_PNDATA_WORKDIR = "${WORKDIR}/cyclonedx"
CYCLONEDX_PNDATA = "${TMPDIR}/cyclonedx/pn"
CYCLONEDX_IMAGEDATA_WORKDIR = "${WORKDIR}/cyclonedx-image"
# Multiconfigs may share TMPDIR while producing different variants of one image.
CYCLONEDX_IMAGEDATA = "${TMPDIR}/cyclonedx/image/${BB_CURRENT_MC}"

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

# If unpatched vulnerabilities are to be included, we need to inherit the cve-check class.
# This is because we rely on the `check_cves` function from that class to query the NVD.
inherit_defer ${@ "cve-check" if d.getVar("CYCLONEDX_INCLUDE_UNPATCHED_VULNS") == "1" else ""}

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

    # Validate renderer-relevant configuration; the supported CycloneDX
    # versions and image types are owned by the renderer.
    error = _cyclonedx_renderer(d).config_errors(
        d.getVar("CYCLONEDX_SPEC_VERSION"), d.getVar("CYCLONEDX_IMAGE_TYPE"))
    if error:
        bb.fatal(error)
}

python do_populate_cyclonedx() {
    """
    Collect package information and CVE data from all packages built for the target architecture.
    """
    from oe.cve_check import decode_cve_status
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
    spdx_purls = (d.getVar("SPDX_PACKAGE_URLS") or "").split()
    references = (generate_source_references(d)
                  if d.getVar("CYCLONEDX_ADD_COMPONENT_SOURCE_REFERENCES") == "1" else None)
    # scarthgap derives the product purl per CVE_PRODUCT name; newer
    # releases hand the renderer a single recipe-identity purl built by
    # oe.purl. The purl is a collected fact, so the derivation stays
    # here while the identity records are the renderer's.
    short_version = version.split("+git")[0]
    if not short_version or short_version.strip() == "":
        short_version = "unknown"

    # append all defined package names for recipe to pn_list pkgs
    # Iterate one CVE_PRODUCT name at a time: the purl fact is
    # name-specific on scarthgap, and the renderer mints the identity
    # records in this stable order.
    for product_token in sorted(set(name.split())):
        if ":" in product_token:
            vendor, product = product_token.split(":", 1)
        else:
            vendor, product = "", product_token
        if spdx_purls:
            purl = spdx_purls[0]
        else:
            purl = 'pkg:generic/{}{}@{}'.format(f"{vendor}/" if vendor else '', product, short_version)
        for pkg in renderer.component_identity(product_token, version, purl, references):
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

            # append any CVEs patched
            patched_cves = get_patched_cves(d)
            for cve_id in patched_cves:
                cve = (
                    cve_id,
                    "Patched",
                    "fix-file-included",
                    ""
                )
                renderer.add_status_vex_statement(
                    cve, cves, bom_ref, d.getVar("BPN"),
                    d.getVar('CYCLONEDX_SBOM_SERIAL_PLACEHOLDER'),
                    d.getVar('CYCLONEDX_ADD_VULN_TIMESTAMPS') == "1",
                    log=_cyclonedx_log)

            # in scarthgap the get_patched_cves function filters CVE_STATUS to only
            # include "Patched" decoded status, however we want "Ignored" statuses as well.
            for cve_id in (d.getVarFlags("CVE_STATUS") or {}):
                decoded_status, state, justification = decode_cve_status(d, cve_id)
                # avoid duplicates
                if decoded_status == "Patched":
                    continue
                cve = (
                    cve_id,
                    decoded_status,
                    state,
                    justification
                )
                if decoded_status == "Unpatched" and d.getVar("CYCLONEDX_INCLUDE_UNPATCHED_VULNS") == "1":
                    _add_unpatched_vex_statement(d, renderer, cve, cves, bom_ref)
                else:
                    renderer.add_status_vex_statement(
                        cve, cves, bom_ref, d.getVar("BPN"),
                        d.getVar('CYCLONEDX_SBOM_SERIAL_PLACEHOLDER'),
                        d.getVar('CYCLONEDX_ADD_VULN_TIMESTAMPS') == "1",
                        log=_cyclonedx_log)

            # The check_cves function is coming from the cve-check class
            # that we conditionally inherit to query the NVD. This
            # populate-time NVD query is scarthgap's legacy
            # implementation of the include-unpatched feature; newer
            # branches serve it through the sbom-cve-check class and its
            # renderer entry point, which does not exist here.
            if d.getVar("CYCLONEDX_INCLUDE_UNPATCHED_VULNS") == "1" and os.path.exists(d.getVar("CVE_CHECK_DB_FILE")):
                with bb.utils.fileslocked([d.getVar("CVE_CHECK_DB_FILE_LOCK")], shared=True):
                    bb.debug(2, f"Querying CVE database for unpatched CVEs for package {pn}")

                    # Turn off warnings and restore afterwards
                    cve_check_show_warnings_original = d.getVar("CVE_CHECK_SHOW_WARNINGS")
                    d.setVar("CVE_CHECK_SHOW_WARNINGS", "0")
                    _, _, unpatched_cve_ids, _ = check_cves(d, patched_cves)
                    d.setVar("CVE_CHECK_SHOW_WARNINGS", cve_check_show_warnings_original)
                    bb.debug(2, f"Found {len(unpatched_cve_ids)} unpatched CVEs for package {pn}")
                    for cve_id in unpatched_cve_ids:
                        cve = (
                            cve_id,
                            "Unpatched",
                            "no-fix-supplied",
                            ""
                        )
                        _add_unpatched_vex_statement(d, renderer, cve, cves, bom_ref)

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
# The renderer module produces the documents; keep its contents in the
# task signatures of every task that executes it. BitBake encodes
# file-checksums entries as `path:exists` (cf. oe-core's SPDX3_DEP_FILES);
# the module is tracked in the layer, so it exists in every build.
do_populate_cyclonedx[file-checksums] += "${CYCLONEDX_LAYERDIR}/lib/meta_cyclonedx.py:True"

python do_populate_cyclonedx_setscene() {
    sstate_setscene(d)
}
addtask do_populate_cyclonedx_setscene

# We cannot set nostamp on do_populate_cyclonedx conditionally due to YP bug #13808.
# Instead, we conditionally include a file.
require ${@ "include/include-unpatched.inc" if d.getVar("CYCLONEDX_INCLUDE_UNPATCHED_VULNS") == "1" else ""}

do_rootfs[recrdeptask] += "do_populate_cyclonedx"
do_rootfs[file-checksums] += "${CYCLONEDX_LAYERDIR}/lib/meta_cyclonedx.py:True"

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

    license_info = []
    # Check if the license is a complex expression
    if "(" in licenses or ")" in licenses or " OR " in licenses or (split_expressions != "1" and " AND " in licenses):
        bb.debug(2, f"Adding {licenses} as expression.")
        license_info.append({"expression": licenses})
        license_info[-1]["acknowledgement"] = "declared"
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
            "url": f"{public_remote_url}@{rev}",
            "type": "vcs",
            "comment": f"Yocto metadata layer {name}{' with uncommitted changes' if ismodified else ''}"
        }
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
        "bzr", "ccrc", "cvs", "git", "gitannex", "gitsm",
        "hg", "osc", "p4", "repo", "svn"
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

            references.append(reference)
    finally:
        if no_network is None:
            d.delVar("BB_NO_NETWORK")
        else:
            d.setVar("BB_NO_NETWORK", no_network)
    return references

def _add_unpatched_vex_statement(d, renderer, cve, cves, bom_ref):
    """
    Map one populate-time "Unpatched" CVE status to a VEX statement.

    scarthgap queries the NVD from do_populate_cyclonedx because this
    branch predates the sbom-cve-check class through which the renderer's
    merge_sbom_cve_check entry maps unpatched issues on newer branches.
    The renderer module is byte-identical across the branches and is not
    edited for this feature (ADR-0014), so the legacy mapping stays on
    the adapter side, mirroring that entry's treatment of unpatched
    issues statement for statement.
    """
    from datetime import datetime, timezone

    cve_id, _, status, justification = cve
    normalized_cve_id = renderer.normalize_cve_id(cve_id)
    bb.debug(2, f"Found unpatched status for {normalized_cve_id} in {d.getVar('BPN')}")

    placeholder = d.getVar("CYCLONEDX_SBOM_SERIAL_PLACEHOLDER")

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
                existing_cve["affects"].append({"ref": f"urn:cdx:{placeholder}/1#{bom_ref}"})
            return

    detail_string = ""
    if status:
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
    vex_state = d.getVar("CYCLONEDX_UNPATCHED_VULNS_STATE")
    if vex_state:
        analysis["state"] = vex_state

    # Add timestamps when enabled
    if d.getVar("CYCLONEDX_ADD_VULN_TIMESTAMPS") == "1":
        timestamp = datetime.now(timezone.utc).isoformat()
        analysis["firstIssued"] = timestamp
        analysis["lastUpdated"] = timestamp

    cves.append({
        "id": normalized_cve_id,
        # vex documents require a valid source, see https://github.com/DependencyTrack/dependency-track/issues/2977
        # this should always be NVD for yocto CVEs.
        "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{normalized_cve_id}"},
        "analysis": analysis,
        "affects": [{"ref": f"urn:cdx:{placeholder}/1#{bom_ref}"}]
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
    write_json(os.path.join(imagedata_dir, "manifest.json"), {
        "sbom": "bom.json",
        "vex": "vex.json",
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

    # Extra runtime recipes are runtime content and direct image-install
    # intent. (scarthgap's component-scope test matched extra recipes
    # explicitly; the renderer derives the scope from this fact.)
    runtime_recipes = set(runtime_recipes) | extra_recipes
    image_install_recipes = set(image_install_recipes).union(extra_recipes)

    # Load the per-recipe facts written by do_populate_cyclonedx. They are
    # plain JSON fragments; the renderer never sees the data store.
    fragments = {}
    pkgarchs = d.getVar("SSTATE_ARCHS").split()
    pkgarchs.reverse()

    if "all" not in pkgarchs:
        pkgarchs.append("all")

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
do_deploy_cyclonedx[file-checksums] += "${CYCLONEDX_LAYERDIR}/lib/meta_cyclonedx.py:True"
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
        bb.build.addtask("do_cyclonedx_complete", "do_build", "do_deploy_cyclonedx", d)
        pn = d.getVar("PN")
        for img in (d.getVar("CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES") or "").split():
            if img != pn:
                d.appendVarFlag("do_rootfs", "depends", f" {img}:do_cyclonedx_complete")
}

