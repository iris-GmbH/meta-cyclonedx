#!/usr/bin/env python3
"""
Validation script for CycloneDX 1.6 SBOM/VEX generation

This script validates that the generated SBOM and VEX files conform to
CycloneDX 1.6 specification requirements.

Usage:
    python3 validate_cyclonedx_1_6.py <path_to_bom.json> <path_to_vex.json>
"""

import json
import sys
from pathlib import Path


def validate_version_and_format(doc, doc_type):
    """Validate basic CycloneDX 1.6 structure"""
    errors = []

    # Check bomFormat
    if doc.get("bomFormat") != "CycloneDX":
        errors.append(f"{doc_type}: bomFormat must be 'CycloneDX'")

    # Check specVersion
    if doc.get("specVersion") != "1.6":
        errors.append(
            f"{doc_type}: specVersion must be '1.6', got '{doc.get('specVersion')}'"
        )

    # Check serialNumber format
    serial = doc.get("serialNumber", "")
    if not serial.startswith("urn:uuid:"):
        errors.append(f"{doc_type}: serialNumber must start with 'urn:uuid:'")

    # Check version
    if not isinstance(doc.get("version"), int) or doc.get("version") < 1:
        errors.append(f"{doc_type}: version must be an integer >= 1")

    return errors


def validate_metadata_tools(doc, doc_type):
    """Validate metadata.tools structure for 1.6"""
    errors = []

    metadata = doc.get("metadata", {})
    tools = metadata.get("tools")

    if not tools:
        errors.append(f"{doc_type}: metadata.tools is required")
        return errors

    # In 1.6, tools should be an object with components array
    if isinstance(tools, list):
        errors.append(
            f"{doc_type}: metadata.tools should be an object with 'components' array (legacy array format is deprecated)"
        )
    elif isinstance(tools, dict):
        components = tools.get("components")
        if not isinstance(components, list):
            errors.append(f"{doc_type}: metadata.tools.components must be an array")
        elif len(components) == 0:
            errors.append(f"{doc_type}: metadata.tools.components should not be empty")
        else:
            # Validate each component
            for idx, comp in enumerate(components):
                if not comp.get("type"):
                    errors.append(
                        f"{doc_type}: metadata.tools.components[{idx}] missing 'type'"
                    )
                if not comp.get("name"):
                    errors.append(
                        f"{doc_type}: metadata.tools.components[{idx}] missing 'name'"
                    )

    return errors


def validate_component_scopes(sbom):
    """Validate component scope fields"""
    errors = []
    warnings = []

    components = sbom.get("components", [])
    valid_scopes = {"required", "optional", "excluded"}

    required_count = 0
    excluded_count = 0
    no_scope_count = 0

    for idx, comp in enumerate(components):
        scope = comp.get("scope")

        if scope is None:
            no_scope_count += 1
            warnings.append(
                f"Component '{comp.get('name')}' has no scope (will default to 'required')"
            )
        elif scope not in valid_scopes:
            errors.append(
                f"Component '{comp.get('name')}' has invalid scope '{scope}'. Must be one of {valid_scopes}"
            )
        elif scope == "required":
            required_count += 1
        elif scope == "excluded":
            excluded_count += 1

    print("  Component scope statistics:")
    print(f"    - Required: {required_count}")
    print(f"    - Excluded: {excluded_count}")
    print(f"    - No scope: {no_scope_count}")

    return errors, warnings


def validate_vulnerability_analysis(vex):
    """Validate vulnerability analysis structure for 1.6"""
    errors = []
    warnings = []

    vulnerabilities = vex.get("vulnerabilities", [])

    has_timestamps = 0
    missing_timestamps = 0

    for _, vuln in enumerate(vulnerabilities):
        analysis = vuln.get("analysis", {})

        # Check for 1.6 timestamp fields
        if "firstIssued" in analysis and "lastUpdated" in analysis:
            has_timestamps += 1
        else:
            missing_timestamps += 1
            warnings.append(
                f"Vulnerability '{vuln.get('id')}' analysis missing timestamp fields (optional in 1.6)"
            )

        # Validate state
        valid_states = {
            "resolved",
            "resolved_with_pedigree",
            "exploitable",
            "in_triage",
            "false_positive",
            "not_affected",
        }
        state = analysis.get("state")
        if state and state not in valid_states:
            errors.append(
                f"Vulnerability '{vuln.get('id')}' has invalid analysis state '{state}'"
            )

    print("  Vulnerability timestamp statistics:")
    print(f"    - With timestamps: {has_timestamps}")
    print(f"    - Without timestamps: {missing_timestamps}")

    return errors, warnings


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)

    sbom_path = Path(sys.argv[1])
    vex_path = Path(sys.argv[2])

    if not sbom_path.exists():
        print(f"Error: SBOM file not found: {sbom_path}")
        sys.exit(1)

    if not vex_path.exists():
        print(f"Error: VEX file not found: {vex_path}")
        sys.exit(1)

    # Load documents
    try:
        with open(sbom_path) as f:
            sbom = json.load(f)
        with open(vex_path) as f:
            vex = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}")
        sys.exit(1)

    all_errors = []
    all_warnings = []

    # Validate SBOM
    print("Validating SBOM (bom.json)...")
    all_errors.extend(validate_version_and_format(sbom, "SBOM"))
    all_errors.extend(validate_metadata_tools(sbom, "SBOM"))

    scope_errors, scope_warnings = validate_component_scopes(sbom)
    all_errors.extend(scope_errors)
    all_warnings.extend(scope_warnings)

    # Validate VEX
    print("\nValidating VEX (vex.json)...")
    all_errors.extend(validate_version_and_format(vex, "VEX"))
    all_errors.extend(validate_metadata_tools(vex, "VEX"))

    vuln_errors, vuln_warnings = validate_vulnerability_analysis(vex)
    all_errors.extend(vuln_errors)
    all_warnings.extend(vuln_warnings)

    # Report results
    print("\n" + "=" * 70)
    if all_errors:
        print(f"❌ VALIDATION FAILED: {len(all_errors)} error(s) found")
        for error in all_errors:
            print(f"  ERROR: {error}")
        exit_code = 1
    else:
        print("✅ VALIDATION PASSED: All CycloneDX 1.6 requirements met")
        exit_code = 0

    if all_warnings:
        print(f"\n⚠️  {len(all_warnings)} warning(s):")
        for warning in all_warnings:
            print(f"  WARNING: {warning}")

    print("=" * 70)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
