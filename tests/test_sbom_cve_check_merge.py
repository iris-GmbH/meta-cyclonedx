"""sbom-cve-check report mapping onto an existing VEX document."""

import meta_cyclonedx

from helpers import TIMESTAMP, default_config, document, fragment, pkg

CPE_A = "cpe:2.3:*:*:openssl:3.2:*:*:*:*:*:*:*"


def sbom_with(components):
    return document("aaaa0000-0000-4000-8000-000000000000", components=components,
                    dependencies=[])


def report(packages):
    return {"package": packages}


def base_config(**overrides):
    return default_config(**overrides)


def test_ignored_issue_attaches_to_cpe_matched_component():
    sbom = sbom_with([pkg("openssl", "3.2", "ref-o", cpe=CPE_A)])
    vex = {"vulnerabilities": []}
    added = meta_cyclonedx.merge_sbom_cve_check(
        sbom, vex,
        report([{"name": "openssl", "cpes": [CPE_A],
                 "issue": [{"id": "CVE-2024-1", "status": "Ignored",
                            "detail": "not-applicable-config: feature off",
                            "description": "config disabled"}]}]),
        base_config())

    assert added == 1
    statement = vex["vulnerabilities"][0]
    assert statement["analysis"]["state"] == "not_affected"
    assert statement["analysis"]["justification"] == "code_not_present"
    assert "JUSTIFICATION: config disabled" in statement["analysis"]["detail"]
    prefix = f"urn:cdx:{sbom['serialNumber'].split(':')[-1]}/1#"
    assert statement["affects"] == [{"ref": prefix + "ref-o"}]


def test_issues_fall_back_to_the_recipe_purl_without_cpe_match():
    sbom = sbom_with([pkg("openssl", "3.2", "ref-o",
                          cpe="cpe:2.3:*:*:other:9:*:*:*:*:*:*:*",
                          purl="pkg:yocto/openssl@3.2-r0")])
    vex = {"vulnerabilities": []}
    added = meta_cyclonedx.merge_sbom_cve_check(
        sbom, vex,
        report([{"name": "openssl", "cpes": [CPE_A],
                 "issue": [{"id": "CVE-2024-2", "status": "Patched",
                            "detail": "fixed-by-backport"}]}]),
        base_config())

    assert added == 1
    assert vex["vulnerabilities"][0]["affects"] == [
        {"ref": f"urn:cdx:{sbom['serialNumber'].split(':')[-1]}/1#ref-o"}]


def test_patched_version_not_in_range_is_not_affected():
    sbom = sbom_with([pkg("busybox", "1.36", "ref-b")])
    vex = {"vulnerabilities": []}
    meta_cyclonedx.merge_sbom_cve_check(
        sbom, vex,
        report([{"name": "busybox", "cpes": [],
                 "issue": [{"id": "CVE-2024-3", "status": "Patched",
                            "detail": "version-not-in-range: fixed before 1.36"}]}]),
        base_config())

    assert vex["vulnerabilities"][0]["analysis"]["state"] == "not_affected"


def test_unpatched_requires_opt_in_and_configured_state():
    sbom = sbom_with([pkg("busybox", "1.36", "ref-b")])
    vex = {"vulnerabilities": []}
    report_doc = report([{"name": "busybox", "cpes": [],
                          "issue": [{"id": "CVE-2024-4", "status": "Unpatched",
                                     "detail": "pending"}]}])

    assert meta_cyclonedx.merge_sbom_cve_check(sbom, vex, report_doc, base_config()) == 0

    added = meta_cyclonedx.merge_sbom_cve_check(
        sbom, vex, report_doc,
        base_config(include_unpatched_vulns=True, unpatched_vulns_state="in_triage"))
    assert added == 1
    assert vex["vulnerabilities"][0]["analysis"]["state"] == "in_triage"


def test_already_covered_references_are_not_restated():
    sbom = sbom_with([pkg("busybox", "1.36", "ref-b")])
    prefix = f"urn:cdx:{sbom['serialNumber'].split(':')[-1]}/1#"
    vex = {"vulnerabilities": [{
        "id": "CVE-2024-5",
        "analysis": {"state": "resolved", "detail": "STATE: patched\n"},
        "affects": [{"ref": prefix + "ref-b"}],
    }]}

    added = meta_cyclonedx.merge_sbom_cve_check(
        sbom, vex,
        report([{"name": "busybox", "cpes": [],
                 "issue": [{"id": "CVE-2024-5", "status": "Patched",
                            "detail": "fixed"}]}]),
        base_config())

    assert added == 0
    assert len(vex["vulnerabilities"]) == 1


def test_one_statement_per_distinct_analysis():
    sbom = sbom_with([pkg("busybox", "1.36", "ref-b"),
                      pkg("bash", "5.2", "ref-s")])
    vex = {"vulnerabilities": []}
    added = meta_cyclonedx.merge_sbom_cve_check(
        sbom,
        vex,
        report([
            {"name": "busybox", "cpes": [],
             "issue": [{"id": "CVE-2024-6", "status": "Patched", "detail": "fixed-a"}]},
            {"name": "bash", "cpes": [],
             "issue": [{"id": "CVE-2024-6", "status": "Patched", "detail": "fixed-b"}]},
        ]),
        base_config())

    assert added == 2
    details = sorted(v["analysis"]["detail"] for v in vex["vulnerabilities"])
    assert details == ["STATE: fixed-a\n", "STATE: fixed-b\n"]


def test_timestamps_follow_configuration():
    sbom = sbom_with([pkg("busybox", "1.36", "ref-b")])
    vex = {"vulnerabilities": []}
    meta_cyclonedx.merge_sbom_cve_check(
        sbom, vex,
        report([{"name": "busybox", "cpes": [],
                 "issue": [{"id": "CVE-2024-7", "status": "Ignored",
                            "detail": "ignored"}]}]),
        base_config(add_vuln_timestamps=True))

    assert "firstIssued" in vex["vulnerabilities"][0]["analysis"]


def test_package_without_sbom_component_produces_nothing():
    sbom = sbom_with([pkg("busybox", "1.36", "ref-b")])
    vex = {"vulnerabilities": []}

    added = meta_cyclonedx.merge_sbom_cve_check(
        sbom, vex,
        report([{"name": "ghost", "cpes": ["cpe:2.3:*:*:ghost:1:*:*:*:*:*:*:*"],
                 "issue": [{"id": "CVE-2024-8", "status": "Patched",
                            "detail": "fixed"}]}]),
        base_config())

    assert added == 0
    assert vex["vulnerabilities"] == []
