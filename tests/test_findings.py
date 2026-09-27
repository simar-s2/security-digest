from security_digest import findings


def test_posture_excludes_products_severities_and_resolved(sh, settings):
    names = {}
    found = findings.posture_findings(sh, settings, names)
    products = {f.title for f in found}
    assert len(found) == 12
    assert not any("missing 4 approved patches" in t for t in products)  # Patch Manager
    assert not any(t.startswith("CVE-") for t in products)  # Inspector
    assert not any(t.startswith("CloudTrail.2") for t in products)  # MEDIUM
    assert not any(t.startswith("EC2.18") for t in products)  # RESOLVED
    assert names["111122223333"] == "prod"
    assert "222233334444" not in names  # that finding had no account name


def test_new_cves_only_last_24_hours(sh):
    cves = findings.new_cves(sh)
    assert sorted(cves["CRITICAL"]) == [
        ("api:1.42.0", "CVE-2024-6387 - openssh"),
        ("api:1.43.0-rc1", "CVE-2024-6387 - openssh"),
    ]
    assert cves["HIGH"] == [("worker:3.1.2", "CVE-2023-44487 - nghttp2")]


def test_control_counts_use_the_exact_id(sh):
    names = {}
    assert dict(findings.failed_control_by_account(sh, "SSM.2", names)) == {"111122223333": 2, "777788889999": 1}
    assert dict(findings.failed_control_by_account(sh, "SSM.3", names)) == {"777788889999": 1}
    assert dict(findings.failed_control_by_account(sh, "SSM", names)) == {}


def test_cve_label_falls_back_to_the_resource_id():
    assert findings.cve_label({"Resources": [{"Id": "arn:aws:ec2:us-east-1:1:instance/i-0abc"}]}) == "i-0abc"
    assert findings.cve_label({}) == "?"


def test_account_names_from_organizations(org):
    names = {"111122223333": "prod"}
    findings.fill_account_names(org, names, {"111122223333", "222233334444"})
    assert names["222233334444"] == "shared-services"
    assert names["111122223333"] == "prod"


def test_organizations_failure_never_breaks_the_digest(sample):
    from security_digest.local import LocalOrganizations

    names = {}
    findings.fill_account_names(LocalOrganizations({}, fail=True), names, {"222233334444"})
    assert names == {}
