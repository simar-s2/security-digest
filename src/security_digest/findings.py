"""Security Hub queries. Every function takes a boto3-style client, so tests and
the preview can pass the in-memory one from security_digest.local."""

from collections import Counter
from dataclasses import dataclass

MAX_ITEMS = 2000  # per query; the digest summarizes, it does not need every finding
ACTIVE_NEW = {
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
}


@dataclass(frozen=True)
class Finding:
    account_id: str
    region: str
    severity: str
    title: str


def _each(sh, filters):
    pages = sh.get_paginator("get_findings").paginate(Filters=filters, PaginationConfig={"MaxItems": MAX_ITEMS})
    for page in pages:
        yield from page["Findings"]


def _equals(field, values, comparison="EQUALS"):
    return {field: [{"Value": v, "Comparison": comparison} for v in values]}


def posture_findings(sh, settings, names):
    """Active, new findings at the chosen severities, minus the excluded products.

    Fills `names` with account names the findings carry.
    """
    filters = {
        **ACTIVE_NEW,
        **_equals("SeverityLabel", settings.severities),
        # Several NOT_EQUALS on one field are AND-ed by Security Hub.
        **_equals("ProductName", settings.excluded_products, "NOT_EQUALS"),
    }
    found = []
    for f in _each(sh, filters):
        if f.get("AwsAccountName"):
            names.setdefault(f["AwsAccountId"], f["AwsAccountName"])
        region = f.get("Region") or (f.get("Resources") or [{}])[0].get("Region", "?")
        found.append(Finding(f["AwsAccountId"], region, f["Severity"]["Label"], f.get("Title", "(no title)")))
    return found


def cve_label(finding):
    """repo:tag for container images, instance ID for EC2, the resource ID tail otherwise."""
    resource = (finding.get("Resources") or [{}])[0]
    image = (resource.get("Details") or {}).get("AwsEcrContainerImage")
    if image:
        tag = (image.get("ImageTags") or ["<untagged>"])[0]
        return f"{image.get('RepositoryName', '?')}:{tag}"
    return (resource.get("Id") or "?").split("/")[-1]


def new_cves(sh, severities=("CRITICAL", "HIGH")):
    """Inspector findings first seen in the last 24 hours, as {severity: [(resource, title)]}.

    With Inspector re-scanning on push, these track newly pushed images and
    packages, which is the part of the CVE backlog someone can act on today.
    """
    filters = {
        **ACTIVE_NEW,
        **_equals("ProductName", ["Inspector"]),
        **_equals("SeverityLabel", severities),
        "FirstObservedAt": [{"DateRange": {"Value": 1, "Unit": "DAYS"}}],
    }
    by_severity = {s: [] for s in severities}
    for f in _each(sh, filters):
        by_severity[f["Severity"]["Label"]].append((cve_label(f), f.get("Title", "(no title)")))
    return by_severity


def failed_control_by_account(sh, control_id, names):
    """Active, new, FAILED findings for one control, counted per account.

    Uses the exact control ID, so SSM.2 never matches SSM.20.
    """
    filters = {
        **ACTIVE_NEW,
        **_equals("ComplianceSecurityControlId", [control_id]),
        **_equals("ComplianceStatus", ["FAILED"]),
    }
    counts = Counter()
    for f in _each(sh, filters):
        counts[f["AwsAccountId"]] += 1
        if f.get("AwsAccountName"):
            names.setdefault(f["AwsAccountId"], f["AwsAccountName"])
    return counts


def fill_account_names(org, names, account_ids):
    """Best-effort names for accounts the findings did not name.

    Works from any delegated administrator account. Names are a nicety, so a
    failure here never stops the digest.
    """
    if all(a in names for a in account_ids):
        return
    try:
        for page in org.get_paginator("list_accounts").paginate():
            for account in page["Accounts"]:
                names.setdefault(account["Id"], account["Name"])
    except Exception:  # noqa: BLE001
        pass
