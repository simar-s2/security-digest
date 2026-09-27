"""In-memory stand-ins for the Security Hub and Organizations clients.

They answer get_findings with the filter semantics the digest relies on
(EQUALS values OR-ed, NOT_EQUALS values AND-ed, DateRange in days), so the
tests and the preview exercise the real query code without AWS.
"""

import json
import re
from datetime import UTC, datetime, timedelta

FIELDS = {
    "RecordState": lambda f: f.get("RecordState"),
    "WorkflowStatus": lambda f: f.get("Workflow", {}).get("Status"),
    "SeverityLabel": lambda f: f.get("Severity", {}).get("Label"),
    "ProductName": lambda f: f.get("ProductName"),
    "ComplianceSecurityControlId": lambda f: f.get("Compliance", {}).get("SecurityControlId"),
    "ComplianceStatus": lambda f: f.get("Compliance", {}).get("Status"),
    "FirstObservedAt": lambda f: f.get("FirstObservedAt"),
}
RELATIVE = re.compile(r"^now-(\d+)([hd])$")


def resolve_times(finding, now):
    """Turn "now-3h" / "now-2d" timestamps in fixtures into ISO timestamps."""
    for key in ("FirstObservedAt", "CreatedAt", "UpdatedAt"):
        match = RELATIVE.match(str(finding.get(key, "")))
        if match:
            amount, unit = int(match[1]), match[2]
            delta = timedelta(hours=amount) if unit == "h" else timedelta(days=amount)
            finding[key] = (now - delta).isoformat().replace("+00:00", "Z")
    return finding


def _matches(finding, filters, now):
    for field, conditions in filters.items():
        value = FIELDS[field](finding)
        equals = [c["Value"] for c in conditions if c.get("Comparison") == "EQUALS"]
        not_equals = [c["Value"] for c in conditions if c.get("Comparison") == "NOT_EQUALS"]
        ranges = [c["DateRange"] for c in conditions if "DateRange" in c]
        if equals and value not in equals:
            return False
        if value in not_equals:
            return False
        for r in ranges:
            observed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if now - observed > timedelta(days=r["Value"]):
                return False
    return True


class _Pages:
    def __init__(self, fetch):
        self._fetch = fetch

    def paginate(self, **kwargs):
        yield self._fetch(**kwargs)


class LocalSecurityHub:
    def __init__(self, findings, now=None):
        self.now = now or datetime.now(UTC)
        self.findings = [resolve_times(dict(f), self.now) for f in findings]
        self.queries = []

    def get_paginator(self, name):
        assert name == "get_findings"
        return _Pages(self._get_findings)

    def _get_findings(self, Filters, PaginationConfig=None):
        self.queries.append(Filters)
        limit = (PaginationConfig or {}).get("MaxItems")
        matched = [f for f in self.findings if _matches(f, Filters, self.now)]
        return {"Findings": matched[:limit]}


class LocalOrganizations:
    def __init__(self, accounts, fail=False):
        self.accounts = accounts
        self.fail = fail

    def get_paginator(self, name):
        assert name == "list_accounts"
        return _Pages(self._list_accounts)

    def _list_accounts(self):
        if self.fail:
            raise RuntimeError("AccessDeniedException")
        return {"Accounts": [{"Id": i, "Name": n} for i, n in self.accounts.items()]}


def load_fixture(path, now=None):
    """(LocalSecurityHub, LocalOrganizations) from a fixture file."""
    with open(path) as f:
        data = json.load(f)
    return LocalSecurityHub(data["findings"], now), LocalOrganizations(data.get("accounts", {}))
