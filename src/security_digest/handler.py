"""Lambda entry point.

A scheduled event (EventBridge Scheduler) sends the daily digest. A
"Security Hub Findings - Imported" event (EventBridge rule, optional) sends a
real-time alert for each new finding in it.
"""

import logging
from datetime import UTC, datetime, timedelta

from . import findings, render, slack
from .settings import Settings

log = logging.getLogger()
log.setLevel(logging.INFO)

FINDINGS_IMPORTED = "Security Hub Findings - Imported"


def build_digest(sh, org, settings):
    """Query Security Hub and return (fallback_text, blocks)."""
    names = {}
    posture = findings.posture_findings(sh, settings, names)
    failed_runs = noncompliant = None
    if settings.include_patch_status:
        failed_runs = findings.failed_control_by_account(sh, "SSM.3", names)
        noncompliant = findings.failed_control_by_account(sh, "SSM.2", names)
    cves = findings.new_cves(sh) if settings.include_new_cves else None
    accounts = {f.account_id for f in posture} | set(failed_runs or {}) | set(noncompliant or {})
    findings.fill_account_names(org, names, accounts)
    return render.digest(settings, posture, names, cves, failed_runs, noncompliant)


def recent(finding, max_age_hours, now=None):
    now = now or datetime.now(UTC)
    created = datetime.fromisoformat(finding.get("CreatedAt", "").replace("Z", "+00:00") or now.isoformat())
    return now - created <= timedelta(hours=max_age_hours)


def handler(event, context, clients=None, settings=None):
    settings = settings or Settings.from_env()
    if clients is None:
        import boto3  # only here, so tests and the preview never need AWS credentials

        clients = {name: boto3.client(name) for name in ("securityhub", "organizations", "ssm")}
    url = slack.webhook_url(clients["ssm"], settings.webhook_param)

    if event.get("detail-type") == FINDINGS_IMPORTED:
        sent = 0
        for finding in event["detail"].get("findings", []):
            if not recent(finding, settings.alert_max_age_hours):
                continue  # an old finding re-imported after an update
            slack.post(url, *render.alert(settings, finding))
            sent += 1
        log.info("sent %d real-time alert(s)", sent)
        return {"alerts": sent}

    text, blocks = build_digest(clients["securityhub"], clients["organizations"], settings)
    slack.post(url, text, blocks)
    log.info("sent digest: %s", text)
    return {"digest": text}
