import io
import json
import urllib.error
from datetime import UTC, datetime, timedelta

import pytest

from security_digest import handler as handler_module
from security_digest.local import LocalSecurityHub
from security_digest.slack import SlackError


class FakeSSM:
    def get_parameter(self, Name, WithDecryption):
        assert WithDecryption
        return {"Parameter": {"Value": "https://hooks.slack.example/services/T000/B000/XXXX"}}


@pytest.fixture
def posted(monkeypatch):
    sent = []

    def urlopen(req, timeout):
        sent.append(json.loads(req.data))

    monkeypatch.setattr(handler_module.slack.urllib.request, "urlopen", urlopen)
    return sent


def test_scheduled_event_sends_one_digest(sh, org, settings, posted):
    result = handler_module.handler(
        {"source": "scheduler"},
        None,
        clients={"securityhub": sh, "organizations": org, "ssm": FakeSSM()},
        settings=settings,
    )
    (payload,) = posted
    assert payload["text"] == result["digest"]
    assert payload["blocks"][0]["type"] == "header"
    assert len(payload["blocks"]) <= 50


def test_patch_and_cve_sections_can_be_turned_off(sh, org, settings, posted):
    from dataclasses import replace

    handler_module.handler(
        {},
        None,
        clients={"securityhub": sh, "organizations": org, "ssm": FakeSSM()},
        settings=replace(settings, include_patch_status=False, include_new_cves=False),
    )
    text = json.dumps(posted[0])
    assert "Patch status" not in text and "New CVEs" not in text


def finding_event(*findings):
    return {"detail-type": "Security Hub Findings - Imported", "detail": {"findings": list(findings)}}


def test_real_time_alert_for_new_findings_only(sample, org, settings, posted):
    now = datetime.now(UTC)
    new = dict(sample["findings"][0], CreatedAt=(now - timedelta(minutes=5)).isoformat())
    old = dict(sample["findings"][1], CreatedAt=(now - timedelta(days=3)).isoformat())
    result = handler_module.handler(
        finding_event(new, old),
        None,
        clients={"securityhub": None, "organizations": org, "ssm": FakeSSM()},
        settings=settings,
    )
    assert result == {"alerts": 1}
    assert posted[0]["text"].startswith("CRITICAL: IAM.6")


def test_slack_rejection_is_raised_with_its_reason(sh, org, settings, monkeypatch):
    def reject(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 400, "Bad Request", {}, io.BytesIO(b"invalid_blocks"))

    monkeypatch.setattr(handler_module.slack.urllib.request, "urlopen", reject)
    with pytest.raises(SlackError, match="HTTP 400: invalid_blocks"):
        handler_module.handler(
            {}, None, clients={"securityhub": sh, "organizations": org, "ssm": FakeSSM()}, settings=settings
        )


def test_settings_from_env():
    from security_digest.settings import Settings

    s = Settings.from_env(
        {
            "WEBHOOK_PARAM": "/x",
            "SEVERITIES": "CRITICAL",
            "INCLUDE_NEW_CVES": "false",
            "MAX_ROWS": "5",
            "AWS_REGION": "eu-west-1",
        }
    )
    assert (s.webhook_param, s.severities, s.include_new_cves, s.max_rows, s.console_region) == (
        "/x",
        ["CRITICAL"],
        False,
        5,
        "eu-west-1",
    )


def test_empty_security_hub_is_a_quiet_day(org, settings, posted):
    handler_module.handler(
        {},
        None,
        clients={"securityhub": LocalSecurityHub([]), "organizations": org, "ssm": FakeSSM()},
        settings=settings,
    )
    assert "Quiet day" in json.dumps(posted[0], ensure_ascii=False)
