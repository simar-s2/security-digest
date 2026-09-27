import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from security_digest.local import LocalOrganizations, LocalSecurityHub
from security_digest.settings import Settings

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "sample-findings.json"
NOW = datetime(2026, 9, 1, 14, 0, tzinfo=UTC)


@pytest.fixture
def sample():
    return json.loads(FIXTURE.read_text())


@pytest.fixture
def sh(sample):
    return LocalSecurityHub(sample["findings"], now=NOW)


@pytest.fixture
def org(sample):
    return LocalOrganizations(sample["accounts"])


@pytest.fixture
def settings():
    return Settings(webhook_param="/security-digest/slack-webhook", console_region="us-east-1")
