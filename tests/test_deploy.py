"""scripts/deploy.sh against the fake AWS CLI in tests/fake-aws."""

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def deploy(tmp_path, *args, bucket_exists=False, region="eu-west-1"):
    log = tmp_path / "aws.jsonl"
    env = {
        "PATH": f"{ROOT / 'tests' / 'fake-aws'}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "FAKE_AWS_LOG": str(log),
        "FAKE_REGION": region,
        "FAKE_BUCKET_EXISTS": "1" if bucket_exists else "0",
    }
    proc = subprocess.run([str(ROOT / "scripts" / "deploy.sh"), *args], env=env, capture_output=True, text=True)
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return proc, calls


def find(calls, word):
    return [c for c in calls if word in c]


def test_creates_the_bucket_uploads_and_deploys(tmp_path):
    proc, calls = deploy(
        tmp_path, "--webhook-param", "/security-digest/slack-webhook", "--param", "RealtimeAlerts=true"
    )
    assert proc.returncode == 0, proc.stderr
    (create,) = find(calls, "create-bucket")
    assert "LocationConstraint=eu-west-1" in create
    assert create[create.index("--bucket") + 1] == "sec-artifacts-333344445555-eu-west-1"
    (upload,) = find(calls, "cp")
    key = upload[-1].split("/", 3)[3]
    assert key.startswith("security-digest/") and key.endswith(".zip")
    (stack,) = find(calls, "deploy")
    overrides = stack[stack.index("--parameter-overrides") + 1 :]
    assert f"CodeKey={key}" in overrides
    assert "WebhookParameterName=/security-digest/slack-webhook" in overrides
    assert overrides[-1] == "RealtimeAlerts=true"


def test_package_contains_only_the_code(tmp_path):
    import zipfile

    deploy(tmp_path, "--webhook-param", "/x", bucket_exists=True)
    names = zipfile.ZipFile(ROOT / "build" / "security-digest.zip").namelist()
    assert "security_digest/handler.py" in names
    assert not any("__pycache__" in n or n.startswith("tests") for n in names)


def test_same_code_same_key(tmp_path):
    _, first = deploy(tmp_path, "--webhook-param", "/x", bucket_exists=True)
    (tmp_path / "aws.jsonl").unlink()
    _, second = deploy(tmp_path, "--webhook-param", "/x", bucket_exists=True)
    assert find(first, "cp")[0][-1] == find(second, "cp")[0][-1]
    assert find(second, "create-bucket") == []


def test_us_east_1_has_no_location_constraint(tmp_path):
    _, calls = deploy(tmp_path, "--webhook-param", "/x", region="us-east-1")
    (create,) = find(calls, "create-bucket")
    assert not any("LocationConstraint" in a for a in create)


def test_requires_the_webhook_parameter(tmp_path):
    proc, calls = deploy(tmp_path)
    assert proc.returncode == 2 and calls == []
