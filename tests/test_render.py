from collections import Counter

from security_digest import render
from security_digest.findings import Finding


def test_cap_leaves_short_text_alone():
    assert render.cap("hello") == "hello"


def test_cap_closes_an_open_code_fence():
    text = "```" + "x" * 5000 + "```"
    capped = render.cap(text)
    assert len(capped) <= render.SLACK_TEXT_MAX
    assert capped.count("```") % 2 == 0
    assert capped.endswith("_…truncated_")


def test_sanitize_caps_every_text_and_the_block_count():
    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": "y" * 4000}}] * 60
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": "z" * 4000}]})
    out = render.sanitize([dict(b, text=dict(b["text"])) if "text" in b else b for b in blocks])
    assert len(out) == render.SLACK_MAX_BLOCKS
    assert all(len(b["text"]["text"]) <= render.SLACK_TEXT_MAX for b in out)


def test_grouped_table_groups_sorts_and_overflows():
    rows = (
        [("A control", "prod")] * 3
        + [("A control", "dev"), ("B control", "prod")]
        + [(f"Z{i}", "prod") for i in range(5)]
    )
    table = render.grouped_table(rows, max_rows=3, noun="findings")
    lines = table.strip("`").splitlines()
    assert lines[0].split()[:3] == ["4", "A", "control"] and lines[0].endswith("dev, prod")
    assert lines[1].startswith("1  B control")
    assert lines[-1] == "… and 4 more distinct findings"


def test_grouped_table_truncates_long_titles():
    table = render.grouped_table([("T" * 100, "prod")], 5, "findings")
    assert "T" * render.TITLE_WIDTH + "…" in table


def test_quiet_day(settings):
    text, blocks = render.digest(settings, [], {})
    assert "0 active new findings" in text
    assert "Quiet day" in blocks[1]["text"]["text"]


def test_digest_sections(settings):
    findings = [
        Finding("111122223333", "us-east-1", "CRITICAL", "S3.2 Public bucket"),
        Finding("111122223333", "us-east-1", "HIGH", "EC2.8 IMDSv2"),
        Finding("444455556666", "us-east-1", "HIGH", "EC2.8 IMDSv2"),
    ]
    names = {"111122223333": "prod"}
    _, blocks = render.digest(settings, findings, names, failed_runs=Counter({"111122223333": 2}))
    texts = [b["text"]["text"] for b in blocks if b["type"] == "section"]
    assert texts[0].startswith("*3 active new findings*")
    assert any(t.startswith("🚨 *CRITICAL: 1 finding*") for t in texts)
    assert any(t.startswith("⚠️ *HIGH: 2 findings*") and "444455556666, prod" in t for t in texts)
    assert any("*By account:* *prod*: 2, *444455556666*: 1" in t for t in texts)
    assert any("failed patch run* (SSM.3): prod: 2" in t for t in texts)
    assert blocks[-1]["type"] == "context"


def test_patch_status_shows_on_a_quiet_day(settings):
    _, blocks = render.digest(settings, [], {}, failed_runs=Counter({"777788889999": 1}))
    assert any("Patch status" in b.get("text", {}).get("text", "") for b in blocks)


def test_alert(settings, sample):
    finding = sample["findings"][0]
    text, blocks = render.alert(settings, finding)
    assert text.startswith("CRITICAL: IAM.6")
    assert "222233334444" in blocks[0]["text"]["text"]
