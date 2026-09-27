import json

from security_digest import preview
from security_digest.render import SLACK_MAX_BLOCKS

from .conftest import FIXTURE


def test_preview_renders_the_fixture(capsys):
    preview.main([str(FIXTURE)])
    out = capsys.readouterr().out
    assert out.startswith("🛡 AWS security daily digest")
    assert "shared-services" in out  # name filled in from Organizations
    assert "\033[" not in out  # no colors when not a terminal


def test_preview_json_is_a_valid_payload(capsys):
    preview.main([str(FIXTURE), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert set(payload) == {"text", "blocks"}
    assert len(payload["blocks"]) <= SLACK_MAX_BLOCKS


def test_mrkdwn_links_and_bold():
    assert preview.mrkdwn_to_terminal("*a* <https://x|Open>", color=False) == "a Open"
