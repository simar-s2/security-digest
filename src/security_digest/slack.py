"""Posting to a Slack incoming webhook."""

import json
import urllib.error
import urllib.request


class SlackError(RuntimeError):
    pass


def post(webhook_url, text, blocks, timeout=10):
    body = json.dumps({"text": text, "blocks": blocks}).encode()
    req = urllib.request.Request(webhook_url, data=body, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        # Slack puts the reason (for example invalid_blocks) in the body, so a
        # rejected message is never silent.
        detail = e.read().decode("utf-8", "replace")
        raise SlackError(f"Slack rejected the message: HTTP {e.code}: {detail}") from e


def webhook_url(ssm, param_name):
    """The webhook URL, kept in an SSM SecureString so it never sits in Terraform state."""
    return ssm.get_parameter(Name=param_name, WithDecryption=True)["Parameter"]["Value"]
