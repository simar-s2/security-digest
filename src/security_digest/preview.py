"""Render a digest from a fixture in the terminal, or print its Slack payload.

    python -m security_digest.preview fixtures/sample-findings.json
    python -m security_digest.preview fixtures/sample-findings.json --json

Runs the same query and formatting code as the Lambda, against the in-memory
Security Hub in security_digest.local, so it needs no AWS account.
"""

import argparse
import json
import re
import sys

from .handler import build_digest
from .local import load_fixture
from .settings import Settings

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"


def mrkdwn_to_terminal(text, color=True):
    """Slack mrkdwn to plain terminal text: *bold*, <url|label> links, ``` fences."""
    text = re.sub(r"<[^|>]+\|([^>]+)>", r"\1", text)
    if color:
        text = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", BOLD + r"\1" + RESET, text)
    else:
        text = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", r"\1", text)
    lines = []
    in_code = False
    for line in text.split("\n"):
        parts = line.split("```")
        for i, part in enumerate(parts):
            if i:
                in_code = not in_code
            if part:
                lines.append(("    " if in_code else "") + part)
    return "\n".join(lines)


def render(blocks, color=True, width=100):
    """Blocks as terminal text. Emoji variation selectors are dropped because
    terminals disagree about their width and overlap the next character."""
    out = []
    for block in blocks:
        kind = block["type"]
        if kind == "header":
            title = block["text"]["text"]
            out.append(f"{BOLD}{title}{RESET}" if color else title)
        elif kind == "divider":
            out.append("─" * width)
        elif kind == "section":
            out.append(mrkdwn_to_terminal(block["text"]["text"], color))
        elif kind == "context":
            text = " ".join(mrkdwn_to_terminal(e["text"], False) for e in block["elements"])
            out.append(f"{DIM}{text}{RESET}" if color else text)
    return "\n".join(out).replace("\ufe0f", "")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("fixture")
    parser.add_argument("--json", action="store_true", help="print the Slack payload instead")
    args = parser.parse_args(argv)

    sh, org = load_fixture(args.fixture)
    settings = Settings(footer="Example organization", console_region="us-east-1")
    text, blocks = build_digest(sh, org, settings)
    if args.json:
        json.dump({"text": text, "blocks": blocks}, sys.stdout, indent=2, ensure_ascii=False)
        print()
    else:
        print(render(blocks, color=sys.stdout.isatty()))


if __name__ == "__main__":
    main()
