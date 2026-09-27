"""Slack Block Kit messages for the daily digest and real-time alerts."""

from collections import Counter

SLACK_TEXT_MAX = 3000  # characters per text object
SLACK_MAX_BLOCKS = 50  # blocks per message
TITLE_WIDTH = 60


def cap(text):
    """Truncate a mrkdwn text to Slack's limit, keeping code fences balanced.

    One over-limit text object makes Slack reject the whole message with a 400.
    """
    if len(text) <= SLACK_TEXT_MAX:
        return text
    cut = text[: SLACK_TEXT_MAX - 40]
    if cut.count("```") % 2:  # cut inside a code block: close it
        cut += "\n```"
    return cut + "\n_…truncated_"


def sanitize(blocks):
    """Enforce Slack's limits on every text object and on the block count."""
    for block in blocks:
        text = block.get("text")
        if isinstance(text, dict) and isinstance(text.get("text"), str):
            text["text"] = cap(text["text"])
        for element in block.get("elements", []) or []:
            if isinstance(element, dict) and isinstance(element.get("text"), str):
                element["text"] = cap(element["text"])
    return blocks[:SLACK_MAX_BLOCKS]


def grouped_table(rows, max_rows, noun):
    """Monospace table of (title, label) rows grouped by title: count, title, labels.

    A control failing across a whole fleet reads as one line, not dozens. Most
    frequent first; past max_rows an "… and N more" line counts the rest.
    """
    groups = {}
    for title, label in rows:
        group = groups.setdefault(title, [0, set()])
        group[0] += 1
        group[1].add(label)
    ordered = sorted(groups.items(), key=lambda kv: (-kv[1][0], kv[0].lower()))
    lines = []
    for title, (count, labels) in ordered[:max_rows]:
        short = title[:TITLE_WIDTH] + ("…" if len(title) > TITLE_WIDTH else "")
        lines.append((str(count), short, ", ".join(sorted(labels))))
    w_count = max(len(c) for c, _, _ in lines)
    w_title = max(len(t) for _, t, _ in lines)
    text = [f"{c:>{w_count}}  {t:<{w_title}}  {labels}" for c, t, labels in lines]
    if len(groups) > max_rows:
        text.append(f"… and {len(groups) - max_rows} more distinct {noun}")
    return "```" + "\n".join(text) + "```"


def _section(text):
    return {"type": "section", "text": {"type": "mrkdwn", "text": text}}


def _plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def _console_link(region, label="Open Security Hub"):
    return f"<https://{region}.console.aws.amazon.com/securityhub/home?region={region}#/findings|{label}>"


def digest(settings, findings, names, cves=None, failed_runs=None, noncompliant=None):
    """Return (fallback_text, blocks) for the daily digest."""
    blocks = [{"type": "header", "text": {"type": "plain_text", "text": f"🛡️ {settings.title}", "emoji": True}}]
    severities = " + ".join(settings.severities)

    if findings:
        blocks.append(
            _section(f"*{_plural(len(findings), 'active new finding')}* ({severities}) across the organization.")
        )
        for severity, icon in (("CRITICAL", "🚨"), ("HIGH", "⚠️"), ("MEDIUM", "🔸"), ("LOW", "▫️")):
            rows = [(f.title, names.get(f.account_id, f.account_id)) for f in findings if f.severity == severity]
            if rows:
                blocks.append({"type": "divider"})
                blocks.append(
                    _section(
                        f"{icon} *{severity}: {_plural(len(rows), 'finding')}*\n"
                        + grouped_table(rows, settings.max_rows, "findings")
                    )
                )
        per_account = Counter(f.account_id for f in findings)
        blocks.append({"type": "divider"})
        blocks.append(
            _section("*By account:* " + ", ".join(f"*{names.get(a, a)}*: {n}" for a, n in per_account.most_common(10)))
        )
    else:
        blocks.append(_section(f"No active new {severities} findings. Quiet day ✅"))

    # Runs whatever the total above: a failed patch run is SSM.3, a LOW finding
    # that a CRITICAL/HIGH digest would otherwise never show.
    if failed_runs or noncompliant:
        lines = []
        if failed_runs:
            lines.append(
                f"🔴 *{sum(failed_runs.values())}* with a *failed patch run* (SSM.3): "
                + ", ".join(f"{names.get(a, a)}: {n}" for a, n in failed_runs.most_common(10))
            )
        if noncompliant:
            lines.append(
                f"• {sum(noncompliant.values())} missing patches (SSM.2): "
                + ", ".join(f"{names.get(a, a)}: {n}" for a, n in noncompliant.most_common(10))
            )
        blocks.append({"type": "divider"})
        blocks.append(_section("🩹 *Patch status*\n" + "\n".join(lines)))

    if cves and any(cves.values()):
        counts = ", ".join(f"{len(rows)} {s.lower()}" for s, rows in cves.items())
        text = f"🧪 *New CVEs, last 24 hours:* {counts} (newly pushed or newly scanned code)"
        for severity, rows in cves.items():
            if rows:
                text += f"\n*{severity.title()}*\n" + grouped_table(
                    [(title, label) for label, title in rows], settings.max_rows, "CVEs"
                )
        blocks.append({"type": "divider"})
        blocks.append(_section(text))

    footer = " · ".join(filter(None, [settings.footer, _console_link(settings.console_region)]))
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": footer}]})

    fallback = f"{settings.title}: {_plural(len(findings), 'active new finding')} ({severities})"
    return fallback, sanitize(blocks)


def alert(settings, finding):
    """Return (fallback_text, blocks) for one real-time finding."""
    severity = finding["Severity"]["Label"]
    account = finding.get("AwsAccountName") or finding["AwsAccountId"]
    region = finding.get("Region") or (finding.get("Resources") or [{}])[0].get("Region", "?")
    resource = (finding.get("Resources") or [{}])[0].get("Id", "?")
    title = finding.get("Title", "(no title)")
    text = (
        f"🚨 *{severity}: {title}*\n"
        f"*Account:* {account} ({finding['AwsAccountId']})  *Region:* {region}\n"
        f"*Resource:* `{resource}`\n"
        f"*Source:* {finding.get('ProductName', '?')}"
    )
    blocks = [
        _section(text),
        {"type": "context", "elements": [{"type": "mrkdwn", "text": _console_link(settings.console_region)}]},
    ]
    return f"{severity}: {title} in {account}", sanitize(blocks)
