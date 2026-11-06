# Design notes

How security-digest gets findings into Slack, the choices I made, and what it costs.

## Architecture

```mermaid
flowchart LR
    subgraph org["Every account and region"]
        sources["GuardDuty, Inspector, Config rules,<br/>Security Hub controls"]
    end

    subgraph sec["Security Hub admin account, home region"]
        hub["Security Hub<br/>aggregated findings"]
        sched["EventBridge Scheduler<br/>weekdays 14:00"]
        rule["EventBridge rule (optional)<br/>new CRITICAL findings"]
        fn["Lambda<br/>security-digest"]
        param[("SSM SecureString<br/>Slack webhook URL")]
    end

    slack(["Slack channel"])

    sources --> hub
    sched -->|"daily"| fn
    hub -->|"Findings - Imported"| rule -->|"each finding"| fn
    fn -->|"GetFindings"| hub
    fn -->|"ListAccounts"| orgs["AWS Organizations"]
    fn --> param
    fn -->|"Block Kit message"| slack
```

It reads findings from the Security Hub delegated administrator's home region, where [org-security-baseline](https://github.com/simar-s2/org-security-baseline) aggregates every account and region, and patch data from [org-patch-manager](https://github.com/simar-s2/org-patch-manager) shows up through controls SSM.2 and SSM.3.

## What it does, in detail

Security Hub is the right place to collect findings, but few people open its console every day. This Lambda function posts a short digest to a Slack channel on a schedule:

- **Findings by severity, grouped by title.** CRITICAL and HIGH by default. A control that fails on 40 instances is one row with a count and the affected account names, not 40 lines. Each section is capped, with an "… and N more" line.
- **A per-account rollup**, using account names from the findings or from AWS Organizations.
- **Patch status** from controls SSM.2 (missing patches) and SSM.3 (failed patch runs). SSM.3 is LOW severity, so a CRITICAL/HIGH view would otherwise never show that a patch run is failing.
- **New CVEs from the last 24 hours**, from Amazon Inspector. The full CVE backlog stays in Security Hub; the digest shows what newly pushed images and packages introduced, which is what a team can act on today.
- **Real-time alerts (optional).** An EventBridge rule sends each new CRITICAL finding to the same channel as it arrives.

It never fails silently: Slack's rejection reason is logged and the function errors, and every message is kept inside Slack's Block Kit limits (3,000 characters per text, 50 blocks), so a long section can't get the whole digest rejected.

**Tech:** Python 3.13 (standard library plus boto3), AWS Lambda, EventBridge Scheduler and rules, Security Hub, Terraform (AWS provider 6), CloudFormation, pytest, ruff, GitHub Actions.

## Why it's built this way

- **Grouped by title, not listed.** In a real organization one misconfiguration usually fails across many resources. Grouping turns 200 findings into a table a person will read.
- **CVEs have their own section.** Tens of thousands of container CVE findings would drown the posture signal. They stay active in Security Hub as the backlog, and the digest shows only the ones first seen in the last 24 hours.
- **Patch findings are rolled up.** Patch Manager emits one finding per instance. The digest counts SSM.2 and SSM.3 per account instead, and the SSM.3 line appears even on a day with no CRITICAL or HIGH findings.
- **Real-time alerts skip what the digest covers.** The rule leaves out Inspector, Patch Manager and SSM.2 control findings by title prefix (they arrive as Security Hub control findings, so a product filter can't catch them), and only CRITICAL alerts by default: HIGH volume is better read once a day.
- **Old findings don't re-alert.** Security Hub re-imports a finding every time it's updated, so the function ignores findings created more than 24 hours earlier.
- **The webhook URL is a secret.** It lives in an SSM SecureString, and Terraform and CloudFormation only ever see the parameter name.
- **Tested without AWS.** `security_digest.local` is an in-memory Security Hub with the same filter semantics the queries rely on (EQUALS OR-ed, NOT_EQUALS AND-ed, date ranges), so the tests and the preview run the real query code.

## Cost

Effectively free for most organizations. The function runs for a few seconds once a day (well inside the Lambda free tier), EventBridge Scheduler's free tier covers the schedule, and `GetFindings` calls are not billed. The real-time rule adds one short invocation per new CRITICAL finding. Security Hub itself is billed separately (see [org-security-baseline](https://github.com/simar-s2/org-security-baseline#cost)).

## Project layout

```
src/security_digest/     the Lambda: handler, queries, Block Kit rendering, Slack, settings
src/security_digest/local.py    in-memory Security Hub and Organizations (tests, preview)
src/security_digest/preview.py  terminal preview
fixtures/                sample findings for the preview and tests
main.tf, variables.tf, … Terraform module
cloudformation/          CloudFormation template
scripts/deploy.sh        package, upload and deploy with CloudFormation
examples/                Terraform examples
tests/                   pytest suites and terraform test
```

## Testing

To get the Slack payload:

```bash
PYTHONPATH=src python3 -m security_digest.preview fixtures/sample-findings.json --json
```

Paste the `--json` output into Slack's [Block Kit Builder](https://app.slack.com/block-kit-builder) to see exactly how the message will look.
