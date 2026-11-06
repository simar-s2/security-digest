# Setup

Every way to deploy it, and every option. The short version is in the [README](../README.md).

## Deploy

Create a Slack [incoming webhook](https://api.slack.com/messaging/webhooks) and store it in the security account, in the Security Hub home region. Keeping it in SSM keeps the URL out of Terraform state and CloudFormation parameters:

```bash
aws ssm put-parameter --name /security-digest/slack-webhook --type SecureString \
  --value "https://hooks.slack.com/services/..."
```

### Terraform

```hcl
module "security_digest" {
  source = "git::https://github.com/simar-s2/security-digest.git?ref=v0.1.0"

  webhook_parameter_name = "/security-digest/slack-webhook"
  schedule_timezone      = "America/New_York"
  schedule_expression    = "cron(0 9 ? * MON-FRI *)"
  realtime_alerts        = true      # optional
}
```

### CloudFormation

```bash
git clone https://github.com/simar-s2/security-digest && cd security-digest
scripts/deploy.sh --profile security --region us-east-1 --webhook-param /security-digest/slack-webhook
```

The script zips `src/`, uploads it to an artifact bucket (created if missing, with public access blocked) under a content-hash key, and deploys the stack.

Send a digest right away with `aws lambda invoke --function-name sec-security-digest /dev/stdout`.

## Configuration

### Terraform inputs

| Name | Type | Default | Description |
|---|---|---|---|
| `webhook_parameter_name` | `string` | required | SSM SecureString with the webhook URL |
| `webhook_kms_key_arn` | `string` | `null` | Customer managed key of that parameter, if any |
| `name_prefix` | `string` | `sec` | Prefix for every name |
| `schedule_expression` | `string` | `cron(0 14 ? * MON-FRI *)` | When the digest is sent |
| `schedule_timezone` | `string` | `UTC` | IANA time zone of the schedule |
| `title` | `string` | `AWS security daily digest` | Message heading |
| `severities` | `list(string)` | `["CRITICAL", "HIGH"]` | Severities in the main tables |
| `excluded_products` | `list(string)` | Inspector, Patch Manager | Kept out of the main tables (they have their own sections) |
| `max_rows` | `number` | `15` | Rows per section before "… and N more" |
| `include_new_cves` | `bool` | `true` | New Inspector CVEs section |
| `include_patch_status` | `bool` | `true` | SSM.2 / SSM.3 patch section |
| `footer` | `string` | `""` | Text before the console link |
| `realtime_alerts` | `bool` | `false` | EventBridge rule for real-time alerts |
| `realtime_severities` | `list(string)` | `["CRITICAL"]` | Severities that alert in real time |
| `log_retention_days` | `number` | `90` | Function log retention |

### Terraform outputs

`function_name`, `function_arn`, `schedule_name`, `realtime_rule_arn`.

### CloudFormation parameters

The same settings as the Terraform inputs, in PascalCase (`ScheduleExpression`, `Severities`, `RealtimeAlerts`, …). Pass them to the deploy script with `--param Key=Value`.
