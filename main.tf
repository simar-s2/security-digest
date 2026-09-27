# A Lambda function that reads the Security Hub findings aggregated in the
# delegated administrator account and posts a digest to Slack on a schedule,
# plus optional real-time alerts from an EventBridge rule. Deploy it in the
# Security Hub home region of that account.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  name       = "${var.name_prefix}-security-digest"
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region
}

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/src"
  output_path = "${path.module}/dist/security-digest.zip"
  excludes    = ["security_digest/__pycache__"]
}

# ---------------------------------------------------------------- function

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "lambda" {
  #checkov:skip=CKV_AWS_356:GetFindings and ListAccounts do not support resource-level permissions.
  #checkov:skip=CKV_AWS_111:Read-only; the actions do not support resource-level permissions.
  statement {
    sid       = "ReadFindings"
    actions   = ["securityhub:GetFindings", "organizations:ListAccounts"]
    resources = ["*"]
  }

  statement {
    sid       = "ReadWebhook"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter/${trimprefix(var.webhook_parameter_name, "/")}"]
  }

  dynamic "statement" {
    for_each = var.webhook_kms_key_arn == null ? [] : [var.webhook_kms_key_arn]
    content {
      sid       = "DecryptWebhook"
      actions   = ["kms:Decrypt"]
      resources = [statement.value]
    }
  }

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }
}

resource "aws_iam_role" "lambda" {
  name               = local.name
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy" "lambda" {
  name   = "read-findings-post-slack"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

resource "aws_cloudwatch_log_group" "lambda" {
  #checkov:skip=CKV_AWS_158:Only run summaries; the findings stay in Security Hub. Default service encryption is enough.
  #checkov:skip=CKV_AWS_338:Operational logs of a notifier; 90 days covers debugging.
  name              = "/aws/lambda/${local.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "digest" {
  #checkov:skip=CKV_AWS_50:One short run a day; tracing would cost more than it shows.
  #checkov:skip=CKV_AWS_115:Reserved concurrency fails in new accounts whose concurrency quota is still at the minimum.
  #checkov:skip=CKV_AWS_116:Failures raise, show in the Errors metric and log Slack's reason; alarm on Errors if you need paging.
  #checkov:skip=CKV_AWS_117:Calls only AWS APIs and Slack; a VPC would need a NAT gateway for no benefit.
  #checkov:skip=CKV_AWS_173:The environment holds settings only; the webhook URL stays in SSM.
  #checkov:skip=CKV_AWS_272:Code is built from this repository by Terraform; no external artifact to sign.
  function_name    = local.name
  description      = "Daily Security Hub digest and real-time alerts for Slack"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "security_digest.handler.handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 120
  memory_size      = 256

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.lambda.name
  }

  environment {
    variables = {
      WEBHOOK_PARAM        = var.webhook_parameter_name
      DIGEST_TITLE         = var.title
      SEVERITIES           = join(",", var.severities)
      EXCLUDED_PRODUCTS    = join(",", var.excluded_products)
      MAX_ROWS             = tostring(var.max_rows)
      INCLUDE_NEW_CVES     = tostring(var.include_new_cves)
      INCLUDE_PATCH_STATUS = tostring(var.include_patch_status)
      CONSOLE_REGION       = local.region
      FOOTER               = var.footer
    }
  }
}

# ---------------------------------------------------------------- daily schedule

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

data "aws_iam_policy_document" "scheduler" {
  statement {
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.digest.arn]
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${local.name}-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

resource "aws_iam_role_policy" "scheduler" {
  name   = "invoke-digest"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler.json
}

resource "aws_scheduler_schedule" "digest" {
  #checkov:skip=CKV_AWS_297:The schedule's only payload is {"source": "schedule"}; a customer managed key protects nothing.
  name                         = local.name
  description                  = "Sends the Security Hub digest to Slack"
  schedule_expression          = var.schedule_expression
  schedule_expression_timezone = var.schedule_timezone

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.digest.arn
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({ source = "schedule" })

    retry_policy {
      maximum_retry_attempts = 2
    }
  }
}

# ---------------------------------------------------------------- real-time alerts (optional)

resource "aws_cloudwatch_event_rule" "realtime" {
  count = var.realtime_alerts ? 1 : 0

  name        = "${local.name}-realtime"
  description = "New Security Hub findings at ${join("/", var.realtime_severities)} severity"

  # Left out: Inspector and Patch Manager (one finding per image or instance;
  # the digest rolls them up) and control SSM.2, the same patch signal arriving
  # as a Security Hub control finding, matched by its title prefix.
  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity    = { Label = var.realtime_severities }
        Workflow    = { Status = ["NEW"] }
        RecordState = ["ACTIVE"]
        ProductName = [{ anything-but = ["Inspector", "Systems Manager Patch Manager"] }]
        Title       = [{ anything-but = { prefix = "SSM.2 " } }]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "realtime" {
  count = var.realtime_alerts ? 1 : 0

  rule = aws_cloudwatch_event_rule.realtime[0].name
  arn  = aws_lambda_function.digest.arn
}

resource "aws_lambda_permission" "realtime" {
  count = var.realtime_alerts ? 1 : 0

  statement_id  = "security-hub-findings"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.digest.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.realtime[0].arn
}
