mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
  override_data {
    target = data.aws_caller_identity.current
    values = { account_id = "333344445555" }
  }
  override_data {
    target = data.aws_partition.current
    values = { partition = "aws" }
  }
  override_data {
    target = data.aws_region.current
    values = { region = "us-east-1" }
  }
}

mock_provider "archive" {}

variables {
  webhook_parameter_name = "/security-digest/slack-webhook"
}

run "digest_on_a_schedule" {
  command = plan

  assert {
    condition     = aws_scheduler_schedule.digest.schedule_expression == "cron(0 14 ? * MON-FRI *)" && aws_scheduler_schedule.digest.schedule_expression_timezone == "UTC"
    error_message = "Weekdays at 14:00 UTC by default."
  }
  assert {
    condition     = aws_lambda_function.digest.environment[0].variables["WEBHOOK_PARAM"] == "/security-digest/slack-webhook"
    error_message = "The function gets the parameter name, never the URL."
  }
  assert {
    condition     = aws_lambda_function.digest.environment[0].variables["SEVERITIES"] == "CRITICAL,HIGH"
    error_message = "CRITICAL and HIGH by default."
  }
  assert {
    condition     = aws_lambda_function.digest.handler == "security_digest.handler.handler" && aws_lambda_function.digest.runtime == "python3.13"
    error_message = "Handler and runtime."
  }
  assert {
    condition     = length(aws_cloudwatch_event_rule.realtime) == 0
    error_message = "Real-time alerts are opt-in."
  }
}

run "realtime_alerts" {
  command = plan

  variables {
    realtime_alerts     = true
    realtime_severities = ["CRITICAL", "HIGH"]
  }

  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.realtime[0].event_pattern).detail.findings.Severity.Label == ["CRITICAL", "HIGH"]
    error_message = "The rule matches the chosen severities."
  }
  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.realtime[0].event_pattern).detail.findings.Title[0]["anything-but"].prefix == "SSM.2 "
    error_message = "SSM.2 control findings are left to the digest."
  }
}

run "rejects_unknown_severity" {
  command = plan

  variables {
    severities = ["URGENT"]
  }

  expect_failures = [var.severities]
}
