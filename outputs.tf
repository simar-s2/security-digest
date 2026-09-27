output "function_name" {
  description = "Lambda function name. Invoke it to send a digest now."
  value       = aws_lambda_function.digest.function_name
}

output "function_arn" {
  description = "Lambda function ARN."
  value       = aws_lambda_function.digest.arn
}

output "schedule_name" {
  description = "EventBridge Scheduler schedule that sends the digest."
  value       = aws_scheduler_schedule.digest.name
}

output "realtime_rule_arn" {
  description = "EventBridge rule for real-time alerts, or null."
  value       = try(aws_cloudwatch_event_rule.realtime[0].arn, null)
}
