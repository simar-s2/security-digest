variable "name_prefix" {
  type        = string
  description = "Prefix for the function, roles, schedule and rule."
  default     = "sec"
}

variable "webhook_parameter_name" {
  type        = string
  description = "SSM SecureString parameter holding the Slack incoming webhook URL. Create it yourself so the URL never enters Terraform state."
}

variable "webhook_kms_key_arn" {
  type        = string
  description = "Customer managed KMS key of the webhook parameter. Null for the default aws/ssm key."
  default     = null
}

variable "schedule_expression" {
  type        = string
  description = "When the digest is sent."
  default     = "cron(0 14 ? * MON-FRI *)"
}

variable "schedule_timezone" {
  type        = string
  description = "IANA time zone of schedule_expression, e.g. America/New_York."
  default     = "UTC"
}

variable "title" {
  type        = string
  description = "Heading of the Slack message."
  default     = "AWS security daily digest"
}

variable "severities" {
  type        = list(string)
  description = "Finding severities listed in the digest."
  default     = ["CRITICAL", "HIGH"]

  validation {
    condition     = alltrue([for s in var.severities : contains(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"], s)])
    error_message = "Use CRITICAL, HIGH, MEDIUM, LOW or INFORMATIONAL."
  }
}

variable "excluded_products" {
  type        = list(string)
  description = "Products left out of the main table. Inspector and Patch Manager have their own sections."
  default     = ["Inspector", "Systems Manager Patch Manager"]
}

variable "max_rows" {
  type        = number
  description = "Distinct findings listed per severity before an \"… and N more\" line."
  default     = 15
}

variable "include_new_cves" {
  type        = bool
  description = "Add a section for Inspector CVEs first seen in the last 24 hours."
  default     = true
}

variable "include_patch_status" {
  type        = bool
  description = "Add a per-account patch section from controls SSM.2 and SSM.3."
  default     = true
}

variable "footer" {
  type        = string
  description = "Text before the console link at the bottom, e.g. your organization's name."
  default     = ""
}

variable "realtime_alerts" {
  type        = bool
  description = "Also post each new finding at realtime_severities as it arrives."
  default     = false
}

variable "realtime_severities" {
  type        = list(string)
  description = "Severities that trigger a real-time alert. The digest still covers the rest."
  default     = ["CRITICAL"]
}

variable "log_retention_days" {
  type        = number
  description = "Retention of the function's logs."
  default     = 90
}
