# Weekday digest at 9:00 New York time. Deploy in the Security Hub delegated
# administrator account, in the home (aggregation) region.
#
# Create the webhook parameter first, outside Terraform:
#   aws ssm put-parameter --name /security-digest/slack-webhook --type SecureString \
#     --value https://hooks.slack.com/services/...

terraform {
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

module "security_digest" {
  source = "../.."

  webhook_parameter_name = "/security-digest/slack-webhook"
  schedule_timezone      = "America/New_York"
  schedule_expression    = "cron(0 9 ? * MON-FRI *)"
  footer                 = "Example Corp security"
}
