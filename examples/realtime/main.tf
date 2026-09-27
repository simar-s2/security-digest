# Daily digest plus an immediate Slack message for every new CRITICAL finding,
# and MEDIUM findings included in the digest.

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
  region = "eu-west-1"
}

module "security_digest" {
  source = "../.."

  name_prefix            = "acme"
  webhook_parameter_name = "/acme/security/slack-webhook"
  severities             = ["CRITICAL", "HIGH", "MEDIUM"]
  max_rows               = 10
  realtime_alerts        = true
}

output "function_name" {
  value = module.security_digest.function_name
}
