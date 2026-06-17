###############################################################################
# Web Application Firewall (WAFv2) module
#
# Implements the task requirement: "Enable a Web Application Firewall (WAF) to
# filter and monitor external traffic."
#
# The web ACL layers:
#   * AWS managed rule groups (common, known-bad-inputs, SQLi, IP reputation)
#   * an IP rate-based rule (DDoS / brute-force throttling)
#   * optional geo-blocking
#   * full request logging to CloudWatch Logs (the "monitor" half)
###############################################################################

locals {
  # WAF logging requires the log group name to start with "aws-waf-logs-".
  log_group_name = "aws-waf-logs-${var.name_prefix}"
}

resource "aws_cloudwatch_log_group" "waf" {
  name              = local.log_group_name
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_wafv2_web_acl" "this" {
  name        = "${var.name_prefix}-web-acl"
  description = "Filters and monitors external traffic for Internee.pk."
  scope       = var.scope
  tags        = var.tags

  default_action {
    allow {}
  }

  # --- Managed rule groups --------------------------------------------------
  rule {
    name     = "aws-common-rule-set"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-known-bad-inputs"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-sqli-rule-set"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-sqli"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-ip-reputation"
    priority = 4

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  # --- Rate-based throttling (block) ---------------------------------------
  rule {
    name     = "ip-rate-limit"
    priority = 5

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # --- Optional geo-blocking ------------------------------------------------
  dynamic "rule" {
    for_each = length(var.blocked_country_codes) > 0 ? [1] : []
    content {
      name     = "geo-block"
      priority = 6

      action {
        block {}
      }

      statement {
        geo_match_statement {
          country_codes = var.blocked_country_codes
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name_prefix}-geo-block"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-web-acl"
    sampled_requests_enabled   = true
  }
}

# --- Request logging (the "monitor" half) -----------------------------------
resource "aws_wafv2_web_acl_logging_configuration" "this" {
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  resource_arn            = aws_wafv2_web_acl.this.arn

  # Redact the Authorization header from logs.
  redacted_fields {
    single_header {
      name = "authorization"
    }
  }
}

# --- Associate the web ACL with regional resources (ALB/API GW) -------------
resource "aws_wafv2_web_acl_association" "this" {
  for_each = var.scope == "REGIONAL" ? toset(var.associated_resource_arns) : toset([])

  resource_arn = each.value
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}
