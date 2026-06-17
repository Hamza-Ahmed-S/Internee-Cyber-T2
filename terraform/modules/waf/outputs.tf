output "web_acl_arn" {
  description = "ARN of the WAFv2 web ACL."
  value       = aws_wafv2_web_acl.this.arn
}

output "web_acl_id" {
  description = "ID of the WAFv2 web ACL."
  value       = aws_wafv2_web_acl.this.id
}

output "web_acl_name" {
  description = "Name of the WAFv2 web ACL."
  value       = aws_wafv2_web_acl.this.name
}

output "log_group_name" {
  description = "CloudWatch Logs group receiving WAF request logs."
  value       = aws_cloudwatch_log_group.waf.name
}
