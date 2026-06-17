output "iam_security_auditor_role_arn" {
  description = "Read-only auditor role ARN."
  value       = module.iam.security_auditor_role_arn
}

output "iam_break_glass_admin_role_arn" {
  description = "Break-glass admin role ARN."
  value       = module.iam.break_glass_admin_role_arn
}

output "backup_primary_bucket_arn" {
  description = "Primary data bucket ARN."
  value       = module.backup.primary_bucket_arn
}

output "backup_replica_bucket_arn" {
  description = "Replica data bucket ARN."
  value       = module.backup.replica_bucket_arn
}

output "backup_plan_arn" {
  description = "AWS Backup plan ARN (cross-region copy)."
  value       = module.backup.backup_plan_arn
}

output "waf_web_acl_arn" {
  description = "WAFv2 web ACL ARN."
  value       = module.waf.web_acl_arn
}
