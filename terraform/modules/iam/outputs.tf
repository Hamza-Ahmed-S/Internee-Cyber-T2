output "security_auditor_role_arn" {
  description = "ARN of the read-only security auditor role."
  value       = aws_iam_role.security_auditor.arn
}

output "break_glass_admin_role_arn" {
  description = "ARN of the MFA-gated break-glass admin role."
  value       = aws_iam_role.break_glass_admin.arn
}

output "developer_role_arn" {
  description = "ARN of the least-privilege developer/CI role."
  value       = aws_iam_role.developer.arn
}

output "permissions_boundary_arn" {
  description = "ARN of the permissions boundary policy."
  value       = aws_iam_policy.boundary.arn
}
