output "primary_bucket_arn" {
  description = "ARN of the primary (source) data bucket."
  value       = aws_s3_bucket.primary.arn
}

output "replica_bucket_arn" {
  description = "ARN of the replica (destination) data bucket."
  value       = aws_s3_bucket.replica.arn
}

output "primary_kms_key_arn" {
  description = "ARN of the primary-region KMS key."
  value       = aws_kms_key.primary.arn
}

output "replica_kms_key_arn" {
  description = "ARN of the replica-region KMS key."
  value       = aws_kms_key.replica.arn
}

output "backup_plan_arn" {
  description = "ARN of the AWS Backup plan with cross-region copy."
  value       = aws_backup_plan.this.arn
}

output "primary_backup_vault_arn" {
  description = "ARN of the primary-region backup vault."
  value       = aws_backup_vault.primary.arn
}

output "replica_backup_vault_arn" {
  description = "ARN of the replica-region backup vault."
  value       = aws_backup_vault.replica.arn
}
