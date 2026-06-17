variable "name_prefix" {
  description = "Prefix applied to backup resource names."
  type        = string
  default     = "internee"
}

variable "data_bucket_name" {
  description = "Name of the primary (source) data bucket to create and replicate."
  type        = string
}

variable "replica_bucket_name" {
  description = "Name of the replica (destination) bucket in the replica region."
  type        = string
}

variable "noncurrent_version_retention_days" {
  description = "Days to retain noncurrent object versions before expiry."
  type        = number
  default     = 365
}

variable "backup_retention_days" {
  description = "Days to retain AWS Backup recovery points."
  type        = number
  default     = 35

  validation {
    condition     = var.backup_retention_days >= 7
    error_message = "backup_retention_days must be at least 7."
  }
}

variable "backup_cold_storage_after_days" {
  description = "Days after which recovery points move to cold storage."
  type        = number
  default     = 30
}

variable "backup_schedule" {
  description = "Cron expression for the backup plan (UTC)."
  type        = string
  default     = "cron(0 3 * * ? *)"
}

variable "tags" {
  description = "Tags applied to all created resources."
  type        = map(string)
  default     = {}
}
