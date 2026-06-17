variable "name_prefix" {
  description = "Prefix applied to all IAM resource names (e.g. \"internee\")."
  type        = string
  default     = "internee"
}

variable "trusted_account_id" {
  description = "AWS account id allowed to assume the human roles. Defaults to the current account."
  type        = string
  default     = null
}

variable "password_minimum_length" {
  description = "Minimum length for IAM user passwords (CIS recommends >= 14)."
  type        = number
  default     = 14

  validation {
    condition     = var.password_minimum_length >= 14
    error_message = "password_minimum_length must be at least 14 to satisfy CIS 1.8."
  }
}

variable "password_max_age_days" {
  description = "Maximum password age in days (CIS recommends <= 90)."
  type        = number
  default     = 90
}

variable "password_reuse_prevention" {
  description = "Number of previous passwords remembered (CIS recommends >= 24)."
  type        = number
  default     = 24
}

variable "break_glass_session_seconds" {
  description = "Max session duration for the break-glass admin role (seconds)."
  type        = number
  default     = 3600
}

variable "artifacts_bucket_arn" {
  description = "ARN of the S3 bucket the CI/developer role may read/write objects in."
  type        = string
  default     = "arn:aws:s3:::internee-artifacts"
}

variable "tags" {
  description = "Tags applied to taggable IAM resources."
  type        = map(string)
  default     = {}
}
