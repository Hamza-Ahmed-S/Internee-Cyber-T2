variable "primary_region" {
  description = "Primary AWS region."
  type        = string
  default     = "us-east-1"
}

variable "replica_region" {
  description = "Replica AWS region for multi-region backups."
  type        = string
  default     = "eu-west-1"
}

variable "name_prefix" {
  description = "Prefix for all resource names."
  type        = string
  default     = "internee"
}

variable "data_bucket_name" {
  description = "Globally-unique name for the primary data bucket."
  type        = string
  default     = "internee-prod-data"
}

variable "replica_bucket_name" {
  description = "Globally-unique name for the replica data bucket."
  type        = string
  default     = "internee-prod-data-replica"
}

variable "waf_rate_limit" {
  description = "WAF per-IP request rate limit per 5-minute window."
  type        = number
  default     = 2000
}

variable "associated_resource_arns" {
  description = "ALB/API Gateway ARNs to protect with the regional WAF."
  type        = list(string)
  default     = []
}
