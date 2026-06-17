variable "name_prefix" {
  description = "Prefix applied to WAF resource names."
  type        = string
  default     = "internee"
}

variable "scope" {
  description = "WAFv2 scope: REGIONAL (ALB/API Gateway/AppSync) or CLOUDFRONT."
  type        = string
  default     = "REGIONAL"

  validation {
    condition     = contains(["REGIONAL", "CLOUDFRONT"], var.scope)
    error_message = "scope must be either REGIONAL or CLOUDFRONT."
  }
}

variable "rate_limit" {
  description = "Max requests from a single IP per 5-minute window before blocking."
  type        = number
  default     = 2000

  validation {
    condition     = var.rate_limit >= 100
    error_message = "rate_limit must be at least 100."
  }
}

variable "blocked_country_codes" {
  description = "Optional ISO 3166-1 alpha-2 country codes to block outright."
  type        = list(string)
  default     = []
}

variable "log_retention_days" {
  description = "Retention for the WAF CloudWatch log group."
  type        = number
  default     = 90
}

variable "associated_resource_arns" {
  description = "Regional resource ARNs (ALB/API GW) to associate with the web ACL."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to taggable resources."
  type        = map(string)
  default     = {}
}
