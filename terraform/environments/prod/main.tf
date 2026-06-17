###############################################################################
# Internee.pk production cloud-security baseline
#
# Composes the three remediation modules into one deployable environment:
#   * iam    — least-privilege roles + strong password policy
#   * backup — multi-region S3 replication + AWS Backup cross-region copy
#   * waf    — WAFv2 web ACL filtering & monitoring external traffic
###############################################################################

locals {
  common_tags = {
    Project   = "internee-cloud-security"
    ManagedBy = "terraform"
    Env       = "prod"
  }
}

module "iam" {
  source = "../../modules/iam"

  name_prefix          = var.name_prefix
  artifacts_bucket_arn = module.backup.primary_bucket_arn
  tags                 = local.common_tags
}

module "backup" {
  source = "../../modules/backup"

  name_prefix         = var.name_prefix
  data_bucket_name    = var.data_bucket_name
  replica_bucket_name = var.replica_bucket_name
  tags                = local.common_tags

  providers = {
    aws.primary = aws
    aws.replica = aws.replica
  }
}

module "waf" {
  source = "../../modules/waf"

  name_prefix              = var.name_prefix
  scope                    = "REGIONAL"
  rate_limit               = var.waf_rate_limit
  associated_resource_arns = var.associated_resource_arns
  tags                     = local.common_tags
}
