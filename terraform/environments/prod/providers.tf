# Primary region provider (default).
provider "aws" {
  region = var.primary_region

  default_tags {
    tags = local.common_tags
  }
}

# Replica region provider used for cross-region backups.
provider "aws" {
  alias  = "replica"
  region = var.replica_region

  default_tags {
    tags = local.common_tags
  }
}
