###############################################################################
# Multi-region backup & data-redundancy module
#
# Remediates the data-durability findings (S3-002 encryption, S3-003 versioning)
# and implements the task requirement: "set up multi-region backups for data
# redundancy".
#
# It provisions, across two regions:
#   * a primary data bucket -> cross-region replication -> replica bucket
#     (both versioned, SSE-KMS, public access fully blocked)
#   * an AWS Backup vault + plan whose recovery points are copied to a second
#     region (cross-region copy_action)
###############################################################################

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

# --- KMS keys (one per region) ----------------------------------------------
resource "aws_kms_key" "primary" {
  provider                = aws.primary
  description             = "${var.name_prefix} primary-region data encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = var.tags
}

resource "aws_kms_alias" "primary" {
  provider      = aws.primary
  name          = "alias/${var.name_prefix}-data-primary"
  target_key_id = aws_kms_key.primary.key_id
}

resource "aws_kms_key" "replica" {
  provider                = aws.replica
  description             = "${var.name_prefix} replica-region data encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = var.tags
}

resource "aws_kms_alias" "replica" {
  provider      = aws.replica
  name          = "alias/${var.name_prefix}-data-replica"
  target_key_id = aws_kms_key.replica.key_id
}

# --- Replica (destination) bucket -------------------------------------------
resource "aws_s3_bucket" "replica" {
  provider = aws.replica
  bucket   = var.replica_bucket_name
  tags     = var.tags
}

resource "aws_s3_bucket_versioning" "replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.replica.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.replica.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.replica.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "replica" {
  provider                = aws.replica
  bucket                  = aws_s3_bucket.replica.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- Primary (source) bucket ------------------------------------------------
resource "aws_s3_bucket" "primary" {
  provider = aws.primary
  bucket   = var.data_bucket_name
  tags     = var.tags
}

resource "aws_s3_bucket_versioning" "primary" {
  provider = aws.primary
  bucket   = aws_s3_bucket.primary.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "primary" {
  provider = aws.primary
  bucket   = aws_s3_bucket.primary.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.primary.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "primary" {
  provider                = aws.primary
  bucket                  = aws_s3_bucket.primary.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "primary" {
  provider = aws.primary
  bucket   = aws_s3_bucket.primary.id

  rule {
    id     = "expire-noncurrent-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# --- Replication IAM role ----------------------------------------------------
data "aws_iam_policy_document" "replication_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "replication" {
  provider           = aws.primary
  name               = "${var.name_prefix}-s3-replication"
  assume_role_policy = data.aws_iam_policy_document.replication_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "replication" {
  statement {
    sid    = "SourceBucketRead"
    effect = "Allow"
    actions = [
      "s3:GetReplicationConfiguration",
      "s3:ListBucket",
    ]
    resources = [aws_s3_bucket.primary.arn]
  }

  statement {
    sid    = "SourceObjectRead"
    effect = "Allow"
    actions = [
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionTagging",
    ]
    resources = ["${aws_s3_bucket.primary.arn}/*"]
  }

  statement {
    sid    = "DestinationReplicate"
    effect = "Allow"
    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags",
    ]
    resources = ["${aws_s3_bucket.replica.arn}/*"]
  }

  statement {
    sid       = "DecryptSource"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.primary.arn]
  }

  statement {
    sid       = "EncryptDestination"
    effect    = "Allow"
    actions   = ["kms:Encrypt"]
    resources = [aws_kms_key.replica.arn]
  }
}

resource "aws_iam_role_policy" "replication" {
  provider = aws.primary
  name     = "${var.name_prefix}-s3-replication"
  role     = aws_iam_role.replication.id
  policy   = data.aws_iam_policy_document.replication.json
}

# --- Cross-region replication configuration ---------------------------------
resource "aws_s3_bucket_replication_configuration" "primary" {
  provider = aws.primary
  role     = aws_iam_role.replication.arn
  bucket   = aws_s3_bucket.primary.id

  # Replication requires versioning on the source bucket.
  depends_on = [aws_s3_bucket_versioning.primary]

  rule {
    id     = "replicate-all"
    status = "Enabled"

    filter {}

    delete_marker_replication {
      status = "Enabled"
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket        = aws_s3_bucket.replica.arn
      storage_class = "STANDARD_IA"

      encryption_configuration {
        replica_kms_key_id = aws_kms_key.replica.arn
      }
    }
  }
}

# --- AWS Backup: vaults in both regions + plan with cross-region copy --------
resource "aws_backup_vault" "primary" {
  provider    = aws.primary
  name        = "${var.name_prefix}-vault-primary"
  kms_key_arn = aws_kms_key.primary.arn
  tags        = var.tags
}

resource "aws_backup_vault" "replica" {
  provider    = aws.replica
  name        = "${var.name_prefix}-vault-replica"
  kms_key_arn = aws_kms_key.replica.arn
  tags        = var.tags
}

resource "aws_backup_plan" "this" {
  provider = aws.primary
  name     = "${var.name_prefix}-backup-plan"
  tags     = var.tags

  rule {
    rule_name         = "daily-with-cross-region-copy"
    target_vault_name = aws_backup_vault.primary.name
    schedule          = var.backup_schedule
    start_window      = 60
    completion_window = 180

    lifecycle {
      cold_storage_after = var.backup_cold_storage_after_days
      delete_after       = var.backup_retention_days
    }

    copy_action {
      destination_vault_arn = aws_backup_vault.replica.arn

      lifecycle {
        cold_storage_after = var.backup_cold_storage_after_days
        delete_after       = var.backup_retention_days
      }
    }
  }
}

data "aws_iam_policy_document" "backup_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "backup" {
  provider           = aws.primary
  name               = "${var.name_prefix}-backup-role"
  assume_role_policy = data.aws_iam_policy_document.backup_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "backup" {
  provider   = aws.primary
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_backup_selection" "this" {
  provider     = aws.primary
  name         = "${var.name_prefix}-backup-selection"
  iam_role_arn = aws_iam_role.backup.arn
  plan_id      = aws_backup_plan.this.id

  # Select resources by tag so app teams opt in by tagging.
  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "true"
  }
}
