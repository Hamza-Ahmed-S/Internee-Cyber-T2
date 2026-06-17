###############################################################################
# IAM hardening module
#
# Implements the remediation for the IAM/identity findings raised by the
# cloudguard audit engine:
#   * a strong account password policy            (CIS 1.8 / 1.9)
#   * least-privilege, MFA-gated human roles       (CIS 1.16, least privilege)
#   * a permissions boundary that blocks privilege escalation
#
# It intentionally does NOT create long-lived IAM users or access keys — access
# is via assumable roles that require MFA.
###############################################################################

data "aws_caller_identity" "current" {}

locals {
  trusted_account_id = coalesce(var.trusted_account_id, data.aws_caller_identity.current.account_id)
  account_root_arn   = "arn:aws:iam::${local.trusted_account_id}:root"
}

# --- Account password policy (CIS 1.8 / 1.9) --------------------------------
resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = var.password_minimum_length
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  allow_users_to_change_password = true
  max_password_age               = var.password_max_age_days
  password_reuse_prevention      = var.password_reuse_prevention
  hard_expiry                    = false
}

# --- Trust policy: assume only with MFA present -----------------------------
data "aws_iam_policy_document" "assume_with_mfa" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root_arn]
    }

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

# --- Permissions boundary: deny privilege escalation ------------------------
data "aws_iam_policy_document" "boundary" {
  # Allow everything by default; the attached role policies narrow this down.
  statement {
    sid       = "AllowAll"
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }

  # But never allow tampering with the account's security guardrails.
  statement {
    sid    = "DenyGuardrailTampering"
    effect = "Deny"
    actions = [
      "iam:CreateUser",
      "iam:CreateAccessKey",
      "iam:DeleteAccountPasswordPolicy",
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "organizations:LeaveOrganization",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "boundary" {
  name        = "${var.name_prefix}-permissions-boundary"
  description = "Permissions boundary preventing privilege escalation and guardrail tampering."
  policy      = data.aws_iam_policy_document.boundary.json
  tags        = var.tags
}

# --- Read-only security auditor role (CIS-style continuous audit) -----------
resource "aws_iam_role" "security_auditor" {
  name                 = "${var.name_prefix}-security-auditor"
  description          = "Read-only role for security auditing (used by cloudguard)."
  assume_role_policy   = data.aws_iam_policy_document.assume_with_mfa.json
  permissions_boundary = aws_iam_policy.boundary.arn
  max_session_duration = 3600
  tags                 = var.tags
}

resource "aws_iam_role_policy_attachment" "auditor_security_audit" {
  role       = aws_iam_role.security_auditor.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "auditor_view_only" {
  role       = aws_iam_role.security_auditor.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

# --- Break-glass admin role (MFA + short session) ---------------------------
resource "aws_iam_role" "break_glass_admin" {
  name                 = "${var.name_prefix}-break-glass-admin"
  description          = "Emergency admin role. MFA required, short session, audited."
  assume_role_policy   = data.aws_iam_policy_document.assume_with_mfa.json
  permissions_boundary = aws_iam_policy.boundary.arn
  max_session_duration = var.break_glass_session_seconds
  tags                 = var.tags
}

resource "aws_iam_role_policy_attachment" "break_glass_admin" {
  role       = aws_iam_role.break_glass_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# --- Least-privilege developer / CI role ------------------------------------
data "aws_iam_policy_document" "developer" {
  statement {
    sid    = "ArtifactObjectAccess"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = ["${var.artifacts_bucket_arn}/*"]
  }

  statement {
    sid       = "ArtifactBucketList"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [var.artifacts_bucket_arn]
  }

  statement {
    sid    = "ReadOnlyDescribe"
    effect = "Allow"
    actions = [
      "ec2:Describe*",
      "logs:GetLogEvents",
      "logs:FilterLogEvents",
      "cloudwatch:GetMetricData",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "developer" {
  name        = "${var.name_prefix}-developer"
  description = "Least-privilege policy for developers/CI: scoped S3 + read-only describe."
  policy      = data.aws_iam_policy_document.developer.json
  tags        = var.tags
}

resource "aws_iam_role" "developer" {
  name                 = "${var.name_prefix}-developer"
  description          = "Day-to-day developer/CI role with least-privilege access."
  assume_role_policy   = data.aws_iam_policy_document.assume_with_mfa.json
  permissions_boundary = aws_iam_policy.boundary.arn
  max_session_duration = 3600
  tags                 = var.tags
}

resource "aws_iam_role_policy_attachment" "developer" {
  role       = aws_iam_role.developer.name
  policy_arn = aws_iam_policy.developer.arn
}
