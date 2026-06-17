# IAM hardening module

Remediates the identity findings raised by the cloudguard audit engine
(`IAM-*` and `CTA-*`).

## What it creates

| Resource | Purpose | Addresses |
| --- | --- | --- |
| `aws_iam_account_password_policy` | 14+ char, complexity, rotation, reuse | `IAM-005` (CIS 1.8/1.9) |
| `internee-permissions-boundary` | Denies privilege escalation + guardrail tampering | `IAM-006`, `CTA-004` |
| `internee-security-auditor` role | Read-only auditing (MFA-gated) | continuous `cloudguard` audits |
| `internee-break-glass-admin` role | Emergency admin, MFA + short session | replaces standing admin users |
| `internee-developer` role | Least-privilege S3 + read-only describe | `IAM-006` least privilege |

All human roles require `aws:MultiFactorAuthPresent = true` to assume, which is
the durable fix for `IAM-003`/`CTA-002` (console access without MFA). No IAM
users or long-lived access keys are created.

## Usage

```hcl
module "iam" {
  source               = "../../modules/iam"
  name_prefix          = "internee"
  artifacts_bucket_arn = "arn:aws:s3:::internee-artifacts"
  tags                 = { Project = "internee-cloud-security" }
}
```

## Inputs

See [`variables.tf`](variables.tf). Key ones: `name_prefix`,
`password_minimum_length` (validated `>= 14`), `break_glass_session_seconds`,
`artifacts_bucket_arn`.

## Outputs

`security_auditor_role_arn`, `break_glass_admin_role_arn`,
`developer_role_arn`, `permissions_boundary_arn`.
