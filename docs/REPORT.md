# CloudGuard Security Audit Report

- **Account:** `123456789012`
- **Generated:** 2026-06-11 16:51 UTC
- **Posture score:** 0/100 (grade **F**)
- **Checks executed:** 18

## Summary

| Severity | Count |
| --- | --- |
| 🟥 CRITICAL | 3 |
| 🟧 HIGH | 7 |
| 🟨 MEDIUM | 9 |
| 🟦 LOW | 2 |
| 🟩 INFO | 0 |

## Findings

| # | Severity | Check | CIS | Resource | Finding |
| --- | --- | --- | --- | --- | --- |
| 1 | 🟥 CRITICAL | `IAM-001` | 1.5 | `account:root` | Root account does not have MFA enabled |
| 2 | 🟥 CRITICAL | `IAM-002` | 1.4 | `account:root` | Root account has active access keys |
| 3 | 🟥 CRITICAL | `S3-001` | 2.1.5 | `s3:bucket/internee-public-website` | S3 bucket 'internee-public-website' is publicly exposed |
| 4 | 🟧 HIGH | `CTA-001` | 4.3 | `account:root` | Root account used 2 time(s) |
| 5 | 🟧 HIGH | `CTA-002` | 4.2 | `arn:aws:iam::123456789012:root` | Console sign-in without MFA by arn:aws:iam::123456789012:root |
| 6 | 🟧 HIGH | `CTA-002` | 4.2 | `arn:aws:iam::123456789012:user/carol-ops` | Console sign-in without MFA by arn:aws:iam::123456789012:user/carol-ops |
| 7 | 🟧 HIGH | `EC2-001` | 5.2 | `ec2:security-group/sg-0a1b2c3d` | Security group 'sg-0a1b2c3d' allows SSH from 0.0.0.0/0 |
| 8 | 🟧 HIGH | `EC2-001` | 5.2 | `ec2:security-group/sg-0e4f5a6b` | Security group 'sg-0e4f5a6b' allows RDP from 0.0.0.0/0 |
| 9 | 🟧 HIGH | `IAM-003` | 1.10 | `iam:user/carol-ops` | IAM user 'carol-ops' has console access without MFA |
| 10 | 🟧 HIGH | `IAM-006` | 1.16 | `arn:aws:iam::123456789012:policy/legacy-full-access` | Customer-managed policy 'legacy-full-access' grants *:* |
| 11 | 🟨 MEDIUM | `CT-002` | 3.2 | `cloudtrail:trail/org-trail` | Trail 'org-trail' has log file validation disabled |
| 12 | 🟨 MEDIUM | `CT-003` | 3.7 | `cloudtrail:trail/org-trail` | Trail 'org-trail' logs are not KMS-encrypted |
| 13 | 🟨 MEDIUM | `CTA-003` | 4.1 | `arn:aws:iam::123456789012:user/bob-ci` | 5 unauthorized API calls from arn:aws:iam::123456789012:user/bob-ci |
| 14 | 🟨 MEDIUM | `CTA-004` | 4.10 | `arn:aws:iam::123456789012:user/carol-ops` | Security group ingress changed (AuthorizeSecurityGroupIngress) |
| 15 | 🟨 MEDIUM | `CTA-004` | 4.5 | `arn:aws:iam::123456789012:user/carol-ops` | CloudTrail logging was stopped (StopLogging) |
| 16 | 🟨 MEDIUM | `EC2-002` | 2.2.1 | `ec2:ebs-encryption` | EBS encryption by default is disabled |
| 17 | 🟨 MEDIUM | `IAM-004` | 1.14 | `iam:user/bob-ci#key0` | Stale access key for IAM user 'bob-ci' |
| 18 | 🟨 MEDIUM | `IAM-005` | 1.8 | `account:password-policy` | IAM password policy is weak |
| 19 | 🟨 MEDIUM | `S3-002` | 2.1.1 | `s3:bucket/internee-user-uploads` | S3 bucket 'internee-user-uploads' has no default encryption |
| 20 | 🟦 LOW | `S3-003` | 2.1.3 | `s3:bucket/internee-public-website` | S3 bucket 'internee-public-website' has versioning disabled |
| 21 | 🟦 LOW | `S3-003` | 2.1.3 | `s3:bucket/internee-user-uploads` | S3 bucket 'internee-user-uploads' has versioning disabled |

## Details & Remediation

### 🟥 `IAM-001` — Root account does not have MFA enabled

- **Severity:** CRITICAL · CIS 1.5
- **Resource:** `account:root`
- **Description:** The root user has unrestricted access to the account. Without MFA, a leaked root password fully compromises the account.
- **Remediation:** Enable a hardware or virtual MFA device on the root user. See terraform/modules/iam (account hardening guidance).
- **Evidence:** `mfa_enabled=False`

### 🟥 `IAM-002` — Root account has active access keys

- **Severity:** CRITICAL · CIS 1.4
- **Resource:** `account:root`
- **Description:** Programmatic root credentials are long-lived and grant full control. They should never exist.
- **Remediation:** Delete all root access keys; use IAM roles instead.
- **Evidence:** `active_access_keys=1`

### 🟥 `S3-001` — S3 bucket 'internee-public-website' is publicly exposed

- **Severity:** CRITICAL · CIS 2.1.5
- **Resource:** `s3:bucket/internee-public-website`
- **Description:** Public buckets risk data exposure. Public Access Block must be enabled and no public ACL/policy should be present.
- **Remediation:** Enable S3 Block Public Access at the bucket/account level.
- **Evidence:** `is_public=True`, `public_access_block=False`

### 🟧 `CTA-001` — Root account used 2 time(s)

- **Severity:** HIGH · CIS 4.3
- **Resource:** `account:root`
- **Description:** The root user performed API actions. Root should be reserved for the few tasks that strictly require it and otherwise unused.
- **Remediation:** Investigate root usage; operate via least-privilege roles.
- **Evidence:** `count=2`, `first_event=ConsoleLogin`, `first_time=2026-06-10T23:01:55Z`, `source_ip=198.51.100.9`

### 🟧 `CTA-002` — Console sign-in without MFA by arn:aws:iam::123456789012:root

- **Severity:** HIGH · CIS 4.2
- **Resource:** `arn:aws:iam::123456789012:root`
- **Description:** A successful console sign-in did not use MFA.
- **Remediation:** Enforce MFA for all console users.
- **Evidence:** `source_ip=198.51.100.9`, `time=2026-06-10T23:01:55Z`, `mfa_used=False`

### 🟧 `CTA-002` — Console sign-in without MFA by arn:aws:iam::123456789012:user/carol-ops

- **Severity:** HIGH · CIS 4.2
- **Resource:** `arn:aws:iam::123456789012:user/carol-ops`
- **Description:** A successful console sign-in did not use MFA.
- **Remediation:** Enforce MFA for all console users.
- **Evidence:** `source_ip=203.0.113.42`, `time=2026-06-10T22:14:03Z`, `mfa_used=False`

### 🟧 `EC2-001` — Security group 'sg-0a1b2c3d' allows SSH from 0.0.0.0/0

- **Severity:** HIGH · CIS 5.2
- **Resource:** `ec2:security-group/sg-0a1b2c3d`
- **Description:** Port 22 (SSH) is open to the entire internet, exposing the host to brute-force and exploitation.
- **Remediation:** Restrict ingress to known CIDRs or use SSM/VPN.
- **Evidence:** `port=22`, `cidr=0.0.0.0/0`, `protocol=tcp`

### 🟧 `EC2-001` — Security group 'sg-0e4f5a6b' allows RDP from 0.0.0.0/0

- **Severity:** HIGH · CIS 5.2
- **Resource:** `ec2:security-group/sg-0e4f5a6b`
- **Description:** Port 3389 (RDP) is open to the entire internet, exposing the host to brute-force and exploitation.
- **Remediation:** Restrict ingress to known CIDRs or use SSM/VPN.
- **Evidence:** `port=3389`, `cidr=0.0.0.0/0`, `protocol=tcp`

### 🟧 `IAM-003` — IAM user 'carol-ops' has console access without MFA

- **Severity:** HIGH · CIS 1.10
- **Resource:** `iam:user/carol-ops`
- **Description:** Console users without MFA are vulnerable to password phishing and reuse attacks.
- **Remediation:** Enforce MFA via the IAM policy in terraform/modules/iam.
- **Evidence:** `console_access=True`, `mfa_enabled=False`

### 🟧 `IAM-006` — Customer-managed policy 'legacy-full-access' grants *:*

- **Severity:** HIGH · CIS 1.16
- **Resource:** `arn:aws:iam::123456789012:policy/legacy-full-access`
- **Description:** A policy allowing all actions on all resources violates least privilege and is equivalent to administrator.
- **Remediation:** Scope the policy to required actions/resources. See the least-privilege roles in terraform/modules/iam.
- **Evidence:** `action=['*']`, `resource=['*']`

### 🟨 `CT-002` — Trail 'org-trail' has log file validation disabled

- **Severity:** MEDIUM · CIS 3.2
- **Resource:** `cloudtrail:trail/org-trail`
- **Description:** Log file validation lets you detect tampering with delivered log files.
- **Remediation:** Enable log file validation on the trail.
- **Evidence:** `log_file_validation=False`

### 🟨 `CT-003` — Trail 'org-trail' logs are not KMS-encrypted

- **Severity:** MEDIUM · CIS 3.7
- **Resource:** `cloudtrail:trail/org-trail`
- **Description:** CloudTrail logs should be encrypted at rest with KMS.
- **Remediation:** Configure a KMS key for the trail (SSE-KMS).
- **Evidence:** `kms_key_id=None`

### 🟨 `CTA-003` — 5 unauthorized API calls from arn:aws:iam::123456789012:user/bob-ci

- **Severity:** MEDIUM · CIS 4.1
- **Resource:** `arn:aws:iam::123456789012:user/bob-ci`
- **Description:** A burst of AccessDenied/Unauthorized errors can indicate credential misuse or permission enumeration.
- **Remediation:** Investigate the principal; rotate credentials if abused.
- **Evidence:** `unauthorized_calls=5`

### 🟨 `CTA-004` — Security group ingress changed (AuthorizeSecurityGroupIngress)

- **Severity:** MEDIUM · CIS 4.10
- **Resource:** `arn:aws:iam::123456789012:user/carol-ops`
- **Description:** A security-sensitive control-plane action was performed and should be confirmed as authorised.
- **Remediation:** Confirm the change was expected; alert on these events.
- **Evidence:** `event_name=AuthorizeSecurityGroupIngress`, `time=2026-06-11T02:30:00Z`, `source_ip=203.0.113.42`, `region=us-east-1`

### 🟨 `CTA-004` — CloudTrail logging was stopped (StopLogging)

- **Severity:** MEDIUM · CIS 4.5
- **Resource:** `arn:aws:iam::123456789012:user/carol-ops`
- **Description:** A security-sensitive control-plane action was performed and should be confirmed as authorised.
- **Remediation:** Confirm the change was expected; alert on these events.
- **Evidence:** `event_name=StopLogging`, `time=2026-06-11T03:45:21Z`, `source_ip=203.0.113.42`, `region=us-east-1`

### 🟨 `EC2-002` — EBS encryption by default is disabled

- **Severity:** MEDIUM · CIS 2.2.1
- **Resource:** `ec2:ebs-encryption`
- **Description:** New EBS volumes may be created unencrypted.
- **Remediation:** Enable EBS encryption by default in every region.
- **Evidence:** `ebs_encryption_by_default=False`

### 🟨 `IAM-004` — Stale access key for IAM user 'bob-ci'

- **Severity:** MEDIUM · CIS 1.14
- **Resource:** `iam:user/bob-ci#key0`
- **Description:** Access keys older than 90 days increase the window of exposure if a key is leaked.
- **Remediation:** Rotate the access key and automate rotation.
- **Evidence:** `last_rotated_days=410`

### 🟨 `IAM-005` — IAM password policy is weak

- **Severity:** MEDIUM · CIS 1.8
- **Resource:** `account:password-policy`
- **Description:** minimum_length=8 (<14); symbols not required
- **Remediation:** Strengthen the password policy in terraform/modules/iam.
- **Evidence:** `weaknesses=['minimum_length=8 (<14)', 'symbols not required']`

### 🟨 `S3-002` — S3 bucket 'internee-user-uploads' has no default encryption

- **Severity:** MEDIUM · CIS 2.1.1
- **Resource:** `s3:bucket/internee-user-uploads`
- **Description:** Default encryption (SSE-S3 or SSE-KMS) is not enabled.
- **Remediation:** Enable default encryption (prefer SSE-KMS).
- **Evidence:** `encryption=None`

### 🟦 `S3-003` — S3 bucket 'internee-public-website' has versioning disabled

- **Severity:** LOW · CIS 2.1.3
- **Resource:** `s3:bucket/internee-public-website`
- **Description:** Versioning protects against accidental deletion/overwrite and is required for cross-region replication (data redundancy).
- **Remediation:** Enable versioning; see the replicated buckets in terraform/modules/backup.
- **Evidence:** `versioning=False`

### 🟦 `S3-003` — S3 bucket 'internee-user-uploads' has versioning disabled

- **Severity:** LOW · CIS 2.1.3
- **Resource:** `s3:bucket/internee-user-uploads`
- **Description:** Versioning protects against accidental deletion/overwrite and is required for cross-region replication (data redundancy).
- **Remediation:** Enable versioning; see the replicated buckets in terraform/modules/backup.
- **Evidence:** `versioning=False`

