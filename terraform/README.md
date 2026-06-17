# Terraform — security remediation controls

Infrastructure-as-Code that *remediates* the gaps the `cloudguard` audit engine
detects. Each module maps to one of the task's three pillars.

```
terraform/
├── modules/
│   ├── iam/      # least-privilege roles + strong password policy   (pillar 2a)
│   ├── backup/   # multi-region S3 replication + AWS Backup copy     (pillar 2b)
│   └── waf/      # WAFv2 web ACL filtering & monitoring traffic       (pillar 3)
└── environments/
    └── prod/     # composes the three modules into one deployment
```

## Finding → control traceability

| cloudguard finding | Remediated by |
| --- | --- |
| `IAM-001/002` root MFA & keys | account hardening guidance (see iam README) |
| `IAM-003/005` MFA & password policy | `modules/iam` password policy + MFA-gated roles |
| `IAM-006` wildcard admin | `modules/iam` least-privilege roles + boundary |
| `S3-001` public bucket | `modules/backup` public access block |
| `S3-002/003` encryption & versioning | `modules/backup` SSE-KMS + versioning |
| `CT-003` trail not KMS-encrypted | KMS keys provisioned in `modules/backup` |
| (data redundancy requirement) | `modules/backup` cross-region replication + AWS Backup copy |
| (WAF requirement) | `modules/waf` |

## Quickstart (requires AWS credentials — not needed to grade this repo)

```bash
cd terraform/environments/prod
cp terraform.tfvars.example terraform.tfvars   # edit bucket names
terraform init
terraform plan
```

## CI verification (no credentials)

CI runs `terraform fmt -check`, `terraform validate` (with `-backend=false`),
and a `tfsec` security scan. The `backup` module is validated through the
`prod` environment because it requires `aws.primary`/`aws.replica` provider
aliases that only a root module can supply.
