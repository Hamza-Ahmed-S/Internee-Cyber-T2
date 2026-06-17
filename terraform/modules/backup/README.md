# Multi-region backup & data-redundancy module

Implements **multi-region backups for data redundancy** and remediates the
S3 durability findings (`S3-002` encryption, `S3-003` versioning).

## What it creates

Across **two regions** (primary + replica):

| Resource | Purpose |
| --- | --- |
| KMS key + alias (×2) | SSE-KMS at rest in each region, rotation enabled |
| Primary S3 bucket | Versioned, SSE-KMS, public access fully blocked, lifecycle |
| Replica S3 bucket | Versioned, SSE-KMS, public access fully blocked |
| Replication IAM role + policy | Lets S3 replicate objects to the replica |
| `aws_s3_bucket_replication_configuration` | Continuous cross-region replication (incl. delete markers, KMS) |
| AWS Backup vaults (×2) | Encrypted recovery-point storage in each region |
| AWS Backup plan | Daily backups with a **`copy_action` to the replica region** |
| Backup selection | Opt-in by `Backup = true` resource tag |

## Why two providers

Cross-region work needs a provider per region. The module declares
`configuration_aliases = [aws.primary, aws.replica]`; the caller passes both:

```hcl
module "backup" {
  source              = "../../modules/backup"
  name_prefix         = "internee"
  data_bucket_name    = "internee-prod-data"
  replica_bucket_name = "internee-prod-data-replica"

  providers = {
    aws.primary = aws            # e.g. us-east-1
    aws.replica = aws.replica    # e.g. eu-west-1
  }
}
```

## Inputs / Outputs

See [`variables.tf`](variables.tf) and [`outputs.tf`](outputs.tf). Notable
outputs: `primary_bucket_arn`, `replica_bucket_arn`, `backup_plan_arn`.
