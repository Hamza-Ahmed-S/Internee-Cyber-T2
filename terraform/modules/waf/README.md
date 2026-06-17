# Web Application Firewall (WAFv2) module

Implements **"Enable a WAF to filter and monitor external traffic"**.

## What it creates

| Rule (priority) | Type | Action |
| --- | --- | --- |
| `aws-common-rule-set` (1) | AWS managed (OWASP-style core) | managed |
| `aws-known-bad-inputs` (2) | AWS managed | managed |
| `aws-sqli-rule-set` (3) | AWS managed (SQL injection) | managed |
| `aws-ip-reputation` (4) | AWS managed (Amazon IP reputation) | managed |
| `ip-rate-limit` (5) | Rate-based (default 2000 / 5 min / IP) | **block** |
| `geo-block` (6, optional) | Geo match | **block** |

Plus a CloudWatch **log group** (`aws-waf-logs-<prefix>`) and a logging
configuration (the *monitor* half), with the `Authorization` header redacted.
Regional web ACLs are associated with any ALB/API Gateway ARNs you pass in.

## Usage

```hcl
module "waf" {
  source     = "../../modules/waf"
  name_prefix = "internee"
  scope      = "REGIONAL"
  rate_limit = 2000
  associated_resource_arns = [aws_lb.app.arn]
}
```

> **CLOUDFRONT scope** must be created in `us-east-1`; pass an aliased
> provider in that region.

## Inputs / Outputs

See [`variables.tf`](variables.tf) and [`outputs.tf`](outputs.tf). Key output:
`web_acl_arn`.
