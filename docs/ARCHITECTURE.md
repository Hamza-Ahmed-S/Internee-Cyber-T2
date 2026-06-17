# Architecture

CloudGuard has two halves that share one narrative: an **audit engine** that
detects security gaps, and **Terraform modules** that remediate them.

## 1. Audit engine (`src/cloudguard`)

### Module map

```
cloudguard/
├── models.py            Severity, Finding, CheckMeta, AuditResult
├── ingest/
│   ├── snapshot.py      AccountSnapshot + typed sub-models + JSON loader
│   └── cloudtrail.py    CloudTrailEvent + JSONL / Records loader
├── checks/
│   ├── base.py          AuditContext, @check decorator, registry
│   ├── config_checks.py 16 CIS-mapped static posture checks
│   └── cloudtrail_checks.py  4 behavioural checks over events
├── engine.py            runs all registered checks → AuditResult
├── report/
│   ├── console.py       ANSI summary + findings table
│   ├── json_report.py   machine-readable JSON
│   └── markdown.py      committable Markdown report
└── cli.py               argparse CLI + CI exit-code gating
```

### Design principles

- **Dependency-free core.** Only the standard library. The toolkit runs on any
  Python 3.10+ interpreter with no install step and no compiled binaries —
  important because the build host enforces WDAC (Windows Application Control).
- **Each unit has one purpose.** Loaders only parse, checks only detect, the
  engine only aggregates, renderers only format. They communicate through the
  small, typed `models.py` interface and can be tested in isolation.
- **Checks are pluggable and self-describing.** A check registers with
  `@check(check_id=…, cis_control=…)` and yields `Finding`s. Adding a control is
  a single function; the registry, scoring, counts, and all three report formats
  pick it up automatically. Duplicate ids are rejected at import time.
- **Determinism.** The registry preserves insertion order and reports sort
  findings most-severe-first, so output is stable and diffable.

### Data flow

```
load_snapshot(json) ─┐
                     ├─► AuditContext ─► [check(ctx) for check in registry] ─► AuditResult
load_cloudtrail(jsonl)┘                                                          │
                                                                                 ▼
                                                  render_console / render_json / render_markdown
```

### Scoring model

`AuditResult.score` starts at 100 and subtracts a per-severity weight
(CRITICAL 40, HIGH 20, MEDIUM 8, LOW 3, INFO 0), floored at 0, then maps to a
letter grade (A ≥ 90 … F < 60). The weights make a single CRITICAL or a cluster
of HIGHs dominate the grade, matching how a human auditor triages.

### Check catalogue

**Configuration posture** (`config_checks.py`) — CIS AWS Foundations Benchmark:

| Check | CIS | Severity |
| --- | --- | --- |
| `IAM-001` root MFA | 1.5 | CRITICAL |
| `IAM-002` no root access keys | 1.4 | CRITICAL |
| `IAM-003` console users have MFA | 1.10 | HIGH |
| `IAM-004` access keys rotated ≤ 90d | 1.14 | MEDIUM |
| `IAM-005` strong password policy | 1.8 | MEDIUM/HIGH |
| `IAM-006` no `*:*` customer policy | 1.16 | HIGH |
| `CT-001` multi-region trail logging | 3.1 | HIGH |
| `CT-002` log file validation | 3.2 | MEDIUM |
| `CT-003` trail KMS-encrypted | 3.7 | MEDIUM |
| `S3-001` no public buckets | 2.1.5 | CRITICAL/MEDIUM |
| `S3-002` bucket encryption | 2.1.1 | MEDIUM |
| `S3-003` bucket versioning | 2.1.3 | LOW |
| `EC2-001` no world-open SSH/RDP | 5.2 | HIGH |
| `EC2-002` EBS default encryption | 2.2.1 | MEDIUM |

**Behavioural** (`cloudtrail_checks.py`) — CIS monitoring (section 4):

| Check | CIS | Detects |
| --- | --- | --- |
| `CTA-001` root usage | 4.3 | any root API activity |
| `CTA-002` console login w/o MFA | 4.2 | successful non-MFA sign-ins |
| `CTA-003` unauthorized bursts | 4.1 | ≥ 5 AccessDenied/Unauthorized per principal |
| `CTA-004` sensitive changes | 4.4–4.10 | StopLogging, IAM/SG/KMS changes |

## 2. Remediation (`terraform/`)

Three modules, composed by `environments/prod`:

- **`modules/iam`** — strong account password policy, MFA-gated assumable roles
  (read-only auditor, break-glass admin, least-privilege developer), and a
  permissions boundary that denies privilege escalation and guardrail tampering.
- **`modules/backup`** — primary→replica S3 cross-region replication (versioned,
  SSE-KMS, public access blocked) plus an AWS Backup plan with a cross-region
  `copy_action`. Uses two provider aliases (`aws.primary`, `aws.replica`).
- **`modules/waf`** — a WAFv2 web ACL with AWS managed rule groups (common,
  known-bad-inputs, SQLi, IP reputation), an IP rate-based block rule, optional
  geo-blocking, and request logging to CloudWatch (the "monitor" half).

See [terraform/README.md](../terraform/README.md) for the finding→control map.

## 3. Quality & CI

- **Local:** `pytest` (48 tests) covering every check (positive + negative),
  loader error paths, engine scoring boundaries, all report formats, and the CLI
  including exit-code gating.
- **CI (`.github/workflows/ci.yml`):** ruff lint + format check, mypy
  `--strict`, pytest, `terraform fmt`/`validate`, and a `tfsec` scan.

## Extending

- **Add a check:** write a function in `checks/`, decorate with `@check(...)`,
  add a unit test. Nothing else changes.
- **Go live:** add an `ingest/aws_live.py` that builds an `AccountSnapshot` from
  `boto3` describe/get calls behind a `--live` flag. The rest of the pipeline is
  unchanged — this is the one documented future extension (currently out of
  scope; the toolkit is offline by design).
