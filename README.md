# CloudGuard — Internee.pk Cloud Security Posture Toolkit (AWS)

[![CI](https://img.shields.io/badge/CI-lint%20%7C%20type%20%7C%20test%20%7C%20tf--validate-blue)](.github/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)

Ensure Internee.pk's cloud platforms follow industry-standard security measures
on AWS. CloudGuard is two cohesive halves that tell **one story**:

1. **`cloudguard`** — a dependency-free Python engine that **audits** an AWS
   account (configuration snapshot + CloudTrail logs) against the
   **CIS AWS Foundations Benchmark** and produces prioritised, remediation-ready
   findings.
2. **`terraform/`** — Infrastructure-as-Code that **remediates** those findings:
   least-privilege **IAM**, **multi-region backups** for data redundancy, and a
   **WAF** to filter and monitor external traffic.

> The auditor finds the gaps; the Terraform closes them. See the
> [finding → control map](terraform/README.md#finding--control-traceability).

## Task coverage

| Task requirement | Delivered by |
| --- | --- |
| Audit cloud accounts for security compliance | `cloudguard` engine + CIS-mapped checks |
| Cloud security logs (CloudTrail) | `data/sample/cloudtrail_events.jsonl` + behavioural checks |
| Apply IAM policies | `terraform/modules/iam` |
| Multi-region backups for data redundancy | `terraform/modules/backup` |
| Enable WAF to filter & monitor traffic | `terraform/modules/waf` |

## Quickstart

```bash
# 1. Run the audit against the bundled sample account (no AWS account needed)
python -m cloudguard audit \
  --snapshot data/sample/account_snapshot.json \
  --cloudtrail data/sample/cloudtrail_events.jsonl

# 2. Generate a Markdown report
python -m cloudguard audit \
  --snapshot data/sample/account_snapshot.json \
  --cloudtrail data/sample/cloudtrail_events.jsonl \
  --format markdown --output docs/REPORT.md

# 3. Use it as a CI gate (exit 2 if any HIGH+ finding)
python -m cloudguard audit --snapshot data/sample/account_snapshot.json --fail-on HIGH
```

On Windows PowerShell, set the source path first: `$env:PYTHONPATH="src"`, or run
`pip install -e .` to install the `cloudguard` command.

### Example output

```
========================================================================
  CloudGuard Audit - account 123456789012
========================================================================
  Posture score: 0/100  (grade F)   checks run: 18

  Findings by severity:
    CRITICAL : 3
        HIGH : 7
      MEDIUM : 9
         LOW : 2
```

A full run of the sample account is committed at [docs/REPORT.md](docs/REPORT.md).

## How it works

```
 account_snapshot.json ─┐
                        ├─► ingest ─► engine(checks) ─► AuditResult ─► report
 cloudtrail_events.jsonl┘                                              (console / json / markdown)
```

- **Checks** are small registered functions (`@check(...)`) split into
  *configuration posture* (static) and *CloudTrail behaviour* (activity). Each
  finding carries a severity, the affected resource, a CIS control id, and a
  remediation pointer.
- **Scoring** starts at 100 and deducts a weight per finding; the result gets a
  letter grade.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.

## Project layout

```
src/cloudguard/        # audit engine (stdlib only)
  ingest/              # snapshot + CloudTrail loaders
  checks/              # CIS config checks + CloudTrail behavioural checks
  report/              # console / json / markdown renderers
terraform/             # IAM + multi-region backup + WAF remediation (IaC)
data/sample/           # committed sample inputs (vulnerable + hardened)
tests/                 # pytest suite (48 tests)
docs/                  # ARCHITECTURE, REPORT, design spec
.github/workflows/     # CI: ruff, mypy, pytest, terraform validate, tfsec
```

## Development

```bash
make install     # editable install with dev extras
make check       # ruff + mypy + pytest
make audit       # run audit on the sample data
make tf-validate # validate the prod Terraform environment
```

> **Note on this build environment:** the machine used to author this project
> enforces Windows Application Control (WDAC), which blocks the compiled `ruff`
> and `mypy` binaries and has no `terraform` installed. Those gates therefore
> run in **GitHub Actions CI** rather than locally; the pure-Python `pytest`
> suite runs everywhere. The engine is intentionally **dependency-free** for
> exactly this kind of portability.

## Where the data comes from

- **CloudTrail logs** — `data/sample/cloudtrail_events.jsonl` uses the native
  CloudTrail record schema (`eventTime`, `eventName`, `userIdentity`, …), the
  same shape delivered to S3 and found in AWS Open Data security samples. The
  loader also accepts the `{"Records": [...]}` envelope.
- **Account snapshot** — `data/sample/account_snapshot.json` models the
  security-relevant configuration that, in production, would be assembled from
  IAM / S3 / EC2 / CloudTrail describe-and-get API calls.
- A **hardened** snapshot (`hardened_account_snapshot.json`) represents the
  post-remediation state and is used to prove the checks don't false-positive.

## License

MIT — see [pyproject.toml](pyproject.toml).
