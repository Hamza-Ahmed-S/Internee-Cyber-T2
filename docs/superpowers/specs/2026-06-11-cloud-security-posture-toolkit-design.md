# Internee.pk Cloud Security Posture Toolkit — Design Spec

- **Date:** 2026-06-11
- **Author:** Hamza Ahmed Siddiqui
- **Status:** Approved
- **Task:** Internee.pk Task 2 — Cloud Security Compliance (AWS)

## 1. Objective

Ensure Internee.pk's cloud-based platforms follow industry-standard security
measures on **AWS**:

1. **Audit** cloud accounts for security compliance (CIS AWS Foundations
   Benchmark) using CloudTrail logs and account configuration snapshots.
2. **Apply IAM policies** (least privilege) and set up **multi-region backups**
   for data redundancy.
3. **Enable a Web Application Firewall (WAF)** to filter and monitor external
   traffic.

## 2. Guiding Principle

The deliverable tells **one coherent story**: the audit engine *detects* the
security gaps (missing MFA, public buckets, single-region data, no WAF, risky
CloudTrail activity), and the Terraform modules are the *remediation* for
exactly those gaps. `docs/REPORT.md` ties each finding category to the control
that closes it.

## 3. Execution Model

- **Offline, no credentials required.** The audit engine runs against committed
  sample data (an AWS account configuration snapshot + CloudTrail event logs in
  the native CloudTrail JSON schema, AWS Open Data style).
- Terraform modules are **valid, formatted, and security-scanned in CI** but not
  deployed (no live account).

## 4. Architecture

Two cohesive halves in one repository:

```
Task 2/
  src/cloudguard/          # Python audit & compliance engine
  terraform/               # Remediation controls as IaC
  data/                    # Committed sample inputs
  tests/                   # pytest suite
  docs/                    # ARCHITECTURE, REPORT, spec
  .github/workflows/       # CI
```

### 4.1 `cloudguard` audit engine (Python, stdlib-only)

```
src/cloudguard/
  __init__.py
  __main__.py
  models.py            # Severity, Finding, CheckMeta, AuditResult, dataclasses for inputs
  config.py            # runtime config / paths
  ingest/
    __init__.py
    snapshot.py        # load AccountSnapshot from JSON
    cloudtrail.py      # load CloudTrail events from JSONL
  checks/
    __init__.py
    base.py            # Check protocol + registry decorator
    config_checks.py   # CIS-mapped posture checks
    cloudtrail_checks.py # behavioral checks over CloudTrail events
  engine.py            # run all registered checks -> AuditResult
  report/
    __init__.py
    console.py         # ANSI table summary
    json_report.py     # machine-readable JSON
    markdown.py        # human-readable Markdown report
  cli.py               # argparse CLI: `cloudguard audit`
```

**Why stdlib-only:** the target machine enforces Windows Application Control
(WDAC), which blocks compiled binaries/extensions (ruff, mypy, pydantic native
wheels) and runs Python 3.14. Restricting the core to the standard library makes
the tool runnable anywhere with zero install friction. Linting/typing run in CI.

**Models** (`dataclasses`, frozen where sensible):
- `Severity` — `Enum`: CRITICAL/HIGH/MEDIUM/LOW/INFO with a numeric weight.
- `Finding` — id, title, severity, resource, cis_control, description,
  remediation, evidence.
- `CheckMeta` — check id, title, cis_control, severity, category.
- `AuditResult` — list of findings + summary counts + scored posture grade.

**Checks** are small functions registered via a decorator into a registry. Each
yields zero or more `Finding`s. Two families:

- *Config posture checks* (`config_checks.py`) mapped to CIS controls, e.g.:
  - Root account MFA enabled (CIS 1.5)
  - No IAM users with console access lacking MFA (CIS 1.10)
  - Strong IAM password policy (CIS 1.8/1.9)
  - No access keys on the root account (CIS 1.4)
  - CloudTrail enabled in all regions + log file validation (CIS 3.1/3.2)
  - CloudTrail logs encrypted with KMS (CIS 3.7)
  - S3 buckets not public; encryption + versioning enabled
  - No security group allowing 0.0.0.0/0 to 22/3389 (CIS 5.2/5.3)
  - EBS/default encryption enabled
  - No customer-managed IAM policy granting `*:*` (least privilege)
- *Behavioral checks* (`cloudtrail_checks.py`) over events, e.g.:
  - Root account usage
  - Console sign-in without MFA
  - Unauthorized API calls (AccessDenied bursts)
  - IAM policy / security-group changes (change monitoring)

**Engine** loads inputs, runs every registered check, aggregates `Finding`s,
computes a weighted posture score (0–100) and letter grade.

**Reports**: console summary (severity-colored counts + table), JSON (CI-
consumable), Markdown (findings with CIS mapping + remediation, suitable for
`docs/REPORT.md`).

**CLI**: `cloudguard audit --snapshot <f> --cloudtrail <f> --format console|json|markdown --output <f> [--fail-on SEVERITY]`. Non-zero exit when findings at/above `--fail-on` exist, so it gates CI.

### 4.2 Terraform remediation modules

```
terraform/
  modules/
    iam/      # least-privilege roles, strict password policy, account controls
    backup/   # S3 versioning + cross-region replication + AWS Backup w/ cross-region copy + KMS
    waf/      # WAFv2 web ACL: AWS managed rule groups, rate limiting, logging
  environments/prod/  # composition wiring the modules together
```

- **iam**: a read-only `security-auditor` role, an MFA-gated `break-glass-admin`
  role, a scoped `developer` role, an account password policy, and an explicit
  deny on wildcard admin. Demonstrates least privilege.
- **backup**: primary + replica S3 buckets in two regions with versioning,
  SSE-KMS, and cross-region replication; an AWS Backup vault + plan that copies
  recovery points to a second region. Demonstrates multi-region redundancy.
- **waf**: WAFv2 `regional`/`CLOUDFRONT` web ACL using AWS managed rule groups
  (Common, Known Bad Inputs, SQLi), a rate-based rule, and logging to CloudWatch
  Logs. Demonstrates filtering + monitoring of external traffic.

Validated with `terraform fmt -check` + `terraform validate`; scanned with
`tfsec`/`checkov` in CI.

## 5. Data Flow

```
sample snapshot.json  ─┐
                       ├─> ingest ─> engine(checks) ─> AuditResult ─> report (console/json/md)
sample cloudtrail.jsonl┘
```

Terraform defines the controls that remediate Finding categories; REPORT.md maps
findings → modules.

## 6. Engineering Quality

- `pyproject.toml` with ruff + mypy config; `py.typed` marker; src layout.
- `pytest` suite covering every check (positive + negative cases), ingest, engine
  scoring, and report rendering. Target: every check has a test.
- `pre-commit` config (ruff, ruff-format, mypy, terraform fmt, end-of-file).
- `Makefile` task runner (`install`, `lint`, `typecheck`, `test`, `audit`,
  `tf-validate`, `tf-scan`).
- **GitHub Actions CI**: ruff → mypy → pytest → terraform validate → tfsec.
- Docs: `README.md` (quickstart), `docs/ARCHITECTURE.md` (design), `docs/REPORT.md`
  (audit findings + methodology + CIS mapping table).

## 7. Out of Scope (YAGNI)

- Live AWS API calls / boto3 (offline deliverable; a `--live` mode is a noted
  future extension, not built).
- Multi-cloud (AWS only).
- Auto-remediation that mutates a live account.

## 8. Testing Strategy

- Unit tests per check: feed a crafted snapshot/events fixture and assert the
  expected `Finding`(s) appear or are absent.
- Ingest tests: malformed input handling.
- Engine test: scoring + grade boundaries.
- Report tests: JSON shape + Markdown contains findings.
- A "clean account" fixture that produces zero high/critical findings, proving
  the checks don't false-positive on a hardened account.
```

