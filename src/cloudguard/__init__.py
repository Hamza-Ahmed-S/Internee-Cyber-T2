"""cloudguard — AWS cloud security posture auditing & compliance toolkit.

The package audits an AWS account configuration snapshot and CloudTrail event
logs against industry-standard controls (CIS AWS Foundations Benchmark) and
produces prioritised findings with remediation guidance.
"""

from __future__ import annotations

__version__ = "1.0.0"

__all__ = ["__version__"]
