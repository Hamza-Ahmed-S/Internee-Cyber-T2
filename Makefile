.DEFAULT_GOAL := help
PYTHON ?= python
SNAPSHOT ?= data/sample/account_snapshot.json
CLOUDTRAIL ?= data/sample/cloudtrail_events.jsonl

.PHONY: help install lint format typecheck test audit report tf-fmt tf-validate tf-scan check

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Install the package with dev extras
	$(PYTHON) -m pip install -e ".[dev]"

lint: ## Lint with ruff
	ruff check src tests

format: ## Auto-format with ruff
	ruff format src tests

typecheck: ## Type-check with mypy
	mypy

test: ## Run the test suite
	$(PYTHON) -m pytest -q

audit: ## Run a console audit against the sample data
	$(PYTHON) -m cloudguard audit --snapshot $(SNAPSHOT) --cloudtrail $(CLOUDTRAIL)

report: ## Regenerate docs/REPORT.md from the sample data
	$(PYTHON) -m cloudguard audit --snapshot $(SNAPSHOT) --cloudtrail $(CLOUDTRAIL) \
		--format markdown --output docs/REPORT.md

tf-fmt: ## Check Terraform formatting
	terraform fmt -check -recursive terraform

tf-validate: ## Validate the prod Terraform environment
	terraform -chdir=terraform/environments/prod init -backend=false -input=false
	terraform -chdir=terraform/environments/prod validate

tf-scan: ## Security-scan Terraform with tfsec (if installed)
	tfsec terraform

check: lint typecheck test ## Run all Python quality gates
