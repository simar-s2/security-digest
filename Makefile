.PHONY: help test lint fmt validate tflint cfn-lint checkov shellcheck ruff preview demo

help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

test: ## pytest (Lambda code, deploy script) and terraform test (mocked providers)
	python3 -m pytest -q
	@terraform init -backend=false -input=false >/dev/null
	terraform test

lint: validate tflint cfn-lint checkov shellcheck ruff ## Every linter CI runs

fmt: ## Format Terraform and Python
	terraform fmt -recursive
	ruff format src tests

validate: ## terraform fmt -check, then validate the module and examples
	terraform fmt -check -recursive
	@for d in . examples/*/; do \
	  terraform -chdir=$$d init -backend=false -input=false >/dev/null && \
	  terraform -chdir=$$d validate -no-color >/dev/null && echo "valid: $$d" || exit 1; \
	done

tflint: ## tflint with the AWS ruleset
	@tflint --init >/dev/null
	tflint --recursive --config "$(CURDIR)/.tflint.hcl"

cfn-lint: ## Lint the CloudFormation template
	cfn-lint cloudformation/*.yaml

checkov: ## Static security scan of Terraform, CloudFormation and CI
	checkov --config-file .checkov.yaml -d . --skip-download

shellcheck: ## Lint the deploy script
	shellcheck scripts/*.sh

ruff: ## Lint and format-check the Python code
	ruff check src tests
	ruff format --check src tests

preview: ## Render a digest from fixtures/sample-findings.json in the terminal (no AWS needed)
	@PYTHONPATH=src python3 -m security_digest.preview fixtures/sample-findings.json

demo: preview ## The recording in the README
