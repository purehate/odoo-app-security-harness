.PHONY: help install test test-cov lint format clean docker-build docker-run

PYTHON := python3
PIP := pip3

help: ## Show this help message
	@echo "Odoo Application Security Harness"
	@echo "================================"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install the harness and dependencies
	$(PIP) install -e ".[dev,scanners]"
	./install.sh

install-dev: ## Install development dependencies only
	$(PIP) install -e ".[dev]"

install-scanners: ## Install scanner dependencies
	$(PIP) install -e ".[scanners]"

test: ## Run tests
	pytest -m "not slow and not integration"

test-all: ## Run all tests including slow/integration
	pytest

test-cov: ## Run tests with coverage report
	pytest --cov=odoo_security_harness --cov-report=html --cov-report=term

lint: ## Run all linters
	black --check .
	ruff check .
	mypy odoo_security_harness

format: ## Format code with black and ruff
	black .
	ruff check --fix .

clean: ## Clean generated files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true

docker-build: ## Build Docker image
	docker build -t odoo-security-harness .

docker-run: ## Run harness in Docker
	docker run --rm -it -v $(PWD):/workspace odoo-security-harness

docker-test: ## Run tests in Docker
	docker run --rm -v $(PWD):/workspace odoo-security-harness pytest

setup: ## Initial setup (install hooks, dependencies)
	$(PIP) install -e ".[dev,scanners]"
	pre-commit install
	./install.sh
