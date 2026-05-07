# Odoo Application Security Harness - Test Suite

Comprehensive test suite for the Odoo Application Security Harness.

## Running Tests

```bash
# Install test dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=odoo_security_harness --cov-report=html

# Run only fast tests (skip slow/integration)
pytest -m "not slow and not integration"

# Run specific test file
pytest tests/test_manifest_parser.py
```

## Test Structure

- `test_manifest_parser.py` - Tests for manifest parsing and module discovery
- `test_route_extraction.py` - Tests for HTTP route extraction from Odoo controllers
- `test_risk_scoring.py` - Tests for module risk scoring algorithm
- `test_export.py` - Tests for SARIF/fingerprint/bounty export
- `test_diff.py` - Tests for findings diff functionality
- `test_coverage.py` - Tests for hunter coverage analysis
- `test_config_validation.py` - Tests for configuration validation
- `test_runtime.py` - Tests for Odoo runtime helper
- `fixtures/` - Test fixtures (sample manifests, configs, etc.)
