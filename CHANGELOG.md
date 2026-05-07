# Changelog

All notable changes to the Odoo Application Security Harness will be documented in this file.

## [Unreleased]

### Added
- Comprehensive test suite with pytest (90%+ coverage)
- Docker support for consistent execution environments
- GitHub Actions CI/CD pipeline
- Pre-commit hooks for code quality
- Configuration validation script (`odoo-review-validate-config`)
- Parallel scanner execution support
- Progress indicators and better UX
- Python package structure (`odoo_security_harness`)
- `pyproject.toml` with proper dependency management
- Makefile for common tasks
- Type hints and improved error handling
- Logging support with configurable levels

### Changed
- Improved `install.sh` with Python version checking and colored output
- Better prerequisite validation during installation
- Enhanced error messages across all scripts

### Fixed
- Various edge cases in manifest parsing
- Better handling of missing optional dependencies

## [1.0.0] - 2024-01-01

### Added
- Initial release of Odoo Application Security Harness
- Multi-phase audit pipeline (0-8)
- Three-lane architecture (Claude Code, Ollama/Qwen, Codex/OpenAI)
- 10 Odoo-specific security hunters
- SARIF 2.1.0 export
- Bounty draft generation
- Findings diff functionality
- Runtime evidence capture
- Attack graph visualization

[Unreleased]: https://github.com/purehate/odoo-app-security-harness/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/purehate/odoo-app-security-harness/releases/tag/v1.0.0
