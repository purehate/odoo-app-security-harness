# Changelog

All notable changes to the Odoo Application Security Harness will be documented in this file.

## [Unreleased]

### Added
- **AI Integration Scanner** — detects hardcoded AI API keys, tainted prompts, and unsanitized AI output rendering (`odoo-ai-*`)
- **Odoo Disclosure Mapper** — classifies findings as `qualifying` / `non_qualifying` / `borderline` against Odoo responsible disclosure criteria
- **Monkey-patch detection** — flags `BaseModel.create/write/unlink = ...` and `setattr(BaseModel, ...)` assignments (`odoo-deep-monkey-patch-base-model`)
- **getattr/setattr tainted-name detection** — flags dynamic attribute access with user-controlled names (`odoo-deep-getattr-setattr-tainted-name`)
- **ORM `read()` field validation** — flags empty/no-fields or tainted field lists in controller `read()` calls (`odoo-deep-orm-read-*`)
- **Onchange/constraint mutation detection** — flags `@api.onchange` and `@api.constrains` methods that call `write()`/`create()`/`unlink()` (`odoo-deep-onchange-database-mutation`, `odoo-deep-constraint-database-mutation`)
- **Markup(f-string) XSS detection** — flags `Markup(f"...")` where f-string interpolation happens before escaping (`odoo-deep-markup-fstring`)
- **Font-awesome accessibility** — flags `<i class="fa...">` without `aria-label`, `aria-hidden`, or `title` (`odoo-qweb-fa-icon-missing-label`)
- **Field tracking validation** — flags `tracking=True` on models not inheriting `mail.thread` (`odoo-field-tracking-without-mail-thread`)
- **Privileged group admin check** — flags `res.groups` with admin-level names missing `base.user_root`/`base.user_admin` (`odoo-xml-privileged-group-missing-admin-users`)
- **QWeb dynamic t-component detection** — flags dynamic `t-component` template selection (`odoo-qweb-dynamic-t-component`)
- **Auto-fix catalog** — 135 rule IDs mapped to Odoo-idiomatic remediation text (`odoo_security_harness/fix_catalog.py`); injected into findings by `normalize_finding()`
- **OCA Corpus Testing** — integration test harness against real OCA modules (`tests/corpus/`); validates scanners don't crash on real-world code
- **OWASP Coverage Matrix** — `docs/owasp-coverage-matrix.md` mapping 589 shapes and 357 rules to OWASP Top 10 2021 with explicit gap analysis
- Expanded taxonomy: 588 Odoo bug-shape → CWE/CAPEC/OWASP mappings (up from 584)
- Comprehensive test suite with pytest (3854 tests, ~89% coverage on core modules)
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
