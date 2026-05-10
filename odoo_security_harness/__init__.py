"""Odoo Application Security Harness - Core utilities and shared functionality."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Import Odoo-specific analyzers
from odoo_security_harness.access_control import analyze_access_control
from odoo_security_harness.access_override_scanner import scan_access_overrides
from odoo_security_harness.action_url_scanner import scan_action_urls
from odoo_security_harness.action_window_scanner import scan_action_windows
from odoo_security_harness.analyzer import analyze_directory, analyze_file
from odoo_security_harness.api_key_scanner import scan_api_keys
from odoo_security_harness.attachment_scanner import scan_attachments
from odoo_security_harness.automation_scanner import scan_automations
from odoo_security_harness.binary_download_scanner import scan_binary_downloads
from odoo_security_harness.button_action_scanner import scan_button_actions
from odoo_security_harness.cache_header_scanner import scan_cache_headers
from odoo_security_harness.config_parameter_scanner import scan_config_parameters
from odoo_security_harness.constraint_scanner import scan_constraints
from odoo_security_harness.controller_response_scanner import scan_controller_responses
from odoo_security_harness.data_integrity_scanner import scan_data_integrity
from odoo_security_harness.database_scanner import scan_database_operations
from odoo_security_harness.default_value_scanner import scan_default_values
from odoo_security_harness.deployment_scanner import scan_deployment_config
from odoo_security_harness.export_scanner import scan_exports
from odoo_security_harness.field_security_scanner import scan_field_security
from odoo_security_harness.file_upload_scanner import scan_file_uploads
from odoo_security_harness.finding_schema import normalize_findings, validate_findings, validation_report
from odoo_security_harness.identity_mutation_scanner import scan_identity_mutations
from odoo_security_harness.integration_scanner import scan_integrations
from odoo_security_harness.json_route_scanner import scan_json_routes
from odoo_security_harness.mail_alias_scanner import scan_mail_aliases
from odoo_security_harness.mail_chatter_scanner import scan_mail_chatter
from odoo_security_harness.mail_template_scanner import scan_mail_templates
from odoo_security_harness.manifest_scanner import scan_manifests
from odoo_security_harness.metadata_scanner import scan_metadata
from odoo_security_harness.migration_scanner import scan_migrations
from odoo_security_harness.model_method_scanner import scan_model_methods
from odoo_security_harness.model_scanner import scan_models
from odoo_security_harness.module_lifecycle_scanner import scan_module_lifecycle
from odoo_security_harness.multi_company import check_multi_company_isolation
from odoo_security_harness.oauth_scanner import scan_oauth_flows
from odoo_security_harness.orm_context_scanner import scan_orm_context
from odoo_security_harness.orm_domain_scanner import scan_orm_domains
from odoo_security_harness.payment_scanner import scan_payments
from odoo_security_harness.poc_generator import generate_pocs, poc_coverage_report
from odoo_security_harness.portal_scanner import scan_portal_routes
from odoo_security_harness.property_field_scanner import scan_property_fields
from odoo_security_harness.publication_scanner import scan_publication
from odoo_security_harness.queue_job_scanner import scan_queue_jobs
from odoo_security_harness.qweb_scanner import scan_qweb_templates
from odoo_security_harness.raw_sql_scanner import scan_raw_sql
from odoo_security_harness.realtime_scanner import scan_realtime
from odoo_security_harness.record_rule_scanner import scan_record_rules
from odoo_security_harness.report_scanner import scan_reports
from odoo_security_harness.route_security_scanner import scan_route_security
from odoo_security_harness.scheduled_job_scanner import scan_scheduled_jobs
from odoo_security_harness.secrets_scanner import scan_secrets
from odoo_security_harness.sequence_scanner import scan_sequences
from odoo_security_harness.serialization_scanner import scan_serialization
from odoo_security_harness.server_action_scanner import scan_loose_python
from odoo_security_harness.session_auth_scanner import scan_session_auth
from odoo_security_harness.settings_scanner import scan_settings
from odoo_security_harness.signup_token_scanner import scan_signup_tokens
from odoo_security_harness.translation_scanner import scan_translations
from odoo_security_harness.ui_exposure_scanner import scan_ui_exposure
from odoo_security_harness.view_domain_scanner import scan_view_domains
from odoo_security_harness.view_inheritance_scanner import scan_view_inheritance
from odoo_security_harness.web_asset_scanner import scan_web_assets
from odoo_security_harness.website_form_scanner import scan_website_forms
from odoo_security_harness.wizard_scanner import scan_wizards
from odoo_security_harness.xml_data_scanner import scan_xml_data

__all__ = [
    "analyze_access_control",
    "analyze_directory",
    "analyze_file",
    "check_multi_company_isolation",
    "generate_pocs",
    "normalize_findings",
    "poc_coverage_report",
    "scan_action_windows",
    "scan_action_urls",
    "scan_access_overrides",
    "scan_api_keys",
    "scan_attachments",
    "scan_automations",
    "scan_binary_downloads",
    "scan_button_actions",
    "scan_cache_headers",
    "scan_config_parameters",
    "scan_constraints",
    "scan_controller_responses",
    "scan_data_integrity",
    "scan_database_operations",
    "scan_default_values",
    "scan_deployment_config",
    "scan_exports",
    "scan_field_security",
    "scan_file_uploads",
    "scan_identity_mutations",
    "scan_integrations",
    "scan_json_routes",
    "scan_mail_aliases",
    "scan_mail_chatter",
    "scan_mail_templates",
    "scan_manifests",
    "scan_metadata",
    "scan_migrations",
    "scan_module_lifecycle",
    "scan_model_methods",
    "scan_models",
    "scan_orm_context",
    "scan_orm_domains",
    "scan_oauth_flows",
    "scan_payments",
    "scan_portal_routes",
    "scan_property_fields",
    "scan_publication",
    "scan_qweb_templates",
    "scan_queue_jobs",
    "scan_raw_sql",
    "scan_record_rules",
    "scan_realtime",
    "scan_reports",
    "scan_route_security",
    "scan_secrets",
    "scan_scheduled_jobs",
    "scan_serialization",
    "scan_session_auth",
    "scan_sequences",
    "scan_loose_python",
    "scan_settings",
    "scan_signup_tokens",
    "scan_translations",
    "scan_ui_exposure",
    "scan_view_domains",
    "scan_view_inheritance",
    "scan_web_assets",
    "scan_website_forms",
    "scan_wizards",
    "scan_xml_data",
    "validate_findings",
    "validation_report",
]

# Configure logging
logger = logging.getLogger("odoo_security_harness")


def setup_logging(level: int = logging.INFO) -> None:
    """Configure logging for the harness."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def clean_output(text: str) -> str:
    """Strip terminal control noise from CLI/model output before logs/artifacts."""
    ansi_re = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b[()][A-Za-z0-9]")
    return ansi_re.sub("", text).replace("\r", "\n")


def progress(message: str) -> None:
    """Print a progress message."""
    print(f"[odoo-review-run] {message}", flush=True)
    logger.info(message)


def rel(path: Path, root: Path) -> str:
    """Get relative path from root."""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def should_skip(path: Path) -> bool:
    """Check if a path should be skipped during scanning."""
    parts = set(path.parts)
    if parts & {
        ".git",
        ".hg",
        ".svn",
        ".audit",
        "__pycache__",
        ".venv",
        "venv",
        "node_modules",
        ".worktrees",
    }:
        return True
    return any(
        part.startswith(".audit-")
        and part
        not in {
            ".audit-accepted-risks.yml",
            ".audit-accepted-risks.yaml",
            ".audit-accepted-risks.json",
            ".audit-fix-list.yml",
            ".audit-fix-list.yaml",
            ".audit-fix-list.json",
            ".audit-baseline",
        }
        for part in path.parts
    )


def normalize_line(text: str) -> str:
    """Normalize whitespace in text."""
    return re.sub(r"\s+", " ", text).strip()


def compute_fingerprint(finding: dict[str, Any]) -> str:
    """Compute stable fingerprint for cross-run deduplication."""
    import hashlib

    parts = [
        (finding.get("rule_id") or finding.get("title") or "")[:80],
        finding.get("file", ""),
        str(finding.get("line", "")),
        normalize_line((finding.get("description") or finding.get("attack_path") or "")[:200]),
    ]
    h = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return f"sha256:{h}"


def severity_rank(sev: str | None) -> int:
    """Convert severity string to numeric rank."""
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get((sev or "").lower(), 2)


def load_json(path: Path) -> dict[str, Any]:
    """Load JSON file safely."""
    try:
        text = path.read_text(encoding="utf-8")
        return json.loads(text)
    except json.JSONDecodeError as exc:
        logger.error(f"Failed to parse JSON {path}: {exc}")
        raise
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
        raise


def write_json(path: Path, data: dict[str, Any], indent: int = 2) -> None:
    """Write JSON file safely."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=indent), encoding="utf-8")


def timestamp() -> str:
    """Return ISO timestamp in UTC."""
    return datetime.now(timezone.utc).isoformat()
