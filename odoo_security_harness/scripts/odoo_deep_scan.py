#!/usr/bin/env python3
"""Odoo Security Deep Scan - Runs all Odoo-specific analyzers.

Usage:
    odoo-deep-scan <repo-path> [--out <dir>] [--pocs]

Runs the full static review harness: Python patterns, XML/QWeb metadata, ACLs,
access overrides, multi-company isolation, manifests, migrations, models, data
exposure, secrets, deployment posture, config-parameters, ir.default values,
sequences, action windows, URL actions, identity mutations, API keys, module lifecycle,
database operations, attachments,
OAuth callback/token flows,
signup/reset token lifecycle,
cache-control response posture,
ORM context, raw SQL, models/settings, model-methods, constraints, button-actions, wizards,
data-integrity, mail, reports, UI, routes, jobs, integrations, loose
server-action Python, and optional PoC generation.

Outputs findings in JSON and Markdown format.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import html
import json
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path

import yaml

from odoo_security_harness import (
    analyze_access_control,
    analyze_directory,
    check_multi_company_isolation,
    compute_fingerprint,
    generate_pocs,
    normalize_findings,
    poc_coverage_report,
    scan_access_overrides,
    scan_action_urls,
    scan_action_windows,
    scan_api_keys,
    scan_attachments,
    scan_automations,
    scan_binary_downloads,
    scan_button_actions,
    scan_cache_headers,
    scan_config_parameters,
    scan_constraints,
    scan_controller_responses,
    scan_data_integrity,
    scan_database_operations,
    scan_default_values,
    scan_deployment_config,
    scan_exports,
    scan_field_security,
    scan_file_uploads,
    scan_identity_mutations,
    scan_integrations,
    scan_json_routes,
    scan_loose_python,
    scan_mail_aliases,
    scan_mail_chatter,
    scan_mail_templates,
    scan_manifests,
    scan_metadata,
    scan_migrations,
    scan_model_methods,
    scan_models,
    scan_module_lifecycle,
    scan_oauth_flows,
    scan_orm_context,
    scan_orm_domains,
    scan_payments,
    scan_portal_routes,
    scan_property_fields,
    scan_publication,
    scan_queue_jobs,
    scan_qweb_templates,
    scan_raw_sql,
    scan_realtime,
    scan_record_rules,
    scan_reports,
    scan_route_security,
    scan_scheduled_jobs,
    scan_secrets,
    scan_sequences,
    scan_serialization,
    scan_session_auth,
    scan_settings,
    scan_signup_tokens,
    scan_translations,
    scan_ui_exposure,
    scan_view_domains,
    scan_view_inheritance,
    scan_web_assets,
    scan_website_forms,
    scan_wizards,
    scan_xml_data,
    validation_report,
)

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK = {severity: index for index, severity in enumerate(_SEVERITY_ORDER)}
_SEVERITY_SCORE = {"critical": 20, "high": 10, "medium": 4, "low": 1, "info": 0}
_TAXONOMY_SHAPE_HINTS = (
    (
        "website_form_sanitize_disabled",
        (
            "odoo-website-form-sanitize-disabled",
            "website form disables input sanitization",
            "website form submits sanitize_form=false",
            "call passes sanitize_form=false",
            "public users cannot persist unsafe html through website_form handling",
        ),
    ),
    (
        "migration_interpolated_sql",
        ("odoo-migration-interpolated-sql",),
    ),
    (
        "loose_python_eval_exec",
        (
            "odoo-loose-python-eval-exec",
            "dynamic python execution in loose script",
            "eval()/exec() in server actions or loose scripts",
            "can become code execution",
            "inputs are not strictly controlled",
        ),
    ),
    (
        "loose_python_safe_eval",
        (
            "odoo-loose-python-safe-eval",
            "safe_eval in loose script",
            "safe_eval() in server actions/scripts",
            "strict input provenance review",
            "sandbox assumptions",
        ),
    ),
    (
        "loose_python_sudo_write",
        (
            "odoo-loose-python-sudo-write",
            "privileged mutation in loose script",
            "sudo()/with_user(superuser_id) is chained into write/create/unlink",
            "bypass intended record rules or company isolation",
        ),
    ),
    (
        "loose_python_sudo_method_call",
        (
            "odoo-loose-python-sudo-method-call",
            "privileged business method call in loose script",
            "loose-python privileged business method call",
        ),
    ),
    (
        "loose_python_sensitive_model_mutation",
        (
            "odoo-loose-python-sensitive-model-mutation",
            "sensitive model mutation in loose script",
            "server action or loose script mutates sensitive model",
            "actor, trigger scope, idempotency, and audit trail",
        ),
    ),
    (
        "loose_python_manual_transaction",
        ("odoo-loose-python-manual-transaction",),
    ),
    (
        "loose_python_http_no_timeout",
        (
            "odoo-loose-python-http-no-timeout",
            "outbound http without timeout in loose script",
            "server actions or loose scripts perform outbound http without timeout",
            "ssrf, retry behavior, and worker exhaustion risk",
        ),
    ),
    (
        "loose_python_tls_verification_disabled",
        (
            "odoo-loose-python-tls-verify-disabled",
            "loose script disables tls verification",
            "server actions or loose scripts pass verify=false to outbound http",
        ),
    ),
    (
        "loose_python_sql_injection",
        (
            "odoo-loose-python-sql-injection",
            "raw sql built with string interpolation",
            "cr.execute() receives sql built with interpolation/concatenation",
            "use parameters or psycopg2.sql for identifiers",
        ),
    ),
    (
        "deep_with_user_admin",
        ("odoo-deep-with-user-admin",),
    ),
    (
        "deep_markup_user_input",
        ("odoo-deep-markup-user-input",),
    ),
    (
        "deep_html_sanitize_false",
        ("odoo-deep-html-sanitize-false",),
    ),
    (
        "multi_company_missing_check_company",
        ("odoo-mc-missing-check-company",),
    ),
    (
        "multi_company_check_company_disabled",
        ("odoo-mc-check-company-disabled",),
    ),
    (
        "multi_company_sudo_search_no_company_scope",
        ("odoo-mc-sudo-search-no-company",),
    ),
    (
        "multi_company_search_no_company_scope",
        ("odoo-mc-search-no-company",),
    ),
    (
        "multi_company_with_company_user_input",
        ("odoo-mc-with-company-user-input",),
    ),
    (
        "multi_company_context_user_input",
        ("odoo-mc-company-context-user-input",),
    ),
    (
        "multi_company_rule_missing_company_scope",
        ("odoo-mc-rule-missing-company",),
    ),
    (
        "api_key_xml_record",
        (
            "odoo-api-key-xml-record",
            "api key record is declared in xml data",
            "module data declares a res.users.apikeys record",
        ),
    ),
    (
        "api_key_csv_record",
        (
            "odoo-api-key-csv-record",
            "api key record is declared in csv data",
            "csv data declares a res.users.apikeys record",
            "credentials are not seeded, exported, or recreated across databases",
        ),
    ),
    (
        "api_key_public_route_mutation",
        (
            "odoo-api-key-public-route-mutation",
            "public route mutates api keys",
            "authenticated owner or administrators can create, revoke, or rename api keys",
        ),
    ),
    (
        "api_key_sudo_mutation",
        (
            "odoo-api-key-sudo-mutation",
            "api key mutation runs with elevated environment",
            "caller identity, owner scoping, revocation semantics, and audit logging",
        ),
    ),
    (
        "api_key_request_derived_mutation",
        (
            "odoo-api-key-request-derived-mutation",
            "request-derived data reaches api key mutation",
            "request-derived data reaches res.users.apikeys",
            "prevent callers from choosing another user_id or scope",
        ),
    ),
    (
        "api_key_tainted_lookup",
        (
            "odoo-api-key-tainted-lookup",
            "request-derived api key lookup",
            "request-derived data is used to query api-key records",
            "constant-time credential validation, hashing, and user scoping",
        ),
    ),
    (
        "secret_hardcoded_value",
        (
            "odoo-secret-hardcoded-value",
            "hardcoded secret-like value",
            "secret-like assignment",
            "contains committed value",
            "rotate and move to environment/config storage",
        ),
    ),
    (
        "secret_config_parameter_code_value",
        (
            "odoo-secret-config-parameter-set-param",
            "sensitive ir.config_parameter value set in code",
            "code sets ir.config_parameter",
            "avoid shipping production secrets in module code",
        ),
    ),
    (
        "secret_config_parameter_xml_value",
        (
            "odoo-secret-config-parameter",
            "sensitive ir.config_parameter value committed",
            "module data commits ir.config_parameter",
            "module updates can overwrite production secrets/config",
        ),
    ),
    (
        "secret_weak_user_password_data",
        (
            "odoo-secret-weak-user-password-data",
            "weak user password committed in module data",
            "res.users password in xml data is a weak default",
        ),
    ),
    (
        "secret_user_password_data",
        (
            "odoo-secret-user-password-data",
            "user password committed in module data",
            "res.users password is committed in xml data",
            "shipping reusable account credentials",
        ),
    ),
    (
        "secret_weak_admin_passwd",
        (
            "odoo-secret-weak-admin-passwd",
            "weak odoo database manager password",
            "admin_passwd is empty or 'admin'",
            "database manager can be brute-forced or guessed",
        ),
    ),
    (
        "secret_config_file_value",
        (
            "odoo-secret-config-file-value",
            "secret-like value committed in config file",
            "config file contains",
            "keep real secrets out of source",
        ),
    ),
    (
        "route_auth_none",
        (
            "odoo-route-auth-none",
            "route bypasses database user authentication",
            "uses auth='none'",
            "before database selection",
        ),
    ),
    (
        "route_cors_wildcard",
        (
            "odoo-route-cors-wildcard",
            "route allows wildcard cors",
            "sets cors='*'",
            "cross-origin callers cannot use ambient sessions",
        ),
    ),
    (
        "route_bearer_save_session",
        (
            "odoo-route-bearer-save-session",
            "bearer route explicitly saves browser session",
            "sets save_session=true",
            "api-token requests cannot create or persist ambient browser sessions",
        ),
    ),
    (
        "route_csrf_disabled_all_methods",
        (
            "odoo-route-csrf-disabled-all-methods",
            "public route disables csrf without method restriction",
            "disables csrf and does not set methods=",
            "constrain verbs and require a non-browser authentication token",
        ),
    ),
    (
        "route_unsafe_csrf_disabled",
        (
            "odoo-route-unsafe-csrf-disabled",
            "mutating route disables csrf",
            "disables csrf on a mutating-looking endpoint",
            "stronger non-browser token",
        ),
    ),
    (
        "csrf_state_change_get",
        (
            "odoo-route-public-get-mutation",
            "public route exposes mutating action over get",
            "mutating-looking action over get",
            "keep get idempotent",
        ),
    ),
    (
        "route_public_all_methods",
        (
            "odoo-route-public-all-methods",
            "public route does not restrict http methods",
            "does not set methods=",
            "reduce unexpected get/post exposure",
        ),
    ),
    (
        "route_public_sitemap_indexed",
        (
            "odoo-route-public-sitemap-indexed",
            "public website route may be sitemap-indexed",
            "can be sitemap-indexed",
            "content is intended for discovery",
        ),
    ),
    (
        "action_window_sensitive_exposure",
        (
            "odoo-act-window-public-sensitive-model",
            "odoo-act-window-sensitive-broad-domain",
        ),
    ),
    (
        "action_window_privileged_context",
        (
            "odoo-act-window-privileged-default-context",
            "odoo-act-window-active-test-disabled",
        ),
    ),
    (
        "action_window_company_scope_context",
        ("odoo-act-window-company-scope-context",),
    ),
    (
        "action_window_tainted_definition",
        (
            "odoo-act-window-tainted-res-model",
            "odoo-act-window-tainted-domain",
            "odoo-act-window-tainted-context",
        ),
    ),
    (
        "view_context_active_test_disabled",
        ("odoo-view-context-active-test-disabled",),
    ),
    (
        "json_route_record_idor",
        (
            "odoo-json-route-tainted-record-mutation",
            "odoo-json-route-tainted-record-read",
            "json request controls record selection",
            "json request controls record selection for mutation",
            "json request controls record selection for read",
            "records selected by request-controlled",
            "request-controlled ids/domains",
        ),
    ),
    (
        "json_route_public_auth",
        (
            "odoo-json-route-public-auth",
            "public json route exposed",
            "authentication, rate limiting, and csrf/session assumptions",
        ),
    ),
    (
        "json_route_csrf_disabled",
        (
            "odoo-json-route-csrf-disabled",
            "json route explicitly disables csrf",
            "sets csrf=false",
            "called cross-site with ambient session credentials",
        ),
    ),
    (
        "json_route_sudo_mutation",
        (
            "odoo-json-route-sudo-mutation",
            "json route mutates records through an elevated environment",
            "json route performs create/write/unlink through sudo",
            "caller authorization, ownership checks, and company isolation",
        ),
    ),
    (
        "json_route_mass_assignment",
        (
            "odoo-json-route-mass-assignment",
            "json request data flows into orm mutation",
            "json route passes request-derived data into create/write/unlink",
            "whitelist fields and reject privilege, workflow, ownership, and company fields",
        ),
    ),
    (
        "json_route_public_sudo_read",
        (
            "odoo-json-route-public-sudo-read",
            "public json route reads through an elevated environment",
            "public json route reads/searches through sudo",
            "cannot expose records outside the caller's ownership or company",
        ),
    ),
    (
        "json_route_tainted_domain",
        ("odoo-json-route-tainted-domain",),
    ),
    ("qweb_xss_t_raw", ("web-owl-qweb-t-raw", "qweb-t-raw", "t-raw", "html-field", "unsafe html")),
    (
        "qweb_dangerous_tag",
        (
            "odoo-qweb-dangerous-tag",
            "qweb renders dangerous html tag",
            "dangerous html tag",
            "script, iframe, object, embed, or link tag",
        ),
    ),
    (
        "qweb_html_widget_render",
        (
            "odoo-qweb-html-widget",
            "qweb renders html widget",
            "html widget renders rich text",
            "widget='html'",
        ),
    ),
    (
        "qweb_inline_event_handler",
        (
            "odoo-qweb-inline-event",
            "qweb inline event handler",
            "inline event handler attribute",
        ),
    ),
    (
        "qweb_sensitive_field_render",
        (
            "web-owl-qweb-sensitive-field-render",
            "odoo-qweb-sensitive-field-render",
            "qweb renders sensitive field",
            "owl inline template renders sensitive-looking field",
            "sensitive field render",
            "password, token, secret, api key, or bank field",
        ),
    ),
    (
        "qweb_dynamic_url_attribute",
        (
            "odoo-qweb-t-att-url",
            "qweb dynamic url attribute",
            "dynamic href/src/action URL",
            "scriptable URL scheme",
        ),
    ),
    (
        "qweb_dynamic_template_render",
        (
            "qweb-dynamic-t-call",
            "dynamic-t-call",
            "t-call uses a dynamic template",
            "chooses a template dynamically",
        ),
    ),
    (
        "qweb_event_handler_injection",
        (
            "web-owl-qweb-dynamic-event-handler",
            "qweb-dynamic-event-handler",
            "dynamic-event-handler",
            "dynamic event handler",
            "javascript event handler",
            "javascript context",
        ),
    ),
    (
        "qweb_markup_escape_bypass",
        (
            "qweb-markup-escape-bypass",
            "markup escape bypass",
            "markup() bypasses escaping",
            "already-safe html",
            "renders a markup() value",
        ),
    ),
    (
        "qweb_inline_script_execution",
        (
            "qweb-script-expression-context",
            "qweb-t-js-inline-script",
            "qweb expression rendered inside javascript block",
            "t-js inline javascript",
            "t-js inline script",
            "inline javascript in a template",
            "html escaping is not javascript-context escaping",
            "script context",
        ),
    ),
    (
        "qweb_raw_output_mode",
        (
            "web-owl-raw-output-mode",
            "qweb-raw-output-mode",
            "owl inline template disables qweb escaping",
            "raw output mode",
            "t-out-mode='raw'",
            "disables normal t-out escaping",
            "disables escaping",
        ),
    ),
    (
        "i18n_dangerous_html",
        (
            "odoo-i18n-dangerous-html",
            "translation injects dangerous html or scriptable url",
            "translated msgstr contains scriptable html",
            "translated msgstr contains dangerous url schemes",
            "translated catalogs can bypass reviewed template text",
        ),
    ),
    (
        "i18n_qweb_raw_output",
        (
            "odoo-i18n-qweb-raw-output",
            "translation injects raw qweb output directive",
            "translated msgstr contains raw qweb output directives",
            "translations cannot disable escaping",
        ),
    ),
    (
        "i18n_template_expression_injection",
        (
            "odoo-i18n-template-expression-injection",
            "translation injects template expression",
            "translated msgstr introduces template expressions",
            "qweb control directives absent from the source string",
            "translators cannot execute template logic",
        ),
    ),
    (
        "i18n_placeholder_mismatch",
        (
            "odoo-i18n-placeholder-mismatch",
            "translation changes interpolation placeholders",
            "translated msgstr placeholders",
            "do not match msgid placeholders",
            "placeholder drift can drop escaped values or break rendering",
        ),
    ),
    (
        "html_sanitizer_relaxed",
        (
            "html-sanitize-strict-false",
            "html-sanitize-relaxed-option",
            "html sanitizer uses non-strict mode",
            "html sanitizer disables sanitizer option",
            "html_sanitize(..., strict=false)",
            "disables part of html sanitization",
            "sanitize_attributes=false",
            "sanitize_tags=false",
            "strict=false",
            "broader html surface",
        ),
    ),
    (
        "field_sensitive_access_control",
        (
            "odoo-field-sensitive-no-groups",
            "odoo-field-sensitive-public-groups",
            "odoo-field-related-sensitive-no-admin-groups",
        ),
    ),
    (
        "field_sensitive_persistence_leak",
        (
            "odoo-field-sensitive-indexed",
            "odoo-field-sensitive-tracking",
            "odoo-field-sensitive-copyable",
        ),
    ),
    (
        "field_compute_sudo_projection",
        (
            "odoo-field-compute-sudo-sensitive",
            "odoo-field-compute-sudo-scalar-no-admin-groups",
        ),
    ),
    (
        "property_field_company_scope",
        (
            "property-field-no-company-field",
            "property-field-default",
            "company-dependent field on model without company_id",
            "company-dependent field defines a default",
            "company_dependent=true but model has no company_id",
            "default does not mask missing company-specific properties",
            "property fallback and cross-company behavior",
        ),
    ),
    (
        "property_field_sensitive_access",
        (
            "property-sensitive-field-no-groups",
            "sensitive company-dependent field lacks groups",
            "sensitive company-dependent field",
            "users cannot alter company-specific accounting/security values",
        ),
    ),
    (
        "property_record_global_default",
        (
            "property-global-default",
            "property-runtime-global-default",
            "ir.property record has no company",
            "runtime ir.property mutation has no company",
            "has no company_id and becomes a global fallback",
            "omits company_id and may create a global fallback",
            "safe for all companies",
        ),
    ),
    (
        "property_record_broad_scope",
        (
            "property-no-resource-scope",
            "property-runtime-no-resource-scope",
            "ir.property record has no resource scope",
            "runtime ir.property mutation has no resource scope",
            "has no res_id and may apply broadly",
            "omits res_id and may apply broadly",
            "intended model/company scope",
        ),
    ),
    (
        "property_sensitive_value",
        (
            "property-sensitive-value",
            "property-runtime-sensitive-value",
            "sensitive ir.property value is preconfigured",
            "runtime ir.property writes sensitive value",
            "configures a sensitive field",
            "accounting/security defaults are company-scoped",
        ),
    ),
    (
        "property_public_mutation",
        (
            "property-public-route-mutation",
            "public route mutates ir.property",
            "public route writes ir.property",
            "unauthenticated users cannot alter company-specific accounting or configuration defaults",
        ),
    ),
    (
        "property_privileged_mutation",
        (
            "property-sudo-mutation",
            "ir.property is mutated through privileged context",
            "sudo()/with_user(superuser_id) mutates ir.property",
            "explicit admin checks and company scoping",
        ),
    ),
    (
        "property_tainted_mutation",
        (
            "property-request-derived-mutation",
            "request-derived data reaches ir.property",
            "request-derived data reaches ir.property mutation",
            "whitelist fields and reject accounting, company, token, and security properties",
        ),
    ),
    (
        "manifest_parse_integrity",
        (
            "manifest-parse-error",
            "manifest cannot be parsed safely",
            "not a literal python dictionary",
            "verify install metadata manually",
        ),
    ),
    (
        "manifest_acl_packaging_gap",
        (
            "manifest-missing-acl-data",
            "installable module with models does not load acl csv",
            "manifest data does not include security/ir.model.access.csv",
            "module defines python models",
        ),
    ),
    (
        "manifest_demo_data_exposure",
        (
            "manifest-demo-in-data",
            "manifest-application-demo-data",
            "demo data loaded as production data",
            "application module ships demo data",
            "manifest data loads demo-looking files",
            "accidental sample users, credentials, or records",
        ),
    ),
    (
        "manifest_license_metadata",
        (
            "manifest-missing-license",
            "manifest-unexpected-license",
            "installable module missing license",
            "manifest uses an unexpected license identifier",
            "redistribution/compliance posture",
            "app-store compliance",
        ),
    ),
    (
        "manifest_auto_install_security",
        (
            "manifest-auto-install-security-data",
            "manifest-auto-install-without-depends",
            "auto-installed module loads security-sensitive data",
            "auto-installed module has no explicit dependencies",
            "auto_install=true modules can be installed implicitly",
            "surprise privilege changes",
            "install unexpectedly",
        ),
    ),
    (
        "manifest_remote_asset_supply_chain",
        (
            "manifest-remote-assets",
            "manifest declares remote frontend assets",
            "frontend assets reference remote urls",
            "supply-chain trust",
            "pinning, csp, and offline install behavior",
        ),
    ),
    (
        "manifest_path_integrity",
        (
            "manifest-suspicious-data-path",
            "manifest loads suspicious local file paths",
            "absolute or parent-directory traversal entries",
            "packaged data and assets cannot load files outside the module",
        ),
    ),
    (
        "manifest_risky_dependency",
        (
            "manifest-risky-python-dependency",
            "manifest-risky-bin-dependency",
            "manifest-direct-python-dependency",
            "manifest declares dependency with security-sensitive usage",
            "manifest declares binary dependency with security-sensitive usage",
            "manifest declares direct python dependency reference",
            "security-sensitive dependency declarations",
            "security-sensitive binary dependency declarations",
            "direct url, vcs, or local-file references",
            "paramiko",
        ),
    ),
    (
        "view_inheritance_broad_security_xpath",
        (
            "view-inherit-broad-security-xpath",
            "inherited view uses broad xpath for security-sensitive control",
            "uses broad xpath",
            "against buttons/fields",
            "unintended secured controls",
        ),
    ),
    (
        "view_inheritance_group_relaxation",
        (
            "view-inherit-removes-groups",
            "view-inherit-public-groups-sensitive-target",
            "inherited view removes groups restriction",
            "exposes sensitive control to public/portal group",
            "removes groups from target",
            "assigns public/portal groups to sensitive target",
            "access-checked server-side",
        ),
    ),
    (
        "view_inheritance_object_button_exposure",
        (
            "view-inherit-replaces-object-button",
            "view-inherit-adds-public-object-button",
            "view-inherit-adds-object-button-no-groups",
            "inherited view replaces object-method button",
            "inherited view inserts public object-method button",
            "inherited view inserts object-method button without groups",
            "forged rpc calls cannot bypass workflow permissions",
            "method enforces server-side authorization",
        ),
    ),
    (
        "view_inheritance_sensitive_field_exposure",
        (
            "view-inherit-reveals-sensitive-field",
            "view-inherit-replaces-sensitive-field",
            "view-inherit-adds-public-sensitive-field",
            "view-inherit-adds-sensitive-field-no-groups",
            "view-inherit-makes-sensitive-field-editable",
            "inherited view may reveal sensitive field/control",
            "inherited view replaces sensitive field",
            "inherited view inserts sensitive field",
            "inherited view may make sensitive field editable",
            "cannot expose secrets or privileges",
            "cannot edit privilege-bearing fields or secrets",
            "groups, readonly, and invisibility restrictions are preserved",
        ),
    ),
    (
        "model_sensitive_display_name",
        (
            "model-rec-name-sensitive",
            "model display name uses sensitive field",
            "sets _rec_name to sensitive-looking field",
            "display names can leak through relational widgets",
        ),
    ),
    (
        "model_delegated_inheritance_exposure",
        (
            "model-delegated-sensitive-inherits",
            "model-delegate-sensitive-field",
            "model delegates to sensitive model",
            "many2one delegates sensitive model fields",
            "uses _inherits to delegate",
            "sets delegate=true to sensitive model",
            "wrapper acls cannot expose delegated fields",
        ),
    ),
    (
        "model_delegated_link_integrity",
        (
            "model-delegated-link-missing",
            "model-delegated-link-not-required",
            "model-delegated-link-no-cascade",
            "delegated inheritance link field is missing",
            "delegated inheritance link is not required",
            "delegated inheritance link does not cascade",
            "no matching many2one field is visible",
            "may exist without the delegated record",
            "delete/orphan semantics preserve delegated-record integrity",
        ),
    ),
    (
        "model_secret_persistence",
        (
            "model-secret-copyable",
            "secret-like field is copyable",
            "does not set copy=false",
            "duplicated records may inherit credentials or access tokens",
        ),
    ),
    (
        "model_audit_metadata_disabled",
        (
            "model-log-access-disabled",
            "model disables odoo access logging",
            "sets _log_access=false",
            "create/write user and timestamp audit fields will not be maintained",
        ),
    ),
    (
        "model_manual_sql_storage",
        (
            "model-auto-false-manual-sql",
            "model uses manually managed sql storage",
            "sets _auto=false",
            "verify sql view/table creation, acls, record rules, and exposed fields",
        ),
    ),
    (
        "model_identifier_uniqueness",
        (
            "model-identifier-missing-unique",
            "required identifier field lacks obvious sql uniqueness",
            "has no visible unique _sql_constraints",
            "duplicate business-key risk",
        ),
    ),
    (
        "model_monetary_currency_integrity",
        (
            "model-monetary-missing-currency",
            "monetary field lacks obvious currency field",
            "has no currency_field and model has no currency_id",
            "cross-company/currency correctness",
        ),
    ),
    (
        "model_method_dynamic_evaluation",
        (
            "model-method-dynamic-eval",
            "odoo model method performs dynamic evaluation",
            "model method calls eval/exec/safe_eval",
            "record field or context value can control evaluated code",
        ),
    ),
    (
        "model_method_sensitive_model_mutation",
        (
            "model-method-onchange-sensitive-model-mutation",
            "model-method-compute-sensitive-model-mutation",
            "model-method-constraint-sensitive-model-mutation",
            "model-method-inverse-sensitive-model-mutation",
            "odoo model method mutates sensitive model",
            "model method mutates sensitive model",
            "lifecycle side effects, caller access, and audit trail",
        ),
    ),
    (
        "model_method_elevated_mutation",
        (
            "model-method-onchange-sudo-mutation",
            "model-method-compute-sudo-mutation",
            "model-method-constraint-sudo-mutation",
            "model-method-inverse-sudo-mutation",
            "odoo model method performs elevated mutation",
            "model method mutates records through sudo()/with_user(superuser_id)",
            "form-triggered side effects",
        ),
    ),
    (
        "migration_missing_lifecycle_hook",
        (
            "migration-missing-lifecycle-hook",
            "manifest lifecycle hook function is missing",
            "no matching python function was found",
            "silently skip required security setup",
        ),
    ),
    (
        "migration_lifecycle_hook_review",
        (
            "odoo-manifest-lifecycle-hook",
            "migration-lifecycle-hook",
            "manifest lifecycle hook requires review",
            "manifest declares lifecycle hook",
            "install/uninstall side effects and privilege assumptions",
        ),
    ),
    (
        "migration_interpolated_sql",
        (
            "odoo-migration-interpolated-sql",
            "migration-interpolated-sql",
            "migration sql uses interpolation",
            "executes sql built with interpolation/formatting",
            "use parameters or psycopg2.sql",
        ),
    ),
    (
        "migration_destructive_sql",
        (
            "migration-destructive-sql",
            "migration executes destructive sql",
            "executes destructive sql",
            "backups, where clauses, tenant filters, and rollback safety",
        ),
    ),
    (
        "migration_sudo_mutation",
        (
            "migration-sudo-mutation",
            "migration/hook performs elevated mutation",
            "migration or lifecycle hook chains sudo()/with_user(superuser_id) into write/create/unlink",
            "cannot corrupt records across companies or tenants",
        ),
    ),
    (
        "migration_manual_transaction",
        (
            "migration-manual-transaction",
            "migration/hook controls transactions manually",
            "migration or lifecycle hook calls commit()/rollback()",
            "partial security state",
        ),
    ),
    (
        "migration_http_without_timeout",
        (
            "migration-http-no-timeout",
            "migration/hook performs http without timeout",
            "migration or lifecycle hook performs outbound http without timeout",
            "install/upgrade can hang workers or deployment pipelines",
        ),
    ),
    (
        "migration_tls_verification_disabled",
        (
            "migration-tls-verify-disabled",
            "migration/hook disables tls verification",
            "migration or lifecycle hook passes verify=false to outbound http",
        ),
    ),
    (
        "migration_process_execution",
        (
            "migration-process-execution",
            "migration/hook executes a subprocess",
            "migration or lifecycle hook executes a subprocess",
            "command injection, deployment portability, timeouts, and privilege assumptions",
        ),
    ),
    (
        "module_lifecycle_public_route",
        (
            "module-public-route-lifecycle",
            "public route changes module lifecycle",
            "public/unauthenticated route calls button_immediate_install",
            "public/unauthenticated route calls button_immediate_upgrade",
            "public/unauthenticated route calls button_immediate_uninstall",
            "attackers cannot install, upgrade, or uninstall odoo modules",
        ),
    ),
    (
        "attachment_sudo_mutation",
        (
            "odoo-attachment-sudo-mutation",
            "attachment mutation runs with elevated environment",
            "ir.attachment mutation runs through sudo()/with_user(superuser_id)",
            "res_model/res_id binding, ownership, company scope, and auditability",
        ),
    ),
    (
        "module_lifecycle_sudo_operation",
        (
            "module-sudo-lifecycle",
            "module lifecycle operation runs with an elevated environment",
            "runs through sudo()/with_user(superuser_id)",
            "only system administrators can alter installed code and data",
        ),
    ),
    (
        "module_lifecycle_immediate_operation",
        (
            "module-immediate-lifecycle",
            "immediate module lifecycle operation",
            "button_immediate_install executes module lifecycle work immediately",
            "button_immediate_upgrade executes module lifecycle work immediately",
            "button_immediate_uninstall executes module lifecycle work immediately",
            "registry reload behavior",
        ),
    ),
    (
        "module_lifecycle_tainted_selection",
        (
            "odoo-module-tainted-selection",
            "module-tainted-selection",
            "request-derived module selection",
            "request-derived data selects an ir.module.module record",
            "restrict to an explicit allowlist and admin-only flow",
        ),
    ),
    (
        "automation_broad_sensitive_trigger",
        (
            "odoo-automation-broad-sensitive-trigger",
            "broad automated action on sensitive model",
            "base.automation runs on",
            "without a filter_domain",
            "cannot mutate/expose every record",
        ),
    ),
    (
        "automation_dynamic_eval",
        (
            "odoo-automation-dynamic-eval",
            "automated action performs dynamic evaluation",
            "base.automation code contains eval/exec/safe_eval",
            "no record or user-controlled expression reaches it",
        ),
    ),
    (
        "automation_sudo_mutation",
        (
            "odoo-automation-sudo-mutation",
            "automated action performs elevated mutation",
            "base.automation code chains sudo()/with_user(superuser_id)",
            "record rules and company isolation are not bypassed",
        ),
    ),
    (
        "automation_sudo_method_call",
        (
            "odoo-automation-sudo-method-call",
            "automated action calls elevated business method",
            "base.automation code uses sudo()/with_user(superuser_id) to call a business/action method",
        ),
    ),
    (
        "automation_sensitive_model_mutation",
        (
            "odoo-automation-sensitive-model-mutation",
            "automated action mutates sensitive model",
            "base.automation code mutates a sensitive model",
            "trigger scope, actor, idempotency, and audit trail",
        ),
    ),
    (
        "automation_http_without_timeout",
        ("odoo-automation-http-no-timeout",),
    ),
    (
        "automation_tls_verification_disabled",
        (
            "automation-tls-verify-disabled",
            "automated action disables tls verification",
            "base.automation code passes verify=false to outbound http",
        ),
    ),
    (
        "scheduled_job_elevated_mutation",
        (
            "scheduled-job-sudo-mutation",
            "scheduled job performs elevated mutation",
            "scheduled job mutates records through sudo()/with_user(superuser_id)",
            "record rules, company isolation, input trust, and retry idempotency",
        ),
    ),
    (
        "scheduled_job_elevated_method_call",
        (
            "odoo-scheduled-job-sudo-method-call",
            "scheduled job calls elevated business method",
            "scheduled job uses sudo()/with_user(superuser_id) to call a business/action method",
        ),
    ),
    (
        "scheduled_job_sensitive_model_mutation",
        (
            "scheduled-job-sensitive-model-mutation",
            "scheduled job mutates sensitive model",
            "verify the cron user, domain scope, idempotency, and audit trail",
        ),
    ),
    (
        "scheduled_job_dynamic_evaluation",
        (
            "scheduled-job-dynamic-eval",
            "scheduled job performs dynamic evaluation",
            "scheduled job calls eval/exec/safe_eval",
            "synchronized data, records, or config values can control evaluated code",
        ),
    ),
    (
        "scheduled_job_manual_transaction",
        (
            "scheduled-job-manual-transaction",
            "scheduled job controls transactions manually",
            "scheduled job calls commit()/rollback()",
            "partial progress, retry behavior, and security state",
        ),
    ),
    (
        "scheduled_job_unbounded_search",
        (
            "scheduled-job-unbounded-search",
            "scheduled job performs unbounded orm search",
            "scheduled job searches with an empty domain and no visible limit",
            "batching, locking, company scoping, and idempotency",
        ),
    ),
    (
        "scheduled_job_http_without_timeout",
        (
            "scheduled-job-http-no-timeout",
            "scheduled job performs http without timeout",
            "scheduled job performs outbound http without timeout",
            "slow upstreams can exhaust cron workers",
        ),
    ),
    (
        "scheduled_job_tls_verification_disabled",
        (
            "scheduled-job-tls-verify-disabled",
            "scheduled job disables tls verification",
            "scheduled job passes verify=false to outbound http",
            "recurring integrations should not permit man-in-the-middle attacks",
        ),
    ),
    (
        "scheduled_job_sync_without_limit",
        (
            "scheduled-job-sync-without-limit",
            "external-sync scheduled job lacks visible batch limit",
            "scheduled sync/import/fetch job searches without a visible limit",
            "batching, locking, timeout, and retry behavior",
        ),
    ),
    (
        "xml_data_group_privilege_implication",
        (
            "odoo-xml-group-implies-privilege",
            "odoo-xml-function-group-implies-privilege",
        ),
    ),
    (
        "xml_data_user_admin_group_assignment",
        (
            "odoo-xml-user-admin-group-assignment",
            "odoo-xml-function-user-group-assignment",
        ),
    ),
    (
        "xml_data_function_security_model_mutation",
        ("odoo-xml-function-security-model-mutation",),
    ),
    (
        "xml_data_public_mail_channel",
        ("odoo-xml-public-mail-channel",),
    ),
    (
        "xml_cron_admin_user",
        (
            "odoo-xml-cron-admin-user",
            "cron executes as admin/root user",
            "ir.cron runs under admin/root user",
            "elevated privileges",
        ),
    ),
    (
        "xml_cron_root_code",
        (
            "odoo-xml-cron-root-code",
            "cron executes python as admin/root",
            "ir.cron uses state='code' under admin/root user",
            "process attacker-controlled records or external input",
        ),
    ),
    (
        "xml_cron_http_without_timeout",
        (
            "odoo-xml-cron-http-no-timeout",
            "cron performs http request without visible timeout",
            "cron code performs outbound http without timeout",
            "ssrf and worker exhaustion risk",
        ),
    ),
    (
        "xml_cron_tls_verification_disabled",
        (
            "odoo-xml-cron-tls-verify-disabled",
            "cron disables tls verification",
            "ir.cron code passes verify=false to outbound http",
            "scheduled integrations should not permit man-in-the-middle attacks",
        ),
    ),
    (
        "xml_cron_doall_enabled",
        (
            "odoo-xml-cron-doall-enabled",
            "cron catches up missed executions",
            "ir.cron has doall=true",
            "replay missed jobs in bulk",
            "duplicate side effects or load spikes",
        ),
    ),
    (
        "xml_cron_short_interval",
        (
            "odoo-xml-cron-short-interval",
            "cron runs at a very short interval",
            "ir.cron runs every five minutes or less",
            "idempotency, locking, and external side effects",
        ),
    ),
    (
        "xml_cron_external_sync_review",
        (
            "odoo-xml-cron-external-sync-review",
            "cron appears to perform external sync without visible guardrails",
            "ir.cron name/function/model suggests external import or sync",
            "timeouts, batching, locking, and retry safety",
        ),
    ),
    (
        "queue_job_missing_identity_key",
        (
            "queue-job-missing-identity-key",
            "delayed job enqueue lacks identity key",
            "with_delay/delayable enqueue has no identity_key",
            "duplicate background jobs and side effects",
        ),
    ),
    (
        "queue_job_public_enqueue",
        (
            "queue-job-public-enqueue",
            "public route enqueues background job",
            "route enqueues a delayed job",
            "authentication, csrf, throttling, and idempotency",
        ),
    ),
    (
        "queue_job_elevated_mutation",
        (
            "queue-job-sudo-mutation",
            "queue job performs elevated mutation",
            "queue_job/delayed job mutates records through sudo()/with_user(superuser_id)",
            "record rules, company isolation, and job input trust boundaries",
        ),
    ),
    (
        "queue_job_elevated_method_call",
        (
            "odoo-queue-job-sudo-method-call",
            "queue job calls elevated business method",
            "queue_job/delayed job uses sudo()/with_user(superuser_id) to call a business/action method",
            "workflow side effects cannot bypass record rules, approvals, audit, or company isolation",
        ),
    ),
    (
        "queue_job_sensitive_model_mutation",
        (
            "queue-job-sensitive-model-mutation",
            "queue job mutates sensitive model",
            "verify job input trust, retry idempotency, and audit trail",
        ),
    ),
    (
        "queue_job_dynamic_evaluation",
        (
            "queue-job-dynamic-eval",
            "queue job performs dynamic evaluation",
            "queue_job/delayed job calls eval/exec/safe_eval",
            "queued payload or record field can control evaluated code",
        ),
    ),
    (
        "queue_job_http_without_timeout",
        (
            "queue-job-http-no-timeout",
            "queue job performs http without timeout",
            "queue_job/delayed job performs outbound http without timeout",
            "exhaust workers or stall job channels",
        ),
    ),
    (
        "queue_job_tls_verification_disabled",
        (
            "queue-job-tls-verify-disabled",
            "queue job disables tls verification",
            "queue_job/delayed job passes verify=false to outbound http",
        ),
    ),
    (
        "serialization_unsafe_deserialization",
        (
            "serialization-unsafe-deserialization",
            "unsafe deserialization sink",
            "can execute code or instantiate attacker-controlled objects",
            "cloudpickle.load",
            "cloudpickle.loads",
            "never use it on request, attachment, or integration data",
            "numpy.load(..., allow_pickle=true)",
        ),
    ),
    (
        "serialization_unsafe_yaml_load",
        (
            "serialization-unsafe-yaml-load",
            "unsafe yaml load",
            "yaml.load() without safeloader",
            "yaml.unsafe_load() can construct arbitrary python objects",
            "use safe_load() or safeloader",
        ),
    ),
    (
        "serialization_yaml_full_load",
        (
            "serialization-yaml-full-load",
            "yaml full_load on addon data",
            "yaml.full_load() accepts a broader yaml type set than safe_load()",
            "prefer safe_load() for request, attachment, or integration data",
        ),
    ),
    (
        "serialization_literal_eval_tainted",
        (
            "serialization-literal-eval-tainted",
            "tainted data parsed with literal_eval",
            "ast.literal_eval() parses request, attachment, or integration data",
            "prefer json/schema validation and enforce size/depth limits",
        ),
    ),
    (
        "serialization_json_load_without_size_check",
        (
            "serialization-json-load-no-size-check",
            "tainted json parsed without visible size check",
            "json.load()/loads() parses request, attachment, or integration data",
            "enforce byte limits before parsing",
        ),
    ),
    (
        "serialization_xml_fromstring_tainted",
        (
            "serialization-xml-fromstring-tainted",
            "tainted xml parsed without hardened parser",
            "request/attachment-derived xml is parsed with elementtree.fromstring",
            "entity expansion, parser hardening, and size limits",
        ),
    ),
    (
        "serialization_unsafe_xml_parser",
        (
            "serialization-unsafe-xml-parser",
            "xml parser enables unsafe options",
            "lxml xmlparser enables dtd/entity/network/huge-tree behavior",
            "disable entity resolution, network access, and unbounded trees",
        ),
    ),
    (
        "wizard_binary_import_field",
        (
            "odoo-wizard-binary-import-field",
            "wizard exposes binary upload/import field",
            "transientmodel wizard defines a binary field",
            "upload size, mime/type validation, parsing safety",
        ),
    ),
    (
        "wizard_sensitive_model_mutation",
        (
            "odoo-wizard-sensitive-model-mutation",
            "wizard mutates sensitive model",
            "transientmodel wizard mutates sensitive model",
            "action exposure, group checks, record rules, and audit trail",
        ),
    ),
    (
        "wizard_sudo_mutation",
        (
            "odoo-wizard-sudo-mutation",
            "wizard mutates records through an elevated environment",
            "transientmodel wizard chains sudo()/with_user(superuser_id)",
            "explicit access, group, and company checks before mutation",
        ),
    ),
    (
        "wizard_upload_parser_no_size_check",
        (
            "odoo-wizard-upload-parser-no-size-check",
            "wizard parses uploaded content without visible size check",
            "without a visible file-size guard",
            "large uploads cannot exhaust memory or parser resources",
        ),
    ),
    (
        "wizard_upload_parser",
        (
            "odoo-wizard-upload-parser",
            "wizard parses uploaded file content",
            "transientmodel wizard parses uploaded content",
            "formula injection, decompression bombs, parser hardening",
        ),
    ),
    (
        "wizard_dynamic_active_model",
        (
            "odoo-wizard-dynamic-active-model",
            "wizard uses context active_model dynamically",
            "uses context active_model to select an env model dynamically",
            "constrain allowed models before browsing or mutating records",
        ),
    ),
    (
        "wizard_active_ids_bulk_mutation",
        (
            "odoo-wizard-active-ids-bulk-mutation",
            "wizard mutates records selected from active_ids",
            "mutates records selected from context active_ids",
            "record rules, company scope, and batch limits",
        ),
    ),
    (
        "wizard_mutation_no_access_check",
        (
            "odoo-wizard-mutation-no-access-check",
            "wizard action mutates without visible access check",
            "mutates records without visible check_access/user_has_groups guard",
            "ui exposure cannot bypass workflow permissions",
        ),
    ),
    (
        "wizard_long_transient_retention",
        (
            "odoo-wizard-long-transient-retention",
            "wizard transient records have long retention",
            "sets _transient_max_hours to 0 or more than 24 hours",
            "sets _transient_max_hours/_transient_max_count to unlimited or high retention",
            "uploaded files, tokens, active_ids, and temporary decisions are not retained longer than needed",
        ),
    ),
    (
        "settings_sensitive_config_field_no_admin_groups",
        (
            "settings-sensitive-config-field-no-admin-groups",
            "sensitive settings field lacks admin-only groups",
            "stores sensitive config parameter",
            "only system administrators can read/write it",
        ),
    ),
    (
        "settings_config_field_public_groups",
        (
            "settings-config-field-public-groups",
            "settings field is exposed to public/portal groups",
            "includes public/portal groups",
            "cannot expose or alter global configuration",
        ),
    ),
    (
        "settings_security_toggle_unsafe_default",
        (
            "settings-security-toggle-unsafe-default",
            "security-sensitive setting defaults to unsafe posture",
            "defaults to",
            "production installs cannot enable unsafe behavior by default",
        ),
    ),
    (
        "settings_security_toggle_no_admin_groups",
        (
            "settings-security-toggle-no-admin-groups",
            "security-sensitive setting lacks admin-only groups",
            "maps to security-sensitive config parameter",
            "only system administrators can alter it",
        ),
    ),
    (
        "settings_implies_admin_group",
        (
            "settings-implies-admin-group",
            "settings toggle implies administrator group",
            "implies elevated group",
            "only existing administrators can toggle it",
        ),
    ),
    (
        "settings_module_toggle_no_admin_groups",
        (
            "settings-module-toggle-no-admin-groups",
            "module install toggle lacks admin-only groups",
            "can install/uninstall modules",
            "only system administrators can access it",
        ),
    ),
    (
        "settings_elevated_config_write",
        (
            "settings-sudo-set-param",
            "settings method writes config parameter through elevated environment",
            "res.config.settings method calls sudo()/with_user(superuser_id).set_param",
            "admin settings flows can alter global security, mail, auth, or integration parameters",
        ),
    ),
    (
        "signup_public_token_route",
        (
            "signup-public-token-route",
            "public signup/reset token route",
            "public signup/reset route should validate token expiry",
            "audience, redirect target, and account state",
        ),
    ),
    (
        "signup_tainted_reset_trigger",
        (
            "signup-tainted-reset-trigger",
            "request-derived signup/reset trigger",
            "request-derived data reaches signup/reset-password helper",
            "rate limiting, account enumeration resistance, and token expiry",
        ),
    ),
    (
        "signup_tainted_token_lookup",
        (
            "signup-tainted-token-lookup",
            "request-derived token lookup",
            "request-derived signup/access token is used to look up identity records",
            "constant-time token checks, expiry, and ownership constraints",
        ),
    ),
    (
        "signup_token_lookup_without_expiry",
        (
            "signup-token-lookup-without-expiry",
            "signup/reset token lookup lacks expiry constraint",
            "does not visibly constrain signup_expiration",
            "expired tokens cannot authenticate or mutate accounts",
        ),
    ),
    (
        "signup_tainted_identity_token_write",
        (
            "signup-tainted-identity-token-write",
            "request-derived signup token or password mutation",
            "request-derived data writes signup/access token or password fields",
            "require validated reset/signup flow state first",
        ),
    ),
    (
        "signup_public_sudo_identity_flow",
        (
            "signup-public-sudo-identity-flow",
            "public signup/reset flow uses sudo identity access",
            "public signup/reset flow uses sudo()/with_user(superuser_id)",
            "token checks happen before privileged reads or writes",
        ),
    ),
    (
        "signup_token_exposed_public_route",
        (
            "signup-token-exposed",
            "signup/reset token exposed from public route",
            "public signup/reset response includes signup/access token data",
            "avoid exposing reusable account takeover tokens",
        ),
    ),
    (
        "identity_public_route_mutation",
        (
            "odoo-identity-public-route-mutation",
            "public route mutates users or groups",
            "mutates res.users",
            "mutates res.groups",
            "only authenticated administrators can change identity",
        ),
    ),
    (
        "identity_elevated_mutation",
        (
            "odoo-identity-elevated-mutation",
            "identity mutation runs in elevated context",
            "identity mutation uses sudo()/with_user(superuser_id)",
            "verify explicit admin checks and audit trail before privilege changes",
        ),
    ),
    (
        "identity_request_derived_mutation",
        (
            "odoo-identity-request-derived-mutation",
            "request-derived data reaches identity mutation",
            "request-derived data reaches res.users",
            "request-derived data reaches res.groups",
            "whitelist allowed fields and reject privilege",
        ),
    ),
    (
        "identity_privilege_field_write",
        (
            "odoo-identity-privilege-field-write",
            "identity mutation writes privilege-bearing fields",
            "writes privilege-bearing field",
            "group/company/user activation changes are admin-only",
        ),
    ),
    (
        "oauth_public_callback_route",
        (
            "odoo-oauth-public-callback-route",
            "public oauth callback route",
            "oauth/oidc callback route is public",
            "redirect uri binding, provider allowlist, and replay resistance",
        ),
    ),
    (
        "oauth_missing_state_nonce",
        (
            "odoo-oauth-missing-state-nonce-validation",
            "oauth callback lacks visible state or nonce validation",
            "oauth callback does not reference state or nonce",
            "public oauth/oidc callback lacks visible state or nonce validation",
            "public oauth/oidc callback does not reference state or nonce",
            "id-token nonce binding before session creation",
        ),
    ),
    (
        "oauth_http_without_timeout",
        (
            "odoo-oauth-http-no-timeout",
            "oauth token/userinfo http call lacks timeout",
            "oauth/oidc token or userinfo validation performs outbound http without timeout",
            "slow providers can exhaust workers",
        ),
    ),
    (
        "oauth_tls_verification_disabled",
        (
            "odoo-oauth-http-verify-disabled",
            "oauth http call disables tls verification",
            "oauth/oidc token or userinfo validation disables tls verification",
            "tokens and identities can be intercepted or forged",
        ),
    ),
    (
        "oauth_tainted_validation_url",
        (
            "odoo-oauth-tainted-validation-url",
            "request-derived oauth validation url",
            "request-derived data controls oauth/oidc token or userinfo url",
            "provider allowlists to avoid ssrf and token exfiltration",
        ),
    ),
    (
        "oauth_tainted_redirect_uri",
        (
            "odoo-oauth-tainted-redirect-uri",
            "request-derived oauth redirect uri is forwarded",
            "forwards a request-derived redirect_uri",
            "bind redirect uris to trusted provider/client configuration",
        ),
    ),
    (
        "oauth_jwt_verification_disabled",
        (
            "odoo-oauth-jwt-verification-disabled",
            "jwt decode disables signature or claim verification",
            "oauth/oidc jwt decode disables verification",
            "require signature, issuer, audience, nonce, and expiry validation",
        ),
    ),
    (
        "oauth_request_token_decode",
        (
            "odoo-oauth-request-token-decode",
            "request-derived token is decoded",
            "request-derived oauth/oidc token is decoded",
            "issuer, audience, nonce, expiry, algorithm, and key selection",
        ),
    ),
    (
        "oauth_token_exchange_missing_pkce",
        (
            "odoo-oauth-token-exchange-missing-pkce",
            "oauth authorization-code exchange lacks pkce verifier",
            "authorization-code token exchange lacks a visible code_verifier",
            "prevents code interception and replay",
        ),
    ),
    (
        "oauth_tainted_identity_write",
        (
            "odoo-oauth-tainted-identity-write",
            "request-derived oauth identity reaches user mutation",
            "request-derived oauth identity data reaches res.users mutation",
            "domain/account linking before writing oauth_uid/login/groups",
        ),
    ),
    (
        "oauth_session_authenticate",
        (
            "odoo-oauth-session-authenticate",
            "oauth flow authenticates a session",
            "oauth/oidc flow calls request.session.authenticate",
            "provider identity binding happen before session creation",
        ),
    ),
    (
        "session_public_authenticate",
        (
            "odoo-session-public-authenticate",
            "public route authenticates with request-controlled credentials",
            "request.session.authenticate with request-derived credentials",
            "rate limiting, csrf, mfa, and redirect handling",
        ),
    ),
    (
        "session_public_user_lookup",
        (
            "odoo-session-public-user-lookup",
            "public route looks up users from request data",
            "public/unauthenticated route queries res.users with request-derived input",
            "cannot enumerate accounts or create pre-auth timing side channels",
        ),
    ),
    (
        "session_direct_uid_assignment",
        (
            "odoo-session-direct-uid-assignment",
            "controller directly assigns request.session.uid",
            "controller directly updates request.session uid",
            "session fixation or account switching",
        ),
    ),
    (
        "session_direct_request_uid_assignment",
        (
            "odoo-session-direct-request-uid-assignment",
            "controller directly assigns request.uid",
            "use odoo authentication and environment-switching apis only after explicit authorization checks",
        ),
    ),
    (
        "session_update_env_superuser",
        (
            "odoo-session-update-env-superuser",
            "controller switches request environment to superuser",
            "request.update_env switches the current request to a superuser/admin identity",
        ),
    ),
    (
        "session_update_env_tainted_user",
        (
            "odoo-session-update-env-tainted-user",
            "request.update_env uses request-controlled user",
            "request.update_env receives a request-derived user/uid",
        ),
    ),
    (
        "session_public_update_env",
        (
            "odoo-session-public-update-env",
            "public route switches request environment",
            "public/unauthenticated route calls request.update_env(user=",
            "authorization and account binding happen before environment switching",
        ),
    ),
    (
        "session_environment_superuser",
        (
            "odoo-session-environment-superuser",
            "manual environment uses superuser",
            "manual odoo environment is constructed with a superuser/admin identity",
        ),
    ),
    (
        "session_environment_tainted_user",
        (
            "odoo-session-environment-tainted-user",
            "manual environment uses request-controlled user",
            "manual odoo environment is constructed from request-derived uid",
        ),
    ),
    (
        "session_logout_weak_route",
        (
            "odoo-session-logout-weak-route",
            "logout route has weak method or csrf posture",
            "public/get/csrf=false route",
            "cross-site logout and session disruption",
        ),
    ),
    (
        "session_token_exposed",
        (
            "odoo-session-token-exposed",
            "controller response exposes session or csrf token",
            "return csrf/session token material",
            "not exposed cross-origin or to unauthenticated users",
        ),
    ),
    (
        "session_ir_http_auth_override",
        (
            "odoo-session-ir-http-auth-override",
            "ir.http authentication boundary is overridden",
            "global request authentication",
            "session, api-key, public-user, and database-selection guarantees",
        ),
    ),
    (
        "session_ir_http_superuser_auth",
        (
            "odoo-session-ir-http-superuser-auth",
            "ir.http authentication override grants elevated user",
            "appears to assign or return a superuser/admin identity",
        ),
    ),
    (
        "session_ir_http_bypass",
        (
            "odoo-session-ir-http-bypass",
            "ir.http authentication override may bypass checks",
            "return success without a visible parent authentication call",
            "bypass login, api-key, or session validation",
        ),
    ),
    (
        "model_method_http_without_timeout",
        (
            "model-method-onchange-http-no-timeout",
            "model-method-compute-http-no-timeout",
            "model-method-constraint-http-no-timeout",
            "model-method-inverse-http-no-timeout",
            "odoo model method performs http without timeout",
            "outbound http without timeout",
            "form/render/background flows can block odoo workers",
        ),
    ),
    (
        "model_method_tls_verification_disabled",
        (
            "model-method-onchange-tls-verify-disabled",
            "model-method-compute-tls-verify-disabled",
            "model-method-constraint-tls-verify-disabled",
            "model-method-inverse-tls-verify-disabled",
            "odoo model method disables tls verification",
            "model method passes verify=false to outbound http",
        ),
    ),
    (
        "constraint_sudo_visibility_gap",
        (
            "constraint-sudo-search",
            "constraint reads through sudo",
            "constraint reads through sudo()/with_user(superuser_id)",
            "cannot hide company or record-rule issues",
        ),
    ),
    (
        "constraint_unbounded_search",
        (
            "constraint-unbounded-search",
            "constraint performs unbounded search",
            "search without a limit",
            "slow or lock-prone on large tables",
        ),
    ),
    (
        "constraint_singleton_assumption",
        (
            "constraint-ensure-one",
            "constraint assumes a singleton recordset",
            "calls ensure_one",
            "constraints may run on multi-record recordsets",
        ),
    ),
    (
        "constraint_ineffective_return",
        (
            "constraint-return-ignored",
            "constraint returns a value instead of raising",
            "returns false/none",
            "constraints must raise validationerror",
        ),
    ),
    (
        "constraint_registration_gap",
        (
            "constraint-empty-fields",
            "constraint-dynamic-field",
            "constraint-dotted-field",
            "constraint decorator has no fields",
            "constraint decorator uses dynamic field expression",
            "constraint decorator uses dotted field",
            "@api.constrains() without fields",
            "non-literal @api.constrains argument",
            "@api.constrains does not trigger reliably",
        ),
    ),
    (
        "access_override_sudo_search",
        (
            "access-override-sudo-search",
            "search override reads through elevated environment",
            "model search override",
            "reads through sudo()/with_user(superuser_id)",
            "cannot bypass record rules or company isolation",
        ),
    ),
    (
        "access_override_allow_all",
        (
            "access-override-allow-all",
            "access override returns allow-all",
            "returns true without super",
            "disable access-right or record-rule enforcement",
        ),
    ),
    (
        "access_override_filter_self",
        (
            "access-override-filter-self",
            "record-rule filter override returns self",
            "access filter override",
            "returns self without super",
            "bypass record-rule filtering for every caller",
        ),
    ),
    (
        "access_override_missing_super",
        (
            "access-override-missing-super",
            "access override does not call super",
            "model access override",
            "does not call super()",
            "preserves base acl and record-rule behavior",
        ),
    ),
    (
        "record_rule_universal_sensitive_domain",
        (
            "record-rule-universal-domain",
            "record rule grants universal domain on sensitive model",
            "empty or tautological domain on sensitive/security model",
            "every permitted group should see all records",
        ),
    ),
    (
        "record_rule_public_sensitive_no_owner_scope",
        (
            "record-rule-public-sensitive-no-owner-scope",
            "public/portal rule on sensitive/security model lacks owner scope",
            "for public/portal users without an obvious owner",
            "without an obvious owner, token, or company scope",
        ),
    ),
    (
        "record_rule_public_company_only_scope",
        (
            "record-rule-public-sensitive-company-only-scope",
            "public/portal rule relies only on company scope",
            "by company only",
            "cannot list unrelated records from the same company",
        ),
    ),
    (
        "record_rule_global_sensitive_mutation",
        (
            "record-rule-global-sensitive-mutation",
            "global record rule enables mutation on sensitive/security model",
            "without group scoping",
        ),
    ),
    (
        "record_rule_portal_sensitive_mutation",
        (
            "record-rule-portal-write-sensitive",
            "public/portal rule enables mutation on sensitive/security model",
            "enables write/create/delete on sensitive/security model",
            "for public/portal users",
        ),
    ),
    (
        "record_rule_domain_group_logic",
        (
            "record-rule-domain-has-group",
            "record-rule domain performs group checks",
            "calls has_group() inside domain_force",
            "privilege-boundary assumptions",
        ),
    ),
    (
        "record_rule_context_dependent_domain",
        (
            "record-rule-context-dependent-domain",
            "record-rule domain depends on context",
            "reads context inside domain_force",
            "caller-controlled context cannot widen access",
            "bypass company/owner scoping",
        ),
    ),
    (
        "record_rule_company_hierarchy_expansion",
        (
            "record-rule-company-child-of",
            "record rule uses company hierarchy expansion",
            "uses child_of with user companies",
            "parent/child company access is intentional",
        ),
    ),
    (
        "record_rule_empty_permissions",
        (
            "record-rule-empty-permissions",
            "record rule has all permissions disabled",
            "sets every perm_* flag false",
            "ineffective or misleading",
        ),
    ),
    (
        "button_action_sensitive_model_mutation",
        (
            "button-action-sensitive-model-mutation",
            "button/action method mutates sensitive model",
            "object-button exposure, rpc access, group checks, and audit trail",
        ),
    ),
    (
        "button_action_sudo_mutation",
        (
            "button-action-sudo-mutation",
            "button/action method performs sudo mutation",
            "chains sudo()/with_user(superuser_id) into write/create/unlink",
            "explicit group, access, and company checks before mutation",
        ),
    ),
    (
        "button_action_sensitive_state_write",
        (
            "button-action-sensitive-state-write",
            "button/action method writes sensitive workflow state",
            "writes approval/payment/posting-like state",
            "groups enforce the workflow boundary",
        ),
    ),
    (
        "button_action_unlink_no_access_check",
        (
            "button-action-unlink-no-access-check",
            "button/action method unlinks without visible access check",
            "deletes records without visible check_access/user_has_groups guard",
            "object button exposure cannot delete unauthorized records",
        ),
    ),
    (
        "button_action_mutation_no_access_check",
        (
            "button-action-mutation-no-access-check",
            "button/action method mutates without visible access check",
            "performs sensitive mutation without visible check_access/user_has_groups guard",
            "rpc calls cannot bypass workflow approvals",
        ),
    ),
    (
        "orm_domain_tainted_sudo_search",
        (
            "orm-domain-tainted-sudo-search",
            "request/context-controlled domain is searched through an elevated environment",
            "request or context-derived domain reaches sudo()/with_user(superuser_id) orm search/read",
            "validate fields/operators, ownership, record rules, and company isolation",
        ),
    ),
    (
        "orm_domain_tainted_search",
        (
            "orm-domain-tainted-search",
            "request/context-controlled domain reaches orm search",
            "request or context-derived domain reaches orm search/read",
            "validate allowed fields/operators",
            "prevent cross-record or cross-company discovery",
        ),
    ),
    (
        "orm_domain_dynamic_evaluation",
        (
            "orm-domain-dynamic-eval",
            "request/context data is evaluated as a domain",
            "request or context-derived data reaches literal_eval/safe_eval for orm domain construction",
            "validate allowed fields and operators",
        ),
    ),
    (
        "orm_domain_filtered_dynamic_logic",
        (
            "orm-domain-filtered-dynamic",
            "record filtering uses dynamic request/env logic",
            "filtered(lambda ...) references request/env/context",
            "python-side filtering cannot replace record-rule or company checks",
        ),
    ),
    (
        "view_domain_sensitive_action_broad_domain",
        (
            "view-domain-sensitive-action-broad-domain",
            "sensitive action uses broad domain without groups",
            "ir.actions.act_window for sensitive model",
            "uses a broad domain and has no groups restriction",
            "menus and acls prevent overexposure",
        ),
    ),
    (
        "view_domain_global_sensitive_filter_broad_domain",
        (
            "view-domain-global-sensitive-filter-broad-domain",
            "global saved filter has broad sensitive-model domain",
            "global ir.filters record applies a broad domain",
            "shared favorites/search defaults",
        ),
    ),
    (
        "view_domain_global_default_sensitive_filter",
        (
            "view-filter-global-default-sensitive",
            "view-domain-default-sensitive-filter",
            "global default saved filter affects sensitive model",
            "shared default search behavior",
            "default search behavior cannot expose archived or overly broad records",
        ),
    ),
    (
        "view_domain_dynamic_evaluation",
        (
            "view-domain-dynamic-eval",
            "xml domain/context performs dynamic evaluation",
            "xml domain/context expression contains eval/exec/safe_eval",
            "user-controlled value can affect evaluated code",
        ),
    ),
    (
        "orm_context_tracking_disabled_mutation",
        (
            "orm-context-tracking-disabled-mutation",
            "orm mutation disables chatter/tracking context",
            "orm create/write/unlink runs with tracking or subscription context disabled",
            "auditability, followers, and security notifications",
        ),
    ),
    (
        "orm_context_notification_disabled_mutation",
        (
            "orm-context-notification-disabled-mutation",
            "orm mutation disables user notification context",
            "orm create/write/unlink runs with no_reset_password=true",
            "account, password, or mail notifications are not suppressed",
        ),
    ),
    (
        "orm_context_privileged_mode_mutation",
        (
            "orm-context-privileged-mode-mutation",
            "orm mutation runs in privileged framework mode",
            "orm mutation runs with install_mode=true",
            "install/uninstall-only behavior cannot bypass normal validation",
        ),
    ),
    (
        "orm_context_privileged_default_mutation",
        (
            "orm-context-privileged-default-mutation",
            "orm mutation uses privilege-bearing default context",
            "orm mutation runs with default_groups_id",
            "callers cannot create records with elevated ownership, groups, companies, or visibility",
        ),
    ),
    (
        "orm_context_active_test_disabled",
        (
            "orm-context-active-test-disabled",
            "orm context disables active record filtering",
            "with_context(active_test=false)",
            "include archived/inactive records",
            "access-safe",
        ),
    ),
    (
        "orm_context_sudo_active_test_read",
        (
            "orm-context-sudo-active-test-read",
            "privileged orm read disables active record filtering",
            "orm read uses sudo()/with_user(superuser_id) with active_test=false",
            "archived/inactive records may be exposed",
        ),
    ),
    (
        "orm_context_privileged_mode",
        (
            "orm-context-privileged-mode",
            "orm context enables privileged framework mode",
            "with_context(install_mode=true)",
            "with_context(module_uninstall=true)",
            "with_context(uninstall_mode=true)",
            "framework mode normally reserved for install/uninstall flows",
        ),
    ),
    (
        "orm_context_privileged_default",
        (
            "orm-context-privileged-default",
            "orm context seeds privilege-bearing default",
            "with_context(default_groups_id",
            "with_context(default_company_id",
            "with_context(default_user_id",
            "with_context(default_share",
            "create flows cannot assign user, group, company, share, or active-state fields",
        ),
    ),
    (
        "orm_context_request_active_test_disabled",
        (
            "orm-context-request-active-test-disabled",
            "request context disables active record filtering",
            "request.update_context(active_test=false)",
            "current request environment",
            "archived/inactive records may become visible",
        ),
    ),
    (
        "orm_context_request_tracking_disabled",
        (
            "orm-context-request-tracking-disabled",
            "request context disables chatter/tracking",
            "request.update_context disables tracking",
            "subscription context for later orm work",
            "auditability and follower notifications",
        ),
    ),
    (
        "orm_context_request_notification_disabled",
        (
            "orm-context-request-notification-disabled",
            "request context disables user notifications",
            "request.update_context(no_reset_password=true)",
            "request.update_context(mail_notify_force_send=true)",
            "suppresses later account, password, or mail notifications",
        ),
    ),
    (
        "orm_context_request_privileged_mode",
        (
            "orm-context-request-privileged-mode",
            "request context enables privileged framework mode",
            "request.update_context(install_mode=true)",
            "request.update_context(module_uninstall=true)",
            "request.update_context(uninstall_mode=true)",
            "framework mode for later orm work in the request",
        ),
    ),
    (
        "orm_context_request_privileged_default",
        (
            "orm-context-request-privileged-default",
            "request context seeds privilege-bearing default",
            "request.update_context(default_groups_id",
            "request.update_context(default_company_id",
            "request.update_context(default_user_id",
            "seeds a privileged default for later create flows",
        ),
    ),
    (
        "metadata_public_write_acl",
        (
            "metadata-public-write-acl",
            "public/portal acl grants write/create/delete",
            "acl grants write/create/delete permissions to base.group_public",
            "acl grants write/create/delete permissions to base.group_portal",
            "safe for public or portal mutation",
        ),
    ),
    (
        "metadata_sensitive_public_read_acl",
        (
            "metadata-sensitive-public-read-acl",
            "public/portal acl grants read on sensitive model",
            "acl grants read permission on sensitive model",
            "record rules prevent cross-user exposure",
        ),
    ),
    (
        "metadata_group_privilege_escalation",
        (
            "metadata-group-implies-admin",
            "metadata-group-implies-internal-user",
            "group implies administrator-level privileges",
            "group implies internal user privileges",
            "res.groups record implies administrator/manager-level groups",
            "res.groups record implies base.group_user",
            "portal/public/signup flows cannot assign this group",
        ),
    ),
    (
        "metadata_user_group_assignment",
        (
            "metadata-user-admin-group-assignment",
            "metadata-user-internal-group-assignment",
            "user data assigns administrator-level group",
            "user data assigns internal user group",
            "res.users metadata assigns administrator/manager-level groups",
            "res.users metadata assigns base.group_user",
            "cannot grant unintended administrator access",
        ),
    ),
    (
        "metadata_sensitive_field_writable",
        (
            "metadata-sensitive-field-readonly-disabled",
            "field metadata makes sensitive field writable",
            "sets readonly=false on sensitive field",
            "write access is explicitly restricted",
        ),
    ),
    (
        "metadata_dynamic_compute_code",
        (
            "metadata-field-dynamic-compute",
            "field metadata contains dynamic compute code",
            "contains dynamic compute code",
            "user-controlled data can affect evaluated or sudo behavior",
        ),
    ),
    (
        "default_public_route_set",
        (
            "odoo-default-public-route-set",
            "public route writes ir.default",
            "unauthenticated users cannot alter persisted defaults",
        ),
    ),
    (
        "default_sudo_set",
        (
            "odoo-default-sudo-set",
            "ir.default is written through privileged context",
            "sudo()/with_user(superuser_id).set() writes persisted defaults",
        ),
    ),
    (
        "default_request_derived_set",
        (
            "odoo-default-request-derived-set",
            "request-derived data reaches ir.default",
            "request-derived field or value reaches ir.default.set()",
        ),
    ),
    (
        "default_sensitive_field_set",
        (
            "odoo-default-sensitive-field-set",
            "sensitive ir.default field is set at runtime",
            "runtime ir.default.set() writes sensitive field",
        ),
    ),
    (
        "default_sensitive_model_set",
        (
            "odoo-default-sensitive-model-set",
            "sensitive model default is set at runtime",
            "runtime ir.default.set() writes a default for sensitive model",
        ),
    ),
    (
        "default_global_scope",
        (
            "odoo-default-global-scope",
            "ir.default record has global scope",
            "has no user_id or company_id",
        ),
    ),
    (
        "default_sensitive_value",
        (
            "odoo-default-sensitive-value",
            "sensitive ir.default value is preconfigured",
            "configures sensitive field",
        ),
    ),
    (
        "default_sensitive_model_value",
        (
            "odoo-default-sensitive-model-value",
            "sensitive model default value is preconfigured",
            "configures a default for sensitive model",
        ),
    ),
    (
        "sequence_public_route_next",
        (
            "odoo-sequence-public-route-next",
            "public route consumes a sequence",
            "calls next_by_code()",
            "calls next_by_id()",
            "cannot enumerate or exhaust business identifiers",
        ),
    ),
    (
        "sequence_tainted_code",
        (
            "odoo-sequence-tainted-code",
            "request controls sequence code",
            "request-derived data controls next_by_code()",
            "constrain allowed sequence codes",
        ),
    ),
    (
        "sequence_sensitive_code_use",
        (
            "odoo-sequence-sensitive-code-use",
            "sensitive flow uses predictable sequence",
            "looks security-sensitive",
            "do not use ir.sequence for access tokens",
            "reset codes, api keys, or invite secrets",
        ),
    ),
    (
        "sequence_sensitive_declaration",
        (
            "odoo-sequence-sensitive-declaration",
            "sequence appears to generate sensitive values",
            "appears tied to tokens, passwords, coupons, invites, or secrets",
            "sequences are predictable counters",
        ),
    ),
    (
        "sequence_sensitive_global_scope",
        (
            "odoo-sequence-sensitive-global-scope",
            "sensitive sequence has global scope",
            "has no company_id while appearing security-sensitive",
            "scope and collision/isolation assumptions",
        ),
    ),
    (
        "sequence_business_global_scope",
        (
            "odoo-sequence-business-global-scope",
            "business sequence has no company scope",
            "appears to generate accounting/sales/stock identifiers without company_id",
            "multi-company numbering requirements",
        ),
    ),
    (
        "website_form_field_allowlisted_sensitive",
        (
            "odoo-website-form-field-allowlisted-sensitive",
            "sensitive field is allowlisted for website forms",
            "website_form_blacklisted=false",
            "public website forms cannot set ownership, workflow, company, token, privilege, or visibility fields",
        ),
    ),
    (
        "realtime_channel_subscription_authorization",
        (
            "odoo-realtime-broad-or-tainted-channel-subscription",
            "bus subscription accepts broad or request-controlled channel",
            "bus subscription mutates channel lists with request-derived or broad channels",
            "subscribe to tenant/user-scoped channels",
        ),
    ),
    (
        "realtime_public_route_bus_send",
        (
            "odoo-realtime-public-route-bus-send",
            "public route sends bus notification",
            "public/unauthenticated route sends realtime bus notifications",
            "authorization, channel scope, and rate limiting",
        ),
    ),
    (
        "realtime_bus_send_sudo",
        (
            "odoo-realtime-bus-send-sudo",
            "bus notification is sent through an elevated environment",
            "realtime bus notification uses sudo()/with_user(superuser_id)",
            "payload cannot bypass record rules or company boundaries",
        ),
    ),
    (
        "realtime_broad_or_tainted_channel",
        (
            "odoo-realtime-broad-or-tainted-channel",
            "bus notification targets broad or request-controlled channel",
            "realtime bus channel is broad or request-derived",
            "tenant/user scoping and channel entropy",
        ),
    ),
    (
        "realtime_sensitive_payload",
        (
            "odoo-realtime-sensitive-payload",
            "bus notification may expose sensitive payload data",
            "realtime bus payload appears request-derived or contains sensitive fields",
            "authorized for every emitted field",
        ),
    ),
    (
        "realtime_notification_sudo",
        (
            "odoo-realtime-notification-sudo",
            "notification is sent through an elevated environment",
            "notification/message call uses sudo()/with_user(superuser_id)",
            "followers, partners, and subtype routing cannot expose private records",
        ),
    ),
    (
        "realtime_tainted_notification_content",
        (
            "odoo-realtime-tainted-notification-content",
            "notification content is request-controlled",
            "notification/message content includes request-derived data",
            "escaping, recipient authorization, and spam/rate controls",
        ),
    ),
    (
        "report_sudo_enabled",
        (
            "odoo-report-sudo-enabled",
            "report renders with sudo",
            "report action enables report_sudo",
            "templates cannot expose records or fields beyond the caller's access",
        ),
    ),
    (
        "report_sudo_render_call",
        (
            "odoo-report-sudo-render-call",
            "report render uses an elevated environment",
            "report rendering/report_action is invoked through sudo()/with_user(superuser_id)",
            "receives elevated records",
        ),
    ),
    (
        "report_sensitive_no_groups",
        (
            "odoo-report-sensitive-no-groups",
            "sensitive model report has no groups restriction",
            "has no groups restriction; verify access rules",
            "groups restriction; verify access rules and report routes",
        ),
    ),
    (
        "report_public_render_route",
        (
            "odoo-report-public-render-route",
            "public route renders report",
            "public/unauthenticated controller route renders a report",
            "before returning pdf/html",
        ),
    ),
    (
        "report_dynamic_attachment_cache",
        (
            "odoo-report-dynamic-attachment-cache",
            "report caches dynamic attachment names",
            "report caches attachments using an object-derived expression",
            "cached pdfs cannot leak after record ownership/state changes",
        ),
    ),
    (
        "report_sensitive_filename_expression",
        (
            "odoo-report-sensitive-filename-expression",
            "report filename expression contains sensitive field",
            "print_report_name expression references token, secret, password, or api-key-like data",
            "leaking secrets through filenames, urls, logs, and browser history",
        ),
    ),
    (
        "report_tainted_render_records",
        (
            "odoo-report-tainted-render-records",
            "report render uses request-controlled records",
            "report rendering receives request-derived ids, records, data, or context",
            "validate ownership and allowed model/report combinations",
        ),
    ),
    (
        "report_tainted_render_data",
        (
            "odoo-report-tainted-render-data",
            "report render uses request-controlled data or context",
            "report rendering receives request-derived data/context options",
            "validate report model domains, filters, and generated output",
        ),
    ),
    (
        "report_tainted_render_action",
        (
            "odoo-report-tainted-render-action",
            "report render uses request-controlled report action",
            "report rendering is invoked on a request-derived report/action object",
            "restrict selectable reports and models",
        ),
    ),
    (
        "export_sensitive_fields",
        (
            "odoo-export-sensitive-fields",
            "orm export includes sensitive fields",
            "export/read includes sensitive fields",
            "authorized users can retrieve these values",
        ),
    ),
    (
        "metadata_sensitive_field_exposure",
        (
            "metadata-sensitive-field-public-groups",
            "metadata-sensitive-field-no-groups",
            "field metadata exposes sensitive field to public/portal groups",
            "field metadata defines sensitive field without groups",
            "ir.model.fields record",
            "sensitive field",
            "cannot leak credentials or tokens",
        ),
    ),
    (
        "view_context_active_test_disabled",
        (
            "view-context-active-test-disabled",
            "xml context disables active_test",
            "xml context sets active_test=false",
            "archived/inactive records may become visible",
        ),
    ),
    (
        "view_context_company_scope_control",
        (
            "view-context-user-company-scope",
            "xml context sets company scope from active/user values",
            "sets force_company/company_id/allowed_company_ids",
            "company membership is enforced",
        ),
    ),
    (
        "view_context_privileged_default",
        (
            "view-context-privileged-default",
            "xml context defaults privileged field",
            "prefill privilege, company, user, or portal/share-sensitive values",
        ),
    ),
    (
        "view_context_default_groups",
        (
            "view-context-default-groups",
            "xml context defaults user/group assignment",
            "sets default group fields",
            "assign elevated groups unexpectedly",
        ),
    ),
    (
        "view_context_risky_framework_flag",
        (
            "view-context-risky-framework-flag",
            "xml context sets risky framework flag",
            "bypass tracking, password reset, install/uninstall, or accounting validation safeguards",
        ),
    ),
    (
        "xml_data_core_xmlid_override",
        (
            "data-core-xmlid-override",
            "module data overrides core external id",
            "appears to target a core module xml id",
            "overrides upstream data and survives upgrades",
        ),
    ),
    (
        "xml_data_core_xmlid_delete",
        (
            "data-core-xmlid-delete",
            "xml data deletes core external id",
            "<delete> targets core external id",
            "removes upstream data and remains safe across upgrades",
        ),
    ),
    (
        "xml_data_sensitive_noupdate",
        (
            "data-sensitive-noupdate-record",
            "data-sensitive-noupdate-delete",
            "data-sensitive-noupdate-function",
            "sensitive data record is protected by noupdate",
            "sensitive xml delete is protected by noupdate",
            "sensitive xml function is protected by noupdate",
            "future security fixes or cleanup changes may not apply",
        ),
    ),
    (
        "xml_data_forcecreate_disabled",
        (
            "data-forcecreate-disabled",
            "xml record disables forcecreate",
            "forcecreate=false",
            "missing records will not be recreated during updates",
        ),
    ),
    (
        "xml_data_manual_model_data_write",
        (
            "data-manual-ir-model-data",
            "module data writes ir.model.data directly",
            "creates or changes ir.model.data directly",
            "xml id ownership, noupdate, and update semantics",
        ),
    ),
    (
        "xml_data_sensitive_delete",
        (
            "data-sensitive-delete",
            "xml data deletes security-sensitive records",
            "<delete> targets sensitive model",
            "cannot remove security, identity, automation, payment, or configuration records",
        ),
    ),
    (
        "xml_data_sensitive_search_delete",
        (
            "data-sensitive-search-delete",
            "xml data search-deletes sensitive records",
            "<delete> uses a search domain on sensitive model",
            "broad or version-dependent matches cannot remove security-critical records",
        ),
    ),
    (
        "xml_data_sensitive_function_mutation",
        (
            "data-sensitive-function-mutation",
            "xml function mutates security-sensitive records",
            "<function> calls",
            "cannot silently alter security, identity, automation, payment, or configuration records",
        ),
    ),
    (
        "xml_data_group_privilege_implication",
        (
            "odoo-xml-group-implies-privilege",
            "odoo-xml-function-group-implies-privilege",
            "xml group implies privileged group",
            "group inherits privileged group",
            "function implies privileged group",
        ),
    ),
    (
        "xml_data_user_admin_group_assignment",
        (
            "odoo-xml-user-admin-group-assignment",
            "odoo-xml-function-user-group-assignment",
            "xml assigns admin group to user",
            "function assigns user to privileged group",
            "user group assignment grants elevated privileges",
        ),
    ),
    (
        "xml_data_function_security_model_mutation",
        (
            "odoo-xml-function-security-model-mutation",
            "xml function mutates security model",
            "function writes ir.model.access, ir.rule, res.groups, or res.users",
            "xml data mutates security-critical model",
        ),
    ),
    (
        "xml_data_public_mail_channel",
        (
            "odoo-xml-public-mail-channel",
            "xml declares public mail channel",
            "public mail channel",
            "mail.channel is public",
        ),
    ),
    (
        "xml_data_server_action_tls_verification_disabled",
        (
            "odoo-xml-server-action-tls-verify-disabled",
            "server action disables tls verification",
            "ir.actions.server code passes verify=false to outbound http",
        ),
    ),
    (
        "ui_action_without_groups",
        (
            "odoo-ui-action-button-no-groups",
            "odoo-ui-object-button-no-groups",
            "ui action button has no groups",
            "object button has no groups",
            "button action is visible without groups",
        ),
    ),
    (
        "ui_public_object_button",
        (
            "odoo-ui-public-object-button",
            "public object button",
            "object button visible to public or portal users",
            "public users can trigger object method from view",
        ),
    ),
    (
        "ui_sensitive_action_without_groups",
        (
            "odoo-ui-sensitive-action-button-no-groups",
            "odoo-ui-sensitive-action-no-groups",
            "odoo-ui-sensitive-menu-no-groups",
            "sensitive action has no groups",
            "sensitive menu has no groups",
            "sensitive ui entry point is visible without groups",
        ),
    ),
    (
        "ui_sensitive_action_external_groups",
        (
            "odoo-ui-sensitive-action-button-external-groups",
            "odoo-ui-sensitive-action-external-groups",
            "odoo-ui-sensitive-server-action-external-groups",
            "odoo-ui-sensitive-menu-external-groups",
            "sensitive action exposed to public or portal users",
            "sensitive server action exposed to public or portal users",
            "sensitive menu exposed to public or portal users",
            "sensitive ui entry point is visible to public or portal users",
        ),
    ),
    (
        "field_sensitive_access_control",
        (
            "field-sensitive-no-groups",
            "field-sensitive-public-groups",
            "field-related-sensitive-no-admin-groups",
            "sensitive field has no group restriction",
            "sensitive field is exposed to public or portal group",
            "related field exposes sensitive target without admin-only groups",
            "has no groups= restriction",
            "assigned to public/portal groups",
            "projects sensitive path",
        ),
    ),
    (
        "field_sensitive_persistence_leak",
        (
            "field-sensitive-indexed",
            "field-sensitive-tracking",
            "field-sensitive-copyable",
            "sensitive field is indexed",
            "sensitive field is tracked in chatter",
            "sensitive field can be copied",
            "review database exposure",
            "value changes can leak into chatter",
            "duplicated records may clone credentials",
        ),
    ),
    (
        "field_compute_sudo_projection",
        (
            "field-compute-sudo-sensitive",
            "field-compute-sudo-scalar-no-admin-groups",
            "field computes through sudo",
            "sudo-computed scalar field lacks admin-only groups",
            "sets compute_sudo=true",
            "project private model data past record rules",
        ),
    ),
    (
        "field_html_sanitizer_bypass",
        (
            "field-html-sanitizer-disabled",
            "field-html-sanitize-overridable-no-admin-groups",
            "html field disables sanitizer protections",
            "html sanitizer override is not admin-only",
            "disables sanitize",
            "allows sanitizer override without admin-only groups",
            "persist unsafe markup",
        ),
    ),
    (
        "portal_public_route",
        (
            "odoo-portal-public-route",
            "portal route is publicly reachable",
            "portal-like route",
            "ownership checks, and record rule boundaries",
        ),
    ),
    (
        "portal_access_token_without_helper",
        (
            "odoo-portal-access-token-without-helper",
            "portal route accepts access_token without access helper",
            "does not call a visible portal access helper",
            "token is actually validated before record access",
        ),
    ),
    (
        "portal_document_check_missing_token",
        (
            "odoo-portal-document-check-missing-token",
            "portal access check does not pass access_token",
            "_document_check_access without passing it",
            "bypass intended token validation",
        ),
    ),
    (
        "portal_sudo_route_id_read",
        (
            "odoo-portal-sudo-route-id-read",
            "portal route reads route-selected records through an elevated environment",
            "url id to read records through sudo",
            "ownership, token validation, and company isolation",
        ),
    ),
    (
        "portal_token_exposed_without_check",
        (
            "odoo-portal-token-exposed-without-check",
            "portal route exposes token data without access helper",
            "returns or renders access_token/access_url data",
            "tokens are not leaked across records",
        ),
    ),
    (
        "portal_url_generated_without_check",
        (
            "odoo-portal-url-generated-without-check",
            "portal url generated without local access check",
            "generates portal urls without a nearby access helper",
            "links are only created for records the caller may access",
        ),
    ),
    (
        "portal_manual_access_token_check",
        (
            "odoo-portal-manual-access-token-check",
            "portal route manually compares access_token",
            "manually compares access_token values instead of using a portal access helper",
            "_document_check_access behavior",
        ),
    ),
    (
        "field_binary_database_storage",
        (
            "field-binary-db-storage",
            "binary field disables attachment storage",
            "uses attachment=false",
            "backup exposure",
            "access behavior",
        ),
    ),
    (
        "frontend_dom_xss",
        (
            "web-owl-qweb-srcdoc-html",
            "web-dom-xss-sink",
            "owl inline template writes iframe srcdoc html",
            "dom html injection sink",
            "writes html in frontend code",
            "domparser.parsefromstring",
            "parsefromstring",
            "createcontextualfragment",
            "srcdoc",
        ),
    ),
    (
        "frontend_message_origin_validation",
        (
            "web-postmessage-dynamic-origin",
            "web-sensitive-postmessage-payload",
            "web-message-handler-missing-origin-check",
            "postmessage uses dynamic target origin",
            "nonliteral or request-derived target origin",
            "sensitive frontend value sent with postmessage",
            "frame or window boundaries",
            "message handler lacks visible origin validation",
            "event.origin allowlist",
            "cross-window messages",
            "postmessage",
        ),
    ),
    (
        "frontend_prototype_pollution",
        (
            "web-prototype-pollution-merge",
            "prototype pollution",
            "prototype-sensitive properties",
            "__proto__",
            "object merge uses untrusted data",
            "reject __proto__/constructor/prototype keys",
        ),
    ),
    (
        "frontend_unsafe_markup",
        (
            "web-owl-unsafe-markup",
            "frontend markup() marks untrusted html as safe",
            "owl/qweb markup() receives request/rpc-derived data",
            "marks it as trusted html",
            "safe-marking",
        ),
    ),
    (
        "frontend_csrf_token_missing",
        (
            "qweb-post-form-missing-csrf",
            "web-unsafe-request-without-csrf",
            "qweb post form lacks visible csrf token",
            "frontend unsafe http request lacks visible csrf token",
            "post form without a visible csrf_token",
            "unsafe method without a visible csrf token",
            "session-protected endpoints cannot be driven cross-site",
        ),
    ),
    (
        "frontend_dynamic_orm_service_call",
        (
            "web-dynamic-orm-service-call",
            "frontend orm service call uses dynamic model",
            "dynamic model, method, domain, or values",
            "client input cannot drive unintended model access",
            "privileged mutations",
        ),
    ),
    (
        "frontend_dynamic_action_window",
        (
            "web-dynamic-action-window",
            "frontend action service receives request-derived action descriptor",
            "frontend act_window uses dynamic model",
            "dynamic or request-derived res_model/domain/context/res_id/view data",
            "client input cannot widen model access",
        ),
    ),
    (
        "action_url_unsafe_scheme",
        (
            "odoo-act-url-unsafe-scheme",
            "url action uses unsafe url scheme",
            "ir.actions.act_url uses url",
            "with an unsafe scheme",
            "allowlisted https destinations",
        ),
    ),
    (
        "website_form_dangerous_success_redirect",
        (
            "odoo-website-form-dangerous-success-redirect",
            "website form success redirect uses dangerous url scheme",
            "website form success page uses dangerous url",
            "restrict success redirects to local routes or reviewed https destinations",
        ),
    ),
    (
        "frontend_dangerous_url_scheme",
        (
            "act-url-unsafe-scheme",
            "url action uses unsafe url scheme",
            "mail-template-dangerous-url-scheme",
            "mail template contains dangerous url scheme",
            "mail.template body_html contains javascript:, data:text/html, vbscript:, or file: urls",
            "i18n-dangerous-html",
            "translated msgstr contains scriptable html",
            "dangerous url schemes such as javascript:, data:text/html, vbscript:, or file:",
            "qweb-js-url",
            "qweb-t-attf-url",
            "qweb-t-att-mapping-url",
            "dangerous url scheme detected",
            "executable or local-file url scheme in attribute",
            "web-dangerous-url-scheme",
            "frontend navigation uses dangerous url scheme",
            "frontend dom url attribute uses dangerous scheme",
            "odoo frontend act_url uses dangerous url scheme",
            "website form success redirect uses dangerous url scheme",
            "literal javascript:, data:text/html, vbscript:, or file: url",
            "executable or local-file schemes",
        ),
    ),
    (
        "frontend_sensitive_object_url",
        (
            "web-sensitive-object-url",
            "sensitive frontend value exposed through object url",
            "creates a blob object url containing token/session/secret-like data",
            "downloadable, shareable, or long-lived browser object urls",
            "url.createobjecturl",
        ),
    ),
    (
        "frontend_raw_crypto_key",
        (
            "web-frontend-raw-crypto-key",
            "frontend imports raw or hard-coded cryptographic key material",
            "imports raw/jwk cryptographic key material",
            "hard-coded or request-derived data",
            "keep signing, encryption, and token keys server-side",
            "crypto.subtle.importkey",
        ),
    ),
    (
        "frontend_sensitive_credential_management",
        (
            "web-sensitive-credential-management",
            "sensitive frontend value stored with browser credential management api",
            "passes password/token/session-like data to browser credential management apis",
            "client-managed auth stores",
            "navigator.credentials.store",
            "passwordcredential",
        ),
    ),
    (
        "frontend_sensitive_history_url",
        (
            "web-sensitive-history-url",
            "sensitive frontend url persisted to browser history",
            "writes a token/session/secret-like url into browser history",
            "address bars, back/forward history",
            "history.pushstate",
            "history.replacestate",
        ),
    ),
    (
        "frontend_sensitive_url_exposure",
        (
            "qweb-sensitive-url-token",
            "web-sensitive-url-token",
            "sensitive frontend value placed in url",
            "qweb url exposes sensitive-looking parameter",
            "token/secret/password-like data in a url",
            "token, secret, password, or api-key-like data in a url",
            "query string, or fragment",
            "logs, referrers, browser history",
        ),
    ),
    (
        "frontend_reverse_tabnabbing",
        (
            "qweb-target-blank-no-noopener",
            "web-window-open-no-noopener",
            "web-target-blank-no-noopener",
            "target='_blank' without rel='noopener'",
            "target='_blank' without rel='noreferrer'",
            "dom link opens new tab without opener isolation",
            "opens new tab without opener isolation",
            "window.open opens a new context without opener isolation",
            "window.opener",
            "opener isolation",
        ),
    ),
    (
        "frontend_iframe_sandbox_missing",
        (
            "qweb-iframe-missing-sandbox",
            "web-iframe-missing-sandbox",
            "iframe lacks sandbox restrictions",
            "dom-created iframe lacks sandbox restrictions",
            "iframe without a sandbox attribute",
            "iframe without a visible sandbox assignment",
            "embedded frames",
            "embedded content privileges",
        ),
    ),
    (
        "frontend_iframe_sandbox_escape",
        (
            "qweb-iframe-sandbox-escape",
            "web-iframe-sandbox-escape",
            "iframe sandbox allows script same-origin escape",
            "dom iframe sandbox allows script same-origin escape",
            "allow-scripts with allow-same-origin",
            "script same-origin escape",
            "same-origin content can remove the sandbox",
        ),
    ),
    (
        "frontend_external_script_missing_sri",
        (
            "qweb-external-script-missing-sri",
            "web-external-script-missing-sri",
            "external script lacks subresource integrity",
            "dom-created external script lacks subresource integrity",
            "external script without an integrity attribute",
            "external script without a visible integrity assignment",
            "third-party assets with sri",
            "third-party scripts",
        ),
    ),
    (
        "frontend_external_stylesheet_missing_sri",
        (
            "qweb-external-stylesheet-missing-sri",
            "web-external-stylesheet-missing-sri",
            "external stylesheet lacks subresource integrity",
            "dom-created external stylesheet lacks subresource integrity",
            "external stylesheet without an integrity attribute",
            "external stylesheet without a visible integrity assignment",
            "third-party css with sri",
            "third-party stylesheets",
        ),
    ),
    (
        "frontend_dynamic_code_import",
        (
            "web-owl-qweb-dynamic-script-src",
            "qweb-dynamic-script-src",
            "web-dynamic-code-import",
            "owl inline template script source uses dynamic target",
            "qweb script source uses dynamic target",
            "dynamic javascript import uses external or request-derived target",
            "imports javascript at runtime",
            "runtime code loading",
            "reviewed bundles or strict allowlists",
        ),
    ),
    (
        "frontend_dynamic_worker_script",
        (
            "web-dynamic-worker-script",
            "worker script uses external or request-derived target",
            "starts a worker from an external or dynamic script target",
            "worker scripts to reviewed bundles or strict allowlists",
            "sharedworker",
        ),
    ),
    (
        "frontend_dynamic_import_scripts",
        (
            "web-dynamic-import-scripts",
            "worker importscripts loads external or request-derived script",
            "imports scripts at runtime from an external or dynamic target",
            "importscripts sources to reviewed same-origin bundles",
            "strict allowlists",
        ),
    ),
    (
        "frontend_dynamic_service_worker",
        (
            "web-dynamic-service-worker",
            "service worker registration uses external or request-derived target",
            "registers a service worker from an external or dynamic script target",
            "persistent worker scripts",
            "strict scope control",
        ),
    ),
    (
        "frontend_dynamic_wasm_loading",
        (
            "web-dynamic-wasm-loading",
            "webassembly loads external or request-derived code",
            "loads webassembly from an external, dynamic, or request-derived source",
            "reviewed same-origin assets with integrity controls",
            "webassembly.instantiatestreaming",
        ),
    ),
    (
        "frontend_dynamic_css_injection",
        (
            "qweb-dynamic-style-attribute",
            "qweb dynamic style attribute",
            "writes dynamic css into a style attribute",
            "qweb-dynamic-class-attribute",
            "qweb dynamic class attribute",
            "writes dynamic css classes",
            "alter privileged ui affordances",
            "qweb-dynamic-stylesheet-href",
            "web-owl-qweb-dynamic-stylesheet-href",
            "qweb stylesheet href uses dynamic target",
            "owl inline template stylesheet href uses dynamic target",
            "loads css from an external or dynamic target",
            "web-dynamic-css-injection",
            "stylesheet injection uses request-derived css text",
            "writes dynamic or request-derived css into a stylesheet",
            "untrusted data hide, overlay, or restyle privileged ui",
            "replaceSync",
            "insertRule",
        ),
    ),
    (
        "frontend_dynamic_live_connection",
        (
            "web-dynamic-live-connection",
            "frontend live connection uses external or request-derived endpoint",
            "opens a websocket/eventsource connection",
            "external or dynamic endpoint",
            "realtime endpoints same-origin or strictly allowlisted",
        ),
    ),
    (
        "frontend_document_domain_relaxation",
        (
            "web-document-domain-relaxation",
            "frontend relaxes same-origin policy with document.domain",
            "assigns document.domain",
            "relaxes browser origin isolation",
            "legacy same-site origin relaxation",
        ),
    ),
    (
        "frontend_sensitive_document_cookie",
        (
            "web-sensitive-document-cookie",
            "frontend writes sensitive value to document.cookie",
            "writes a session/token/secret-like cookie through document.cookie",
            "javascript-readable credential cookies",
            "set sensitive cookies server-side with httponly",
        ),
    ),
    (
        "frontend_sensitive_browser_storage",
        (
            "odoo-web-sensitive-browser-storage",
            "web-sensitive-browser-storage",
            "frontend stores sensitive value in browser storage",
            "sensitive value read from browser storage",
            "localstorage, sessionstorage, indexeddb, or window.name",
            "token/session/secret-like values in browser storage",
            "xss-readable browser storage for credentials",
        ),
    ),
    (
        "frontend_string_code_execution",
        (
            "odoo-web-string-code-execution",
            "web-string-code-execution",
            "frontend executes string-built code",
            "eval, function constructor, settimeout string, or setinterval string",
            "javascript code execution from strings",
        ),
    ),
    (
        "frontend_sensitive_window_name",
        (
            "web-sensitive-window-name",
            "sensitive frontend value written to window.name",
            "writes token/session/secret-like values to window.name",
            "navigation-persistent browser state",
            "cross-origin transitions",
        ),
    ),
    (
        "frontend_sensitive_indexeddb_storage",
        (
            "web-sensitive-indexeddb-storage",
            "sensitive value stored in indexeddb",
            "writes token/secret/session-like data to an indexeddb object store",
            "recover credentials from browser storage",
            "indexeddb object store",
        ),
    ),
    (
        "frontend_sensitive_cache_api_storage",
        (
            "web-sensitive-cache-api-storage",
            "sensitive value stored in browser cache api",
            "writes token/session-like urls or responses to the browser cache api",
            "caching credential-bearing requests",
            "authenticated responses in persistent client storage",
        ),
    ),
    (
        "frontend_sensitive_console_logging",
        (
            "web-sensitive-console-logging",
            "sensitive frontend value logged to console",
            "logs token/session/secret-like values to the browser console",
            "credential-bearing debug output",
            "browser console",
        ),
    ),
    (
        "frontend_sensitive_send_beacon",
        (
            "web-sensitive-send-beacon",
            "sensitive frontend value sent with sendbeacon",
            "sends token/session/secret-like values through navigator.sendbeacon",
            "background credential exfiltration paths",
            "telemetry payloads credential-free",
        ),
    ),
    (
        "frontend_sensitive_clipboard_write",
        (
            "web-sensitive-clipboard-write",
            "sensitive frontend value written to clipboard",
            "writes token/session/secret-like values to the system clipboard",
            "copying credentials into cross-application paste buffers",
            "clipboard.writetext",
        ),
    ),
    (
        "frontend_sensitive_notification",
        (
            "web-sensitive-notification",
            "sensitive frontend value shown in browser notification",
            "displays token/session/secret-like values in browser notifications",
            "os-level notification history",
            "shared screens",
        ),
    ),
    (
        "frontend_sensitive_broadcast_channel",
        (
            "web-sensitive-broadcast-channel",
            "sensitive frontend value used in broadcastchannel",
            "uses token/session/secret-like values in broadcastchannel names or messages",
            "spreading credentials across same-origin tabs",
            "browser contexts",
        ),
    ),
    (
        "frontend_dynamic_bus_channel",
        (
            "web-dynamic-bus-channel",
            "frontend bus service subscribes to dynamic or broad channel",
            "request-derived or broad realtime channel",
            "tenant, company, partner, or record-scoped notifications",
            "users can only receive",
        ),
    ),
    (
        "mail_template_html_injection",
        (
            "mail-template-raw-html",
            "mail template renders raw html",
            "mail.template body_html uses raw/unsafe rendering",
            "inject scriptable html into outbound mail",
        ),
    ),
    (
        "mail_template_token_exposure",
        (
            "mail-template-sensitive-token",
            "mail-template-token-not-auto-deleted",
            "mail-template-token-dynamic-recipient",
            "mail-template-external-link-sensitive",
            "mail template includes token/access fields",
            "token-bearing mail template is retained",
            "token-bearing mail template uses dynamic recipients",
            "sensitive template contains external link",
            "references access/password/signup token fields",
            "without auto_delete=true",
            "capability links",
            "external url; verify links cannot leak tokens",
        ),
    ),
    (
        "mail_template_privileged_rendering",
        (
            "mail-template-sudo-expression",
            "mail template expression uses privileged context",
            "expression calls sudo()/with_user(superuser_id)",
            "rendered content cannot disclose fields outside the recipient's access",
        ),
    ),
    (
        "mail_template_recipient_control",
        (
            "mail-template-dynamic-sensitive-recipient",
            "mail-template-dynamic-sender",
            "sensitive template uses dynamic recipients",
            "sensitive template uses dynamic sender or reply-to",
            "derives recipients from expressions",
            "derives email_from/reply_to from expressions",
            "attacker-controlled records cannot redirect private mail",
            "attackers cannot spoof senders or redirect replies",
        ),
    ),
    (
        "mail_alias_sensitive_model_ingress",
        (
            "mail-alias-public-sensitive-model",
            "public inbound alias targets sensitive model",
            "mail.alias allows",
            "create or route mail into sensitive model",
            "private or privileged records",
        ),
    ),
    (
        "mail_alias_broad_sender_policy",
        (
            "mail-alias-broad-contact-policy",
            "inbound alias accepts broad senders",
            "mail.alias accepts everyone",
            "no explicit alias_contact policy",
            "spam, spoofing, and unauthorized record creation",
        ),
    ),
    (
        "mail_alias_privileged_defaults",
        (
            "mail-alias-elevated-defaults",
            "inbound alias applies privileged defaults",
            "alias_defaults appears to set users, groups, sudo/company fields",
            "elevated defaults",
            "assign privileged ownership or access",
        ),
    ),
    (
        "mail_alias_dynamic_defaults",
        (
            "mail-alias-dynamic-defaults",
            "inbound alias defaults perform dynamic evaluation",
            "alias_defaults contains eval/exec/safe_eval",
            "inbound email data can affect evaluated code",
        ),
    ),
    (
        "mail_alias_privileged_owner",
        (
            "mail-alias-privileged-owner",
            "inbound alias runs as privileged owner",
            "admin/root alias_user_id",
            "privileged ownership",
        ),
    ),
    (
        "mail_alias_forced_thread_injection",
        (
            "mail-alias-public-force-thread",
            "broad inbound alias forces messages into an existing thread",
            "alias_force_thread_id",
            "external senders cannot inject chatter, attachments, or state changes",
        ),
    ),
    (
        "mail_chatter_public_notification",
        (
            "mail-chatter-public-route-send",
            "mail-send-public-route",
            "mail-create-public-route",
            "public route posts chatter/mail notification",
            "public route sends email",
            "public route creates outbound mail",
            "public/unauthenticated route posts chatter or mail notifications",
            "public/unauthenticated route sends email",
            "public/unauthenticated route creates mail.mail records",
            "anti-spam controls",
            "recipient restrictions",
        ),
    ),
    (
        "mail_chatter_privileged_notification",
        (
            "mail-chatter-sudo-post",
            "mail-send-sudo",
            "chatter post is performed through elevated environment",
            "email send uses elevated environment",
            "message_post/message_notify uses sudo()/with_user",
            "mail send uses sudo()/with_user",
            "do not bypass record rules",
        ),
    ),
    (
        "mail_chatter_force_send",
        (
            "mail-force-send",
            "email is force-sent synchronously",
            "force_send=true",
            "bypasses normal mail queue timing",
            "spam/rate controls",
        ),
    ),
    (
        "mail_chatter_follower_subscription",
        (
            "mail-sensitive-model-follower-subscribe",
            "mail-public-follower-subscribe",
            "mail-tainted-follower-subscribe",
            "follower subscription targets sensitive model",
            "public route changes record followers",
            "follower subscription uses request-controlled values",
            "message_subscribe receives request-derived partner/subtype values",
            "subscribers cannot receive private record updates",
            "subscribe arbitrary partners",
        ),
    ),
    (
        "mail_followers_mutation_exposure",
        (
            "mail-followers-sensitive-model-mutation",
            "mail-followers-public-route-mutation",
            "mail-followers-sudo-mutation",
            "mail-followers-tainted-mutation",
            "mail.followers mutation targets sensitive model",
            "public route mutates mail.followers",
            "mail.followers mutation uses elevated environment",
            "mail.followers mutation uses request-controlled values",
            "request-derived values reach mail.followers fields",
            "mutating subscriptions",
        ),
    ),
    (
        "mail_chatter_sensitive_content",
        (
            "mail-sensitive-body",
            "chatter/mail body includes sensitive values",
            "body or subject references token/password/secret-like data",
            "links expire appropriately",
        ),
    ),
    (
        "mail_chatter_tainted_content",
        (
            "mail-tainted-body",
            "chatter/mail body uses request-controlled content",
            "body or subject includes request-derived data",
            "escaping, spam controls, and recipient authorization",
        ),
    ),
    (
        "mail_chatter_tainted_recipients",
        (
            "mail-tainted-recipients",
            "chatter/mail recipients are request-controlled",
            "recipient fields are request-derived",
            "redirect private record notifications",
            "send arbitrary email",
        ),
    ),
    (
        "report_privileged_rendering",
        (
            "report-sudo-enabled",
            "report-sudo-render-call",
            "report action renders with sudo",
            "report render uses sudo",
            "ir.actions.report has report_sudo enabled",
            "report render runs through sudo()",
            "report contents respect recipient access rights",
        ),
    ),
    (
        "report_access_control_exposure",
        (
            "report-sensitive-no-groups",
            "report-public-render-route",
            "sensitive report lacks groups",
            "public route renders report",
            "lacks groups_id",
            "authorization and record ownership checks before report generation",
        ),
    ),
    (
        "report_cached_document_exposure",
        (
            "report-dynamic-attachment-cache",
            "report-sensitive-filename-expression",
            "report caches dynamic attachment",
            "sensitive report filename expression",
            "dynamic attachment expression and attachment_use=true",
            "cached pdfs cannot leak between users",
            "filenames do not leak tokens or private fields",
        ),
    ),
    (
        "report_tainted_render_selection",
        (
            "report-tainted-render-records",
            "report-tainted-render-action",
            "report render receives request-controlled records",
            "report action receives request-controlled data",
            "render call receives request-controlled record ids",
            "attackers cannot select arbitrary reports",
            "idor checks before rendering",
        ),
    ),
    (
        "config_parameter_sensitive_read",
        (
            "config-param-public-sensitive-read",
            "config-param-sudo-sensitive-read",
            "public route reads sensitive config parameter",
            "sensitive config parameter is read with elevated environment",
            "public route reads sensitive ir.config_parameter key",
            "get_param reads sensitive key",
            "global secrets",
        ),
    ),
    (
        "config_parameter_tainted_access",
        (
            "config-param-tainted-key-read",
            "config-param-tainted-key-write",
            "config-param-tainted-value-write",
            "config parameter key is request-controlled",
            "config parameter write key is request-controlled",
            "config parameter value is request-controlled",
            "get_param key is request-derived",
            "set_param key is request-derived",
            "set_param writes request-derived value",
            "arbitrary system-parameter disclosure",
            "modify arbitrary system parameters",
        ),
    ),
    (
        "config_parameter_security_toggle_write",
        (
            "config-param-tainted-security-toggle-write",
            "config-param-security-toggle-enabled",
            "security-sensitive config toggle receives request-controlled value",
            "security-sensitive config toggle is enabled",
            "set_param writes a request-derived value to security-sensitive key",
            "set_param enables security-sensitive key",
            "runtime security posture",
        ),
    ),
    (
        "config_parameter_base_url_write",
        (
            "config-param-tainted-base-url-write",
            "config-param-insecure-base-url-write",
            "base url config parameter receives request-controlled value",
            "base url config parameter is set to an insecure endpoint",
            "set_param writes request-derived web.base.url",
            "set_param writes web.base.url to http",
            "generated portal, oauth, payment, or password-reset links",
        ),
    ),
    (
        "config_parameter_secret_default",
        (
            "config-param-sensitive-default",
            "config-param-hardcoded-sensitive-write",
            "sensitive config parameter has hardcoded default",
            "sensitive config parameter is set to a hardcoded value",
            "literal default",
            "deployable fallback secrets",
            "set_param writes a literal value to sensitive key",
            "committing deployable secrets",
        ),
    ),
    (
        "config_parameter_elevated_write",
        (
            "config-param-sudo-write",
            "config parameter is written with elevated environment",
            "set_param writes key",
            "alter global security, mail, oauth, signup, or integration settings",
        ),
    ),
    (
        "controller_cors_wildcard_origin",
        (
            "controller-cors-wildcard-origin",
            "controller-cors-reflected-origin",
            "controller response allows any cors origin",
            "controller reflects request origin into cors header",
            "controller allows wildcard cors origin",
            "access-control-allow-origin: *",
            "request-derived origin into access-control-allow-origin",
            "cross-origin reads are intended",
            "private data cannot be exposed",
        ),
    ),
    (
        "controller_cors_credentials",
        (
            "odoo-controller-cors-credentials-enabled",
            "controller enables credentialed cors",
            "access-control-allow-credentials: true",
            "allowed origins are fixed, trusted",
            "never wildcarded or reflected",
        ),
    ),
    (
        "controller_response_header_injection",
        (
            "controller-response-header-injection",
            "response header uses request-controlled value",
            "response headers include request-controlled value",
            "writes request-derived data into response headers",
            "header argument is request-derived",
            "crlf/header injection",
            "unsafe filenames",
        ),
    ),
    (
        "controller_weak_csp_header",
        (
            "odoo-controller-weak-csp-header",
            "controller sets weak content-security-policy",
            "content-security-policy with 'unsafe-inline'",
            "content-security-policy with 'unsafe-eval'",
            "content-security-policy with script-src *",
            "content-security-policy with default-src *",
            "content-security-policy with object-src *",
            "content-security-policy with frame-ancestors *",
            "tighten script/style sources",
        ),
    ),
    (
        "controller_weak_frame_options",
        (
            "odoo-controller-weak-frame-options",
            "controller sets weak x-frame-options",
            "use deny/sameorigin or csp frame-ancestors",
            "clickjacking exposure",
        ),
    ),
    (
        "controller_weak_referrer_policy",
        (
            "odoo-controller-weak-referrer-policy",
            "controller sets weak referrer-policy",
            "referrer-policy to 'unsafe-url'",
            "referrer-policy to 'no-referrer-when-downgrade'",
            "tokenized url leakage",
        ),
    ),
    (
        "controller_weak_hsts_header",
        (
            "odoo-controller-weak-hsts-header",
            "controller sets weak strict-transport-security",
            "weak strict-transport-security header",
            "max-age=0 disables hsts",
            "use a long max-age",
        ),
    ),
    (
        "controller_weak_cross_origin_policy",
        (
            "odoo-controller-weak-cross-origin-policy",
            "controller sets weak cross-origin isolation policy",
            "cross-origin-opener-policy to unsafe-none",
            "cross-origin-resource-policy to cross-origin",
            "same-origin or require-corp style policies",
        ),
    ),
    (
        "controller_weak_permissions_policy",
        (
            "odoo-controller-weak-permissions-policy",
            "controller sets weak browser permissions policy",
            "allows sensitive browser feature",
            "restrict camera, microphone, geolocation",
        ),
    ),
    (
        "controller_tainted_html_response",
        (
            "controller-tainted-html-response",
            "controller returns request-derived html response",
            "request-derived data as text/html",
            "sanitize or render through trusted qweb templates",
        ),
    ),
    (
        "controller_jsonp_callback_response",
        (
            "odoo-controller-jsonp-callback-response",
            "controller returns request-controlled jsonp callback",
            "javascript/jsonp response from a request-controlled callback",
            "strictly validate callback names",
            "remove jsonp",
        ),
    ),
    (
        "controller_tainted_cookie",
        (
            "controller-tainted-cookie-name",
            "controller-tainted-cookie-value",
            "cookie name is request-controlled",
            "cookie value is request-controlled",
            "set_cookie name is request-derived",
            "set_cookie value is request-derived",
            "arbitrary client-side state changes",
            "session fixation",
        ),
    ),
    (
        "controller_cookie_missing_security_flags",
        (
            "odoo-controller-cookie-missing-security-flags",
            "controller sets cookie without secure, httponly, or samesite",
            "cookie missing security flags",
            "set_cookie lacks secure, httponly, or samesite",
        ),
    ),
    (
        "controller_tainted_file_response",
        (
            "controller-tainted-file-download",
            "controller-tainted-file-read",
            "controller-tainted-file-offload-header",
            "controller sends request-controlled file path",
            "controller reads request-controlled file path",
            "file offload header uses request-controlled path",
            "send_file path is request-controlled",
            "request-controlled filesystem path",
            "x-accel-redirect/x-sendfile from request input",
            "arbitrary file disclosure",
            "storage root",
        ),
    ),
    (
        "binary_content_sudo",
        (
            "odoo-binary-ir-http-binary-content-sudo",
            "ir.http binary_content is called with an elevated environment",
            "ir.http.binary_content is reached through sudo()/with_user(superuser_id)",
            "cannot bypass record rules or attachment ownership",
        ),
    ),
    (
        "binary_attachment_data_response",
        (
            "odoo-binary-attachment-data-response",
            "controller returns attachment/binary data directly",
            "controller responds with attachment/binary data",
            "attachment or binary field data directly",
            "record ownership, access_token handling, and response headers",
        ),
    ),
    (
        "raw_sql_interpolated_query",
        (
            "odoo-raw-sql-interpolated-query",
            "raw sql query is built with interpolation",
            "sql built through f-strings",
            ".format(), or concatenation",
            "use bound parameters and psycopg2.sql for identifiers",
        ),
    ),
    (
        "raw_sql_request_derived_input",
        (
            "odoo-raw-sql-request-derived-input",
            "request-derived value reaches raw sql",
            "request-derived data reaches cr.execute()",
            "verify parameter binding, allowed identifiers",
            "domain-equivalent access checks",
        ),
    ),
    (
        "raw_sql_broad_destructive_query",
        (
            "odoo-raw-sql-broad-destructive-query",
            "raw sql performs broad destructive operation",
            "destructive sql without an obvious where clause",
            "tenant scoping, backups, and orm invariants",
        ),
    ),
    (
        "raw_sql_write_no_company_scope",
        (
            "odoo-raw-sql-write-no-company-scope",
            "raw sql write lacks company scoping",
            "update/delete sql has a where clause but no visible company filter",
            "multi-company isolation and record rule equivalence",
        ),
    ),
    (
        "raw_sql_manual_transaction",
        (
            "odoo-raw-sql-manual-transaction",
            "manual transaction control in runtime code",
            "runtime code calls commit()/rollback()",
            "partial writes cannot bypass odoo request, orm, and security transaction expectations",
        ),
    ),
    (
        "action_window_sensitive_exposure",
        (
            "act-window-public-sensitive-model",
            "act-window-sensitive-broad-domain",
            "public route returns sensitive action window",
            "action window exposes sensitive model with broad domain",
            "public route returns an act_window for sensitive model",
            "ir.actions.act_window for sensitive model",
            "broad domain",
            "record rules",
        ),
    ),
    (
        "action_window_privileged_context",
        (
            "act-window-privileged-default-context",
            "act-window-active-test-disabled",
            "action window context sets privileged defaults",
            "action window disables active_test",
            "default_groups_id",
            "sel_groups_",
            "active_test=false",
            "archived records may become visible",
        ),
    ),
    (
        "action_window_company_scope_context",
        (
            "act-window-company-scope-context",
            "action window context changes company scope",
            "allowed_company_ids",
            "force_company",
            "multi-company isolation",
        ),
    ),
    (
        "action_window_tainted_definition",
        (
            "act-window-tainted-context",
            "act-window-tainted-res-model",
            "act-window-tainted-domain",
            "action window context is request-controlled",
            "action window model is request-controlled",
            "action window domain uses request-derived data",
            "res_model is request-derived",
            "context is request-derived",
            "domain is request-derived",
            "explicit models",
            "forged defaults",
        ),
    ),
    (
        "action_url_public_route",
        (
            "odoo-act-url-public-route",
            "public route returns url action",
            "public route returns ir.actions.act_url",
            "public route mutates ir.actions.act_url",
            "unauthenticated users cannot drive external navigation",
        ),
    ),
    (
        "action_url_external_no_groups",
        (
            "odoo-act-url-external-no-groups",
            "external url action has no groups",
            "' without groups",
            "only intended users can trigger this navigation",
        ),
    ),
    (
        "action_url_external_new_window",
        (
            "odoo-act-url-external-new-window",
            "url action opens external url in new window",
            "with target='new'",
            "phishing, tabnabbing, and allowlist expectations",
        ),
    ),
    (
        "action_url_external_navigation",
        (
            "act-url-public-route",
            "act-url-external-no-groups",
            "act-url-external-new-window",
            "public route returns ir.actions.act_url",
            "public route mutates ir.actions.act_url",
            "opens external url",
            "without groups",
            "target='new'",
            "new window",
            "phishing, tabnabbing",
            "external navigation",
        ),
    ),
    (
        "controller_open_redirect",
        (
            "odoo-controller-open-redirect",
            "controller redirects to request-controlled url",
            "controller redirects to a request-derived url",
            "restrict redirects to local paths or an allowlisted host set",
        ),
    ),
    (
        "website_form_dynamic_success_redirect",
        (
            "odoo-website-form-dynamic-success-redirect",
            "website form success redirect is request-derived",
            "website form success page is built from request-derived expression",
            "validate against local routes or allowlisted hosts before redirecting",
        ),
    ),
    (
        "action_url_tainted_navigation",
        (
            "act-url-tainted-url",
            "returned ir.actions.act_url uses a request-derived url",
            "ir.actions.act_url url is assigned from request-derived data",
            "request-derived url",
            "allowlisted hosts",
            "navigation abuse",
        ),
    ),
    (
        "action_url_sensitive_url_material",
        (
            "act-url-sensitive-url",
            "ir.actions.act_url url appears to contain token",
            "secret, password, or api-key material",
            "browser history and referrers",
        ),
    ),
    (
        "database_listing_exposure",
        (
            "database-listing-route",
            "route lists available databases",
            "controller lists database names",
            "list_db/dbfilter posture",
            "tenant names",
        ),
    ),
    (
        "database_tainted_management_input",
        (
            "database-tainted-management-input",
            "request-derived input reaches database manager operation",
            "request-derived data reaches database create/drop/backup/restore behavior",
            "attacker-chosen database names",
            "backup payloads",
        ),
    ),
    (
        "database_manager_exposure",
        (
            "database-management-call",
            "controller calls database manager operation",
            "database create/drop/backup/restore behavior",
            "admin-only, csrf-protected, audited",
            "not reachable pre-auth",
        ),
    ),
    (
        "database_tainted_selection",
        (
            "database-tainted-selection",
            "request-derived database selection",
            "request-derived data reaches database selection/filtering",
            "hostname dbfilter",
            "user-controlled database names",
        ),
    ),
    (
        "database_session_selection",
        (
            "database-session-db-assignment",
            "request controls session database",
            "request.session.db",
            "host/dbfilter cannot be bypassed",
        ),
    ),
    (
        "export_spreadsheet_formula_injection",
        (
            "export-csv-formula-injection",
            "export-xlsx-formula-injection",
            "csv export writes unsanitized record/request data",
            "xlsx export writes unsanitized record/request data",
            "formula escaping",
            "neutralize values beginning with",
            "force strings or neutralize formula prefixes",
        ),
    ),
    (
        "export_tainted_formula",
        (
            "export-tainted-formula",
            "xlsx formula uses request/record data",
            "formula is built from request/record-derived data",
            "attacker-controlled spreadsheet expressions",
        ),
    ),
    (
        "export_request_controlled_fields",
        (
            "export-request-controlled-fields",
            "orm export fields are request-controlled",
            "export/read field list is request-derived",
            "server-side allowlist",
        ),
    ),
    (
        "sensitive_model_default_export",
        (
            "export-sensitive-model-default-fields",
            "sensitive model export omits field allowlist",
            "sensitive model read/export uses default fields",
            "omits an explicit fields allowlist",
            "restrict returned fields before exposing data",
        ),
    ),
    (
        "website_form_external_success_redirect",
        (
            "odoo-website-form-external-success-redirect",
            "website form redirects to external success url",
            "website form success page points to external url",
            "phishing, token leakage, or open-redirect surface",
        ),
    ),
    (
        "binary_tainted_web_content_redirect",
        (
            "odoo-binary-tainted-web-content-redirect",
            "controller redirects to request-controlled web content url",
            "controller builds a /web/content or /web/image url from request input",
            "allowed model/field scope",
        ),
    ),
    (
        "open_redirect_portal",
        (
            "redirect",
            "return-url",
            "next-url",
            "url-action",
            "web-client-side-redirect",
            "client-side navigation",
            "dynamic target",
            "window.location",
            "window.open",
        ),
    ),
    (
        "outbound_integration_credential_forwarding",
        (
            "integration-tainted-auth-header",
            "odoo-integration-tainted-auth-header",
            "integration-tainted-http-auth",
            "odoo-integration-tainted-http-auth",
            "auth header uses request-controlled value",
            "auth parameter uses request-controlled value",
            "forwards request-derived authorization",
        ),
    ),
    (
        "integration_hardcoded_auth_header",
        (
            "odoo-integration-hardcoded-auth-header",
            "outbound http auth header is hardcoded",
            "sends literal authorization, cookie, api key, or token header material",
            "move integration credentials to trusted server-side configuration",
        ),
    ),
    (
        "integration_hardcoded_http_auth",
        (
            "odoo-integration-hardcoded-http-auth",
            "outbound http auth parameter is hardcoded",
            "auth= material contains literal credential-like values",
            "move integration credentials to trusted server-side configuration",
        ),
    ),
    (
        "integration_http_no_timeout",
        (
            "odoo-integration-http-no-timeout",
            "outbound http call has no timeout",
            "outbound http call lacks a timeout",
            "slow upstream can exhaust odoo workers",
        ),
    ),
    (
        "integration_tls_verify_disabled",
        (
            "odoo-integration-tls-verify-disabled",
            "outbound http disables tls verification",
            "outbound http call passes verify=false",
            "permits man-in-the-middle attacks against integration traffic",
        ),
    ),
    (
        "integration_tainted_url_ssrf",
        (
            "odoo-integration-tainted-url-ssrf",
            "outbound http url is request-controlled",
            "outbound http url is derived from request/controller input",
            "private-network reachability to prevent ssrf",
        ),
    ),
    (
        "integration_tainted_proxy",
        (
            "odoo-integration-tainted-proxy",
            "outbound http proxy is request-controlled",
            "proxy configuration is derived from request/controller input",
            "redirect integration traffic through controlled proxies",
        ),
    ),
    (
        "integration_internal_url_ssrf",
        (
            "odoo-integration-internal-url-ssrf",
            "outbound http targets internal url",
            "literal loopback, private, link-local, or metadata url",
            "cloud metadata or internal odoo/admin services",
        ),
    ),
    (
        "integration_subprocess_shell_true",
        (
            "odoo-integration-subprocess-shell-true",
            "subprocess uses shell=true",
            "subprocess call uses shell=true",
            "shell interpretation for integration commands",
        ),
    ),
    (
        "integration_os_command_execution",
        (
            "odoo-integration-os-command-execution",
            "os command execution sink",
            "executes through the shell",
            "replace with bounded subprocess argument lists",
        ),
    ),
    (
        "integration_tainted_command_args",
        (
            "odoo-integration-tainted-command-args",
            "process command uses request-controlled input",
            "process command or arguments are derived from request/controller input",
            "validate allowlisted commands, arguments, paths, and environment",
        ),
    ),
    (
        "integration_process_no_timeout",
        (
            "odoo-integration-process-no-timeout",
            "process execution has no timeout",
            "process execution lacks timeout",
            "external converters and commands can hang odoo workers",
        ),
    ),
    (
        "integration_report_command_review",
        (
            "odoo-integration-report-command-review",
            "external report/document converter command",
            "command invokes an external report/document converter",
            "input file control, output path safety, timeout, and sandboxing",
        ),
    ),
    (
        "deployment_oauth_validation_missing",
        (
            "odoo-deploy-oauth-missing-validation-endpoint",
            "oauth provider lacks validation endpoint",
            "has no validation_endpoint",
            "tokens are validated against the provider",
        ),
    ),
    (
        "deployment_oauth_insecure_endpoint",
        (
            "odoo-deploy-oauth-insecure-endpoint",
            "oauth provider uses insecure http endpoint",
            "auth.oauth.provider field",
            "uses http; oauth tokens and identities must use https endpoints",
        ),
    ),
    (
        "deployment_committed_secret",
        (
            "odoo-deploy-oauth-client-secret-committed",
            "odoo-deploy-admin-passwd-committed",
            "oauth client secret committed in module data",
            "database manager master password is committed",
            "move it to secret storage and rotate",
            "move provider secrets to environment/provisioning storage",
        ),
    ),
    (
        "deployment_weak_master_password",
        (
            "odoo-deploy-weak-admin-passwd",
            "database manager master password is weak",
            "admin_passwd is empty, short, or placeholder-like",
            "strong environment-specific master password",
        ),
    ),
    (
        "deployment_dev_or_test_mode",
        (
            "odoo-deploy-dev-mode-enabled",
            "odoo-deploy-test-enable",
            "developer mode is enabled in deployment config",
            "test mode is enabled in deployment config",
            "production deployments should not run",
        ),
    ),
    (
        "deployment_database_manager_exposure",
        (
            "odoo-deploy-list-db-enabled",
            "odoo-deploy-database-create-enabled",
            "odoo-deploy-database-drop-enabled",
            "database listing is enabled",
            "database creation is enabled",
            "database drop is enabled",
            "database-manager access is disabled or strongly restricted",
        ),
    ),
    (
        "deployment_dbfilter_weak",
        (
            "odoo-deploy-empty-dbfilter",
            "odoo-deploy-wildcard-dbfilter",
            "database filter is empty",
            "database filter matches arbitrary database names",
            "bind databases to expected hostnames",
        ),
    ),
    (
        "deployment_proxy_mode_disabled",
        (
            "odoo-deploy-proxy-mode-disabled",
            "proxy mode is disabled",
            "reverse-proxy deployments can mishandle scheme/client ip",
            "secure-cookie or url behavior",
        ),
    ),
    (
        "deployment_database_tls_weak",
        (
            "odoo-deploy-db-sslmode-opportunistic",
            "database tls mode is opportunistic or disabled",
            "db_sslmode does not require verified postgresql tls",
            "use verify-full or verify-ca",
        ),
    ),
    (
        "deployment_worker_limits_weak",
        (
            "odoo-deploy-workers-disabled",
            "odoo-deploy-time-limit-disabled",
            "odoo workers are disabled",
            "worker execution time limit is disabled",
            "enforce worker time limits",
            "prefork workers",
        ),
    ),
    (
        "deployment_debug_logging",
        (
            "odoo-deploy-debug-logging",
            "odoo-deploy-debug-log-handler",
            "debug logging is enabled",
            "sensitive debug log handler is enabled",
            "production logs can expose sql, request data, tokens, or pii",
        ),
    ),
    (
        "deployment_base_url_integrity",
        (
            "odoo-deploy-base-url-not-frozen",
            "odoo-deploy-insecure-base-url",
            "base url is not frozen",
            "base url uses an insecure or local endpoint",
            "host-header or proxy mistakes can affect generated links",
            "generated portal, oauth, and password-reset links",
        ),
    ),
    (
        "deployment_open_signup",
        (
            "odoo-deploy-open-signup",
            "odoo-deploy-oauth-auto-signup",
            "odoo-deploy-b2c-signup",
            "uninvited public signup is enabled",
            "oauth auto-signup is enabled",
            "b2c signup scope is enabled",
            "public account creation",
        ),
    ),
    ("raw_sql_injection", ("raw-sql", "sql", "cr.execute", "execute")),
    ("safe_eval_user_input", ("safe-eval", "safe_eval", "eval", "server-action", "loose-python")),
    (
        "session_cookie_weak_flags",
        (
            "session-sensitive-cookie-weak-flags",
            "sensitive-cookie-weak-flags",
            "cookie without secure",
            "without secure=true",
            "httponly",
            "samesite",
        ),
    ),
    (
        "sensitive_cookie_cacheable_response",
        (
            "cache-public-sensitive-cookie-response",
            "sensitive cookie without no-store",
            "session/token/csrf-shaped cookie without obvious cache-control",
            "sets sensitive cookie without no-store",
        ),
    ),
    (
        "cache_public_sensitive_response",
        (
            "odoo-cache-public-sensitive-response",
            "public sensitive response lacks no-store cache-control",
            "public controller response includes token/secret-like data without obvious cache-control",
            "browser/proxy caching of account or document secrets",
        ),
    ),
    (
        "cache_public_sensitive_render",
        (
            "odoo-cache-public-sensitive-render",
            "public render includes token/secret-like data",
            "public route renders token/secret-like values",
            "shared caches or referrers",
        ),
    ),
    (
        "cache_public_file_download",
        (
            "odoo-cache-public-file-download",
            "public file download may be cacheable",
            "public sensitive-looking download uses send_file without cache disabling arguments",
            "private documents are not cached by browsers or proxies",
        ),
    ),
    (
        "cache_public_cacheable_sensitive_route",
        (
            "odoo-cache-public-cacheable-sensitive-route",
            "public sensitive route sets cacheable headers",
            "public sensitive-looking route sets cacheable cache-control headers",
            "tokenized pages, invoices, exports, and downloads should use no-store/private policies",
        ),
    ),
    (
        "payment_public_callback_no_signature",
        (
            "odoo-payment-public-callback-no-signature",
            "public payment callback lacks visible signature validation",
            "public csrf=false payment/webhook route has no visible signature/hmac validation",
            "forged provider notifications cannot update transactions",
        ),
    ),
    (
        "payment_weak_signature_compare",
        (
            "odoo-payment-weak-signature-compare",
            "payment handler compares signatures without constant-time check",
            "compares signature-like values with == or !=",
            "hmac.compare_digest",
            "timing leaks",
        ),
    ),
    (
        "payment_state_without_validation",
        (
            "odoo-payment-state-without-validation",
            "payment handler changes transaction state without visible validation",
            "changes transaction state without visible signature/reference validation",
        ),
    ),
    (
        "payment_state_without_reconciliation",
        (
            "odoo-payment-state-without-amount-currency-check",
            "payment handler changes state without amount/currency reconciliation",
            "without visible amount and currency checks",
            "wrong-currency notifications cannot complete payment",
        ),
    ),
    (
        "payment_state_without_idempotency",
        (
            "odoo-payment-state-without-idempotency-check",
            "payment handler changes state without visible idempotency guard",
            "duplicate event",
            "retried notifications cannot duplicate fulfillment",
        ),
    ),
    (
        "payment_transaction_lookup_weak",
        (
            "odoo-payment-transaction-lookup-weak",
            "payment transaction lookup lacks provider/reference scoping",
            "searches payment.transaction without visible provider/reference scoping",
            "bind to the wrong transaction",
        ),
    ),
    (
        "payment_webhook_integrity",
        (
            "payment-public-callback-no-signature",
            "payment-state-without-validation",
            "payment-state-without-amount-currency-check",
            "payment-state-without-idempotency-check",
            "payment-transaction-lookup-weak",
            "payment notification/webhook",
            "provider notifications",
        ),
    ),
    (
        "website_form_route_csrf_disabled",
        (
            "odoo-website-form-route-csrf-disabled",
            "website form route disables csrf protection",
            "disables csrf protection for a website form endpoint",
            "cross-site request can create or mutate records",
        ),
    ),
    (
        "website_form_public_model_create",
        (
            "odoo-website-form-public-model-create",
            "website form posts directly to an odoo model",
            "website form submits to odoo model creation",
            "allowed fields, required authentication, rate limiting, and post-create side effects",
        ),
    ),
    (
        "website_form_sensitive_field",
        (
            "odoo-website-form-sensitive-field",
            "website form exposes sensitive model field",
            "public users cannot set ownership, workflow, company, token, privilege, or visibility fields",
        ),
    ),
    (
        "website_form_file_upload",
        (
            "odoo-website-form-file-upload",
            "website form accepts file uploads",
            "public website form accepts file uploads",
            "mime/type checks, size limits, attachment visibility, and malware scanning",
        ),
    ),
    (
        "website_form_missing_csrf_token",
        (
            "odoo-website-form-missing-csrf-token",
            "website form has no visible csrf token",
            "without a visible csrf_token input",
            "csrf protection is present and cannot be bypassed cross-site",
        ),
    ),
    (
        "website_form_hidden_model_selector",
        (
            "odoo-website-form-hidden-model-selector",
            "website form carries model selector in hidden input",
            "website form includes a hidden model selector",
            "clients cannot tamper with submitted model/field metadata",
        ),
    ),
    (
        "website_form_public_record_mutation",
        (
            "website-form-route-csrf-disabled",
            "website-form-public-model-create",
            "website-form-sensitive-field",
            "website-form-sanitize-disabled",
            "website form route disables csrf",
            "website form posts directly to an odoo model",
            "website form exposes sensitive model field",
            "sanitize_form=false",
            "disables input sanitization",
        ),
    ),
    (
        "publication_public_route_mutation",
        (
            "odoo-publication-public-route-mutation",
            "public route changes website publication",
            "public/unauthenticated route writes publication flags",
            "attackers cannot publish private records",
        ),
    ),
    (
        "attachment_public_route_mutation",
        (
            "odoo-attachment-public-route-mutation",
            "public route mutates attachments",
            "public/unauthenticated route mutates ir.attachment",
            "upload/delete authority, record ownership, and token checks",
        ),
    ),
    (
        "attachment_tainted_res_model_write",
        (
            "odoo-attachment-tainted-res-model-write",
            "attachment res_model is changed from request input",
            "ir.attachment.write uses request-derived res_model",
            "rebind files to unintended protected models",
        ),
    ),
    (
        "attachment_tainted_res_id_write",
        (
            "odoo-attachment-tainted-res-id-write",
            "attachment res_id is changed from request input",
            "ir.attachment.write uses request-derived res_id",
            "ownership before rebinding files to existing records",
        ),
    ),
    (
        "attachment_tainted_res_model",
        (
            "odoo-attachment-tainted-res-model",
            "attachment res_model is request-controlled",
            "ir.attachment.create uses request-derived res_model",
            "bind uploads to unintended protected models",
        ),
    ),
    (
        "attachment_tainted_res_id",
        (
            "odoo-attachment-tainted-res-id",
            "attachment res_id is request-controlled",
            "ir.attachment.create uses request-derived res_id",
            "ownership before binding files to existing records",
        ),
    ),
    (
        "attachment_public_orphan",
        (
            "odoo-attachment-public-orphan",
            "public attachment lacks record binding",
            "public=true without both res_model and res_id",
            "intended to be world-readable",
        ),
    ),
    (
        "attachment_public_sensitive_binding",
        (
            "odoo-attachment-public-sensitive-binding",
            "public attachment is bound to sensitive model",
            "public=true on sensitive model",
            "private business document is exposed",
        ),
    ),
    (
        "attachment_public_write",
        (
            "odoo-attachment-public-write",
            "attachment write makes file public",
            "ir.attachment.write sets public=true",
            "linked record, and storage object are intentionally world-readable",
        ),
    ),
    (
        "attachment_tainted_access_token_write",
        (
            "odoo-attachment-tainted-access-token-write",
            "attachment access_token is request-controlled",
            "ir.attachment.write stores a request-derived access_token",
            "generate attachment tokens server-side",
        ),
    ),
    (
        "attachment_tainted_lookup",
        (
            "odoo-attachment-tainted-lookup",
            "request-derived attachment lookup",
            "request-derived input selects ir.attachment records",
            "ownership, res_model/res_id constraints, access_token, and record-rule behavior",
        ),
    ),
    (
        "file_upload_tainted_path_write",
        (
            "odoo-file-upload-tainted-path-write",
            "request-controlled path is opened for write",
            "request-controlled path receives file copy/move",
            "request-controlled path object is written",
            "validate basename, extension, destination, and traversal handling",
        ),
    ),
    (
        "file_upload_base64_decode",
        (
            "odoo-file-upload-base64-decode",
            "request-derived base64 upload is decoded",
            "request-derived base64 data is decoded",
            "size limits, mime validation, and storage destination",
        ),
    ),
    (
        "file_upload_attachment_from_request",
        (
            "odoo-file-upload-attachment-from-request",
            "attachment is created from request-derived upload data",
            "ir.attachment is created from request-derived data",
            "size, mime, acls, res_model/res_id binding, and public flag",
        ),
    ),
    (
        "file_upload_public_attachment_create",
        (
            "odoo-file-upload-public-attachment-create",
            "uploaded attachment is created public",
            "ir.attachment.create sets public=true",
            "uploaded content is intentionally world-readable",
        ),
    ),
    (
        "file_upload_archive_extraction",
        (
            "odoo-file-upload-archive-extraction",
            "archive extraction requires traversal review",
            "archive extract/extractall can write files outside the intended directory",
            "validate every member path before extraction",
        ),
    ),
    (
        "file_upload_secure_filename_only",
        (
            "odoo-file-upload-secure-filename-only",
            "upload path write relies on secure_filename only",
            "secure_filename() normalizes a basename but does not enforce destination",
            "extension, content type, uniqueness, or overwrite handling",
        ),
    ),
    (
        "file_upload_unsafe_tempfile",
        (
            "odoo-file-upload-unsafe-tempfile",
            "upload flow uses tempfile.mktemp",
            "tempfile.mktemp() creates predictable race-prone paths",
            "use mkstemp(), namedtemporaryfile(), or temporarydirectory()",
        ),
    ),
    (
        "binary_tainted_content_args",
        (
            "odoo-binary-tainted-binary-content-args",
            "binary_content receives request-controlled arguments",
            "ir.http.binary_content receives request-derived model/id/field arguments",
            "constrain model, field, record ownership, and token semantics",
        ),
    ),
    (
        "binary_tainted_content_disposition",
        (
            "odoo-binary-tainted-content-disposition",
            "download filename is request-controlled",
            "content_disposition uses request-derived filename",
            "validate crlf, path separators, extension",
        ),
    ),
    ("csrf_state_change_get", ("csrf", "state-change", "unsafe-method", "get-route")),
    ("portal_route_no_auth", ("public-route", "auth-none", "auth-public", "portal-route", "public-write-route")),
    (
        "publication_public_attachment",
        (
            "odoo-publication-public-attachment",
            "attachment is published publicly",
            "ir.attachment record sets public=true",
            "binary cannot expose private customer",
        ),
    ),
    (
        "publication_sensitive_public_attachment",
        (
            "odoo-publication-sensitive-public-attachment",
            "sensitive-looking attachment is public",
            "public attachment name/model suggests sensitive content",
            "intentionally world-readable",
        ),
    ),
    (
        "publication_sensitive_website_published",
        (
            "odoo-publication-sensitive-website-published",
            "sensitive model record is website-published",
            "marked website-published",
            "portal/public routes cannot expose private fields",
        ),
    ),
    (
        "publication_portal_share_sensitive",
        (
            "odoo-publication-portal-share-sensitive",
            "portal/share record targets sensitive data",
            "portal/share wizard data targets sensitive records",
            "generated links, recipients, and expiration behavior",
        ),
    ),
    (
        "publication_sensitive_default_published",
        (
            "odoo-publication-sensitive-default-published",
            "sensitive model defaults records to website-published",
            "truthy default",
            "published to website/public routes by default",
        ),
    ),
    (
        "publication_sensitive_runtime_published",
        (
            "odoo-publication-sensitive-runtime-published",
            "sensitive model publication flag is written at runtime",
            "runtime write changes publication flags",
            "record ownership, and portal/public field exposure",
        ),
    ),
    (
        "publication_tainted_runtime_published",
        (
            "odoo-publication-tainted-runtime-published",
            "request-derived publication flag is written",
            "request-derived data controls publication flags",
            "require explicit publish permissions",
        ),
    ),
    (
        "sensitive_model_default_configuration",
        (
            "default-sensitive-model",
            "sensitive model default",
            "default for sensitive model",
            "ir.default",
        ),
    ),
    (
        "sensitive_model_public_exposure",
        (
            "publication-sensitive",
            "portal-share-sensitive",
            "sensitive-public-attachment",
            "website-published",
            "follower subscription targets sensitive model",
            "mail.followers mutation targets sensitive model",
            "public attachment",
            "portal/share",
        ),
    ),
    (
        "sensitive_model_mutation",
        (
            "sensitive-model-mutation",
            "sensitive model mutation",
            "mutates sensitive model",
            "mutating sensitive model",
            "sensitive model '",
        ),
    ),
    ("sudo_misuse_idor", ("sudo", "acl", "access", "idor", "authorization", "record-rule", "multi-company")),
    ("domain_injection", ("domain", "search", "search_read")),
    (
        "api_key_credential_exposure",
        (
            "api-key-config-parameter-request-secret",
            "api-key-public-route-mutation",
            "api-key-request-derived-mutation",
            "api-key-returned-from-route",
            "api-key-tainted-lookup",
            "api key is stored",
            "api-key/token material",
        ),
    ),
    (
        "runtime_config_security_misconfiguration",
        (
            "config-param-tainted-security-toggle-write",
            "config-param-tainted-base-url-write",
            "config-param-security-toggle-enabled",
            "config-param-insecure-base-url-write",
            "security-sensitive config toggle",
            "request-derived web.base.url",
        ),
    ),
    (
        "controller_sensitive_response_exposure",
        (
            "controller-sensitive-token-response",
            "response returns sensitive token-shaped data",
            "token, password, API key, or secret-shaped data",
        ),
    ),
    (
        "realtime_bus_channel_authorization",
        (
            "realtime-broad-or-tainted-channel-subscription",
            "realtime-broad-or-tainted-channel",
            "realtime-sensitive-payload",
            "request-controlled channel",
            "broad or request-controlled channel",
            "bus subscription",
        ),
    ),
    ("ssrf_outbound_request", ("ssrf", "request", "requests.", "urllib", "callback", "webhook")),
    ("path_traversal_attachment", ("path", "traversal", "attachment", "file-upload", "binary-download")),
    ("hardcoded_secret", ("secret", "api-key", "token", "password", "credential", "oauth")),
    ("weak_crypto", ("crypto", "md5", "sha1", "weak-random", "random")),
    ("deserialize_user_input", ("serialization", "deserialize", "pickle", "yaml", "marshal")),
    ("mass_assignment", ("mass-assignment", "arbitrary-fields", "request-params", "kw-write")),
    ("ir_rule_global_bypass", ("global-rule", "domain_force", "ir-rule", "record-rule")),
    ("external_id_xml_id_clobber", ("external-id", "xml-id", "noupdate", "xml-data")),
    ("race_condition_state", ("race", "toctou", "state", "workflow", "approval")),
    (
        "deployment_security_misconfiguration",
        (
            "deployment",
            "deploy",
            "database-manager",
            "list_db",
            "dbfilter",
            "proxy_mode",
            "database.create",
            "database.drop",
        ),
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Odoo Security Deep Scan")
    parser.add_argument("repo", help="Path to Odoo repository")
    parser.add_argument("--out", default=".audit-deep", help="Output directory")
    parser.add_argument("--pocs", action="store_true", help="Generate PoC scripts")
    parser.add_argument("--base-url", default="http://localhost:8069", help="Base URL for PoCs")
    parser.add_argument("--database", default="odoo", help="Database name for PoCs")
    parser.add_argument(
        "--baseline",
        help="Baseline findings JSON or audit directory for fingerprint delta reporting",
    )
    parser.add_argument(
        "--accepted-risks",
        help="Accepted-risk YAML/JSON file for suppressing already-triaged findings",
    )
    parser.add_argument(
        "--check-only-accepted-risks",
        action="store_true",
        help="Validate accepted-risk policy, write inventory/report, and exit non-zero on errors or expired entries",
    )
    parser.add_argument(
        "--fix-list",
        help="Fix-list YAML/JSON file for tracking confirmed bugs without suppressing findings",
    )
    parser.add_argument(
        "--check-only-fix-list",
        action="store_true",
        help="Validate fix-list policy, write inventory/report, and exit non-zero on errors or overdue entries",
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "critical", "high", "medium", "low"],
        default="none",
        help="Exit 2 when findings at or above this severity are present",
    )
    parser.add_argument(
        "--fail-on-new",
        choices=["none", "critical", "high", "medium", "low"],
        default="none",
        help="Exit 2 when new findings at or above this severity are present compared to --baseline",
    )
    parser.add_argument(
        "--fail-on-unmapped-taxonomy",
        action="store_true",
        help="Exit 2 when emitted rule IDs lack CWE/CAPEC/OWASP taxonomy mapping",
    )
    parser.add_argument(
        "--fail-on-policy-errors",
        action="store_true",
        help="Exit 2 when accepted-risk or fix-list files have loader/validation errors",
    )
    parser.add_argument(
        "--fail-on-expired-accepted-risk",
        action="store_true",
        help="Exit 2 when expired accepted-risk entries or matches are present",
    )
    parser.add_argument(
        "--fail-on-overdue-fix",
        action="store_true",
        help="Exit 2 when open/in-progress fix-list entries are overdue and still present",
    )
    parser.add_argument(
        "--fail-on-fix-regression",
        action="store_true",
        help="Exit 2 when a fix-list entry marked fixed still matches a finding",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).expanduser().resolve()
    out = Path(args.out).expanduser().resolve()

    if not repo.exists():
        print(f"Repository not found: {repo}", file=sys.stderr)
        return 1
    if args.fail_on_new != "none" and not args.baseline:
        print("--fail-on-new requires --baseline", file=sys.stderr)
        return 1

    out.mkdir(parents=True, exist_ok=True)
    print(f"Scanning {repo}...")
    print(f"Output: {out}")
    print()

    check_only_status = run_policy_check_only(repo, out, args)
    if check_only_status is not None:
        return check_only_status

    all_findings: list[dict] = []

    # 1. Deep pattern analysis
    print("1. Running deep pattern analysis...")
    findings = analyze_directory(repo)
    deep_findings = [
        {
            "source": "deep-pattern",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
        }
        for f in findings
    ]
    all_findings.extend(deep_findings)
    print(f"   Found {len(deep_findings)} issues")

    # 2. QWeb scanning
    print("2. Scanning QWeb templates...")
    qweb_findings = scan_qweb_templates(repo)
    qweb_results = [
        {
            "source": "qweb",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "element": f.element,
            "attribute": f.attribute,
        }
        for f in qweb_findings
    ]
    all_findings.extend(qweb_results)
    print(f"   Found {len(qweb_results)} issues")

    # 3. Access control analysis
    print("3. Analyzing access control...")
    acl_findings = analyze_access_control(repo)
    acl_results = [
        {
            "source": "access-control",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "group": f.group,
        }
        for f in acl_findings
    ]
    all_findings.extend(acl_results)
    print(f"   Found {len(acl_results)} issues")

    # 4. Record rule domain scan
    print("4. Scanning record-rule domains...")
    record_rule_findings = scan_record_rules(repo)
    record_rule_results = [
        {
            "source": "record-rules",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "record_id": f.record_id,
            "group": f.group,
        }
        for f in record_rule_findings
    ]
    all_findings.extend(record_rule_results)
    print(f"   Found {len(record_rule_results)} issues")

    # 5. Access override scan
    print("5. Scanning model access/search overrides...")
    access_override_findings = scan_access_overrides(repo)
    access_override_results = [
        {
            "source": "access-overrides",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "method": f.method,
        }
        for f in access_override_findings
    ]
    all_findings.extend(access_override_results)
    print(f"   Found {len(access_override_results)} issues")

    # 6. Multi-company isolation
    print("6. Checking multi-company isolation...")
    mc_findings = check_multi_company_isolation(repo)
    mc_results = [
        {
            "source": "multi-company",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
        }
        for f in mc_findings
    ]
    all_findings.extend(mc_results)
    print(f"   Found {len(mc_results)} issues")

    # 7. Manifest/package scan
    print("7. Scanning Odoo manifests...")
    manifest_findings = scan_manifests(repo)
    manifest_results = [
        {
            "source": "manifest",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "module": f.module,
        }
        for f in manifest_findings
    ]
    all_findings.extend(manifest_results)
    print(f"   Found {len(manifest_results)} issues")

    # 8. Migration/lifecycle hook scan
    print("8. Scanning migrations and lifecycle hooks...")
    migration_findings = scan_migrations(repo)
    migration_results = [
        {
            "source": "migrations",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "context": f.context,
        }
        for f in migration_findings
    ]
    all_findings.extend(migration_results)
    print(f"   Found {len(migration_results)} issues")

    # 9. Model structure scan
    print("9. Scanning Odoo model structure...")
    model_findings = scan_models(repo)
    model_results = [
        {
            "source": "model-structure",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "field": f.field,
        }
        for f in model_findings
    ]
    all_findings.extend(model_results)
    print(f"   Found {len(model_results)} issues")

    # 10. Field security scan
    print("10. Scanning Odoo field security metadata...")
    field_security_findings = scan_field_security(repo)
    field_security_results = [
        {
            "source": "field-security",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "field": f.field,
        }
        for f in field_security_findings
    ]
    all_findings.extend(field_security_results)
    print(f"   Found {len(field_security_results)} issues")

    # 11. Property/company-dependent field scan
    print("11. Scanning property and company-dependent fields...")
    property_findings = scan_property_fields(repo)
    property_results = [
        {
            "source": "property-fields",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "field": f.field,
            "record_id": f.record_id,
        }
        for f in property_findings
    ]
    all_findings.extend(property_results)
    print(f"   Found {len(property_results)} issues")

    # 12. Settings model scan
    print("12. Scanning Odoo settings models...")
    settings_findings = scan_settings(repo)
    settings_results = [
        {
            "source": "settings",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "field": f.field,
        }
        for f in settings_findings
    ]
    all_findings.extend(settings_results)
    print(f"   Found {len(settings_results)} issues")

    # 13. Model method behavior scan
    print("13. Scanning Odoo model method behavior...")
    model_method_findings = scan_model_methods(repo)
    model_method_results = [
        {
            "source": "model-methods",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "method": f.method,
        }
        for f in model_method_findings
    ]
    all_findings.extend(model_method_results)
    print(f"   Found {len(model_method_results)} issues")

    # 14. Model constraint scan
    print("14. Scanning Odoo model constraints...")
    constraint_findings = scan_constraints(repo)
    constraint_results = [
        {
            "source": "constraints",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "method": f.method,
            "field": f.field,
        }
        for f in constraint_findings
    ]
    all_findings.extend(constraint_results)
    print(f"   Found {len(constraint_results)} issues")

    # 15. Button/action method scan
    print("15. Scanning Odoo button/action methods...")
    button_findings = scan_button_actions(repo)
    button_results = [
        {
            "source": "button-actions",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "method": f.method,
        }
        for f in button_findings
    ]
    all_findings.extend(button_results)
    print(f"   Found {len(button_results)} issues")

    # 16. Wizard/transient model scan
    print("16. Scanning transient model wizards...")
    wizard_findings = scan_wizards(repo)
    wizard_results = [
        {
            "source": "wizards",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "method": f.method,
        }
        for f in wizard_findings
    ]
    all_findings.extend(wizard_results)
    print(f"   Found {len(wizard_results)} issues")

    # 17. Metadata/data security scan
    print("17. Scanning security-sensitive metadata...")
    metadata_findings = scan_metadata(repo)
    metadata_results = [
        {
            "source": "metadata",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "record_id": f.record_id,
        }
        for f in metadata_findings
    ]
    all_findings.extend(metadata_results)
    print(f"   Found {len(metadata_results)} issues")

    # 18. XML data/external-ID integrity scan
    print("18. Scanning XML data and external-ID integrity...")
    data_integrity_findings = scan_data_integrity(repo)
    data_integrity_results = [
        {
            "source": "data-integrity",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "record_id": f.record_id,
        }
        for f in data_integrity_findings
    ]
    all_findings.extend(data_integrity_results)
    print(f"   Found {len(data_integrity_results)} issues")

    # 19. Publication/data exposure scan
    print("19. Scanning published data and attachments...")
    publication_findings = scan_publication(repo)
    publication_results = [
        {
            "source": "publication",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "record_id": f.record_id,
        }
        for f in publication_findings
    ]
    all_findings.extend(publication_results)
    print(f"   Found {len(publication_results)} issues")

    # 20. Secrets/config scan
    print("20. Scanning secrets and committed config...")
    secret_findings = scan_secrets(repo)
    secret_results = [
        {
            "source": "secrets",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "secret_kind": f.secret_kind,
            "redacted": f.redacted,
        }
        for f in secret_findings
    ]
    all_findings.extend(secret_results)
    print(f"   Found {len(secret_results)} issues")

    # 21. Deployment posture scan
    print("21. Scanning deployment posture...")
    deployment_findings = scan_deployment_config(repo)
    deployment_results = [
        {
            "source": "deployment",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "key": f.key,
            "value": f.value,
        }
        for f in deployment_findings
    ]
    all_findings.extend(deployment_results)
    print(f"   Found {len(deployment_results)} issues")

    # 22. Runtime ir.config_parameter scan
    print("22. Scanning runtime config parameter access...")
    config_param_findings = scan_config_parameters(repo)
    config_param_results = [
        {
            "source": "config-parameters",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "key": f.key,
            "sink": f.sink,
        }
        for f in config_param_findings
    ]
    all_findings.extend(config_param_results)
    print(f"   Found {len(config_param_results)} issues")

    # 23. ORM context override scan
    print("23. Scanning ORM context overrides...")
    context_findings = scan_orm_context(repo)
    context_results = [
        {
            "source": "orm-context",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
            "flag": f.flag,
        }
        for f in context_findings
    ]
    all_findings.extend(context_results)
    print(f"   Found {len(context_results)} issues")

    # 24. Runtime ORM domain construction scan
    print("24. Scanning runtime ORM domain construction...")
    domain_findings = scan_orm_domains(repo)
    domain_results = [
        {
            "source": "orm-domains",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
        }
        for f in domain_findings
    ]
    all_findings.extend(domain_results)
    print(f"   Found {len(domain_results)} issues")

    # 25. Runtime raw SQL scan
    print("25. Scanning runtime raw SQL usage...")
    raw_sql_findings = scan_raw_sql(repo)
    raw_sql_results = [
        {
            "source": "raw-sql",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
        }
        for f in raw_sql_findings
    ]
    all_findings.extend(raw_sql_results)
    print(f"   Found {len(raw_sql_results)} issues")

    # 26. Inbound mail alias scan
    print("26. Scanning inbound mail aliases...")
    alias_findings = scan_mail_aliases(repo)
    alias_results = [
        {
            "source": "mail-aliases",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "alias": f.alias,
            "model": f.model,
        }
        for f in alias_findings
    ]
    all_findings.extend(alias_results)
    print(f"   Found {len(alias_results)} issues")

    # 27. Mail template exposure scan
    print("27. Scanning mail templates...")
    mail_findings = scan_mail_templates(repo)
    mail_results = [
        {
            "source": "mail-templates",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "template": f.template,
            "field": f.field,
        }
        for f in mail_findings
    ]
    all_findings.extend(mail_results)
    print(f"   Found {len(mail_results)} issues")

    # 28. Python mail/chatter scan
    print("28. Scanning Python mail/chatter usage...")
    chatter_findings = scan_mail_chatter(repo)
    chatter_results = [
        {
            "source": "mail-chatter",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
        }
        for f in chatter_findings
    ]
    all_findings.extend(chatter_results)
    print(f"   Found {len(chatter_results)} issues")

    # 29. Report action exposure scan
    print("29. Scanning report actions...")
    report_findings = scan_reports(repo)
    report_results = [
        {
            "source": "reports",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "report": f.report,
        }
        for f in report_findings
    ]
    all_findings.extend(report_results)
    print(f"   Found {len(report_results)} issues")

    # 30. UI exposure scan
    print("30. Scanning XML UI exposure...")
    ui_findings = scan_ui_exposure(repo)
    ui_results = [
        {
            "source": "ui-exposure",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "element": f.element,
            "target": f.target,
        }
        for f in ui_findings
    ]
    all_findings.extend(ui_results)
    print(f"   Found {len(ui_results)} issues")

    # 31. XML inherited view modification scan
    print("31. Scanning inherited view modifications...")
    view_inherit_findings = scan_view_inheritance(repo)
    view_inherit_results = [
        {
            "source": "view-inheritance",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "element": f.element,
            "target": f.target,
        }
        for f in view_inherit_findings
    ]
    all_findings.extend(view_inherit_results)
    print(f"   Found {len(view_inherit_results)} issues")

    # 32. XML domain/context scan
    print("32. Scanning XML domains and contexts...")
    view_domain_findings = scan_view_domains(repo)
    view_domain_results = [
        {
            "source": "view-domains",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "element": f.element,
            "attribute": f.attribute,
        }
        for f in view_domain_findings
    ]
    all_findings.extend(view_domain_results)
    print(f"   Found {len(view_domain_results)} issues")

    # 33. Frontend/static asset scan
    print("33. Scanning frontend/static assets...")
    web_findings = scan_web_assets(repo)
    web_results = [
        {
            "source": "web-assets",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
        }
        for f in web_findings
    ]
    all_findings.extend(web_results)
    print(f"   Found {len(web_results)} issues")

    # 34. Website form scan
    print("34. Scanning website forms...")
    website_form_findings = scan_website_forms(repo)
    website_form_results = [
        {
            "source": "website-forms",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "field": f.field,
        }
        for f in website_form_findings
    ]
    all_findings.extend(website_form_results)
    print(f"   Found {len(website_form_results)} issues")

    # 35. Binary/download response scan
    print("35. Scanning binary/download responses...")
    binary_findings = scan_binary_downloads(repo)
    binary_results = [
        {
            "source": "binary-downloads",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
        }
        for f in binary_findings
    ]
    all_findings.extend(binary_results)
    print(f"   Found {len(binary_results)} issues")

    # 36. Controller response scan
    print("36. Scanning controller responses...")
    response_findings = scan_controller_responses(repo)
    response_results = [
        {
            "source": "controller-responses",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
        }
        for f in response_findings
    ]
    all_findings.extend(response_results)
    print(f"   Found {len(response_results)} issues")

    # 36a. Controller cache-control/header posture scan
    print("36a. Scanning controller cache-control posture...")
    cache_findings = scan_cache_headers(repo)
    cache_results = [
        {
            "source": "cache-headers",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "route": f.route,
            "sink": f.sink,
        }
        for f in cache_findings
    ]
    all_findings.extend(cache_results)
    print(f"   Found {len(cache_results)} issues")

    # 37. Portal route scan
    print("37. Scanning portal routes...")
    portal_findings = scan_portal_routes(repo)
    portal_results = [
        {
            "source": "portal-routes",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "route": f.route,
            "sink": f.sink,
        }
        for f in portal_findings
    ]
    all_findings.extend(portal_results)
    print(f"   Found {len(portal_results)} issues")

    # 38. Route decorator security scan
    print("38. Scanning route decorator security...")
    route_security_findings = scan_route_security(repo)
    route_security_results = [
        {
            "source": "route-security",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "route": f.route,
            "attribute": f.attribute,
        }
        for f in route_security_findings
    ]
    all_findings.extend(route_security_results)
    print(f"   Found {len(route_security_results)} issues")

    # 39. JSON route scan
    print("39. Scanning JSON routes...")
    json_route_findings = scan_json_routes(repo)
    json_route_results = [
        {
            "source": "json-routes",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "route": f.route,
            "sink": f.sink,
        }
        for f in json_route_findings
    ]
    all_findings.extend(json_route_results)
    print(f"   Found {len(json_route_results)} issues")

    # 40. Session/authentication scan
    print("40. Scanning session and authentication handling...")
    session_findings = scan_session_auth(repo)
    session_results = [
        {
            "source": "session-auth",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
        }
        for f in session_findings
    ]
    all_findings.extend(session_results)
    print(f"   Found {len(session_results)} issues")

    # 40a. Runtime OAuth/OIDC callback and token validation scan
    print("40a. Scanning OAuth/OIDC callback and token validation flows...")
    oauth_findings = scan_oauth_flows(repo)
    oauth_results = [
        {
            "source": "oauth-flows",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "route": f.route,
            "sink": f.sink,
        }
        for f in oauth_findings
    ]
    all_findings.extend(oauth_results)
    print(f"   Found {len(oauth_results)} issues")

    # 40b. Runtime signup/reset token lifecycle scan
    print("40b. Scanning signup/reset token lifecycle flows...")
    signup_token_findings = scan_signup_tokens(repo)
    signup_token_results = [
        {
            "source": "signup-tokens",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "route": f.route,
            "sink": f.sink,
        }
        for f in signup_token_findings
    ]
    all_findings.extend(signup_token_results)
    print(f"   Found {len(signup_token_results)} issues")

    # 41. Realtime bus/notification scan
    print("41. Scanning realtime bus and notifications...")
    realtime_findings = scan_realtime(repo)
    realtime_results = [
        {
            "source": "realtime",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
        }
        for f in realtime_findings
    ]
    all_findings.extend(realtime_results)
    print(f"   Found {len(realtime_results)} issues")

    # 42. Automated action scan
    print("42. Scanning automated actions...")
    automation_findings = scan_automations(repo)
    automation_results = [
        {
            "source": "automations",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "record_id": f.record_id,
        }
        for f in automation_findings
    ]
    all_findings.extend(automation_results)
    print(f"   Found {len(automation_results)} issues")

    # 43. Executable XML data scan
    print("43. Scanning executable XML data records...")
    xml_data_findings = scan_xml_data(repo)
    xml_data_results = [
        {
            "source": "xml-data",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "record_id": f.record_id,
        }
        for f in xml_data_findings
    ]
    all_findings.extend(xml_data_results)
    print(f"   Found {len(xml_data_results)} issues")

    # 44. Scheduled job Python scan
    print("44. Scanning scheduled job Python methods...")
    scheduled_findings = scan_scheduled_jobs(repo)
    scheduled_results = [
        {
            "source": "scheduled-jobs",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "job": f.job,
            "sink": f.sink,
        }
        for f in scheduled_findings
    ]
    all_findings.extend(scheduled_results)
    print(f"   Found {len(scheduled_results)} issues")

    # 45. File upload/filesystem scan
    print("45. Scanning file upload and filesystem handling...")
    file_findings = scan_file_uploads(repo)
    file_results = [
        {
            "source": "file-uploads",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
        }
        for f in file_findings
    ]
    all_findings.extend(file_results)
    print(f"   Found {len(file_results)} issues")

    # 46. CSV/XLSX export scan
    print("46. Scanning CSV/XLSX exports...")
    export_findings = scan_exports(repo)
    export_results = [
        {
            "source": "exports",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
        }
        for f in export_findings
    ]
    all_findings.extend(export_results)
    print(f"   Found {len(export_results)} issues")

    # 47. Payment/webhook handler scan
    print("47. Scanning payment and webhook handlers...")
    payment_findings = scan_payments(repo)
    payment_results = [
        {
            "source": "payments",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "handler": f.handler,
        }
        for f in payment_findings
    ]
    all_findings.extend(payment_results)
    print(f"   Found {len(payment_results)} issues")

    # 48. Unsafe deserialization/parser scan
    print("48. Scanning unsafe deserialization and parsers...")
    serialization_findings = scan_serialization(repo)
    serialization_results = [
        {
            "source": "serialization",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
        }
        for f in serialization_findings
    ]
    all_findings.extend(serialization_results)
    print(f"   Found {len(serialization_results)} issues")

    # 49. Queue/delayed job scan
    print("49. Scanning queue/delayed jobs...")
    queue_findings = scan_queue_jobs(repo)
    queue_results = [
        {
            "source": "queue-jobs",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "job": f.job,
        }
        for f in queue_findings
    ]
    all_findings.extend(queue_results)
    print(f"   Found {len(queue_results)} issues")

    # 50. Translation catalog scan
    print("50. Scanning translation catalogs...")
    translation_findings = scan_translations(repo)
    translation_results = [
        {
            "source": "translations",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "msgid": f.msgid,
            "locale": f.locale,
        }
        for f in translation_findings
    ]
    all_findings.extend(translation_results)
    print(f"   Found {len(translation_results)} issues")

    # 51. Outbound integration scan
    print("51. Scanning outbound integrations...")
    integration_findings = scan_integrations(repo)
    integration_results = [
        {
            "source": "integrations",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
        }
        for f in integration_findings
    ]
    all_findings.extend(integration_results)
    print(f"   Found {len(integration_results)} issues")

    # 52. Loose Python/server action scan
    print("52. Scanning loose Python/server actions...")
    loose_findings = scan_loose_python(repo)
    loose_results = [
        {
            "source": "loose-python",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "context": f.context,
        }
        for f in loose_findings
    ]
    all_findings.extend(loose_results)
    print(f"   Found {len(loose_results)} issues")

    # 53. User/group identity mutation scan
    print("53. Scanning user and group identity mutations...")
    identity_findings = scan_identity_mutations(repo)
    identity_results = [
        {
            "source": "identity-mutations",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "route": f.route,
            "sink": f.sink,
        }
        for f in identity_findings
    ]
    all_findings.extend(identity_results)
    print(f"   Found {len(identity_results)} issues")

    # 54. ir.default persistent default scan
    print("54. Scanning persisted ir.default values...")
    default_findings = scan_default_values(repo)
    default_results = [
        {
            "source": "default-values",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "field": f.field,
            "sink": f.sink,
            "record_id": f.record_id,
        }
        for f in default_findings
    ]
    all_findings.extend(default_results)
    print(f"   Found {len(default_results)} issues")

    # 55. ir.sequence declaration/runtime scan
    print("55. Scanning ir.sequence declarations and usage...")
    sequence_findings = scan_sequences(repo)
    sequence_results = [
        {
            "source": "sequences",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "code": f.code,
            "route": f.route,
            "sink": f.sink,
            "record_id": f.record_id,
        }
        for f in sequence_findings
    ]
    all_findings.extend(sequence_results)
    print(f"   Found {len(sequence_results)} issues")

    # 56. URL action scan
    print("56. Scanning URL actions...")
    action_url_findings = scan_action_urls(repo)
    action_url_results = [
        {
            "source": "action-urls",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "url": f.url,
            "route": f.route,
            "sink": f.sink,
            "record_id": f.record_id,
        }
        for f in action_url_findings
    ]
    all_findings.extend(action_url_results)
    print(f"   Found {len(action_url_results)} issues")

    # 57. API key handling scan
    print("57. Scanning API key handling...")
    api_key_findings = scan_api_keys(repo)
    api_key_results = [
        {
            "source": "api-keys",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "route": f.route,
            "sink": f.sink,
            "record_id": f.record_id,
        }
        for f in api_key_findings
    ]
    all_findings.extend(api_key_results)
    print(f"   Found {len(api_key_results)} issues")

    # 58. Runtime module lifecycle scan
    print("58. Scanning runtime module lifecycle operations...")
    module_lifecycle_findings = scan_module_lifecycle(repo)
    module_lifecycle_results = [
        {
            "source": "module-lifecycle",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "route": f.route,
            "sink": f.sink,
        }
        for f in module_lifecycle_findings
    ]
    all_findings.extend(module_lifecycle_results)
    print(f"   Found {len(module_lifecycle_results)} issues")

    # 59. Database operation route scan
    print("59. Scanning database operation routes...")
    database_findings = scan_database_operations(repo)
    database_results = [
        {
            "source": "database-operations",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "route": f.route,
            "sink": f.sink,
        }
        for f in database_findings
    ]
    all_findings.extend(database_results)
    print(f"   Found {len(database_results)} issues")

    # 60. Attachment metadata/mutation scan
    print("60. Scanning attachment metadata and mutations...")
    attachment_findings = scan_attachments(repo)
    attachment_results = [
        {
            "source": "attachments",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "route": f.route,
            "sink": f.sink,
        }
        for f in attachment_findings
    ]
    all_findings.extend(attachment_results)
    print(f"   Found {len(attachment_results)} issues")

    # 61. Python action window scan
    print("61. Scanning Python action windows...")
    action_window_findings = scan_action_windows(repo)
    action_window_results = [
        {
            "source": "action-windows",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "route": f.route,
            "sink": f.sink,
            "flag": f.flag,
        }
        for f in action_window_findings
    ]
    all_findings.extend(action_window_results)
    print(f"   Found {len(action_window_results)} issues")

    all_findings = normalize_findings(all_findings)
    accepted_risks = load_deep_scan_accepted_risks(repo, args.accepted_risks)
    accepted_risk_report = apply_accepted_risks(repo, all_findings, accepted_risks)
    all_findings = accepted_risk_report["findings"]
    fix_list = load_deep_scan_fix_list(repo, args.fix_list)
    fix_list_report = apply_fix_list(repo, all_findings, fix_list)
    all_findings = fix_list_report["findings"]
    schema_report = validation_report(all_findings)
    coverage_report = build_surface_coverage(repo, all_findings)
    coverage_report["accepted_risks"] = accepted_risk_report["summary"]
    coverage_report["fix_list"] = fix_list_report["summary"]
    governance_gate = build_governance_gate(
        accepted_risk_report["summary"],
        fix_list_report["summary"],
        fail_on_policy_errors=args.fail_on_policy_errors,
        fail_on_expired_accepted_risk=args.fail_on_expired_accepted_risk,
        fail_on_overdue_fix=args.fail_on_overdue_fix,
        fail_on_fix_regression=args.fail_on_fix_regression,
    )
    coverage_report["governance_gate"] = governance_gate
    review_gate = build_review_gate(all_findings, fail_on=args.fail_on)
    coverage_report["review_gate"] = review_gate
    taxonomy_gate = build_taxonomy_gate(
        coverage_report["taxonomy_coverage"],
        fail_on_unmapped=args.fail_on_unmapped_taxonomy,
    )
    coverage_report["taxonomy_gate"] = taxonomy_gate
    baseline_report: dict[str, object] | None = None
    baseline_gate: dict[str, object] | None = None
    if args.baseline:
        try:
            baseline_findings = load_baseline_findings(Path(args.baseline).expanduser())
        except (FileNotFoundError, ValueError) as exc:
            print(f"Baseline error: {exc}", file=sys.stderr)
            return 1
        baseline_report = build_baseline_delta(baseline_findings, all_findings)
        baseline_gate = build_baseline_gate(baseline_report, fail_on_new=args.fail_on_new)
        coverage_report["baseline_delta"] = baseline_report
        coverage_report["baseline_gate"] = baseline_gate

    # Write findings
    findings_file = out / "deep-scan-findings.json"
    findings_file.write_text(json.dumps(all_findings, indent=2), encoding="utf-8")
    print(f"\nWrote {len(all_findings)} total findings to {findings_file}")

    validation_file = out / "deep-scan-validation.json"
    validation_file.write_text(json.dumps(schema_report, indent=2), encoding="utf-8")
    print(f"Wrote validation report to {validation_file}")

    review_gate_file = out / "review-gate.json"
    review_gate_file.write_text(json.dumps(review_gate, indent=2), encoding="utf-8")
    print(f"Wrote review gate report to {review_gate_file}")

    taxonomy_gate_file = out / "taxonomy-gate.json"
    taxonomy_gate_file.write_text(json.dumps(taxonomy_gate, indent=2), encoding="utf-8")
    print(f"Wrote taxonomy gate report to {taxonomy_gate_file}")

    governance_gate_file = out / "governance-gate.json"
    governance_gate_file.write_text(json.dumps(governance_gate, indent=2), encoding="utf-8")
    print(f"Wrote governance gate report to {governance_gate_file}")

    baseline_delta_file = out / "deep-scan-delta.json"
    baseline_delta_markdown_file = out / "deep-scan-delta.md"
    if baseline_report is not None and baseline_gate is not None:
        baseline_delta_file.write_text(json.dumps(baseline_report, indent=2), encoding="utf-8")
        baseline_delta_markdown_file.write_text(
            generate_baseline_delta_report(baseline_report, baseline_gate),
            encoding="utf-8",
        )
        print(f"Wrote baseline delta to {baseline_delta_file}")
        print(f"Wrote baseline delta summary to {baseline_delta_markdown_file}")

    accepted_risks_file = out / "inventory" / "accepted-risks.json"
    accepted_risks_file.parent.mkdir(parents=True, exist_ok=True)
    accepted_risks_file.write_text(json.dumps(accepted_risk_report["inventory"], indent=2), encoding="utf-8")
    accepted_risks_markdown_file = out / "00-accepted-risks.md"
    accepted_risks_markdown_file.write_text(generate_accepted_risks_report(accepted_risk_report), encoding="utf-8")
    print(f"Wrote accepted-risk inventory to {accepted_risks_file}")
    print(f"Wrote accepted-risk report to {accepted_risks_markdown_file}")

    fix_list_file = out / "inventory" / "fix-list.json"
    fix_list_file.write_text(json.dumps(fix_list_report["inventory"], indent=2), encoding="utf-8")
    fix_list_markdown_file = out / "00-fix-list.md"
    fix_list_markdown_file.write_text(generate_fix_list_report(fix_list_report), encoding="utf-8")
    print(f"Wrote fix-list inventory to {fix_list_file}")
    print(f"Wrote fix-list report to {fix_list_markdown_file}")

    coverage_file = out / "inventory" / "coverage" / "matcher-coverage.json"
    coverage_file.parent.mkdir(parents=True, exist_ok=True)
    coverage_file.write_text(json.dumps(coverage_report, indent=2), encoding="utf-8")
    print(f"Wrote surface coverage report to {coverage_file}")

    rule_catalog = coverage_report["rule_catalog"]
    rule_catalog_file = out / "inventory" / "coverage" / "rule-catalog.json"
    rule_catalog_file.write_text(json.dumps(rule_catalog, indent=2), encoding="utf-8")
    print(f"Wrote rule catalog to {rule_catalog_file}")

    taxonomy_coverage = coverage_report["taxonomy_coverage"]
    taxonomy_coverage_file = out / "inventory" / "coverage" / "taxonomy-coverage.json"
    taxonomy_coverage_file.write_text(json.dumps(taxonomy_coverage, indent=2), encoding="utf-8")
    print(f"Wrote taxonomy coverage to {taxonomy_coverage_file}")

    module_risk_file = out / "inventory" / "module-risk.json"
    module_risk_file.parent.mkdir(parents=True, exist_ok=True)
    module_risk_file.write_text(json.dumps(coverage_report["module_risk"], indent=2), encoding="utf-8")
    print(f"Wrote module risk inventory to {module_risk_file}")

    module_risk_markdown_file = out / "module-risk.md"
    module_risk_markdown_file.write_text(generate_module_risk_report(coverage_report["module_risk"]), encoding="utf-8")
    print(f"Wrote module risk summary to {module_risk_markdown_file}")

    scanner_manifest = coverage_report["scanner_registry"]["manifest_entries"]
    manifest_file = out / "inventory" / "coverage" / "scanner-manifest.json"
    manifest_report = {
        "total_entries": len(scanner_manifest),
        "entries": scanner_manifest,
        "callables_without_source": coverage_report["scanner_registry"]["callables_without_source"],
        "sources_without_callable": coverage_report["scanner_registry"]["sources_without_callable"],
    }
    manifest_file.write_text(json.dumps(manifest_report, indent=2), encoding="utf-8")
    print(f"Wrote scanner manifest to {manifest_file}")

    tooling_file = out / "tooling.md"
    tooling_file.write_text(generate_tooling_report(coverage_report), encoding="utf-8")
    print(f"Wrote tooling coverage summary to {tooling_file}")

    # Generate Markdown report
    report_file = out / "deep-scan-report.md"
    report = generate_report(all_findings)
    report_file.write_text(report, encoding="utf-8")
    print(f"Wrote report to {report_file}")

    html_report_file = out / "findings.html"
    html_report_file.write_text(generate_html_report(all_findings, coverage_report), encoding="utf-8")
    print(f"Wrote HTML triage report to {html_report_file}")

    sarif_file = out / "deep-scan.sarif"
    sarif_report = generate_sarif_report(repo, all_findings)
    sarif_file.write_text(json.dumps(sarif_report, indent=2), encoding="utf-8")
    print(f"Wrote SARIF report to {sarif_file}")

    # Generate PoCs if requested
    generated_pocs: list[Path] = []
    if args.pocs:
        print("\nGenerating PoC scripts...")
        pocs_dir = out / "pocs"
        generated_pocs = generate_pocs(all_findings, pocs_dir, base_url=args.base_url, database=args.database)
        poc_report = poc_coverage_report(all_findings, base_url=args.base_url, database=args.database)
        poc_report["generated_files"] = sorted(str(path.relative_to(out)) for path in generated_pocs)
        coverage_report["poc_coverage"] = poc_report
        coverage_file.write_text(json.dumps(coverage_report, indent=2), encoding="utf-8")
        poc_coverage_file = out / "inventory" / "coverage" / "poc-coverage.json"
        poc_coverage_file.write_text(json.dumps(poc_report, indent=2), encoding="utf-8")
        tooling_file.write_text(generate_tooling_report(coverage_report), encoding="utf-8")
        print(f"Generated {len(generated_pocs)} PoC scripts in {pocs_dir}")
        print(f"Wrote PoC coverage report to {poc_coverage_file}")

    artifact_manifest_file = out / "inventory" / "artifacts.json"
    artifact_specs = [
        {
            "path": findings_file,
            "kind": "json",
            "required": True,
            "description": "Normalized deep-scan findings",
            "count": len(all_findings),
        },
        {
            "path": validation_file,
            "kind": "json",
            "required": True,
            "description": "Finding schema validation report",
            "count": schema_report.get("issue_count", 0),
        },
        {
            "path": review_gate_file,
            "kind": "json",
            "required": True,
            "description": "CI review gate verdict and blocking findings",
            "count": review_gate["blocking_findings"],
        },
        {
            "path": taxonomy_gate_file,
            "kind": "json",
            "required": True,
            "description": "CI taxonomy drift gate for unmapped emitted rule IDs",
            "count": taxonomy_gate["blocking_rules"],
        },
        {
            "path": governance_gate_file,
            "kind": "json",
            "required": True,
            "description": "CI governance gate for accepted-risk and fix-list policy rot",
            "count": governance_gate["blocking_conditions"],
        },
        {
            "path": baseline_delta_file,
            "kind": "json",
            "required": False,
            "description": "Fingerprint delta against a baseline findings file",
            "count": len(baseline_report["new"]) if baseline_report else 0,
        },
        {
            "path": baseline_delta_markdown_file,
            "kind": "markdown",
            "required": False,
            "description": "Human-readable fingerprint delta against baseline",
        },
        {
            "path": accepted_risks_file,
            "kind": "json",
            "required": True,
            "description": "Accepted-risk suppression inventory and run matches",
            "count": accepted_risk_report["summary"]["suppressed_findings"],
        },
        {
            "path": accepted_risks_markdown_file,
            "kind": "markdown",
            "required": True,
            "description": "Human-readable accepted-risk suppression report",
        },
        {
            "path": fix_list_file,
            "kind": "json",
            "required": True,
            "description": "Fix-list tracking inventory and reconciliation buckets",
            "count": fix_list_report["summary"]["tracked_findings"] + fix_list_report["summary"]["regressions"],
        },
        {
            "path": fix_list_markdown_file,
            "kind": "markdown",
            "required": True,
            "description": "Human-readable fix-list tracking report",
        },
        {
            "path": coverage_file,
            "kind": "json",
            "required": True,
            "description": "Surface, scanner, rule, and prioritization coverage",
            "count": len(coverage_report.get("surfaces", {})),
        },
        {
            "path": rule_catalog_file,
            "kind": "json",
            "required": True,
            "description": "Declared rule IDs discovered from scanner source",
            "count": rule_catalog.get("total_rules", 0),
        },
        {
            "path": taxonomy_coverage_file,
            "kind": "json",
            "required": True,
            "description": "CWE/CAPEC/OWASP taxonomy coverage for emitted rules",
            "count": taxonomy_coverage.get("mapped_rules", 0),
        },
        {
            "path": module_risk_file,
            "kind": "json",
            "required": True,
            "description": "Per-module finding and route risk ranking",
            "count": coverage_report["module_risk"].get("total_modules", 0),
        },
        {
            "path": module_risk_markdown_file,
            "kind": "markdown",
            "required": True,
            "description": "Human-readable module risk report",
        },
        {
            "path": manifest_file,
            "kind": "json",
            "required": True,
            "description": "Scanner callable to source-label manifest",
            "count": manifest_report.get("total_entries", 0),
        },
        {
            "path": report_file,
            "kind": "markdown",
            "required": True,
            "description": "Human-readable deep-scan findings report",
            "count": len(all_findings),
        },
        {
            "path": html_report_file,
            "kind": "html",
            "required": True,
            "description": "Self-contained HTML findings report with accepted-risk and fix-list triage queues",
            "count": len(all_findings),
        },
        {
            "path": sarif_file,
            "kind": "sarif",
            "required": True,
            "description": "SARIF report for code review and code scanning integrations",
            "count": len(all_findings),
        },
        {
            "path": tooling_file,
            "kind": "markdown",
            "required": True,
            "description": "Human-readable tooling coverage summary",
        },
        {
            "path": out / "inventory" / "coverage" / "poc-coverage.json",
            "kind": "json",
            "required": False,
            "description": "PoC generator coverage report",
            "count": len(generated_pocs),
        },
        {
            "path": out / "pocs",
            "kind": "directory",
            "required": False,
            "description": "Generated PoC scripts",
            "count": len(generated_pocs),
        },
        {
            "path": artifact_manifest_file,
            "kind": "json",
            "required": True,
            "description": "Inventory of deep-scan output artifacts",
        },
    ]
    tooling_context = {
        **coverage_report,
        "artifact_manifest": {
            "path": str(artifact_manifest_file.relative_to(out)),
            "total_artifacts": len(artifact_specs),
        },
    }
    tooling_file.write_text(generate_tooling_report(tooling_context), encoding="utf-8")
    write_artifact_manifest(out, artifact_manifest_file, artifact_specs)
    print(f"Wrote artifact manifest to {artifact_manifest_file}")

    # Summary
    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\n" + "=" * 50)
    print("Summary:")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"  {sev.upper():.<10} {count:>3}")
    print("=" * 50)

    if not review_gate["passed"]:
        print(f"Review gate failed: {review_gate['blocking_findings']} findings at or above {args.fail_on}.")
        return 2

    if not taxonomy_gate["passed"]:
        print(f"Taxonomy gate failed: {taxonomy_gate['blocking_rules']} emitted rule IDs lack taxonomy mapping.")
        return 2

    if not governance_gate["passed"]:
        print(f"Governance gate failed: {governance_gate['blocking_conditions']} policy conditions are blocking.")
        return 2

    if baseline_gate is not None and not baseline_gate["passed"]:
        print(
            f"Baseline gate failed: {baseline_gate['blocking_new_findings']} new findings at or above {args.fail_on_new}."
        )
        return 2

    return 0


def run_policy_check_only(repo: Path, out: Path, args: argparse.Namespace) -> int | None:
    """Validate accepted-risk/fix-list policy files without running scanners."""
    check_accepted = bool(getattr(args, "check_only_accepted_risks", False))
    check_fix_list = bool(getattr(args, "check_only_fix_list", False))
    if not check_accepted and not check_fix_list:
        return None

    failed = False
    if check_accepted:
        accepted_inventory = load_deep_scan_accepted_risks(repo, getattr(args, "accepted_risks", None))
        accepted_report = apply_accepted_risks(repo, [], accepted_inventory)
        _write_accepted_risk_outputs(out, accepted_report)
        accepted_summary = accepted_report["summary"]
        failed = failed or bool(accepted_summary["errors"]) or bool(accepted_summary["expired_entries"])
        if accepted_summary["errors"]:
            print(f"Accepted-risk policy check failed: {accepted_summary['errors']} loader/validation errors.")
        if accepted_summary["expired_entries"]:
            print(f"Accepted-risk policy check failed: {accepted_summary['expired_entries']} expired entries.")

    if check_fix_list:
        fix_inventory = load_deep_scan_fix_list(repo, getattr(args, "fix_list", None))
        fix_report = apply_fix_list(repo, [], fix_inventory)
        overdue_entries = _policy_overdue_fix_entries(fix_inventory)
        fix_report["inventory"]["policy_overdue"] = overdue_entries
        fix_report["summary"]["policy_overdue_entries"] = len(overdue_entries)
        _write_fix_list_outputs(out, fix_report)
        fix_summary = fix_report["summary"]
        failed = failed or bool(fix_summary["errors"]) or bool(fix_summary["policy_overdue_entries"])
        if fix_summary["errors"]:
            print(f"Fix-list policy check failed: {fix_summary['errors']} loader/validation errors.")
        if fix_summary["policy_overdue_entries"]:
            print(f"Fix-list policy check failed: {fix_summary['policy_overdue_entries']} overdue entries.")

    return 2 if failed else 0


def _write_accepted_risk_outputs(out: Path, report: dict[str, object]) -> None:
    accepted_risks_file = out / "inventory" / "accepted-risks.json"
    accepted_risks_file.parent.mkdir(parents=True, exist_ok=True)
    accepted_risks_file.write_text(json.dumps(report["inventory"], indent=2), encoding="utf-8")
    accepted_risks_markdown_file = out / "00-accepted-risks.md"
    accepted_risks_markdown_file.write_text(generate_accepted_risks_report(report), encoding="utf-8")
    print(f"Wrote accepted-risk inventory to {accepted_risks_file}")
    print(f"Wrote accepted-risk report to {accepted_risks_markdown_file}")


def _write_fix_list_outputs(out: Path, report: dict[str, object]) -> None:
    fix_list_file = out / "inventory" / "fix-list.json"
    fix_list_file.parent.mkdir(parents=True, exist_ok=True)
    fix_list_file.write_text(json.dumps(report["inventory"], indent=2), encoding="utf-8")
    fix_list_markdown_file = out / "00-fix-list.md"
    fix_list_markdown_file.write_text(generate_fix_list_report(report), encoding="utf-8")
    print(f"Wrote fix-list inventory to {fix_list_file}")
    print(f"Wrote fix-list report to {fix_list_markdown_file}")


def _policy_overdue_fix_entries(inventory: dict[str, object]) -> list[dict[str, object]]:
    today = date.today()
    overdue = []
    for entry in inventory.get("active", []):
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("status") or "open")
        target = entry.get("target_date")
        if status in {"open", "in-progress"} and target and date.fromisoformat(str(target)) < today:
            overdue.append(entry)
    return overdue


def build_surface_coverage(repo: Path, findings: list[dict]) -> dict:
    """Build coarse Odoo surface coverage metrics for the deep-scan run."""
    python_files = _repo_files(repo, {".py"})
    xml_files = _repo_files(repo, {".xml"})
    module_roots = _module_roots(repo)
    controller_files = _controller_files(python_files)
    routes = _route_inventory(repo, python_files)
    public_routes = [route for route in routes if route["auth"] in {"public", "none"}]

    finding_locations = _finding_locations(repo, findings)
    finding_files = {path for path, _line in finding_locations}
    finding_files.discard(None)

    def file_count(files: list[Path]) -> dict[str, int | float]:
        with_findings = sum(1 for path in files if path.resolve() in finding_files)
        return _surface_metric(len(files), with_findings)

    module_paths_with_findings = {
        module
        for module in module_roots
        if any(_is_relative_to(finding_file, module) for finding_file in finding_files if finding_file is not None)
    }
    for route in routes:
        route["has_findings"] = _route_has_findings(repo, route, finding_locations)
    public_routes_with_findings = [route for route in public_routes if route["has_findings"]]

    surfaces = {
        "python_files": file_count(python_files),
        "xml_files": file_count(xml_files),
        "controller_files": file_count(controller_files),
        "modules": _surface_metric(len(module_roots), len(module_paths_with_findings)),
        "public_routes": _surface_metric(len(public_routes), len(public_routes_with_findings)),
    }
    scanner_sources = _source_coverage(findings)
    scanner_registry = _scanner_registry_coverage()
    rule_catalog = _rule_catalog_coverage(findings)
    taxonomy_coverage = _taxonomy_coverage(findings)
    finding_summary = _finding_summary(findings)
    module_risk = _module_risk(repo, module_roots, routes, findings)
    warnings = _coverage_warnings(surfaces)
    warnings.extend(_source_warnings(scanner_sources))
    warnings.extend(_registry_warnings(scanner_registry))
    warnings.extend(_rule_catalog_warnings(rule_catalog))
    warnings.extend(_taxonomy_warnings(taxonomy_coverage))

    return {
        "schema_version": 1,
        "repo": str(repo),
        "surfaces": surfaces,
        "scanner_sources": scanner_sources,
        "scanner_registry": scanner_registry,
        "rule_catalog": rule_catalog,
        "taxonomy_coverage": taxonomy_coverage,
        "finding_summary": finding_summary,
        "module_risk": module_risk,
        "routes": {
            "total": len(routes),
            "public_or_none": len(public_routes),
            "public_or_none_with_findings": len(public_routes_with_findings),
            "entries": routes,
        },
        "warnings": warnings,
    }


def build_review_gate(findings: list[dict], fail_on: str = "none") -> dict[str, object]:
    """Build a CI-friendly gate summary for normalized findings."""
    severity_counts: Counter[str] = Counter(_normalized_severity(finding.get("severity")) for finding in findings)
    threshold_rank = _SEVERITY_RANK.get(fail_on)
    blocking = []
    if threshold_rank is not None:
        blocking = [
            {
                "id": finding.get("id"),
                "rule_id": finding.get("rule_id"),
                "severity": _normalized_severity(finding.get("severity")),
                "source": finding.get("source"),
                "file": finding.get("file"),
                "line": finding.get("line"),
                "title": finding.get("title"),
                "fingerprint": finding.get("fingerprint"),
            }
            for finding in findings
            if _SEVERITY_RANK[_normalized_severity(finding.get("severity"))] <= threshold_rank
        ]
    blocking.sort(
        key=lambda finding: (
            _SEVERITY_RANK[_normalized_severity(finding.get("severity"))],
            str(finding.get("rule_id") or ""),
            str(finding.get("file") or ""),
            int(finding.get("line") or 0),
        )
    )
    return {
        "fail_on": fail_on,
        "passed": not blocking,
        "total_findings": len(findings),
        "blocking_findings": len(blocking),
        "severity_counts": {severity: severity_counts.get(severity, 0) for severity in _SEVERITY_ORDER},
        "blocking_severity_counts": {
            severity: sum(1 for finding in blocking if finding["severity"] == severity) for severity in _SEVERITY_ORDER
        },
        "blocking": blocking[:100],
        "truncated": len(blocking) > 100,
    }


def load_baseline_findings(path: Path) -> list[dict]:
    """Load baseline findings from a JSON file or audit output directory."""
    candidates = [path]
    if path.is_dir():
        candidates = [
            path / "deep-scan-findings.json",
            path / "findings.json",
        ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        payload = json.loads(candidate.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            findings = payload.get("findings")
            if isinstance(findings, list):
                return findings
        raise ValueError(f"baseline must be a findings list or object with findings[]: {candidate}")
    if path.is_dir():
        raise FileNotFoundError(f"no deep-scan-findings.json or findings.json found in {path}")
    raise FileNotFoundError(str(path))


def build_baseline_delta(baseline_findings: list[dict], current_findings: list[dict]) -> dict[str, object]:
    """Classify current findings against a baseline by stable fingerprint."""
    baseline_index = _findings_by_fingerprint(baseline_findings)
    current_index = _findings_by_fingerprint(current_findings)
    new = []
    fixed = []
    unchanged = []
    changed = []

    for fingerprint, current in sorted(current_index.items()):
        baseline = baseline_index.get(fingerprint)
        if baseline is None:
            new.append(_baseline_finding_summary(current))
            continue
        severity_changed = _normalized_severity(baseline.get("severity")) != _normalized_severity(
            current.get("severity")
        )
        triage_changed = str(baseline.get("triage") or "") != str(current.get("triage") or "")
        if severity_changed or triage_changed:
            changed.append(
                {
                    "fingerprint": fingerprint,
                    "current": _baseline_finding_summary(current),
                    "baseline": _baseline_finding_summary(baseline),
                    "severity_changed": severity_changed,
                    "triage_changed": triage_changed,
                }
            )
        else:
            unchanged.append(_baseline_finding_summary(current))

    for fingerprint, baseline in sorted(baseline_index.items()):
        if fingerprint not in current_index:
            fixed.append(_baseline_finding_summary(baseline))

    return {
        "baseline_findings": len(baseline_findings),
        "current_findings": len(current_findings),
        "new_count": len(new),
        "fixed_count": len(fixed),
        "changed_count": len(changed),
        "unchanged_count": len(unchanged),
        "new": new,
        "fixed": fixed,
        "changed": changed,
        "unchanged": unchanged[:100],
        "unchanged_truncated": len(unchanged) > 100,
    }


def build_baseline_gate(delta: dict[str, object], fail_on_new: str = "none") -> dict[str, object]:
    """Build a CI gate for new findings introduced since a baseline."""
    threshold_rank = _SEVERITY_RANK.get(fail_on_new)
    new_findings = delta.get("new", [])
    if not isinstance(new_findings, list):
        new_findings = []
    blocking = []
    if threshold_rank is not None:
        blocking = [
            finding
            for finding in new_findings
            if _SEVERITY_RANK[_normalized_severity(finding.get("severity"))] <= threshold_rank
        ]
    blocking.sort(
        key=lambda finding: (
            _SEVERITY_RANK[_normalized_severity(finding.get("severity"))],
            str(finding.get("rule_id") or ""),
            str(finding.get("file") or ""),
            int(finding.get("line") or 0),
        )
    )
    return {
        "fail_on_new": fail_on_new,
        "passed": not blocking,
        "new_findings": len(new_findings),
        "blocking_new_findings": len(blocking),
        "blocking_severity_counts": {
            severity: sum(1 for finding in blocking if _normalized_severity(finding.get("severity")) == severity)
            for severity in _SEVERITY_ORDER
        },
        "blocking": blocking[:100],
        "truncated": len(blocking) > 100,
    }


def _findings_by_fingerprint(findings: list[dict]) -> dict[str, dict]:
    indexed = {}
    for finding in findings:
        fingerprint = str(finding.get("fingerprint") or compute_fingerprint(finding))
        indexed[fingerprint] = finding
    return indexed


def load_deep_scan_accepted_risks(repo: Path, override: str | None = None) -> dict[str, object]:
    """Load accepted-risk policy for the standalone deep scanner."""
    candidates = (
        [Path(override).expanduser()]
        if override
        else [
            repo / ".audit-accepted-risks.yml",
            repo / ".audit-accepted-risks.yaml",
            repo / ".audit-accepted-risks.json",
        ]
    )
    chosen = next((path.resolve() for path in candidates if path.exists()), None)
    inventory: dict[str, object] = {
        "version": 1,
        "loaded_from": str(chosen) if chosen else None,
        "active": [],
        "expired": [],
        "errors": [],
    }
    if chosen is None:
        return inventory

    try:
        if chosen.suffix.lower() == ".json":
            data = json.loads(chosen.read_text(encoding="utf-8"))
        else:
            data = yaml.safe_load(chosen.read_text(encoding="utf-8")) or {}
    except (OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
        inventory["errors"] = [f"failed to load accepted-risks file {chosen}: {exc}"]
        return inventory

    entries, errors = _validated_accepted_risk_entries(data)
    today = date.today()
    active = []
    expired = []
    for entry in entries:
        expires = date.fromisoformat(str(entry["expires"]))
        normalized = {**entry, "days_remaining": (expires - today).days}
        if expires < today:
            expired.append(normalized)
        else:
            active.append(normalized)
    inventory["active"] = active
    inventory["expired"] = expired
    inventory["errors"] = errors
    return inventory


def apply_accepted_risks(repo: Path, findings: list[dict], inventory: dict[str, object]) -> dict[str, object]:
    """Suppress findings matching active accepted risks and annotate expired matches."""
    active = [entry for entry in inventory.get("active", []) if isinstance(entry, dict)]
    expired = [entry for entry in inventory.get("expired", []) if isinstance(entry, dict)]
    visible = []
    suppressed = []
    expired_matches = []

    for finding in findings:
        active_matches = [entry for entry in active if _accepted_risk_matches(repo, finding, entry)]
        if active_matches:
            winning = sorted(active_matches, key=lambda entry: str(entry.get("id") or ""))[-1]
            suppressed.append({"accepted_risk_id": winning.get("id"), "finding": _baseline_finding_summary(finding)})
            continue
        expired_match_ids = [str(entry.get("id")) for entry in expired if _accepted_risk_matches(repo, finding, entry)]
        if expired_match_ids:
            finding = dict(finding)
            finding["expired_accepted_risk_ids"] = expired_match_ids
            expired_matches.append(
                {"accepted_risk_ids": expired_match_ids, "finding": _baseline_finding_summary(finding)}
            )
        visible.append(finding)

    summary = {
        "loaded_from": inventory.get("loaded_from"),
        "active_entries": len(active),
        "expired_entries": len(expired),
        "errors": len(inventory.get("errors", [])),
        "input_findings": len(findings),
        "suppressed_findings": len(suppressed),
        "expired_matches": len(expired_matches),
        "output_findings": len(visible),
    }
    run_inventory = {**inventory, "suppressed": suppressed, "expired_matches": expired_matches, "summary": summary}
    return {"findings": visible, "inventory": run_inventory, "summary": summary}


def load_deep_scan_fix_list(repo: Path, override: str | None = None) -> dict[str, object]:
    """Load fix-list tracking policy for the standalone deep scanner."""
    candidates = (
        [Path(override).expanduser()]
        if override
        else [
            repo / ".audit-fix-list.yml",
            repo / ".audit-fix-list.yaml",
            repo / ".audit-fix-list.json",
        ]
    )
    chosen = next((path.resolve() for path in candidates if path.exists()), None)
    inventory: dict[str, object] = {
        "version": 1,
        "loaded_from": str(chosen) if chosen else None,
        "active": [],
        "errors": [],
    }
    if chosen is None:
        return inventory

    try:
        if chosen.suffix.lower() == ".json":
            data = json.loads(chosen.read_text(encoding="utf-8"))
        else:
            data = yaml.safe_load(chosen.read_text(encoding="utf-8")) or {}
    except (OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
        inventory["errors"] = [f"failed to load fix-list file {chosen}: {exc}"]
        return inventory

    entries, errors = _validated_fix_list_entries(data)
    today = date.today()
    active = []
    for entry in entries:
        target = entry.get("target_date")
        days_remaining = None
        if target:
            days_remaining = (date.fromisoformat(str(target)) - today).days
        active.append({**entry, "days_remaining": days_remaining})
    inventory["active"] = active
    inventory["errors"] = errors
    return inventory


def apply_fix_list(repo: Path, findings: list[dict], inventory: dict[str, object]) -> dict[str, object]:
    """Tag findings that match the fix-list and reconcile stale tracker entries."""
    entries = [entry for entry in inventory.get("active", []) if isinstance(entry, dict)]
    buckets: dict[str, list] = {
        "tracked": [],
        "regression": [],
        "wontfix": [],
        "overdue": [],
        "likely_fixed": [],
        "confirmed_fixed": [],
        "drifted": [],
    }
    matched_ids: set[str] = set()
    visible = []
    today = date.today()

    for finding in findings:
        matches = [entry for entry in entries if _accepted_risk_matches(repo, finding, entry)]
        if not matches:
            visible.append(finding)
            continue
        entry = sorted(matches, key=lambda item: str(item.get("id") or ""))[-1]
        entry_id = str(entry.get("id"))
        matched_ids.add(entry_id)
        finding = dict(finding)
        status = str(entry.get("status") or "open")
        if status in {"open", "in-progress"}:
            finding["fix_list_status"] = "tracked"
            finding["fix_list_id"] = entry_id
            finding["fix_list_target_date"] = entry.get("target_date")
            buckets["tracked"].append(
                {"fix_id": entry_id, "entry": entry, "finding": _baseline_finding_summary(finding)}
            )
            target = entry.get("target_date")
            if target and date.fromisoformat(str(target)) < today:
                buckets["overdue"].append(
                    {"fix_id": entry_id, "entry": entry, "finding": _baseline_finding_summary(finding)}
                )
        elif status == "fixed":
            finding["fix_list_status"] = "regression"
            finding["fix_list_id"] = entry_id
            buckets["regression"].append(
                {"fix_id": entry_id, "entry": entry, "finding": _baseline_finding_summary(finding)}
            )
        elif status == "wontfix":
            finding["fix_list_status"] = "wontfix"
            finding["fix_list_id"] = entry_id
            buckets["wontfix"].append(
                {"fix_id": entry_id, "entry": entry, "finding": _baseline_finding_summary(finding)}
            )
        visible.append(finding)

    for entry in entries:
        entry_id = str(entry.get("id"))
        if entry_id in matched_ids:
            continue
        status = str(entry.get("status") or "open")
        if status in {"open", "in-progress"}:
            buckets["likely_fixed"].append(entry)
        elif status == "fixed":
            buckets["confirmed_fixed"].append(entry)
        elif status == "wontfix":
            buckets["drifted"].append(entry)

    summary = {
        "loaded_from": inventory.get("loaded_from"),
        "entries": len(entries),
        "errors": len(inventory.get("errors", [])),
        "tracked_findings": len(buckets["tracked"]),
        "regressions": len(buckets["regression"]),
        "wontfix_findings": len(buckets["wontfix"]),
        "overdue": len(buckets["overdue"]),
        "likely_fixed": len(buckets["likely_fixed"]),
        "confirmed_fixed": len(buckets["confirmed_fixed"]),
        "drifted": len(buckets["drifted"]),
    }
    run_inventory = {**inventory, "buckets": buckets, "summary": summary}
    return {"findings": visible, "inventory": run_inventory, "summary": summary}


def _validated_accepted_risk_entries(data: object) -> tuple[list[dict[str, object]], list[str]]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return [], ["accepted-risks file must be a mapping"]
    if data.get("version") != 1:
        errors.append("version must be 1")
    risks = data.get("risks", data.get("accepted_risks", []))
    if not isinstance(risks, list):
        return [], errors + ["risks must be a list"]

    seen_ids: set[str] = set()
    entries: list[dict[str, object]] = []
    for index, raw in enumerate(risks, start=1):
        if not isinstance(raw, dict):
            errors.append(f"risk[{index}] must be a mapping")
            continue
        entry = dict(raw)
        risk_id = str(entry.get("id") or "")
        if not risk_id:
            errors.append(f"risk[{index}] missing id")
        elif risk_id in seen_ids:
            errors.append(f"risk[{index}] duplicate id: {risk_id}")
        seen_ids.add(risk_id)
        for required in ("title", "reason", "owner", "accepted", "expires"):
            if not str(entry.get(required) or "").strip():
                errors.append(f"{risk_id or f'risk[{index}]'} missing {required}")
        fingerprint = str(entry.get("fingerprint") or "")
        file_pattern = str(entry.get("file") or "")
        if not fingerprint and not file_pattern:
            errors.append(f"{risk_id or f'risk[{index}]'} requires fingerprint or file")
        if fingerprint and not re.fullmatch(r"(sha256:)?[0-9a-f]{16,64}", fingerprint):
            errors.append(f"{risk_id or f'risk[{index}]'} fingerprint must be 16-64 hex chars")
        pattern_kind = str(entry.get("pattern_kind") or "literal")
        if pattern_kind not in {"literal", "regex"}:
            errors.append(f"{risk_id or f'risk[{index}]'} pattern_kind must be literal or regex")
        if pattern_kind == "regex" and entry.get("match"):
            try:
                re.compile(str(entry["match"]))
            except re.error as exc:
                errors.append(f"{risk_id or f'risk[{index}]'} invalid regex: {exc}")
        try:
            accepted = _coerce_date(entry.get("accepted"))
            expires = _coerce_date(entry.get("expires"))
            if accepted > expires:
                errors.append(f"{risk_id or f'risk[{index}]'} accepted date is after expires")
            entry["accepted"] = accepted.isoformat()
            entry["expires"] = expires.isoformat()
        except ValueError:
            errors.append(f"{risk_id or f'risk[{index}]'} accepted/expires must be YYYY-MM-DD")
        entry["pattern_kind"] = pattern_kind
        entries.append(entry)
    return entries, errors


def _validated_fix_list_entries(data: object) -> tuple[list[dict[str, object]], list[str]]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return [], ["fix-list file must be a mapping"]
    if data.get("version") != 1:
        errors.append("version must be 1")
    fixes = data.get("fixes", data.get("fix_list", []))
    if not isinstance(fixes, list):
        return [], errors + ["fixes must be a list"]

    seen_ids: set[str] = set()
    entries: list[dict[str, object]] = []
    for index, raw in enumerate(fixes, start=1):
        if not isinstance(raw, dict):
            errors.append(f"fix[{index}] must be a mapping")
            continue
        entry = dict(raw)
        fix_id = str(entry.get("id") or "")
        if not fix_id:
            errors.append(f"fix[{index}] missing id")
        elif fix_id in seen_ids:
            errors.append(f"fix[{index}] duplicate id: {fix_id}")
        seen_ids.add(fix_id)
        for required in ("title", "severity", "owner", "status"):
            if not str(entry.get(required) or "").strip():
                errors.append(f"{fix_id or f'fix[{index}]'} missing {required}")
        status = str(entry.get("status") or "")
        if status not in {"open", "in-progress", "fixed", "wontfix"}:
            errors.append(f"{fix_id or f'fix[{index}]'} status must be open, in-progress, fixed, or wontfix")
        severity = str(entry.get("severity") or "").lower()
        if severity not in _SEVERITY_RANK:
            errors.append(f"{fix_id or f'fix[{index}]'} severity must be critical, high, medium, low, or info")
        if status == "wontfix" and not str(entry.get("notes") or "").strip():
            errors.append(f"{fix_id or f'fix[{index}]'} wontfix entries require notes")
        fingerprint = str(entry.get("fingerprint") or "")
        file_pattern = str(entry.get("file") or "")
        if not fingerprint and not file_pattern:
            errors.append(f"{fix_id or f'fix[{index}]'} requires fingerprint or file")
        if fingerprint and not re.fullmatch(r"(sha256:)?[0-9a-f]{16,64}", fingerprint):
            errors.append(f"{fix_id or f'fix[{index}]'} fingerprint must be 16-64 hex chars")
        for field in ("target_date", "fixed_at"):
            if entry.get(field):
                try:
                    entry[field] = _coerce_date(entry[field]).isoformat()
                except ValueError:
                    errors.append(f"{fix_id or f'fix[{index}]'} {field} must be YYYY-MM-DD")
        entry["severity"] = severity
        entries.append(entry)
    return entries, errors


def _coerce_date(value: object) -> date:
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))


def _accepted_risk_matches(repo: Path, finding: dict, entry: dict) -> bool:
    fingerprint = str(entry.get("fingerprint") or "")
    if fingerprint:
        finding_fingerprint = str(finding.get("fingerprint") or compute_fingerprint(finding))
        normalized = finding_fingerprint.removeprefix("sha256:")
        entry_fingerprint = fingerprint.removeprefix("sha256:")
        if entry_fingerprint == normalized or normalized.startswith(entry_fingerprint):
            return True

    file_pattern = str(entry.get("file") or "")
    if not file_pattern:
        return False
    finding_file = _repo_relative_finding_file(repo, finding)
    if not (finding_file == file_pattern or fnmatch.fnmatch(finding_file, file_pattern)):
        return False
    lines = entry.get("lines")
    if lines and not _line_in_accepted_risk_range(finding.get("line"), lines):
        return False
    match = entry.get("match")
    if match and not _accepted_risk_text_matches(
        repo, finding_file, int(finding.get("line") or 0), str(match), str(entry.get("pattern_kind") or "literal")
    ):
        return False
    return True


def _repo_relative_finding_file(repo: Path, finding: dict) -> str:
    raw = Path(str(finding.get("file") or ""))
    try:
        if raw.is_absolute():
            return raw.resolve().relative_to(repo).as_posix()
    except ValueError:
        return raw.as_posix()
    return raw.as_posix()


def _line_in_accepted_risk_range(line: object, lines: object) -> bool:
    try:
        finding_line = int(line or 0)
    except (TypeError, ValueError):
        return False
    if isinstance(lines, int):
        return finding_line == lines
    if isinstance(lines, list) and len(lines) == 2:
        try:
            start, end = int(lines[0]), int(lines[1])
        except (TypeError, ValueError):
            return False
        return start <= finding_line <= end
    return False


def _accepted_risk_text_matches(repo: Path, file_name: str, line: int, pattern: str, pattern_kind: str) -> bool:
    path = repo / file_name
    try:
        content = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return False
    start = max(0, line - 11)
    end = min(len(content), line + 10)
    snippet = "\n".join(content[start:end])
    if pattern_kind == "regex":
        return re.search(pattern, snippet) is not None
    return pattern in snippet


def _baseline_finding_summary(finding: dict) -> dict[str, object]:
    return {
        "id": finding.get("id"),
        "fingerprint": str(finding.get("fingerprint") or compute_fingerprint(finding)),
        "rule_id": finding.get("rule_id"),
        "severity": _normalized_severity(finding.get("severity")),
        "triage": finding.get("triage"),
        "source": finding.get("source"),
        "file": finding.get("file"),
        "line": finding.get("line"),
        "title": finding.get("title"),
    }


def write_artifact_manifest(out: Path, manifest_file: Path, artifact_specs: list[dict]) -> dict[str, object]:
    """Write a manifest describing every deep-scan output artifact."""
    manifest_file.parent.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, object] = {}
    previous = ""
    for _ in range(5):
        entries = [artifact_entry(out, spec) for spec in artifact_specs]
        manifest = {
            "total_artifacts": len(entries),
            "required_artifacts": sum(1 for entry in entries if entry["required"]),
            "optional_artifacts": sum(1 for entry in entries if not entry["required"]),
            "missing_required": [entry["path"] for entry in entries if entry["required"] and not entry["exists"]],
            "entries": entries,
        }
        payload = json.dumps(manifest, indent=2)
        if payload == previous:
            break
        manifest_file.write_text(payload, encoding="utf-8")
        previous = payload
    return manifest


def artifact_entry(out: Path, spec: dict) -> dict[str, object]:
    """Build a normalized output artifact manifest entry."""
    path = spec["path"]
    if not isinstance(path, Path):
        path = Path(path)
    exists = path.exists()
    entry: dict[str, object] = {
        "path": _artifact_relative_path(out, path),
        "kind": spec["kind"],
        "required": spec.get("required", True),
        "exists": exists,
        "bytes": _artifact_size(path) if exists else 0,
        "description": spec.get("description", ""),
    }
    if "count" in spec:
        entry["count"] = spec["count"]
    return entry


def _artifact_relative_path(out: Path, path: Path) -> str:
    try:
        return str(path.relative_to(out))
    except ValueError:
        return str(path)


def _artifact_size(path: Path) -> int:
    if path.is_dir():
        return sum(child.stat().st_size for child in path.rglob("*") if child.is_file())
    return path.stat().st_size


def generate_tooling_report(coverage_report: dict) -> str:
    """Generate a short Markdown tooling/coverage summary."""
    lines = [
        "# Deep Scan Tooling",
        "",
        "## Surface Coverage",
        "",
        "| Surface | Total | With Findings | Ratio |",
        "|---------|------:|--------------:|------:|",
    ]
    for surface, metric in coverage_report["surfaces"].items():
        lines.append(
            f"| {surface.replace('_', ' ')} | {metric['total']} | "
            f"{metric['with_findings']} | {metric['coverage_ratio']:.2f} |"
        )

    warnings = coverage_report.get("warnings", [])
    lines.extend(["", "## Warnings", ""])
    if warnings:
        lines.extend(f"- {warning}" for warning in warnings)
    else:
        lines.append("- None")
    lines.extend(
        [
            "",
            "## Scanner Sources",
            "",
            "| Source | Findings |",
            "|--------|---------:|",
        ]
    )
    for entry in coverage_report.get("scanner_sources", {}).get("entries", []):
        lines.append(f"| {entry['source']} | {entry['findings']} |")

    summary = coverage_report.get("finding_summary", {})
    lines.extend(["", "## Finding Summary", ""])
    if summary:
        lines.append(f"- Total findings: {summary['total_findings']}")
        severity_counts = summary.get("severity_counts", {})
        lines.append(
            "- Severity mix: "
            + ", ".join(f"{severity}={severity_counts.get(severity, 0)}" for severity in _SEVERITY_ORDER)
        )
        lines.extend(
            [
                "",
                "| Source | Critical | High | Medium | Low | Info | Total |",
                "|--------|---------:|-----:|-------:|----:|-----:|------:|",
            ]
        )
        for entry in summary.get("sources", [])[:15]:
            counts = entry.get("severity_counts", {})
            lines.append(
                f"| {entry['source']} | {counts.get('critical', 0)} | {counts.get('high', 0)} | "
                f"{counts.get('medium', 0)} | {counts.get('low', 0)} | {counts.get('info', 0)} | "
                f"{entry['total']} |"
            )
        lines.extend(["", "| Rule | Findings | Max Severity |", "|------|---------:|--------------|"])
        for entry in summary.get("top_rules", [])[:15]:
            lines.append(f"| {entry['rule_id']} | {entry['findings']} | {entry['max_severity']} |")
    else:
        lines.append("- Unavailable")

    review_gate = coverage_report.get("review_gate", {})
    lines.extend(["", "## Review Gate", ""])
    if review_gate:
        verdict = "passed" if review_gate["passed"] else "failed"
        lines.append(f"- Verdict: {verdict}")
        lines.append(f"- Fail on: {review_gate['fail_on']}")
        lines.append(f"- Blocking findings: {review_gate['blocking_findings']}")
    else:
        lines.append("- Unavailable")

    module_risk = coverage_report.get("module_risk", {})
    lines.extend(["", "## Module Risk", ""])
    if module_risk:
        lines.append(f"- Modules: {module_risk['total_modules']}")
        band_counts = module_risk.get("band_counts", {})
        lines.append(
            "- Risk bands: "
            + ", ".join(f"{band}={band_counts.get(band, 0)}" for band in ("critical", "high", "medium", "low"))
        )
        lines.extend(
            [
                "",
                "| Module | Band | Score | Findings | Public Routes |",
                "|--------|------|------:|---------:|--------------:|",
            ]
        )
        for entry in module_risk.get("modules", [])[:15]:
            lines.append(
                f"| {entry['module']} | {entry['band']} | {entry['score']} | "
                f"{entry['findings']} | {entry['public_routes']} |"
            )
    else:
        lines.append("- Unavailable")

    registry = coverage_report.get("scanner_registry", {})
    lines.extend(["", "## Scanner Registry", ""])
    if registry:
        lines.append(f"- Exported scanner callables: {registry['total_exported']}")
        lines.append(f"- Wired scanner callables: {registry['wired_exported']}")
        lines.append(f"- Scanner source labels: {registry['source_labels']}")
        lines.append(f"- Manifest entries: {len(registry.get('manifest_entries', []))}")
        missing = registry.get("missing_from_deep_scan", [])
        lines.append(f"- Missing from deep scan: {', '.join(missing) if missing else 'None'}")
        unlabeled = registry.get("callables_without_source", [])
        lines.append(f"- Callables without source: {', '.join(unlabeled) if unlabeled else 'None'}")
        uncalled = registry.get("sources_without_callable", [])
        lines.append(f"- Sources without callable: {', '.join(uncalled) if uncalled else 'None'}")
    else:
        lines.append("- Unavailable")

    catalog = coverage_report.get("rule_catalog", {})
    lines.extend(["", "## Rule Catalog", ""])
    if catalog:
        lines.append(f"- Declared rule IDs: {catalog['total_rules']}")
        lines.append(f"- Rule ID occurrences: {catalog['total_occurrences']}")
        lines.append(f"- Emitted rule IDs: {catalog['emitted_rules']}")
        undocumented = catalog.get("undocumented_rule_ids", [])
        lines.append(f"- Findings with undocumented rule IDs: {', '.join(undocumented) if undocumented else 'None'}")
    else:
        lines.append("- Unavailable")

    taxonomy = coverage_report.get("taxonomy_coverage", {})
    lines.extend(["", "## Taxonomy Coverage", ""])
    if taxonomy:
        lines.append(f"- Emitted rules: {taxonomy['total_emitted_rules']}")
        lines.append(f"- Mapped rules: {taxonomy['mapped_rules']}")
        lines.append(f"- Coverage ratio: {taxonomy['coverage_ratio']:.2%}")
        unmapped = taxonomy.get("unmapped_rule_ids", [])
        lines.append(f"- Unmapped emitted rule IDs: {', '.join(unmapped[:20]) if unmapped else 'None'}")
        if len(unmapped) > 20:
            lines.append(f"- Additional unmapped rule IDs: {len(unmapped) - 20}")
    else:
        lines.append("- Unavailable")

    taxonomy_gate = coverage_report.get("taxonomy_gate", {})
    lines.extend(["", "## Taxonomy Gate", ""])
    if taxonomy_gate:
        verdict = "passed" if taxonomy_gate["passed"] else "failed"
        lines.append(f"- Verdict: {verdict}")
        lines.append(f"- Fail on unmapped taxonomy: {taxonomy_gate['fail_on_unmapped_taxonomy']}")
        lines.append(f"- Blocking unmapped rules: {taxonomy_gate['blocking_rules']}")
    else:
        lines.append("- Unavailable")

    baseline_delta = coverage_report.get("baseline_delta", {})
    baseline_gate = coverage_report.get("baseline_gate", {})
    lines.extend(["", "## Baseline Delta", ""])
    if baseline_delta:
        lines.append(f"- Baseline findings: {baseline_delta['baseline_findings']}")
        lines.append(f"- Current findings: {baseline_delta['current_findings']}")
        lines.append(f"- New findings: {baseline_delta['new_count']}")
        lines.append(f"- Fixed findings: {baseline_delta['fixed_count']}")
        lines.append(f"- Changed findings: {baseline_delta['changed_count']}")
        if baseline_gate:
            verdict = "passed" if baseline_gate["passed"] else "failed"
            lines.append(f"- Baseline gate: {verdict}")
            lines.append(f"- Fail on new: {baseline_gate['fail_on_new']}")
            lines.append(f"- Blocking new findings: {baseline_gate['blocking_new_findings']}")
    else:
        lines.append("- Not configured")

    accepted = coverage_report.get("accepted_risks", {})
    lines.extend(["", "## Accepted Risks", ""])
    if accepted:
        lines.append(f"- Loaded from: {accepted.get('loaded_from') or 'None'}")
        lines.append(f"- Active entries: {accepted['active_entries']}")
        lines.append(f"- Expired entries: {accepted['expired_entries']}")
        lines.append(f"- Suppressed findings: {accepted['suppressed_findings']}")
        lines.append(f"- Expired matches: {accepted['expired_matches']}")
        lines.append(f"- Loader errors: {accepted['errors']}")
    else:
        lines.append("- Not configured")

    fix_list = coverage_report.get("fix_list", {})
    lines.extend(["", "## Fix List", ""])
    if fix_list:
        lines.append(f"- Loaded from: {fix_list.get('loaded_from') or 'None'}")
        lines.append(f"- Entries: {fix_list['entries']}")
        lines.append(f"- Tracked findings: {fix_list['tracked_findings']}")
        lines.append(f"- Regressions: {fix_list['regressions']}")
        lines.append(f"- Overdue: {fix_list['overdue']}")
        lines.append(f"- Likely fixed: {fix_list['likely_fixed']}")
    else:
        lines.append("- Not configured")

    governance_gate = coverage_report.get("governance_gate", {})
    lines.extend(["", "## Governance Gate", ""])
    if governance_gate:
        verdict = "passed" if governance_gate["passed"] else "failed"
        lines.append(f"- Verdict: {verdict}")
        lines.append(f"- Blocking conditions: {governance_gate['blocking_conditions']}")
        enabled = [condition["id"] for condition in governance_gate.get("conditions", []) if condition.get("enabled")]
        lines.append(f"- Enabled checks: {', '.join(enabled) if enabled else 'None'}")
    else:
        lines.append("- Unavailable")

    poc_coverage = coverage_report.get("poc_coverage", {})
    if poc_coverage:
        lines.extend(["", "## PoC Coverage", ""])
        lines.append(f"- Findings: {poc_coverage['total_findings']}")
        lines.append(f"- Generated PoCs: {poc_coverage['generated_pocs']}")
        lines.append(f"- Coverage ratio: {poc_coverage['coverage_ratio']:.2%}")
        unsupported = poc_coverage.get("unsupported_findings", [])
        lines.append(f"- Unsupported findings: {len(unsupported)}")
        generated_files = poc_coverage.get("generated_files", [])
        lines.append(f"- Generated files: {len(generated_files)}")
    artifact_manifest = coverage_report.get("artifact_manifest", {})
    if artifact_manifest:
        lines.extend(["", "## Artifact Manifest", ""])
        lines.append(f"- Manifest: {artifact_manifest['path']}")
        lines.append(f"- Tracked artifacts: {artifact_manifest['total_artifacts']}")
    lines.append("")
    return "\n".join(lines)


def generate_accepted_risks_report(report: dict[str, object]) -> str:
    """Generate a Markdown report for deep-scan accepted-risk suppression."""
    inventory = report["inventory"]
    summary = report["summary"]
    lines = [
        "# Accepted Risks",
        "",
        f"- Loaded from: {summary.get('loaded_from') or 'None'}",
        f"- Active entries: {summary['active_entries']}",
        f"- Expired entries: {summary['expired_entries']}",
        f"- Suppressed findings: {summary['suppressed_findings']}",
        f"- Expired matches: {summary['expired_matches']}",
        f"- Loader errors: {summary['errors']}",
        "",
    ]
    errors = inventory.get("errors", [])
    if errors:
        lines.extend(["## Errors", ""])
        lines.extend(f"- {error}" for error in errors)
        lines.append("")
    lines.extend(_accepted_risk_entries_table("Active Entries", inventory.get("active", [])))
    lines.extend(_accepted_risk_entries_table("Expired Entries", inventory.get("expired", [])))
    lines.extend(_accepted_risk_findings_table("Suppressed Findings", inventory.get("suppressed", [])))
    lines.extend(_accepted_risk_findings_table("Expired Matches", inventory.get("expired_matches", [])))
    return "\n".join(lines)


def _accepted_risk_entries_table(title: str, entries: object) -> list[str]:
    rows = entries if isinstance(entries, list) else []
    lines = [f"## {title}", ""]
    if not rows:
        lines.extend(["None", ""])
        return lines
    lines.extend(["| ID | Owner | Expires | Days | Title |", "|----|-------|---------|-----:|-------|"])
    for entry in rows[:50]:
        lines.append(
            f"| {entry.get('id')} | {entry.get('owner')} | {entry.get('expires')} | "
            f"{entry.get('days_remaining')} | {entry.get('title')} |"
        )
    if len(rows) > 50:
        lines.append(f"| ... | ... | ... | ... | {len(rows) - 50} additional entries omitted |")
    lines.append("")
    return lines


def _accepted_risk_findings_table(title: str, entries: object) -> list[str]:
    rows = entries if isinstance(entries, list) else []
    lines = [f"## {title}", ""]
    if not rows:
        lines.extend(["None", ""])
        return lines
    lines.extend(
        [
            "| Accepted Risk | Severity | Rule | File | Line | Title |",
            "|---------------|----------|------|------|-----:|-------|",
        ]
    )
    for entry in rows[:50]:
        finding = entry.get("finding", {}) if isinstance(entry, dict) else {}
        risk_id = entry.get("accepted_risk_id") or ", ".join(entry.get("accepted_risk_ids", []))
        lines.append(
            f"| {risk_id} | {finding.get('severity')} | {finding.get('rule_id')} | {finding.get('file')} | "
            f"{finding.get('line')} | {finding.get('title')} |"
        )
    if len(rows) > 50:
        lines.append(f"| ... | ... | ... | ... | ... | {len(rows) - 50} additional entries omitted |")
    lines.append("")
    return lines


def generate_fix_list_report(report: dict[str, object]) -> str:
    """Generate a Markdown report for deep-scan fix-list tracking."""
    inventory = report["inventory"]
    summary = report["summary"]
    buckets = inventory.get("buckets", {})
    lines = [
        "# Fix List",
        "",
        f"- Loaded from: {summary.get('loaded_from') or 'None'}",
        f"- Entries: {summary['entries']}",
        f"- Tracked findings: {summary['tracked_findings']}",
        f"- Regressions: {summary['regressions']}",
        f"- Wontfix findings: {summary['wontfix_findings']}",
        f"- Overdue: {summary['overdue']}",
        f"- Likely fixed: {summary['likely_fixed']}",
        f"- Confirmed fixed: {summary['confirmed_fixed']}",
        f"- Drifted: {summary['drifted']}",
        f"- Loader errors: {summary['errors']}",
    ]
    if "policy_overdue_entries" in summary:
        lines.append(f"- Policy overdue entries: {summary['policy_overdue_entries']}")
    lines.append("")
    errors = inventory.get("errors", [])
    if errors:
        lines.extend(["## Errors", ""])
        lines.extend(f"- {error}" for error in errors)
        lines.append("")
    for title, key in (
        ("Regressions", "regression"),
        ("Overdue", "overdue"),
        ("Tracked", "tracked"),
        ("Wontfix", "wontfix"),
    ):
        lines.extend(_fix_list_finding_table(title, buckets.get(key, [])))
    for title, key in (
        ("Policy Overdue Entries", "policy_overdue"),
        ("Likely Fixed", "likely_fixed"),
        ("Confirmed Fixed", "confirmed_fixed"),
        ("Drifted", "drifted"),
    ):
        lines.extend(_fix_list_entry_table(title, buckets.get(key, [])))
    return "\n".join(lines)


def _fix_list_finding_table(title: str, entries: object) -> list[str]:
    rows = entries if isinstance(entries, list) else []
    lines = [f"## {title}", ""]
    if not rows:
        lines.extend(["None", ""])
        return lines
    lines.extend(
        [
            "| Fix | Status | Severity | Rule | File | Line | Title |",
            "|-----|--------|----------|------|------|-----:|-------|",
        ]
    )
    for row in rows[:50]:
        entry = row.get("entry", {}) if isinstance(row, dict) else {}
        finding = row.get("finding", {}) if isinstance(row, dict) else {}
        lines.append(
            f"| {entry.get('id')} | {entry.get('status')} | {finding.get('severity')} | "
            f"{finding.get('rule_id')} | {finding.get('file')} | {finding.get('line')} | {finding.get('title')} |"
        )
    if len(rows) > 50:
        lines.append(f"| ... | ... | ... | ... | ... | ... | {len(rows) - 50} additional entries omitted |")
    lines.append("")
    return lines


def _fix_list_entry_table(title: str, entries: object) -> list[str]:
    rows = entries if isinstance(entries, list) else []
    lines = [f"## {title}", ""]
    if not rows:
        lines.extend(["None", ""])
        return lines
    lines.extend(
        ["| Fix | Status | Severity | Owner | Target | Title |", "|-----|--------|----------|-------|--------|-------|"]
    )
    for entry in rows[:50]:
        lines.append(
            f"| {entry.get('id')} | {entry.get('status')} | {entry.get('severity')} | "
            f"{entry.get('owner')} | {entry.get('target_date')} | {entry.get('title')} |"
        )
    if len(rows) > 50:
        lines.append(f"| ... | ... | ... | ... | ... | {len(rows) - 50} additional entries omitted |")
    lines.append("")
    return lines


def generate_baseline_delta_report(delta: dict[str, object], gate: dict[str, object]) -> str:
    """Generate a Markdown baseline delta report."""
    lines = [
        "# Deep Scan Baseline Delta",
        "",
        f"- Baseline findings: {delta['baseline_findings']}",
        f"- Current findings: {delta['current_findings']}",
        f"- New: {delta['new_count']}",
        f"- Fixed: {delta['fixed_count']}",
        f"- Changed: {delta['changed_count']}",
        f"- Unchanged: {delta['unchanged_count']}",
        f"- Gate: {'passed' if gate['passed'] else 'failed'}",
        f"- Fail on new: {gate['fail_on_new']}",
        f"- Blocking new findings: {gate['blocking_new_findings']}",
        "",
    ]
    lines.extend(_baseline_delta_table("New Findings", delta.get("new", [])))
    lines.extend(_baseline_delta_table("Changed Findings", [entry["current"] for entry in delta.get("changed", [])]))
    lines.extend(_baseline_delta_table("Fixed Findings", delta.get("fixed", [])))
    return "\n".join(lines)


def _baseline_delta_table(title: str, findings: object) -> list[str]:
    rows = findings if isinstance(findings, list) else []
    lines = [f"## {title}", ""]
    if not rows:
        lines.extend(["None", ""])
        return lines
    lines.extend(["| Severity | Rule | File | Line | Title |", "|----------|------|------|-----:|-------|"])
    for finding in rows[:50]:
        lines.append(
            f"| {finding.get('severity')} | {finding.get('rule_id')} | {finding.get('file')} | "
            f"{finding.get('line')} | {finding.get('title')} |"
        )
    if len(rows) > 50:
        lines.append(f"| ... | ... | ... | ... | {len(rows) - 50} additional entries omitted |")
    lines.append("")
    return lines


def generate_module_risk_report(module_risk: dict[str, object]) -> str:
    """Generate a Markdown report for module risk prioritization."""
    lines = [
        "# Module Risk",
        "",
        "| Module | Band | Score | Findings | Critical | High | Public Routes | Top Rules |",
        "|--------|------|------:|---------:|---------:|-----:|--------------:|-----------|",
    ]
    for entry in module_risk.get("modules", []):
        severity_counts = entry.get("severity_counts", {})
        top_rules = ", ".join(rule["rule_id"] for rule in entry.get("top_rules", [])[:3])
        lines.append(
            f"| {entry['module']} | {entry['band']} | {entry['score']} | {entry['findings']} | "
            f"{severity_counts.get('critical', 0)} | {severity_counts.get('high', 0)} | "
            f"{entry['public_routes']} | {top_rules or 'None'} |"
        )
    lines.append("")
    return "\n".join(lines)


def generate_sarif_report(repo: Path, findings: list[dict]) -> dict[str, object]:
    """Generate a SARIF 2.1.0 report for code scanning integrations."""
    rules = {
        rule_id: _sarif_rule(rule_id, rule_findings)
        for rule_id, rule_findings in sorted(_findings_by_rule(findings).items())
    }
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "odoo-app-security-harness",
                        "informationUri": "https://github.com/purehate/odoo-app-security-harness",
                        "rules": list(rules.values()),
                    }
                },
                "taxonomies": _sarif_taxonomies(rules.values()),
                "originalUriBaseIds": {"SRCROOT": {"uri": repo.as_uri() + "/"}},
                "results": [_sarif_result(repo, finding) for finding in findings],
            }
        ],
    }


def _findings_by_rule(findings: list[dict]) -> dict[str, list[dict]]:
    rules: dict[str, list[dict]] = {}
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "unknown")
        rules.setdefault(rule_id, []).append(finding)
    return rules


def _sarif_rule(rule_id: str, findings: list[dict]) -> dict[str, object]:
    sample = findings[0] if findings else {}
    taxonomy = _security_taxonomy_for_rule(rule_id, findings)
    properties = {
        "source": sorted({str(finding.get("source") or "unknown") for finding in findings}),
        "severity": _normalized_severity(sample.get("severity")),
        "finding_count": len(findings),
    }
    if taxonomy:
        properties.update(taxonomy)
        tags = {tag for key in ("cwe", "capec") for tag in taxonomy.get(key, [])}
        owasp = str(taxonomy.get("owasp", ""))
        if owasp:
            tags.add(owasp)
        properties["tags"] = sorted(tags)
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": str(sample.get("title") or rule_id)},
        "fullDescription": {"text": str(sample.get("message") or sample.get("title") or rule_id)},
        "defaultConfiguration": {"level": _sarif_level(sample.get("severity"))},
        "properties": properties,
    }


def _sarif_result(repo: Path, finding: dict) -> dict[str, object]:
    taxonomy = _security_taxonomy_for_finding(finding)
    result: dict[str, object] = {
        "ruleId": str(finding.get("rule_id") or "unknown"),
        "level": _sarif_level(finding.get("severity")),
        "message": {"text": str(finding.get("message") or finding.get("title") or finding.get("rule_id") or "Finding")},
        "locations": [_sarif_location(repo, finding)],
        "properties": {
            "id": finding.get("id"),
            "source": finding.get("source"),
            "severity": _normalized_severity(finding.get("severity")),
            "triage": finding.get("triage"),
        },
    }
    if taxonomy:
        result["properties"].update(taxonomy)
    governance_properties = _sarif_governance_properties(finding)
    if governance_properties:
        result["properties"].update(governance_properties)
    suppressions = _sarif_result_suppressions(finding)
    if suppressions:
        result["suppressions"] = suppressions
    fingerprint = finding.get("fingerprint")
    if fingerprint:
        result["partialFingerprints"] = {"primaryLocationLineHash": str(fingerprint)}
    return result


def _sarif_governance_properties(finding: dict) -> dict[str, object]:
    properties: dict[str, object] = {}
    if finding.get("expired_accepted_risk_ids"):
        properties["expired_accepted_risk_ids"] = list(finding.get("expired_accepted_risk_ids") or [])
    if finding.get("fix_list_status"):
        properties["fix_list_status"] = finding.get("fix_list_status")
        properties["fix_list_id"] = finding.get("fix_list_id")
        if finding.get("fix_list_target_date"):
            properties["fix_list_target_date"] = finding.get("fix_list_target_date")
    return properties


def _sarif_result_suppressions(finding: dict) -> list[dict[str, object]]:
    expired = [str(risk_id) for risk_id in finding.get("expired_accepted_risk_ids", [])]
    return [
        {
            "kind": "external",
            "status": "rejected",
            "justification": f"Expired accepted risk {risk_id}; finding remains active for re-review",
        }
        for risk_id in expired
    ]


def _sarif_taxonomies(rules: object) -> list[dict[str, object]]:
    cwes = sorted(
        {
            cwe
            for rule in rules
            for cwe in rule.get("properties", {}).get("cwe", [])
            if isinstance(cwe, str) and cwe.startswith("CWE-")
        }
    )
    if not cwes:
        return []
    return [
        {
            "name": "CWE",
            "organization": "MITRE",
            "informationUri": "https://cwe.mitre.org/",
            "taxa": [{"id": cwe, "name": cwe} for cwe in cwes],
        }
    ]


def _security_taxonomy_for_rule(rule_id: str, findings: list[dict]) -> dict[str, object]:
    explicit = _explicit_taxonomy(findings)
    if explicit:
        return explicit
    text = " ".join(
        [
            rule_id,
            " ".join(str(finding.get("source") or "") for finding in findings),
            " ".join(str(finding.get("title") or "") for finding in findings[:3]),
            " ".join(str(finding.get("message") or "") for finding in findings[:3]),
        ]
    ).lower()
    return _taxonomy_for_text(text)


def _security_taxonomy_for_finding(finding: dict) -> dict[str, object]:
    explicit = _explicit_taxonomy([finding])
    if explicit:
        return explicit
    text = " ".join(
        str(finding.get(key) or "") for key in ("rule_id", "source", "title", "message", "sink", "flag")
    ).lower()
    return _taxonomy_for_text(text)


def _explicit_taxonomy(findings: list[dict]) -> dict[str, object]:
    cwes = sorted(
        {
            cwe
            for finding in findings
            for cwe in _string_list(finding.get("cwe", []))
            if isinstance(cwe, str) and cwe.startswith("CWE-")
        }
    )
    if not cwes:
        return {}
    return {"cwe": cwes}


def _taxonomy_for_text(text: str) -> dict[str, object]:
    mappings = _cwe_shape_mappings()
    for shape, hints in _TAXONOMY_SHAPE_HINTS:
        if shape not in mappings:
            continue
        if any(hint in text for hint in hints):
            mapping = mappings[shape]
            taxonomy: dict[str, object] = {
                "taxonomy_shape": shape,
                "taxonomy_label": mapping.get("label", shape),
                "cwe": list(mapping.get("cwe", [])),
            }
            if mapping.get("capec"):
                taxonomy["capec"] = list(mapping["capec"])
            if mapping.get("owasp"):
                taxonomy["owasp"] = mapping["owasp"]
            return taxonomy
    return {}


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [entry for entry in value if isinstance(entry, str)]
    return []


def _cwe_shape_mappings() -> dict[str, dict[str, object]]:
    path = Path(__file__).resolve().parents[2] / "skills" / "odoo-code-review" / "references" / "cwe-map.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    mappings = data.get("mappings", {})
    return mappings if isinstance(mappings, dict) else {}


def _sarif_location(repo: Path, finding: dict) -> dict[str, object]:
    file_path = _finding_path(repo, finding)
    uri = _sarif_uri(repo, file_path)
    raw_line = finding.get("line")
    line = raw_line if isinstance(raw_line, int) and raw_line > 0 else 1
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri, "uriBaseId": "SRCROOT"},
            "region": {"startLine": line},
        }
    }


def _sarif_uri(repo: Path, path: Path | None) -> str:
    if path is None:
        return "unknown"
    try:
        return path.relative_to(repo).as_posix()
    except ValueError:
        return path.as_posix()


def _sarif_level(severity: object) -> str:
    normalized = _normalized_severity(severity)
    if normalized in {"critical", "high"}:
        return "error"
    if normalized == "medium":
        return "warning"
    return "note"


def _source_coverage(findings: list[dict]) -> dict[str, object]:
    expected_source_counts = _deep_scan_source_counts()
    expected_sources = sorted(expected_source_counts)
    source_counts = dict.fromkeys(expected_sources, 0)
    unexpected_sources: dict[str, int] = {}
    for finding in findings:
        source = finding.get("source", "unknown")
        if not isinstance(source, str):
            source = "unknown"
        if source in source_counts:
            source_counts[source] += 1
        else:
            unexpected_sources[source] = unexpected_sources.get(source, 0) + 1

    entries = [{"source": source, "findings": count} for source, count in sorted(source_counts.items())]
    entries.extend(
        {"source": source, "findings": count, "unexpected": True}
        for source, count in sorted(unexpected_sources.items())
    )
    return {
        "total_sources": len(expected_sources),
        "sources_with_findings": sum(1 for count in source_counts.values() if count > 0),
        "zero_finding_sources": sorted(source for source, count in source_counts.items() if count == 0),
        "unexpected_sources": sorted(unexpected_sources),
        "duplicate_expected_sources": sorted(source for source, count in expected_source_counts.items() if count > 1),
        "entries": entries,
    }


def _source_warnings(scanner_sources: dict[str, object]) -> list[str]:
    warnings: list[str] = []
    zero_finding_sources = scanner_sources.get("zero_finding_sources", [])
    if zero_finding_sources:
        sources = ", ".join(str(source) for source in zero_finding_sources)
        warnings.append(f"No findings were produced by scanner sources: {sources}.")

    unexpected_sources = scanner_sources.get("unexpected_sources", [])
    if unexpected_sources:
        sources = ", ".join(str(source) for source in unexpected_sources)
        warnings.append(f"Findings used unexpected scanner sources: {sources}.")

    duplicate_sources = scanner_sources.get("duplicate_expected_sources", [])
    if duplicate_sources:
        sources = ", ".join(str(source) for source in duplicate_sources)
        warnings.append(f"Scanner source labels are reused in deep scan: {sources}.")
    return warnings


def _finding_summary(findings: list[dict]) -> dict[str, object]:
    severity_counts: Counter[str] = Counter()
    source_counts: dict[str, Counter[str]] = {}
    rule_counts: dict[str, Counter[str]] = {}
    for finding in findings:
        severity = _normalized_severity(finding.get("severity"))
        source = str(finding.get("source") or "unknown")
        rule_id = str(finding.get("rule_id") or "unknown")
        severity_counts[severity] += 1
        source_counts.setdefault(source, Counter())[severity] += 1
        rule_counts.setdefault(rule_id, Counter())[severity] += 1

    return {
        "total_findings": len(findings),
        "severity_counts": {severity: severity_counts.get(severity, 0) for severity in _SEVERITY_ORDER},
        "sources": [
            {
                "source": source,
                "total": sum(counts.values()),
                "severity_counts": {severity: counts.get(severity, 0) for severity in _SEVERITY_ORDER},
                "max_severity": _max_severity(counts),
            }
            for source, counts in sorted(
                source_counts.items(),
                key=lambda item: (_descending_weighted_severity_key(item[1]), item[0]),
            )
        ],
        "top_rules": [
            {
                "rule_id": rule_id,
                "findings": sum(counts.values()),
                "severity_counts": {severity: counts.get(severity, 0) for severity in _SEVERITY_ORDER},
                "max_severity": _max_severity(counts),
            }
            for rule_id, counts in sorted(
                rule_counts.items(),
                key=lambda item: (_descending_weighted_severity_key(item[1]), item[0]),
            )[:25]
        ],
    }


def _taxonomy_coverage(findings: list[dict]) -> dict[str, object]:
    by_rule = _findings_by_rule(findings)
    mapped_entries: list[dict[str, object]] = []
    unmapped_rule_ids: list[str] = []
    cwe_counts: Counter[str] = Counter()
    shape_counts: Counter[str] = Counter()

    for rule_id, rule_findings in sorted(by_rule.items()):
        taxonomy = _security_taxonomy_for_rule(rule_id, rule_findings)
        if not taxonomy:
            unmapped_rule_ids.append(rule_id)
            continue
        cwes = _string_list(taxonomy.get("cwe", []))
        shape = str(taxonomy.get("taxonomy_shape") or "explicit")
        mapped_entries.append(
            {
                "rule_id": rule_id,
                "finding_count": len(rule_findings),
                "shape": shape,
                "cwe": cwes,
                "capec": _string_list(taxonomy.get("capec", [])),
                "owasp": taxonomy.get("owasp"),
            }
        )
        cwe_counts.update(cwes)
        shape_counts[shape] += 1

    total = len(by_rule)
    mapped = len(mapped_entries)
    return {
        "total_emitted_rules": total,
        "mapped_rules": mapped,
        "unmapped_rules": len(unmapped_rule_ids),
        "coverage_ratio": round(mapped / total, 4) if total else 1.0,
        "unmapped_rule_ids": unmapped_rule_ids,
        "mapped_entries": mapped_entries,
        "cwe_counts": [{"cwe": cwe, "rules": count} for cwe, count in sorted(cwe_counts.items())],
        "shape_counts": [{"shape": shape, "rules": count} for shape, count in sorted(shape_counts.items())],
    }


def _taxonomy_warnings(taxonomy_coverage: dict[str, object]) -> list[str]:
    unmapped = taxonomy_coverage.get("unmapped_rule_ids", [])
    if not unmapped:
        return []
    preview = ", ".join(str(rule_id) for rule_id in unmapped[:20])
    suffix = f" (+{len(unmapped) - 20} more)" if len(unmapped) > 20 else ""
    return [f"Emitted rule IDs without CWE taxonomy mapping: {preview}{suffix}."]


def build_taxonomy_gate(taxonomy_coverage: dict[str, object], *, fail_on_unmapped: bool = False) -> dict[str, object]:
    """Build a CI-friendly gate for taxonomy mapping drift."""
    unmapped = [str(rule_id) for rule_id in taxonomy_coverage.get("unmapped_rule_ids", [])]
    blocking = sorted(unmapped) if fail_on_unmapped else []
    return {
        "fail_on_unmapped_taxonomy": fail_on_unmapped,
        "passed": not blocking,
        "total_emitted_rules": int(taxonomy_coverage.get("total_emitted_rules", 0) or 0),
        "mapped_rules": int(taxonomy_coverage.get("mapped_rules", 0) or 0),
        "unmapped_rules": len(unmapped),
        "coverage_ratio": float(taxonomy_coverage.get("coverage_ratio", 1.0) or 0.0),
        "blocking_rules": len(blocking),
        "blocking_rule_ids": blocking[:100],
        "truncated": len(blocking) > 100,
    }


def build_governance_gate(
    accepted_summary: dict[str, object],
    fix_summary: dict[str, object],
    *,
    fail_on_policy_errors: bool = False,
    fail_on_expired_accepted_risk: bool = False,
    fail_on_overdue_fix: bool = False,
    fail_on_fix_regression: bool = False,
) -> dict[str, object]:
    """Build a CI gate for accepted-risk and fix-list policy health."""
    conditions = [
        {
            "id": "policy-errors",
            "enabled": fail_on_policy_errors,
            "count": int(accepted_summary.get("errors", 0) or 0) + int(fix_summary.get("errors", 0) or 0),
            "description": "accepted-risk or fix-list loader/validation errors",
        },
        {
            "id": "expired-accepted-risks",
            "enabled": fail_on_expired_accepted_risk,
            "count": int(accepted_summary.get("expired_entries", 0) or 0)
            + int(accepted_summary.get("expired_matches", 0) or 0),
            "description": "expired accepted-risk entries or expired accepted-risk finding matches",
        },
        {
            "id": "overdue-fixes",
            "enabled": fail_on_overdue_fix,
            "count": int(fix_summary.get("overdue", 0) or 0),
            "description": "open or in-progress fix-list entries past target date and still present",
        },
        {
            "id": "fix-regressions",
            "enabled": fail_on_fix_regression,
            "count": int(fix_summary.get("regressions", 0) or 0),
            "description": "fix-list entries marked fixed but still matching findings",
        },
    ]
    blocking = [condition for condition in conditions if condition["enabled"] and condition["count"] > 0]
    return {
        "passed": not blocking,
        "blocking_conditions": len(blocking),
        "blocking": blocking,
        "conditions": conditions,
    }


def _module_risk(
    repo: Path, module_roots: list[Path], routes: list[dict[str, object]], findings: list[dict]
) -> dict[str, object]:
    modules = [{"module": module.name, "path": module} for module in sorted(module_roots)]
    route_counts: dict[str, Counter[str]] = {module["module"]: Counter() for module in modules}
    finding_counts: dict[str, Counter[str]] = {module["module"]: Counter() for module in modules}
    rule_counts: dict[str, Counter[str]] = {module["module"]: Counter() for module in modules}

    for route in routes:
        module = _module_for_repo_path(repo / str(route["file"]), modules)
        if module is None:
            continue
        route_counts[module]["total"] += 1
        if route.get("auth") in {"public", "none"}:
            route_counts[module]["public"] += 1
        if route.get("has_findings"):
            route_counts[module]["with_findings"] += 1

    for finding in findings:
        path = _finding_path(repo, finding)
        module = _module_for_repo_path(path, modules) if path is not None else None
        if module is None:
            continue
        severity = _normalized_severity(finding.get("severity"))
        rule_id = str(finding.get("rule_id") or "unknown")
        finding_counts[module][severity] += 1
        rule_counts[module][rule_id] += 1

    rows: list[dict[str, object]] = []
    for module in modules:
        name = module["module"]
        severity_counts = {severity: finding_counts[name].get(severity, 0) for severity in _SEVERITY_ORDER}
        finding_score = sum(severity_counts[severity] * _SEVERITY_SCORE[severity] for severity in _SEVERITY_ORDER)
        score = (
            finding_score
            + route_counts[name].get("total", 0)
            + route_counts[name].get("public", 0) * 5
            + route_counts[name].get("with_findings", 0) * 3
        )
        rows.append(
            {
                "module": name,
                "path": str(Path(module["path"]).relative_to(repo)),
                "score": score,
                "band": _module_risk_band(score),
                "findings": sum(severity_counts.values()),
                "severity_counts": severity_counts,
                "routes": route_counts[name].get("total", 0),
                "public_routes": route_counts[name].get("public", 0),
                "routes_with_findings": route_counts[name].get("with_findings", 0),
                "top_rules": [
                    {"rule_id": rule_id, "findings": count} for rule_id, count in rule_counts[name].most_common(10)
                ],
            }
        )

    rows.sort(key=lambda row: (-int(row["score"]), str(row["module"])))
    band_counts: Counter[str] = Counter(str(row["band"]) for row in rows)
    return {
        "total_modules": len(rows),
        "band_counts": {band: band_counts.get(band, 0) for band in ("critical", "high", "medium", "low")},
        "modules": rows,
    }


def _module_for_repo_path(path: Path, modules: list[dict[str, object]]) -> str | None:
    resolved = path.resolve()
    for module in modules:
        module_path = Path(module["path"]).resolve()
        if _is_relative_to(resolved, module_path):
            return str(module["module"])
    return None


def _module_risk_band(score: int) -> str:
    if score >= 250:
        return "critical"
    if score >= 100:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _normalized_severity(value: object) -> str:
    severity = str(value or "medium").lower()
    return severity if severity in _SEVERITY_RANK else "medium"


def _max_severity(counts: Counter[str]) -> str:
    for severity in _SEVERITY_ORDER:
        if counts.get(severity, 0):
            return severity
    return "info"


def _weighted_severity_count(counts: Counter[str]) -> tuple[int, int, int, int, int, int]:
    return (
        counts.get("critical", 0),
        counts.get("high", 0),
        counts.get("medium", 0),
        counts.get("low", 0),
        counts.get("info", 0),
        sum(counts.values()),
    )


def _descending_weighted_severity_key(counts: Counter[str]) -> tuple[int, int, int, int, int, int]:
    return tuple(-value for value in _weighted_severity_count(counts))


def _scanner_registry_coverage() -> dict[str, object]:
    exported = _exported_deep_scan_callables()
    called = _deep_scan_called_callables()
    wired = exported & called
    source_counts = _deep_scan_source_counts()
    manifest = _deep_scan_manifest()
    manifest_callables = {entry["callable"] for entry in manifest}
    manifest_sources = {entry["source"] for entry in manifest}
    return {
        "total_exported": len(exported),
        "wired_exported": len(wired),
        "source_labels": len(source_counts),
        "source_label_occurrences": sum(source_counts.values()),
        "source_labels_match_wired": len(source_counts) == len(wired),
        "exported_callables": sorted(exported),
        "wired_callables": sorted(wired),
        "missing_from_deep_scan": sorted(exported - called),
        "manifest_entries": manifest,
        "callables_without_source": sorted(wired - manifest_callables),
        "sources_without_callable": sorted(set(source_counts) - manifest_sources),
    }


def _registry_warnings(scanner_registry: dict[str, object]) -> list[str]:
    warnings: list[str] = []
    missing = scanner_registry.get("missing_from_deep_scan", [])
    if missing:
        callables = ", ".join(str(callable_name) for callable_name in missing)
        warnings.append(f"Exported scanner callables missing from deep scan: {callables}.")

    if scanner_registry.get("source_labels_match_wired") is False:
        warnings.append(
            "Scanner source labels do not match wired callables: "
            f"{scanner_registry.get('source_labels', '?')} source labels for "
            f"{scanner_registry.get('wired_exported', '?')} wired callables."
        )

    callables_without_source = scanner_registry.get("callables_without_source", [])
    if callables_without_source:
        callables = ", ".join(str(callable_name) for callable_name in callables_without_source)
        warnings.append(f"Wired scanner callables without source labels: {callables}.")

    sources_without_callable = scanner_registry.get("sources_without_callable", [])
    if sources_without_callable:
        sources = ", ".join(str(source) for source in sources_without_callable)
        warnings.append(f"Scanner source labels without wired callables: {sources}.")
    return warnings


def _rule_catalog_coverage(findings: list[dict]) -> dict[str, object]:
    catalog = _rule_catalog()
    declared_rules = {entry["rule_id"] for entry in catalog}
    emitted_counts: Counter[str] = Counter()
    for finding in findings:
        rule_id = finding.get("rule_id")
        if isinstance(rule_id, str) and rule_id:
            emitted_counts[rule_id] += 1

    emitted_rules = set(emitted_counts)
    return {
        "total_rules": len(declared_rules),
        "total_occurrences": len(catalog),
        "emitted_rules": len(emitted_rules),
        "unemitted_rules": sorted(declared_rules - emitted_rules),
        "undocumented_rule_ids": sorted(emitted_rules - declared_rules),
        "entries": [
            {
                "rule_id": rule_id,
                "emitted_findings": emitted_counts.get(rule_id, 0),
                "locations": [
                    {"file": entry["file"], "line": entry["line"]} for entry in catalog if entry["rule_id"] == rule_id
                ],
            }
            for rule_id in sorted(declared_rules)
        ],
    }


def _rule_catalog_warnings(rule_catalog: dict[str, object]) -> list[str]:
    undocumented = rule_catalog.get("undocumented_rule_ids", [])
    if not undocumented:
        return []
    rules = ", ".join(str(rule_id) for rule_id in undocumented)
    return [f"Findings used undocumented rule IDs: {rules}."]


def _rule_catalog() -> list[dict[str, object]]:
    package_root = Path(__file__).resolve().parents[1]
    entries: list[dict[str, object]] = []
    seen: set[tuple[str, str, int]] = set()
    for path in sorted(package_root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        rel_path = path.relative_to(package_root.parent).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if not node.value.startswith("odoo-"):
                continue
            line = getattr(node, "lineno", 0)
            key = (node.value, rel_path, line)
            if key in seen:
                continue
            seen.add(key)
            entries.append({"rule_id": node.value, "file": rel_path, "line": line})
    return sorted(entries, key=lambda entry: (str(entry["rule_id"]), str(entry["file"]), int(entry["line"])))


def _exported_deep_scan_callables() -> set[str]:
    init_path = Path(__file__).resolve().parents[1] / "__init__.py"
    try:
        tree = ast.parse(init_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return set()

    exported: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets):
            continue
        if not isinstance(node.value, ast.List):
            continue
        exported.update(
            element.value
            for element in node.value.elts
            if isinstance(element, ast.Constant)
            and isinstance(element.value, str)
            and (
                element.value.startswith("scan_")
                or element.value in {"analyze_access_control", "analyze_directory", "check_multi_company_isolation"}
            )
        )
    return exported


def _deep_scan_called_callables() -> set[str]:
    try:
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return set()
    return {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}


def _deep_scan_manifest() -> list[dict[str, object]]:
    try:
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []

    exported = _exported_deep_scan_callables()
    calls = sorted(
        (node.lineno, node.func.id)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in exported
    )
    source_nodes = sorted(_deep_scan_source_nodes(tree))
    entries: list[dict[str, object]] = []
    used_source_indexes: set[int] = set()

    for index, (line, callable_name) in enumerate(calls):
        next_line = calls[index + 1][0] if index + 1 < len(calls) else sys.maxsize
        for source_index, (source_line, source) in enumerate(source_nodes):
            if source_index in used_source_indexes:
                continue
            if line < source_line < next_line:
                entries.append({"callable": callable_name, "source": source, "line": line})
                used_source_indexes.add(source_index)
                break
    return entries


def _deep_scan_sources() -> list[str]:
    return sorted(_deep_scan_source_counts())


def _deep_scan_source_counts() -> Counter[str]:
    try:
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return Counter()

    return Counter(source for _, source in _deep_scan_source_nodes(tree))


def _deep_scan_source_nodes(tree: ast.AST) -> list[tuple[int, str]]:
    sources: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values):
            if (
                isinstance(key, ast.Constant)
                and key.value == "source"
                and isinstance(value, ast.Constant)
                and isinstance(value.value, str)
            ):
                sources.append((getattr(value, "lineno", getattr(node, "lineno", 0)), value.value))
    return sources


def _repo_files(repo: Path, suffixes: set[str]) -> list[Path]:
    return sorted(
        path for path in repo.rglob("*") if path.is_file() and path.suffix in suffixes and not _should_skip(path)
    )


def _module_roots(repo: Path) -> list[Path]:
    roots = {
        path.parent.resolve()
        for manifest_name in ("__manifest__.py", "__openerp__.py")
        for path in repo.rglob(manifest_name)
        if not _should_skip(path)
    }
    return sorted(roots)


def _controller_files(python_files: list[Path]) -> list[Path]:
    controllers: list[Path] = []
    for path in python_files:
        text = _read_text(path)
        if "/controllers/" in path.as_posix() or "@http.route" in text or "@route" in text:
            controllers.append(path)
    return controllers


def _route_inventory(repo: Path, python_files: list[Path]) -> list[dict[str, str | int]]:
    routes: list[dict[str, str | int]] = []
    for path in python_files:
        text = _read_text(path)
        try:
            tree = ast.parse(text)
        except SyntaxError:
            routes.extend(_regex_route_inventory(repo, path, text))
            continue
        visitor = _RouteInventoryVisitor(repo, path, _module_constants(tree))
        visitor.visit(tree)
        routes.extend(visitor.routes)
    return routes


ROUTE_DECORATOR_RE = re.compile(
    r"@(?:(?:[A-Za-z_][A-Za-z0-9_]*\.)?http|[A-Za-z_][A-Za-z0-9_]*_http)\.route\((?P<args>.*?)\)",
    re.DOTALL,
)


def _regex_route_inventory(repo: Path, path: Path, text: str) -> list[dict[str, str | int]]:
    routes: list[dict[str, str | int]] = []
    for match in ROUTE_DECORATOR_RE.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        tail = text[match.end() : match.end() + 500]
        def_match = re.search(r"(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", tail)
        route = _regex_route_from_args(match.group("args"))
        routes.append(
            {
                "file": str(path.relative_to(repo)),
                "line": line,
                "end_line": line,
                "function": def_match.group(1) if def_match else "<unknown>",
                "route": route["route"],
                "auth": route["auth"],
                "csrf": route["csrf"],
                "type": route["type"],
                "methods": route["methods"],
            }
        )
    return routes


def _regex_route_from_args(args_text: str) -> dict[str, str]:
    try:
        node = ast.parse(f"_route({args_text})", mode="eval")
    except SyntaxError:
        return {"route": "<dynamic>", "auth": "user", "csrf": "True", "type": "http", "methods": ""}
    if not isinstance(node.body, ast.Call):
        return {"route": "<dynamic>", "auth": "user", "csrf": "True", "type": "http", "methods": ""}
    route = _route_text(node.body.args[0]) if node.body.args else "<dynamic>"
    auth = "user"
    csrf = "True"
    route_type = "http"
    methods = ""
    for keyword in node.body.keywords:
        if keyword.arg == "auth":
            value = keyword.value
            if isinstance(value, ast.Constant):
                auth = str(value.value)
        elif keyword.arg == "csrf":
            value = keyword.value
            if isinstance(value, ast.Constant):
                csrf = str(value.value)
        elif keyword.arg == "type":
            value = keyword.value
            if isinstance(value, ast.Constant):
                route_type = str(value.value)
        elif keyword.arg == "methods":
            methods = _route_text(keyword.value)
        elif keyword.arg in {"route", "routes"}:
            route = _route_text(keyword.value)
    return {"route": route, "auth": auth, "csrf": csrf, "type": route_type, "methods": methods}


class _RouteInventoryVisitor(ast.NodeVisitor):
    def __init__(self, repo: Path, path: Path, module_constants: dict[str, ast.AST]) -> None:
        self.repo = repo
        self.path = path
        self.module_constants = module_constants
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.route_decorator_names: set[str] = set()
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.routes: list[dict[str, str | int]] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "odoo":
                self.odoo_module_names.add(alias.asname or alias.name)
            elif alias.name == "odoo.http" and alias.asname:
                self.http_module_names.add(alias.asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "odoo":
            for alias in node.names:
                if alias.name == "http":
                    self.http_module_names.add(alias.asname or alias.name)
        elif node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "route":
                    self.route_decorator_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)
        self.generic_visit(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        constants = self._effective_constants()
        for decorator in node.decorator_list:
            route = _route_from_decorator(
                decorator,
                constants,
                http_module_names=self.http_module_names,
                odoo_module_names=self.odoo_module_names,
                route_decorator_names=self.route_decorator_names,
            )
            if route is None:
                continue
            self.routes.append(
                {
                    "file": str(self.path.relative_to(self.repo)),
                    "line": getattr(decorator, "lineno", node.lineno),
                    "end_line": getattr(node, "end_lineno", node.lineno),
                    "function": node.name,
                    "route": route["route"],
                    "auth": route["auth"],
                    "csrf": route["csrf"],
                    "type": route["type"],
                    "methods": route["methods"],
                }
            )

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack:
            return self.module_constants
        constants = dict(self.module_constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants


def _route_from_decorator(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    *,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
    route_decorator_names: set[str] | None = None,
) -> dict[str, str] | None:
    if not _is_http_route(
        node,
        http_module_names=http_module_names,
        odoo_module_names=odoo_module_names,
        route_decorator_names=route_decorator_names,
    ):
        return None
    constants = constants or {}
    auth = "user"
    csrf = "True"
    route_type = "http"
    methods = ""
    route = "<unknown>"
    if isinstance(node, ast.Call):
        if node.args:
            route = _route_text(node.args[0], constants)
        for keyword in node.keywords:
            for key, value in _route_keyword_items(keyword, constants).items():
                if key == "auth" and isinstance(value, ast.Constant):
                    auth = str(value.value)
                elif key == "csrf" and isinstance(value, ast.Constant):
                    csrf = str(value.value)
                elif key == "type" and isinstance(value, ast.Constant):
                    route_type = str(value.value)
                elif key == "methods":
                    methods = _route_text(value, constants)
                elif key in {"route", "routes"}:
                    route = _route_text(value, constants)
    return {"route": route, "auth": auth, "csrf": csrf, "type": route_type, "methods": methods}


def _route_keyword_items(keyword: ast.keyword, constants: dict[str, ast.AST]) -> dict[str, ast.AST]:
    if keyword.arg is not None:
        return {keyword.arg: _resolve_constant(keyword.value, constants)}
    value = _resolve_constant(keyword.value, constants)
    if not isinstance(value, ast.Dict):
        return {}
    items: dict[str, ast.AST] = {}
    for raw_key, raw_value in zip(value.keys, value.values, strict=True):
        key = _resolve_constant(raw_key, constants) if raw_key is not None else raw_key
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            continue
        items[key.value] = _resolve_constant(raw_value, constants)
    return items


def _is_http_route(
    node: ast.AST,
    *,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
    route_decorator_names: set[str] | None = None,
) -> bool:
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    route_decorator_names = route_decorator_names or set()
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Attribute):
        return target.attr == "route" and _is_odoo_http_expr(
            target.value,
            http_module_names=http_module_names,
            odoo_module_names=odoo_module_names,
        )
    if isinstance(target, ast.Name):
        return target.id in route_decorator_names
    return False


def _is_odoo_http_expr(
    node: ast.AST,
    *,
    http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in http_module_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "http"
        and isinstance(node.value, ast.Name)
        and node.value.id in odoo_module_names
    )


def _route_text(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> str:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        values = [
            element.value
            for raw_element in node.elts
            if isinstance((element := _resolve_constant(raw_element, constants)), ast.Constant)
        ]
        return ",".join(str(value) for value in values)
    return "<dynamic>"


def _module_constants(tree: ast.Module) -> dict[str, ast.AST]:
    return _static_constants_from_body(tree.body)


def _static_constants_from_body(statements: list[ast.stmt]) -> dict[str, ast.AST]:
    constants: dict[str, ast.AST] = {}
    for statement in statements:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name) and _is_static_literal(statement.value):
                    constants[target.id] = statement.value
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.value is not None
            and _is_static_literal(statement.value)
        ):
            constants[statement.target.id] = statement.value
    return constants


def _resolve_constant(node: ast.AST, constants: dict[str, ast.AST], seen: set[str] | None = None) -> ast.AST:
    seen = seen or set()
    if isinstance(node, ast.Name):
        if node.id in seen:
            return node
        value = constants.get(node.id)
        if value is None:
            return node
        seen.add(node.id)
        return _resolve_constant(value, constants, seen)
    return node


def _is_static_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str | bool | int | float | type(None))
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(isinstance(element, ast.Constant | ast.Name) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (
                key is None
                or (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and _is_static_literal(value)
                )
            )
            for key, value in zip(node.keys, node.values, strict=True)
        )
    if isinstance(node, ast.Name):
        return True
    return False


def _finding_path(repo: Path, finding: dict) -> Path | None:
    raw_file = finding.get("file")
    if not isinstance(raw_file, str) or not raw_file:
        return None
    path = Path(raw_file)
    if not path.is_absolute():
        path = repo / path
    try:
        return path.resolve()
    except Exception:
        return path


def _finding_locations(repo: Path, findings: list[dict]) -> set[tuple[Path, int | None]]:
    locations: set[tuple[Path, int | None]] = set()
    for finding in findings:
        path = _finding_path(repo, finding)
        if path is None:
            continue
        raw_line = finding.get("line")
        line = raw_line if isinstance(raw_line, int) else None
        locations.add((path, line))
    return locations


def _route_has_findings(repo: Path, route: dict[str, object], locations: set[tuple[Path, int | None]]) -> bool:
    route_file = (repo / str(route["file"])).resolve()
    start = int(route["line"])
    end = int(route.get("end_line") or start)
    for finding_file, line in locations:
        if finding_file != route_file:
            continue
        if line is None or start <= line <= end:
            return True
    return False


def _surface_metric(total: int, with_findings: int) -> dict[str, int | float]:
    return {
        "total": total,
        "with_findings": with_findings,
        "coverage_ratio": round(with_findings / total, 4) if total else 1.0,
    }


def _coverage_warnings(surfaces: dict[str, dict[str, int | float]]) -> list[str]:
    warnings: list[str] = []
    for surface, metric in surfaces.items():
        total = int(metric["total"])
        with_findings = int(metric["with_findings"])
        ratio = float(metric["coverage_ratio"])
        if total > 0 and with_findings == 0:
            warnings.append(f"No findings were associated with discovered {surface.replace('_', ' ')}.")
        elif total >= 10 and ratio < 0.05:
            warnings.append(
                f"Very low finding coverage for {surface.replace('_', ' ')}: " f"{with_findings}/{total} ({ratio:.2%})."
            )
    return warnings


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def generate_report(findings: list[dict]) -> str:
    """Generate Markdown report from findings."""
    lines = [
        "# Odoo Security Deep Scan Report",
        "",
        f"**Total Findings:** {len(findings)}",
        "",
        "## Findings by Source",
        "",
    ]

    # Group by source
    by_source: dict[str, list[dict]] = {}
    for f in findings:
        source = f.get("source", "unknown")
        by_source.setdefault(source, []).append(f)

    for source, source_findings in sorted(by_source.items()):
        lines.append(f"### {source.title()}")
        lines.append("")
        lines.append(f"Found {len(source_findings)} issues:")
        lines.append("")
        lines.append("| Severity | Title | File | Line |")
        lines.append("|----------|-------|------|------|")
        for f in sorted(source_findings, key=lambda x: x.get("severity", "")):
            lines.append(
                f"| {f.get('severity', '?')} | {f.get('title', '?')} | "
                f"`{f.get('file', '?')}` | {f.get('line', '?')} |"
            )
        lines.append("")

    return "\n".join(lines)


def generate_html_report(findings: list[dict], coverage_report: dict[str, object] | None = None) -> str:
    """Generate a self-contained HTML triage report from deep-scan findings."""
    coverage_report = coverage_report or {}
    severity_counts = Counter(str(f.get("severity", "unknown")).lower() for f in findings)
    module_risk = coverage_report.get("module_risk", {}) if isinstance(coverage_report, dict) else {}
    modules = module_risk.get("modules", []) if isinstance(module_risk, dict) else []
    generated_at = date.today().isoformat()
    rows = "\n".join(_html_finding_row(finding) for finding in findings)
    details = "\n".join(_html_finding_detail(finding) for finding in findings)
    module_rows = "\n".join(_html_module_risk_row(module) for module in modules[:25])
    if not module_rows:
        module_rows = '<tr><td colspan="5">No module risk inventory available.</td></tr>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Odoo Deep Scan Findings</title>
  <style>
    :root {{
      color-scheme: light;
      --critical: #b42318;
      --high: #c2410c;
      --medium: #a16207;
      --low: #475569;
      --info: #64748b;
      --line: #d7dde8;
      --bg: #f8fafc;
      --panel: #ffffff;
      --text: #0f172a;
      --muted: #475569;
      font-family: Arial, Helvetica, sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--text); }}
    header, main, footer {{ max-width: 1180px; margin: 0 auto; padding: 24px; }}
    header {{ padding-top: 32px; }}
    h1 {{ margin: 0 0 8px; font-size: 28px; }}
    h2 {{ margin: 28px 0 12px; font-size: 20px; }}
    p {{ color: var(--muted); }}
    table {{ width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); }}
    th, td {{ padding: 9px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }}
    th {{ background: #e9eef6; cursor: pointer; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(135px, 1fr)); gap: 10px; margin-top: 18px; }}
    .stat, details, .toolbar {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 12px; }}
    .stat strong {{ display: block; font-size: 22px; }}
    .filter-bar {{ margin: 18px 0; display: flex; gap: 8px; }}
    .filter-bar input {{ flex: 1; padding: 10px; border: 1px solid var(--line); border-radius: 6px; }}
    .sev {{ display: inline-block; min-width: 72px; padding: 3px 7px; border-radius: 999px; color: white; text-align: center; font-size: 12px; font-weight: 700; }}
    .sev-critical {{ background: var(--critical); }}
    .sev-high {{ background: var(--high); }}
    .sev-medium {{ background: var(--medium); }}
    .sev-low {{ background: var(--low); }}
    .sev-info {{ background: var(--info); }}
    code, pre {{ background: #eef2f7; border-radius: 6px; }}
    code {{ padding: 2px 4px; }}
    pre {{ padding: 12px; overflow-x: auto; }}
    details {{ margin: 12px 0; }}
    summary {{ cursor: pointer; font-weight: 700; }}
    button, select, input {{ font: inherit; }}
    button {{ border: 1px solid var(--line); background: #ffffff; border-radius: 6px; padding: 7px 10px; cursor: pointer; }}
    button[aria-pressed="true"] {{ background: #dbeafe; border-color: #60a5fa; }}
    .triage-controls {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }}
    .toolbar {{ position: sticky; bottom: 0; margin-top: 24px; box-shadow: 0 -4px 16px rgba(15, 23, 42, 0.08); }}
    .toolbar-actions {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 8px 0; }}
    .hidden {{ display: none; }}
    @media print {{
      .filter-bar, .toolbar, button {{ display: none; }}
      details {{ break-inside: avoid; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>Odoo Deep Scan Findings</h1>
    <p>Generated {html.escape(generated_at)}. Single-file offline report with accepted-risk and fix-list triage queues.</p>
    <section class="stats" aria-label="Finding summary">
      {_html_stat("Total", len(findings))}
      {_html_stat("Critical", severity_counts.get("critical", 0))}
      {_html_stat("High", severity_counts.get("high", 0))}
      {_html_stat("Medium", severity_counts.get("medium", 0))}
      {_html_stat("Low", severity_counts.get("low", 0))}
    </section>
  </header>
  <main>
    <section aria-labelledby="module-risk-heading">
      <h2 id="module-risk-heading">Module Risk</h2>
      <table>
        <thead><tr><th>Module</th><th>Band</th><th>Score</th><th>Findings</th><th>Public Routes</th></tr></thead>
        <tbody>{module_rows}</tbody>
      </table>
    </section>
    <section aria-labelledby="findings-heading">
      <h2 id="findings-heading">Findings</h2>
      <div class="filter-bar">
        <input id="filter" type="search" aria-label="Filter findings" placeholder="Filter findings by rule, severity, file, title, or triage state">
      </div>
      <table id="findings-table">
        <thead>
          <tr>
            <th data-sort aria-label="Sort by id">ID</th>
            <th data-sort aria-label="Sort by severity">Severity</th>
            <th data-sort aria-label="Sort by triage">Triage</th>
            <th data-sort aria-label="Sort by rule">Rule</th>
            <th data-sort aria-label="Sort by file">File:Line</th>
            <th data-sort aria-label="Sort by title">Title</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </section>
    <section aria-labelledby="details-heading">
      <h2 id="details-heading">Finding Details</h2>
      {details}
    </section>
    <section class="toolbar" aria-label="Triage export toolbar">
      <strong>Triage Queues</strong>
      <p><span id="ar-count">0</span> accepted-risk additions. <span id="fl-count">0</span> fix-list additions.</p>
      <div class="toolbar-actions">
        <button type="button" id="copy-ar">Copy accepted-risks YAML</button>
        <button type="button" id="copy-fl">Copy fix-list YAML</button>
        <button type="button" id="download-ar">Download accepted-risks additions</button>
        <button type="button" id="download-fl">Download fix-list additions</button>
        <button type="button" id="clear-queues">Clear queues</button>
      </div>
      <pre id="triage-preview" aria-live="polite"></pre>
    </section>
  </main>
  <footer>
    <p>Open this file locally; it has no external dependencies or network calls.</p>
  </footer>
  <script>
    const ar = new Map();
    const fl = new Map();
    function yamlValue(value) {{
      return String(value || "").replace(/"/g, '\\"');
    }}
    function arYaml() {{
      const entries = [...ar.values()];
      const body = entries.map((f, idx) => [
        "  - id: AR-NEW-" + String(idx + 1).padStart(3, "0"),
        "    title: \\"" + yamlValue(f.title) + "\\"",
        "    fingerprint: \\"" + yamlValue(f.fingerprint) + "\\"",
        "    file: \\"" + yamlValue(f.file) + "\\"",
        "    lines: " + yamlValue(f.line || 1),
        "    rule_id: \\"" + yamlValue(f.rule) + "\\"",
        "    severity: \\"" + yamlValue(f.severity) + "\\"",
        "    reason: \\"TODO: document compensating control or false-positive reason\\"",
        "    owner: \\"security@example.com\\"",
        "    accepted: \\"" + new Date().toISOString().slice(0, 10) + "\\"",
        "    expires: \\"TODO: YYYY-MM-DD\\"",
      ].join("\\n")).join("\\n");
      return "# Generated by findings.html accepted-risk queue\\nversion: 1\\nrisks:\\n" + (body || "  []") + "\\n";
    }}
    function flYaml() {{
      const entries = [...fl.values()];
      const body = entries.map((f, idx) => [
        "  - id: FIX-NEW-" + String(idx + 1).padStart(3, "0"),
        "    title: \\"" + yamlValue(f.title) + "\\"",
        "    fingerprint: \\"" + yamlValue(f.fingerprint) + "\\"",
        "    file: \\"" + yamlValue(f.file) + "\\"",
        "    lines: " + yamlValue(f.line || 1),
        "    rule_id: \\"" + yamlValue(f.rule) + "\\"",
        "    severity: \\"" + yamlValue(f.severity) + "\\"",
        "    owner: \\"security@example.com\\"",
        "    status: open",
        "    target_date: \\"TODO: YYYY-MM-DD\\"",
      ].join("\\n")).join("\\n");
      return "# Generated by findings.html fix-list queue\\nversion: 1\\nfixes:\\n" + (body || "  []") + "\\n";
    }}
    function refresh() {{
      document.getElementById("ar-count").textContent = ar.size;
      document.getElementById("fl-count").textContent = fl.size;
      document.getElementById("triage-preview").textContent = arYaml() + "\\n" + flYaml();
    }}
    function findingData(button) {{
      const card = button.closest("[data-fingerprint]");
      return {{
        fingerprint: card.dataset.fingerprint,
        id: card.dataset.findingId,
        rule: card.dataset.rule,
        severity: card.dataset.severity,
        file: card.dataset.file,
        line: card.dataset.line,
        title: card.dataset.title,
      }};
    }}
    document.querySelectorAll(".ar-toggle").forEach((button) => {{
      button.addEventListener("click", () => {{
        const data = findingData(button);
        if (ar.has(data.fingerprint)) {{
          ar.delete(data.fingerprint);
          button.setAttribute("aria-pressed", "false");
        }} else {{
          fl.delete(data.fingerprint);
          ar.set(data.fingerprint, data);
          button.setAttribute("aria-pressed", "true");
          button.parentElement.querySelector(".fl-toggle").setAttribute("aria-pressed", "false");
        }}
        refresh();
      }});
    }});
    document.querySelectorAll(".fl-toggle").forEach((button) => {{
      button.addEventListener("click", () => {{
        const data = findingData(button);
        if (fl.has(data.fingerprint)) {{
          fl.delete(data.fingerprint);
          button.setAttribute("aria-pressed", "false");
        }} else {{
          ar.delete(data.fingerprint);
          fl.set(data.fingerprint, data);
          button.setAttribute("aria-pressed", "true");
          button.parentElement.querySelector(".ar-toggle").setAttribute("aria-pressed", "false");
        }}
        refresh();
      }});
    }});
    document.getElementById("filter").addEventListener("input", (event) => {{
      const query = event.target.value.toLowerCase();
      document.querySelectorAll(".finding-row").forEach((row) => {{
        row.hidden = query && !row.textContent.toLowerCase().includes(query);
      }});
    }});
    document.querySelectorAll("th[data-sort]").forEach((th) => {{
      th.addEventListener("click", () => {{
        const idx = [...th.parentNode.children].indexOf(th);
        const tbody = th.closest("table").tBodies[0];
        const rows = [...tbody.rows];
        const dir = th.dataset.dir === "asc" ? -1 : 1;
        th.dataset.dir = dir === 1 ? "asc" : "desc";
        rows.sort((a, b) => dir * a.cells[idx].textContent.localeCompare(b.cells[idx].textContent, undefined, {{ numeric: true }}));
        rows.forEach((row) => tbody.appendChild(row));
      }});
    }});
    async function copyText(text) {{
      await navigator.clipboard.writeText(text);
    }}
    function download(name, text) {{
      const blob = new Blob([text], {{ type: "text/yaml" }});
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = name;
      link.click();
      URL.revokeObjectURL(url);
    }}
    document.getElementById("copy-ar").addEventListener("click", () => copyText(arYaml()));
    document.getElementById("copy-fl").addEventListener("click", () => copyText(flYaml()));
    document.getElementById("download-ar").addEventListener("click", () => download("accepted-risks-additions.yml", arYaml()));
    document.getElementById("download-fl").addEventListener("click", () => download("fix-list-additions.yml", flYaml()));
    document.getElementById("clear-queues").addEventListener("click", () => {{
      ar.clear();
      fl.clear();
      document.querySelectorAll(".ar-toggle,.fl-toggle").forEach((button) => button.setAttribute("aria-pressed", "false"));
      refresh();
    }});
    refresh();
  </script>
</body>
</html>
"""


def _html_stat(label: str, value: object) -> str:
    return f'<div class="stat"><span>{html.escape(label)}</span><strong>{html.escape(str(value))}</strong></div>'


def _html_finding_row(finding: dict) -> str:
    severity = str(finding.get("severity", "info")).lower()
    file_name = html.escape(str(finding.get("file", "?")))
    line = html.escape(str(finding.get("line", "?")))
    return (
        '<tr class="finding-row">'
        f"<td>{html.escape(str(finding.get('id', '?')))}</td>"
        f'<td><span class="sev sev-{html.escape(severity)}">{html.escape(severity.upper())}</span></td>'
        f"<td>{html.escape(str(finding.get('triage', 'NEEDS-MANUAL')))}</td>"
        f"<td><code>{html.escape(str(finding.get('rule_id', '?')))}</code></td>"
        f"<td><code>{file_name}:{line}</code></td>"
        f"<td>{html.escape(str(finding.get('title', '?')))}</td>"
        "</tr>"
    )


def _html_finding_detail(finding: dict) -> str:
    severity = str(finding.get("severity", "info")).lower()
    fingerprint = str(finding.get("fingerprint", ""))
    file_name = str(finding.get("file", ""))
    line = str(finding.get("line", ""))
    rule_id = str(finding.get("rule_id", ""))
    title = str(finding.get("title", "Untitled finding"))
    message = str(finding.get("message", ""))
    governance = _html_governance_notes(finding)
    return f"""
<details
  class="finding"
  data-finding-id="{html.escape(str(finding.get('id', '')))}"
  data-fingerprint="{html.escape(fingerprint)}"
  data-rule="{html.escape(rule_id)}"
  data-severity="{html.escape(severity)}"
  data-file="{html.escape(file_name)}"
  data-line="{html.escape(line)}"
  data-title="{html.escape(title)}"
>
  <summary><span class="sev sev-{html.escape(severity)}">{html.escape(severity.upper())}</span> {html.escape(title)}</summary>
  <div class="triage-controls">
    <button type="button" class="ar-toggle" aria-pressed="false">Mark as accepted risk</button>
    <button type="button" class="fl-toggle" aria-pressed="false">Add to fix-it list</button>
  </div>
  <p><strong>Rule:</strong> <code>{html.escape(rule_id)}</code></p>
  <p><strong>Location:</strong> <code>{html.escape(file_name)}:{html.escape(line)}</code></p>
  <p><strong>Fingerprint:</strong> <code>{html.escape(fingerprint)}</code></p>
  {governance}
  <pre><code>{html.escape(message)}</code></pre>
</details>
"""


def _html_governance_notes(finding: dict) -> str:
    notes: list[str] = []
    if finding.get("fix_list_status"):
        fix_id = html.escape(str(finding.get("fix_list_id", "")))
        status = html.escape(str(finding.get("fix_list_status", "")))
        target = html.escape(str(finding.get("fix_list_target_date", "")))
        suffix = f" target {target}" if target else ""
        notes.append(f"<li>Fix-list: {status} {fix_id}{suffix}</li>")
    expired = finding.get("expired_accepted_risk_ids") or []
    if expired:
        notes.append(f"<li>Expired accepted risks: {html.escape(', '.join(str(item) for item in expired))}</li>")
    if not notes:
        return ""
    return "<ul>" + "".join(notes) + "</ul>"


def _html_module_risk_row(module: object) -> str:
    if not isinstance(module, dict):
        return ""
    band = str(module.get("band", "info")).lower()
    return (
        "<tr>"
        f"<td>{html.escape(str(module.get('module', '?')))}</td>"
        f'<td><span class="sev sev-{html.escape(band)}">{html.escape(band.upper())}</span></td>'
        f"<td>{html.escape(str(module.get('score', 0)))}</td>"
        f"<td>{html.escape(str(module.get('findings', 0)))}</td>"
        f"<td>{html.escape(str(module.get('public_routes', 0)))}</td>"
        "</tr>"
    )


if __name__ == "__main__":
    sys.exit(main())
