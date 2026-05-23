# Odoo Security Harness — Scanner Index

Compact reference for agent context windows.
For full implementation details, see individual scanner modules in `odoo_security_harness/`.

**Total scanners:** 75  
**Total unique rule IDs:** 950

---

## Quick Reference Table

| Scanner | Rules | Target | Description |
|---------|-------|--------|-------------|
| `__init__` | 0 | Python/XML | Odoo Application Security Harness - Core utilit... |
| `access_control` | 14 | __manifest__.py, __openerp_... | Access Control Analyzer - Automated analysis of... |
| `access_override_scanner` | 4 | *.py | Scanner for risky Odoo model access/search over... |
| `action_url_scanner` | 7 | Python/XML | Scanner for risky Odoo ir.actions.act_url usage |
| `action_window_scanner` | 8 | Python/XML | Scanner for risky Python-returned Odoo act_wind... |
| `ai_integration_scanner` | 3 | *.py | Scanner for AI/LLM integration security risks i... |
| `analyzer` | 33 | *.py | Odoo Deep Pattern Analyzer - AST-based analysis... |
| `api_key_scanner` | 8 | Python/XML | Scanner for risky Odoo API key creation, lookup... |
| `attachment_scanner` | 15 | *.py | Scanner for risky Odoo ir.attachment metadata a... |
| `automation_scanner` | 9 | Python/XML | Scanner for risky Odoo automated actions |
| `base_scanner` | 0 | Python/XML | Shared base classes and utilities for Odoo secu... |
| `binary_download_scanner` | 8 | *.py | Scanner for risky Odoo binary download and atta... |
| `button_action_scanner` | 5 | *.py | Scanner for risky Odoo button/action model methods |
| `cache_header_scanner` | 5 | *.py | Scanner for risky Odoo controller cache-control... |
| `config_parameter_scanner` | 13 | *.py | Scanner for risky runtime ir.config_parameter a... |
| `constraint_scanner` | 7 | *.py | Scanner for risky Odoo model constraint behavior |
| `controller_path_scanner` | 2 | *.py | Scanner for path traversal vulnerabilities in O... |
| `controller_response_scanner` | 22 | *.py | Scanner for risky Odoo controller response hand... |
| `data_integrity_scanner` | 10 | Python/XML | Scanner for risky Odoo XML data/external-ID int... |
| `database_scanner` | 5 | *.py | Scanner for risky Odoo database selection and m... |
| `default_value_scanner` | 8 | Python/XML | Scanner for risky Odoo ir.default values and ru... |
| `deployment_scanner` | 25 | Python/XML | Deployment posture scanner for Odoo configurati... |
| `export_scanner` | 6 | *.py | Scanner for CSV/XLSX export formula-injection r... |
| `field_security_scanner` | 14 | *.py | Scanner for risky Odoo model field security dec... |
| `file_upload_scanner` | 9 | *.py | Scanner for risky Odoo file upload and filesyst... |
| `finding_schema` | 0 | Python/XML | Finding normalization and schema validation hel... |
| `fix_catalog` | 135 | Python/XML | Odoo-idiomatic auto-fix catalog |
| `identity_mutation_scanner` | 4 | *.py | Scanner for risky Odoo user/group identity muta... |
| `integration_scanner` | 16 | *.py | Scanner for risky outbound integrations in Odoo... |
| `json_route_scanner` | 8 | *.py | Scanner for risky Odoo JSON route patterns |
| `mail_alias_scanner` | 6 | Python/XML | Scanner for risky Odoo inbound mail alias records |
| `mail_chatter_scanner` | 16 | *.py | Scanner for risky Odoo chatter and outbound mai... |
| `mail_template_scanner` | 11 | Python/XML | Scanner for risky Odoo mail template records |
| `manifest_scanner` | 22 | *.py, Module defines Python... | Odoo manifest security and packaging scanner |
| `metadata_scanner` | 10 | Python/XML | Scanner for security-sensitive Odoo metadata re... |
| `migration_scanner` | 11 | *.py, __manifest__.py | Scanner for Odoo migration scripts and lifecycl... |
| `model_method_scanner` | 25 | *.py | Scanner for risky Odoo model method behavior |
| `model_scanner` | 11 | *.py | Odoo model-structure scanner |
| `module_lifecycle_scanner` | 4 | *.py | Scanner for risky Odoo module install, upgrade,... |
| `multi_company` | 7 | *.py, security/*.xml | Multi-Company Isolation Checker - Detects cross... |
| `oauth_scanner` | 14 | *.py | Scanner for risky Odoo OAuth callback and token... |
| `odoo_disclosure_mapper` | 33 | Python/XML | Odoo Responsible Disclosure Policy classifier |
| `orm_context_scanner` | 19 | *.py | Scanner for risky Odoo ORM context overrides |
| `orm_domain_scanner` | 4 | *.py | Scanner for risky Odoo ORM domain construction |
| `parallel` | 0 | Python/XML | Odoo Application Security Harness - Parallel sc... |
| `payment_scanner` | 6 | *.py | Scanner for risky Odoo payment/webhook handlers |
| `poc_generator` | 0 | Python/XML | Automated PoC Generator - Generates reproductio... |
| `portal_scanner` | 7 | *.py | Scanner for risky Odoo portal route access-toke... |
| `progress` | 0 | Python/XML | Progress indicators and UX improvements for the... |
| `property_field_scanner` | 12 | Python/XML | Scanner for risky Odoo property and company-dep... |
| `publication_scanner` | 9 | *.py | Scanner for Odoo XML data that publishes record... |
| `queue_job_scanner` | 10 | *.py | Scanner for risky Odoo queue_job and delayed-jo... |
| `qweb_scanner` | 33 | *.xml | QWeb Template Security Scanner - Detects XSS an... |
| `raw_sql_scanner` | 6 | *.py | Scanner for risky Odoo runtime raw SQL usage |
| `realtime_scanner` | 7 | *.py | Scanner for risky Odoo bus/realtime notificatio... |
| `record_rule_scanner` | 9 | Python/XML | Scanner for risky Odoo record-rule domain decla... |
| `registry` | 0 | Python/XML | Scanner plugin registry for auto-discovery and ... |
| `report_scanner` | 9 | *.csv, *.py | Scanner for Odoo report action exposure risks |
| `route_security_scanner` | 10 | *.py | Scanner for risky Odoo route decorator security... |
| `scheduled_job_scanner` | 11 | *.csv, *.py | Scanner for risky Odoo scheduled-job Python met... |
| `secrets_scanner` | 8 | Python/XML | Heuristic secret and committed config scanner f... |
| `sequence_scanner` | 6 | Python/XML | Scanner for risky Odoo ir.sequence declarations... |
| `serialization_scanner` | 7 | *.py | Scanner for unsafe deserialization and parser u... |
| `server_action_scanner` | 11 | *.csv, *.py | Loose Python and server-action scanner for Odoo... |
| `session_auth_scanner` | 15 | *.py | Scanner for risky Odoo controller session/authe... |
| `settings_scanner` | 7 | *.py | Scanner for risky Odoo res.config.settings decl... |
| `signup_token_scanner` | 7 | *.py | Scanner for risky Odoo signup, reset-password, ... |
| `translation_scanner` | 6 | Python/XML | Scanner for risky Odoo translation catalog entries |
| `ui_exposure_scanner` | 11 | Python/XML | Scanner for Odoo XML UI exposure risks |
| `view_domain_scanner` | 10 | Python/XML | Scanner for risky Odoo XML domain/context expre... |
| `view_inheritance_scanner` | 11 | *.xml | Scanner for risky Odoo inherited view modificat... |
| `web_asset_scanner` | 73 | Python/XML | Scanner for Odoo JavaScript/OWL frontend assets |
| `website_form_scanner` | 14 | *.py, *.xml | Scanner for risky Odoo website form submission ... |
| `wizard_scanner` | 9 | *.py | Scanner for risky Odoo TransientModel wizard be... |
| `xml_data_scanner` | 30 | Python/XML | Scanner for executable/risky Odoo XML data records |

---

## Scanner Details

### `__init__`

Odoo Application Security Harness - Core utilities and shared functionality.  
**Lines:** ~264 | **Rules:** 0


### `access_control`

Access Control Analyzer - Automated analysis of Odoo ACLs and record rules.  
**Lines:** ~606 | **Rules:** 14

**Rule IDs:**
- `odoo-acl-global-read-sensitive`
- `odoo-acl-global-write`
- `odoo-acl-missing-company-filter`
- `odoo-acl-missing-sensitive`
- `odoo-acl-public-read-sensitive`
- `odoo-acl-public-rule-broad-sensitive`
- `odoo-acl-public-rule-sensitive-mutation`
- `odoo-acl-public-write`
- ... and 6 more

**Target patterns:**
- `__manifest__.py`
- `__openerp__.py`
- `ir.model.access.csv`
- `security/*.xml`

### `access_override_scanner`

Scanner for risky Odoo model access/search overrides.  
**Lines:** ~350 | **Rules:** 4

**Rule IDs:**
- `odoo-access-override-allow-all`
- `odoo-access-override-filter-self`
- `odoo-access-override-missing-super`
- `odoo-access-override-sudo-search`

**Target patterns:**
- `*.py`

### `action_url_scanner`

Scanner for risky Odoo ir.actions.act_url usage.  
**Lines:** ~1158 | **Rules:** 7

**Rule IDs:**
- `odoo-act-url-embedded-credentials`
- `odoo-act-url-external-new-window`
- `odoo-act-url-external-no-groups`
- `odoo-act-url-public-route`
- `odoo-act-url-sensitive-url`
- `odoo-act-url-tainted-url`
- `odoo-act-url-unsafe-scheme`

### `action_window_scanner`

Scanner for risky Python-returned Odoo act_window actions.  
**Lines:** ~1313 | **Rules:** 8

**Rule IDs:**
- `odoo-act-window-active-test-disabled`
- `odoo-act-window-company-scope-context`
- `odoo-act-window-privileged-default-context`
- `odoo-act-window-public-sensitive-model`
- `odoo-act-window-sensitive-broad-domain`
- `odoo-act-window-tainted-context`
- `odoo-act-window-tainted-domain`
- `odoo-act-window-tainted-res-model`

### `ai_integration_scanner`

Scanner for AI/LLM integration security risks in Odoo modules.  
**Lines:** ~396 | **Rules:** 3

**Rule IDs:**
- `odoo-ai-hardcoded-api-key`
- `odoo-ai-tainted-prompt`
- `odoo-ai-unsanitized-output`

**Target patterns:**
- `*.py`

### `analyzer`

Odoo Deep Pattern Analyzer - AST-based analysis of Odoo-specific security pat....  
**Lines:** ~1555 | **Rules:** 33

**Rule IDs:**
- `odoo-deep-attachment-sudo-access`
- `odoo-deep-auth-none-env`
- `odoo-deep-constraint-database-mutation`
- `odoo-deep-csrf-write`
- `odoo-deep-empty-search-sudo`
- `odoo-deep-field-compute-sudo`
- `odoo-deep-getattr-setattr-tainted-name`
- `odoo-deep-html-sanitize-false`
- ... and 25 more

**Target patterns:**
- `*.py`

### `api_key_scanner`

Scanner for risky Odoo API key creation, lookup, and exposure.  
**Lines:** ~1248 | **Rules:** 8

**Rule IDs:**
- `odoo-api-key-config-parameter-request-secret`
- `odoo-api-key-csv-record`
- `odoo-api-key-public-route-mutation`
- `odoo-api-key-request-derived-mutation`
- `odoo-api-key-returned-from-route`
- `odoo-api-key-sudo-mutation`
- `odoo-api-key-tainted-lookup`
- `odoo-api-key-xml-record`

### `attachment_scanner`

Scanner for risky Odoo ir.attachment metadata and mutation patterns.  
**Lines:** ~1288 | **Rules:** 15

**Rule IDs:**
- `odoo-attachment-active-content`
- `odoo-attachment-public-orphan`
- `odoo-attachment-public-route-mutation`
- `odoo-attachment-public-sensitive-binding`
- `odoo-attachment-public-write`
- `odoo-attachment-sensitive-filename`
- `odoo-attachment-sudo-mutation`
- `odoo-attachment-tainted-access-token-write`
- ... and 7 more

**Target patterns:**
- `*.py`

### `automation_scanner`

Scanner for risky Odoo automated actions.  
**Lines:** ~963 | **Rules:** 9

**Rule IDs:**
- `odoo-automation-broad-sensitive-trigger`
- `odoo-automation-cleartext-http-url`
- `odoo-automation-dynamic-eval`
- `odoo-automation-http-no-timeout`
- `odoo-automation-sensitive-model-mutation`
- `odoo-automation-sudo-method-call`
- `odoo-automation-sudo-mutation`
- `odoo-automation-tls-verify-disabled`
- ... and 1 more

### `base_scanner`

Shared base classes and utilities for Odoo security scanners.  
**Lines:** ~557 | **Rules:** 0


### `binary_download_scanner`

Scanner for risky Odoo binary download and attachment response handling.  
**Lines:** ~1363 | **Rules:** 8

**Rule IDs:**
- `odoo-binary-active-inline-response`
- `odoo-binary-attachment-data-response`
- `odoo-binary-ir-http-binary-content-sudo`
- `odoo-binary-sensitive-content-disposition-filename`
- `odoo-binary-tainted-binary-content-args`
- `odoo-binary-tainted-content-disposition`
- `odoo-binary-tainted-web-content-redirect`
- `odoo-binary-tokenized-web-content-redirect`

**Target patterns:**
- `*.py`

### `button_action_scanner`

Scanner for risky Odoo button/action model methods.  
**Lines:** ~667 | **Rules:** 5

**Rule IDs:**
- `odoo-button-action-mutation-no-access-check`
- `odoo-button-action-sensitive-model-mutation`
- `odoo-button-action-sensitive-state-write`
- `odoo-button-action-sudo-mutation`
- `odoo-button-action-unlink-no-access-check`

**Target patterns:**
- `*.py`

### `cache_header_scanner`

Scanner for risky Odoo controller cache-control behavior.  
**Lines:** ~1153 | **Rules:** 5

**Rule IDs:**
- `odoo-cache-public-cacheable-sensitive-route`
- `odoo-cache-public-file-download`
- `odoo-cache-public-sensitive-cookie-response`
- `odoo-cache-public-sensitive-render`
- `odoo-cache-public-sensitive-response`

**Target patterns:**
- `*.py`

### `config_parameter_scanner`

Scanner for risky runtime ir.config_parameter access.  
**Lines:** ~1169 | **Rules:** 13

**Rule IDs:**
- `odoo-config-param-base-url-embedded-credentials`
- `odoo-config-param-hardcoded-sensitive-write`
- `odoo-config-param-insecure-base-url-write`
- `odoo-config-param-public-sensitive-read`
- `odoo-config-param-security-toggle-enabled`
- `odoo-config-param-sensitive-default`
- `odoo-config-param-sudo-sensitive-read`
- `odoo-config-param-sudo-write`
- ... and 5 more

**Target patterns:**
- `*.py`

### `constraint_scanner`

Scanner for risky Odoo model constraint behavior.  
**Lines:** ~669 | **Rules:** 7

**Rule IDs:**
- `odoo-constraint-dotted-field`
- `odoo-constraint-dynamic-field`
- `odoo-constraint-empty-fields`
- `odoo-constraint-ensure-one`
- `odoo-constraint-return-ignored`
- `odoo-constraint-sudo-search`
- `odoo-constraint-unbounded-search`

**Target patterns:**
- `*.py`

### `controller_path_scanner`

Scanner for path traversal vulnerabilities in Odoo controllers.  
**Lines:** ~380 | **Rules:** 2

**Rule IDs:**
- `odoo-controller-path-traversal`
- `odoo-controller-unsafe-send-file`

**Target patterns:**
- `*.py`

### `controller_response_scanner`

Scanner for risky Odoo controller response handling.  
**Lines:** ~1577 | **Rules:** 22

**Rule IDs:**
- `odoo-controller-cookie-missing-security-flags`
- `odoo-controller-cors-credentials-enabled`
- `odoo-controller-cors-reflected-origin`
- `odoo-controller-cors-wildcard-origin`
- `odoo-controller-jsonp-callback-response`
- `odoo-controller-open-redirect`
- `odoo-controller-redirect-embedded-credentials`
- `odoo-controller-response-header-injection`
- ... and 14 more

**Target patterns:**
- `*.py`

### `data_integrity_scanner`

Scanner for risky Odoo XML data/external-ID integrity patterns.  
**Lines:** ~357 | **Rules:** 10

**Rule IDs:**
- `odoo-data-core-xmlid-delete`
- `odoo-data-core-xmlid-override`
- `odoo-data-forcecreate-disabled`
- `odoo-data-manual-ir-model-data`
- `odoo-data-sensitive-delete`
- `odoo-data-sensitive-function-mutation`
- `odoo-data-sensitive-noupdate-delete`
- `odoo-data-sensitive-noupdate-function`
- ... and 2 more

### `database_scanner`

Scanner for risky Odoo database selection and management routes.  
**Lines:** ~870 | **Rules:** 5

**Rule IDs:**
- `odoo-database-listing-route`
- `odoo-database-management-call`
- `odoo-database-session-db-assignment`
- `odoo-database-tainted-management-input`
- `odoo-database-tainted-selection`

**Target patterns:**
- `*.py`

### `default_value_scanner`

Scanner for risky Odoo ir.default values and runtime writes.  
**Lines:** ~1106 | **Rules:** 8

**Rule IDs:**
- `odoo-default-global-scope`
- `odoo-default-public-route-set`
- `odoo-default-request-derived-set`
- `odoo-default-sensitive-field-set`
- `odoo-default-sensitive-model-set`
- `odoo-default-sensitive-model-value`
- `odoo-default-sensitive-value`
- `odoo-default-sudo-set`

### `deployment_scanner`

Deployment posture scanner for Odoo configuration and XML parameters.  
**Lines:** ~817 | **Rules:** 25

**Rule IDs:**
- `odoo-deploy-admin-passwd-committed`
- `odoo-deploy-b2c-signup`
- `odoo-deploy-base-url-embedded-credentials`
- `odoo-deploy-base-url-not-frozen`
- `odoo-deploy-database-create-enabled`
- `odoo-deploy-database-drop-enabled`
- `odoo-deploy-db-sslmode-opportunistic`
- `odoo-deploy-debug-log-handler`
- ... and 17 more

### `export_scanner`

Scanner for CSV/XLSX export formula-injection risks.  
**Lines:** ~772 | **Rules:** 6

**Rule IDs:**
- `odoo-export-csv-formula-injection`
- `odoo-export-request-controlled-fields`
- `odoo-export-sensitive-fields`
- `odoo-export-sensitive-model-default-fields`
- `odoo-export-tainted-formula`
- `odoo-export-xlsx-formula-injection`

**Target patterns:**
- `*.py`

### `field_security_scanner`

Scanner for risky Odoo model field security declarations.  
**Lines:** ~711 | **Rules:** 14

**Rule IDs:**
- `odoo-field-binary-db-storage`
- `odoo-field-compute-sudo-scalar-no-admin-groups`
- `odoo-field-compute-sudo-sensitive`
- `odoo-field-html-sanitize-overridable-no-admin-groups`
- `odoo-field-html-sanitizer-disabled`
- `odoo-field-json-sensitive-no-groups`
- `odoo-field-json-unstructured-no-groups`
- `odoo-field-related-sensitive-no-admin-groups`
- ... and 6 more

**Target patterns:**
- `*.py`

### `file_upload_scanner`

Scanner for risky Odoo file upload and filesystem handling.  
**Lines:** ~1138 | **Rules:** 9

**Rule IDs:**
- `odoo-file-upload-active-content-attachment`
- `odoo-file-upload-archive-extraction`
- `odoo-file-upload-attachment-from-request`
- `odoo-file-upload-base64-decode`
- `odoo-file-upload-public-attachment-create`
- `odoo-file-upload-secure-filename-only`
- `odoo-file-upload-tainted-path-read`
- `odoo-file-upload-tainted-path-write`
- ... and 1 more

**Target patterns:**
- `*.py`

### `finding_schema`

Finding normalization and schema validation helpers.  
**Lines:** ~132 | **Rules:** 0


### `fix_catalog`

Odoo-idiomatic auto-fix catalog.  
**Lines:** ~652 | **Rules:** 135

**Rule IDs:**
- `odoo-acl-global-read-sensitive`
- `odoo-acl-global-write`
- `odoo-acl-missing-company-filter`
- `odoo-acl-missing-sensitive`
- `odoo-acl-public-read-sensitive`
- `odoo-acl-public-rule-broad-sensitive`
- `odoo-acl-public-rule-sensitive-mutation`
- `odoo-acl-public-write`
- ... and 127 more

### `identity_mutation_scanner`

Scanner for risky Odoo user/group identity mutations.  
**Lines:** ~1043 | **Rules:** 4

**Rule IDs:**
- `odoo-identity-elevated-mutation`
- `odoo-identity-privilege-field-write`
- `odoo-identity-public-route-mutation`
- `odoo-identity-request-derived-mutation`

**Target patterns:**
- `*.py`

### `integration_scanner`

Scanner for risky outbound integrations in Odoo Python code.  
**Lines:** ~1214 | **Rules:** 16

**Rule IDs:**
- `odoo-integration-cleartext-http-url`
- `odoo-integration-hardcoded-auth-header`
- `odoo-integration-hardcoded-http-auth`
- `odoo-integration-http-no-timeout`
- `odoo-integration-internal-url-ssrf`
- `odoo-integration-os-command-execution`
- `odoo-integration-process-no-timeout`
- `odoo-integration-report-command-review`
- ... and 8 more

**Target patterns:**
- `*.py`

### `json_route_scanner`

Scanner for risky Odoo JSON route patterns.  
**Lines:** ~1001 | **Rules:** 8

**Rule IDs:**
- `odoo-json-route-csrf-disabled`
- `odoo-json-route-mass-assignment`
- `odoo-json-route-public-auth`
- `odoo-json-route-public-sudo-read`
- `odoo-json-route-sudo-mutation`
- `odoo-json-route-tainted-domain`
- `odoo-json-route-tainted-record-mutation`
- `odoo-json-route-tainted-record-read`

**Target patterns:**
- `*.py`

### `mail_alias_scanner`

Scanner for risky Odoo inbound mail alias records.  
**Lines:** ~326 | **Rules:** 6

**Rule IDs:**
- `odoo-mail-alias-broad-contact-policy`
- `odoo-mail-alias-dynamic-defaults`
- `odoo-mail-alias-elevated-defaults`
- `odoo-mail-alias-privileged-owner`
- `odoo-mail-alias-public-force-thread`
- `odoo-mail-alias-public-sensitive-model`

### `mail_chatter_scanner`

Scanner for risky Odoo chatter and outbound mail usage in Python.  
**Lines:** ~1152 | **Rules:** 16

**Rule IDs:**
- `odoo-mail-chatter-public-route-send`
- `odoo-mail-chatter-sudo-post`
- `odoo-mail-create-public-route`
- `odoo-mail-followers-public-route-mutation`
- `odoo-mail-followers-sensitive-model-mutation`
- `odoo-mail-followers-sudo-mutation`
- `odoo-mail-followers-tainted-mutation`
- `odoo-mail-force-send`
- ... and 8 more

**Target patterns:**
- `*.py`

### `mail_template_scanner`

Scanner for risky Odoo mail template records.  
**Lines:** ~447 | **Rules:** 11

**Rule IDs:**
- `odoo-mail-template-dangerous-url-scheme`
- `odoo-mail-template-dynamic-sender`
- `odoo-mail-template-dynamic-sensitive-recipient`
- `odoo-mail-template-external-link-sensitive`
- `odoo-mail-template-insecure-url`
- `odoo-mail-template-raw-html`
- `odoo-mail-template-sensitive-token`
- `odoo-mail-template-sudo-expression`
- ... and 3 more

### `manifest_scanner`

Odoo manifest security and packaging scanner.  
**Lines:** ~575 | **Rules:** 22

**Rule IDs:**
- `odoo-manifest-application-demo-data`
- `odoo-manifest-auto-install-security-data`
- `odoo-manifest-auto-install-without-depends`
- `odoo-manifest-demo-in-data`
- `odoo-manifest-direct-python-dependency`
- `odoo-manifest-floating-vcs-python-dependency`
- `odoo-manifest-insecure-python-dependency`
- `odoo-manifest-insecure-remote-asset`
- ... and 14 more

**Target patterns:**
- `*.py`
- `Module defines Python models but manifest data does not include security/ir.model.access.csv`
- `__manifest__.py`
- `__openerp__.py`

### `metadata_scanner`

Scanner for security-sensitive Odoo metadata records.  
**Lines:** ~470 | **Rules:** 10

**Rule IDs:**
- `odoo-metadata-field-dynamic-compute`
- `odoo-metadata-group-implies-admin`
- `odoo-metadata-group-implies-internal-user`
- `odoo-metadata-public-write-acl`
- `odoo-metadata-sensitive-field-no-groups`
- `odoo-metadata-sensitive-field-public-groups`
- `odoo-metadata-sensitive-field-readonly-disabled`
- `odoo-metadata-sensitive-public-read-acl`
- ... and 2 more

### `migration_scanner`

Scanner for Odoo migration scripts and lifecycle hooks.  
**Lines:** ~785 | **Rules:** 11

**Rule IDs:**
- `odoo-migration-cleartext-http-url`
- `odoo-migration-destructive-sql`
- `odoo-migration-http-no-timeout`
- `odoo-migration-interpolated-sql`
- `odoo-migration-lifecycle-hook`
- `odoo-migration-manual-transaction`
- `odoo-migration-missing-lifecycle-hook`
- `odoo-migration-process-execution`
- ... and 3 more

**Target patterns:**
- `*.py`
- `__manifest__.py`
- `__openerp__.py`
- `migrations/**/*.py`

### `model_method_scanner`

Scanner for risky Odoo model method behavior.  
**Lines:** ~973 | **Rules:** 25

**Rule IDs:**
- `odoo-model-method-compute-cleartext-http-url`
- `odoo-model-method-compute-http-no-timeout`
- `odoo-model-method-compute-sensitive-model-mutation`
- `odoo-model-method-compute-sudo-mutation`
- `odoo-model-method-compute-tls-verify-disabled`
- `odoo-model-method-compute-url-embedded-credentials`
- `odoo-model-method-constraint-cleartext-http-url`
- `odoo-model-method-constraint-http-no-timeout`
- ... and 17 more

**Target patterns:**
- `*.py`

### `model_scanner`

Odoo model-structure scanner.  
**Lines:** ~598 | **Rules:** 11

**Rule IDs:**
- `odoo-model-auto-false-manual-sql`
- `odoo-model-delegate-sensitive-field`
- `odoo-model-delegated-link-missing`
- `odoo-model-delegated-link-no-cascade`
- `odoo-model-delegated-link-not-required`
- `odoo-model-delegated-sensitive-inherits`
- `odoo-model-identifier-missing-unique`
- `odoo-model-log-access-disabled`
- ... and 3 more

**Target patterns:**
- `*.py`

### `module_lifecycle_scanner`

Scanner for risky Odoo module install, upgrade, and uninstall flows.  
**Lines:** ~923 | **Rules:** 4

**Rule IDs:**
- `odoo-module-immediate-lifecycle`
- `odoo-module-public-route-lifecycle`
- `odoo-module-sudo-lifecycle`
- `odoo-module-tainted-selection`

**Target patterns:**
- `*.py`

### `multi_company`

Multi-Company Isolation Checker - Detects cross-company data leakage in Odoo.  
**Lines:** ~742 | **Rules:** 7

**Rule IDs:**
- `odoo-mc-check-company-disabled`
- `odoo-mc-company-context-user-input`
- `odoo-mc-missing-check-company`
- `odoo-mc-rule-missing-company`
- `odoo-mc-search-no-company`
- `odoo-mc-sudo-search-no-company`
- `odoo-mc-with-company-user-input`

**Target patterns:**
- `*.py`
- `security/*.xml`

### `oauth_scanner`

Scanner for risky Odoo OAuth callback and token validation flows.  
**Lines:** ~1477 | **Rules:** 14

**Rule IDs:**
- `odoo-oauth-cleartext-http-url`
- `odoo-oauth-http-no-timeout`
- `odoo-oauth-http-verify-disabled`
- `odoo-oauth-jwt-missing-algorithms`
- `odoo-oauth-jwt-verification-disabled`
- `odoo-oauth-missing-state-nonce-validation`
- `odoo-oauth-public-callback-route`
- `odoo-oauth-request-token-decode`
- ... and 6 more

**Target patterns:**
- `*.py`

### `odoo_disclosure_mapper`

Odoo Responsible Disclosure Policy classifier.  
**Lines:** ~343 | **Rules:** 33

**Rule IDs:**
- `odoo-action-url-open-redirect`
- `odoo-ai-unsanitized-output`
- `odoo-automation-dynamic-eval`
- `odoo-controller-response-open-redirect`
- `odoo-deep-empty-search-sudo`
- `odoo-deep-html-sanitize-false`
- `odoo-deep-markup-user-input`
- `odoo-deep-public-sudo`
- ... and 25 more

### `orm_context_scanner`

Scanner for risky Odoo ORM context overrides.  
**Lines:** ~909 | **Rules:** 19

**Rule IDs:**
- `odoo-orm-context-accounting-validation-disabled`
- `odoo-orm-context-accounting-validation-disabled-mutation`
- `odoo-orm-context-active-test-disabled`
- `odoo-orm-context-bin-size-disabled`
- `odoo-orm-context-notification-disabled-mutation`
- `odoo-orm-context-privileged-default`
- `odoo-orm-context-privileged-default-mutation`
- `odoo-orm-context-privileged-mode`
- ... and 11 more

**Target patterns:**
- `*.py`

### `orm_domain_scanner`

Scanner for risky Odoo ORM domain construction.  
**Lines:** ~812 | **Rules:** 4

**Rule IDs:**
- `odoo-orm-domain-dynamic-eval`
- `odoo-orm-domain-filtered-dynamic`
- `odoo-orm-domain-tainted-search`
- `odoo-orm-domain-tainted-sudo-search`

**Target patterns:**
- `*.py`

### `parallel`

Odoo Application Security Harness - Parallel scanner execution.  
**Lines:** ~162 | **Rules:** 0


### `payment_scanner`

Scanner for risky Odoo payment/webhook handlers.  
**Lines:** ~1017 | **Rules:** 6

**Rule IDs:**
- `odoo-payment-public-callback-no-signature`
- `odoo-payment-state-without-amount-currency-check`
- `odoo-payment-state-without-idempotency-check`
- `odoo-payment-state-without-validation`
- `odoo-payment-transaction-lookup-weak`
- `odoo-payment-weak-signature-compare`

**Target patterns:**
- `*.py`

### `poc_generator`

Automated PoC Generator - Generates reproduction scripts for Odoo security fi....  
**Lines:** ~477 | **Rules:** 0


### `portal_scanner`

Scanner for risky Odoo portal route access-token patterns.  
**Lines:** ~984 | **Rules:** 7

**Rule IDs:**
- `odoo-portal-access-token-without-helper`
- `odoo-portal-document-check-missing-token`
- `odoo-portal-manual-access-token-check`
- `odoo-portal-public-route`
- `odoo-portal-sudo-route-id-read`
- `odoo-portal-token-exposed-without-check`
- `odoo-portal-url-generated-without-check`

**Target patterns:**
- `*.py`

### `progress`

Progress indicators and UX improvements for the harness.  
**Lines:** ~152 | **Rules:** 0


### `property_field_scanner`

Scanner for risky Odoo property and company-dependent fields.  
**Lines:** ~1313 | **Rules:** 12

**Rule IDs:**
- `odoo-property-field-default`
- `odoo-property-field-no-company-field`
- `odoo-property-global-default`
- `odoo-property-no-resource-scope`
- `odoo-property-public-route-mutation`
- `odoo-property-request-derived-mutation`
- `odoo-property-runtime-global-default`
- `odoo-property-runtime-no-resource-scope`
- ... and 4 more

### `publication_scanner`

Scanner for Odoo XML data that publishes records or attachments.  
**Lines:** ~1174 | **Rules:** 9

**Rule IDs:**
- `odoo-publication-active-public-attachment`
- `odoo-publication-portal-share-sensitive`
- `odoo-publication-public-attachment`
- `odoo-publication-public-route-mutation`
- `odoo-publication-sensitive-default-published`
- `odoo-publication-sensitive-public-attachment`
- `odoo-publication-sensitive-runtime-published`
- `odoo-publication-sensitive-website-published`
- ... and 1 more

**Target patterns:**
- `*.py`

### `queue_job_scanner`

Scanner for risky Odoo queue_job and delayed-job usage.  
**Lines:** ~924 | **Rules:** 10

**Rule IDs:**
- `odoo-queue-job-cleartext-http-url`
- `odoo-queue-job-dynamic-eval`
- `odoo-queue-job-http-no-timeout`
- `odoo-queue-job-missing-identity-key`
- `odoo-queue-job-public-enqueue`
- `odoo-queue-job-sensitive-model-mutation`
- `odoo-queue-job-sudo-method-call`
- `odoo-queue-job-sudo-mutation`
- ... and 2 more

**Target patterns:**
- `*.py`

### `qweb_scanner`

QWeb Template Security Scanner - Detects XSS and injection in Odoo QWeb/OWL t....  
**Lines:** ~1835 | **Rules:** 33

**Rule IDs:**
- `odoo-qweb-dangerous-tag`
- `odoo-qweb-dynamic-class-attribute`
- `odoo-qweb-dynamic-event-handler`
- `odoo-qweb-dynamic-script-src`
- `odoo-qweb-dynamic-style-attribute`
- `odoo-qweb-dynamic-stylesheet-href`
- `odoo-qweb-dynamic-t-call`
- `odoo-qweb-dynamic-t-component`
- ... and 25 more

**Target patterns:**
- `*.xml`

### `raw_sql_scanner`

Scanner for risky Odoo runtime raw SQL usage.  
**Lines:** ~796 | **Rules:** 6

**Rule IDs:**
- `odoo-raw-sql-broad-destructive-query`
- `odoo-raw-sql-interpolated-query`
- `odoo-raw-sql-manual-transaction`
- `odoo-raw-sql-query-order-injection`
- `odoo-raw-sql-request-derived-input`
- `odoo-raw-sql-write-no-company-scope`

**Target patterns:**
- `*.py`

### `realtime_scanner`

Scanner for risky Odoo bus/realtime notification behavior.  
**Lines:** ~1018 | **Rules:** 7

**Rule IDs:**
- `odoo-realtime-broad-or-tainted-channel`
- `odoo-realtime-broad-or-tainted-channel-subscription`
- `odoo-realtime-bus-send-sudo`
- `odoo-realtime-notification-sudo`
- `odoo-realtime-public-route-bus-send`
- `odoo-realtime-sensitive-payload`
- `odoo-realtime-tainted-notification-content`

**Target patterns:**
- `*.py`

### `record_rule_scanner`

Scanner for risky Odoo record-rule domain declarations.  
**Lines:** ~427 | **Rules:** 9

**Rule IDs:**
- `odoo-record-rule-company-child-of`
- `odoo-record-rule-context-dependent-domain`
- `odoo-record-rule-domain-has-group`
- `odoo-record-rule-empty-permissions`
- `odoo-record-rule-global-sensitive-mutation`
- `odoo-record-rule-portal-write-sensitive`
- `odoo-record-rule-public-sensitive-company-only-scope`
- `odoo-record-rule-public-sensitive-no-owner-scope`
- ... and 1 more

### `registry`

Scanner plugin registry for auto-discovery and orchestration.  
**Lines:** ~149 | **Rules:** 0


### `report_scanner`

Scanner for Odoo report action exposure risks.  
**Lines:** ~1163 | **Rules:** 9

**Rule IDs:**
- `odoo-report-dynamic-attachment-cache`
- `odoo-report-public-render-route`
- `odoo-report-sensitive-filename-expression`
- `odoo-report-sensitive-no-groups`
- `odoo-report-sudo-enabled`
- `odoo-report-sudo-render-call`
- `odoo-report-tainted-render-action`
- `odoo-report-tainted-render-data`
- ... and 1 more

**Target patterns:**
- `*.csv`
- `*.py`
- `*.xml`

### `route_security_scanner`

Scanner for risky Odoo route decorator security posture.  
**Lines:** ~587 | **Rules:** 10

**Rule IDs:**
- `odoo-route-auth-none`
- `odoo-route-bearer-save-session`
- `odoo-route-cors-external-origin`
- `odoo-route-cors-wildcard`
- `odoo-route-csrf-disabled-all-methods`
- `odoo-route-inherited-security-relaxed`
- `odoo-route-public-all-methods`
- `odoo-route-public-get-mutation`
- ... and 2 more

**Target patterns:**
- `*.py`

### `scheduled_job_scanner`

Scanner for risky Odoo scheduled-job Python methods.  
**Lines:** ~987 | **Rules:** 11

**Rule IDs:**
- `odoo-scheduled-job-cleartext-http-url`
- `odoo-scheduled-job-dynamic-eval`
- `odoo-scheduled-job-http-no-timeout`
- `odoo-scheduled-job-manual-transaction`
- `odoo-scheduled-job-sensitive-model-mutation`
- `odoo-scheduled-job-sudo-method-call`
- `odoo-scheduled-job-sudo-mutation`
- `odoo-scheduled-job-sync-without-limit`
- ... and 3 more

**Target patterns:**
- `*.csv`
- `*.py`
- `*.xml`

### `secrets_scanner`

Heuristic secret and committed config scanner for Odoo repositories.  
**Lines:** ~541 | **Rules:** 8

**Rule IDs:**
- `odoo-secret-config-file-value`
- `odoo-secret-config-parameter`
- `odoo-secret-config-parameter-set-param`
- `odoo-secret-hardcoded-value`
- `odoo-secret-private-key-block`
- `odoo-secret-user-password-data`
- `odoo-secret-weak-admin-passwd`
- `odoo-secret-weak-user-password-data`

### `sequence_scanner`

Scanner for risky Odoo ir.sequence declarations and runtime use.  
**Lines:** ~925 | **Rules:** 6

**Rule IDs:**
- `odoo-sequence-business-global-scope`
- `odoo-sequence-public-route-next`
- `odoo-sequence-sensitive-code-use`
- `odoo-sequence-sensitive-declaration`
- `odoo-sequence-sensitive-global-scope`
- `odoo-sequence-tainted-code`

### `serialization_scanner`

Scanner for unsafe deserialization and parser usage in Odoo addons.  
**Lines:** ~893 | **Rules:** 7

**Rule IDs:**
- `odoo-serialization-json-load-no-size-check`
- `odoo-serialization-literal-eval-tainted`
- `odoo-serialization-unsafe-deserialization`
- `odoo-serialization-unsafe-xml-parser`
- `odoo-serialization-unsafe-yaml-load`
- `odoo-serialization-xml-fromstring-tainted`
- `odoo-serialization-yaml-full-load`

**Target patterns:**
- `*.py`

### `server_action_scanner`

Loose Python and server-action scanner for Odoo review contexts.  
**Lines:** ~998 | **Rules:** 11

**Rule IDs:**
- `odoo-loose-python-cleartext-http-url`
- `odoo-loose-python-eval-exec`
- `odoo-loose-python-http-no-timeout`
- `odoo-loose-python-manual-transaction`
- `odoo-loose-python-safe-eval`
- `odoo-loose-python-sensitive-model-mutation`
- `odoo-loose-python-sql-injection`
- `odoo-loose-python-sudo-method-call`
- ... and 3 more

**Target patterns:**
- `*.csv`
- `*.py`
- `*.xml`

### `session_auth_scanner`

Scanner for risky Odoo controller session/authentication handling.  
**Lines:** ~1431 | **Rules:** 15

**Rule IDs:**
- `odoo-session-direct-request-uid-assignment`
- `odoo-session-direct-uid-assignment`
- `odoo-session-environment-superuser`
- `odoo-session-environment-tainted-user`
- `odoo-session-ir-http-auth-override`
- `odoo-session-ir-http-bypass`
- `odoo-session-ir-http-superuser-auth`
- `odoo-session-logout-weak-route`
- ... and 7 more

**Target patterns:**
- `*.py`

### `settings_scanner`

Scanner for risky Odoo res.config.settings declarations.  
**Lines:** ~746 | **Rules:** 7

**Rule IDs:**
- `odoo-settings-config-field-public-groups`
- `odoo-settings-implies-admin-group`
- `odoo-settings-module-toggle-no-admin-groups`
- `odoo-settings-security-toggle-no-admin-groups`
- `odoo-settings-security-toggle-unsafe-default`
- `odoo-settings-sensitive-config-field-no-admin-groups`
- `odoo-settings-sudo-set-param`

**Target patterns:**
- `*.py`

### `signup_token_scanner`

Scanner for risky Odoo signup, reset-password, and access-token flows.  
**Lines:** ~1405 | **Rules:** 7

**Rule IDs:**
- `odoo-signup-public-sudo-identity-flow`
- `odoo-signup-public-token-route`
- `odoo-signup-tainted-identity-token-write`
- `odoo-signup-tainted-reset-trigger`
- `odoo-signup-tainted-token-lookup`
- `odoo-signup-token-exposed`
- `odoo-signup-token-lookup-without-expiry`

**Target patterns:**
- `*.py`

### `translation_scanner`

Scanner for risky Odoo translation catalog entries.  
**Lines:** ~267 | **Rules:** 6

**Rule IDs:**
- `odoo-i18n-dangerous-html`
- `odoo-i18n-insecure-url`
- `odoo-i18n-placeholder-mismatch`
- `odoo-i18n-qweb-raw-output`
- `odoo-i18n-template-expression-injection`
- `odoo-i18n-url-embedded-credentials`

### `ui_exposure_scanner`

Scanner for Odoo XML UI exposure risks.  
**Lines:** ~645 | **Rules:** 11

**Rule IDs:**
- `odoo-ui-action-button-no-groups`
- `odoo-ui-object-button-no-groups`
- `odoo-ui-public-object-button`
- `odoo-ui-sensitive-action-button-external-groups`
- `odoo-ui-sensitive-action-button-no-groups`
- `odoo-ui-sensitive-action-external-groups`
- `odoo-ui-sensitive-action-no-groups`
- `odoo-ui-sensitive-menu-external-groups`
- ... and 3 more

### `view_domain_scanner`

Scanner for risky Odoo XML domain/context expressions.  
**Lines:** ~463 | **Rules:** 10

**Rule IDs:**
- `odoo-view-context-active-test-disabled`
- `odoo-view-context-default-groups`
- `odoo-view-context-privileged-default`
- `odoo-view-context-risky-framework-flag`
- `odoo-view-context-user-company-scope`
- `odoo-view-domain-default-sensitive-filter`
- `odoo-view-domain-dynamic-eval`
- `odoo-view-domain-global-sensitive-filter-broad-domain`
- ... and 2 more

### `view_inheritance_scanner`

Scanner for risky Odoo inherited view modifications.  
**Lines:** ~428 | **Rules:** 11

**Rule IDs:**
- `odoo-view-inherit-adds-object-button-no-groups`
- `odoo-view-inherit-adds-public-object-button`
- `odoo-view-inherit-adds-public-sensitive-field`
- `odoo-view-inherit-adds-sensitive-field-no-groups`
- `odoo-view-inherit-broad-security-xpath`
- `odoo-view-inherit-makes-sensitive-field-editable`
- `odoo-view-inherit-public-groups-sensitive-target`
- `odoo-view-inherit-removes-groups`
- ... and 3 more

**Target patterns:**
- `*.xml`

### `web_asset_scanner`

Scanner for Odoo JavaScript/OWL frontend assets.  
**Lines:** ~2256 | **Rules:** 73

**Rule IDs:**
- `odoo-web-client-side-redirect`
- `odoo-web-dangerous-url-scheme`
- `odoo-web-document-domain-relaxation`
- `odoo-web-dom-xss-sink`
- `odoo-web-dynamic-action-window`
- `odoo-web-dynamic-bus-channel`
- `odoo-web-dynamic-code-import`
- `odoo-web-dynamic-css-injection`
- ... and 65 more

### `website_form_scanner`

Scanner for risky Odoo website form submission surfaces.  
**Lines:** ~1173 | **Rules:** 14

**Rule IDs:**
- `odoo-website-form-active-file-upload`
- `odoo-website-form-dangerous-success-redirect`
- `odoo-website-form-dynamic-success-redirect`
- `odoo-website-form-external-success-redirect`
- `odoo-website-form-field-allowlisted-sensitive`
- `odoo-website-form-file-upload`
- `odoo-website-form-get-method`
- `odoo-website-form-hidden-model-selector`
- ... and 6 more

**Target patterns:**
- `*.py`
- `*.xml`

### `wizard_scanner`

Scanner for risky Odoo TransientModel wizard behavior.  
**Lines:** ~748 | **Rules:** 9

**Rule IDs:**
- `odoo-wizard-active-ids-bulk-mutation`
- `odoo-wizard-binary-import-field`
- `odoo-wizard-dynamic-active-model`
- `odoo-wizard-long-transient-retention`
- `odoo-wizard-mutation-no-access-check`
- `odoo-wizard-sensitive-model-mutation`
- `odoo-wizard-sudo-mutation`
- `odoo-wizard-upload-parser`
- ... and 1 more

**Target patterns:**
- `*.py`

### `xml_data_scanner`

Scanner for executable/risky Odoo XML data records.  
**Lines:** ~1350 | **Rules:** 30

**Rule IDs:**
- `odoo-xml-config-param-base-url-embedded-credentials`
- `odoo-xml-config-param-insecure-base-url`
- `odoo-xml-config-param-security-toggle-enabled`
- `odoo-xml-cron-admin-user`
- `odoo-xml-cron-cleartext-http-url`
- `odoo-xml-cron-doall-enabled`
- `odoo-xml-cron-external-sync-review`
- `odoo-xml-cron-http-no-timeout`
- ... and 22 more

