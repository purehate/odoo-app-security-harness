# OWASP Top 10 2021 Coverage Matrix

This document maps the Odoo Application Security Harness detection rules to OWASP Top 10 2021 categories.

## Summary

| OWASP Category | Shapes | Scanner Rules | Coverage |
|----------------|--------|---------------|----------|
| A01:2021 Broken Access Control | 272 | 184 | Excellent |
| A05:2021 Security Misconfiguration | 79 | 45 | Good |
| A02:2021 Cryptographic Failures | 69 | 36 | Good |
| A03:2021 Injection | 65 | 39 | Good |
| A07:2021 Identification and Authentication Failures | 45 | 37 | Good |
| A08:2021 Software and Data Integrity Failures | 25 | 1 | Moderate |
| A04:2021 Insecure Design | 18 | 9 | Moderate |
| A09:2021 Security Logging and Monitoring Failures | 8 | 2 | Poor |
| A10:2021 Server-Side Request Forgery | 5 | 4 | Very Poor |
| A06:2021 Vulnerable and Outdated Components | 3 | 0 | Very Poor |

**Total:** 589 taxonomy shapes, 357 scanner rules with OWASP mapping.

## Category Breakdown

### A01:2021 Broken Access Control

- **Shapes:** 272
- **Scanner Rules:** 184

**Example Rules:**

- `odoo-deep-constraint-database-mutation` (high)
- `odoo-deep-onchange-database-mutation` (high)
- `odoo-loose-python-sensitive-model-mutation` (high)
- `odoo-loose-python-sudo-method-call` (high)
- `odoo-loose-python-sudo-write` (high)
- `odoo-mc-sudo-search-no-company` (high)
- `odoo-publication-public-route-mutation` (critical)
- `odoo-publication-sensitive-default-published` (high)
- `odoo-publication-sensitive-runtime-published` (high)
- `odoo-qweb-sensitive-field-render` (high)
- `odoo-ui-sensitive-menu-external-groups` (high)
- `odoo-website-form-route-csrf-disabled` (high)
- `odoo-act-url-external-no-groups` (unknown)
- `odoo-act-url-public-route` (unknown)
- `odoo-act-window-active-test-disabled` (unknown)
- ... and 169 more

### A05:2021 Security Misconfiguration

- **Shapes:** 79
- **Scanner Rules:** 45

**Example Rules:**

- `odoo-act-url-external-new-window` (unknown)
- `odoo-automation-http-no-timeout` (unknown)
- `odoo-binary-tainted-content-disposition` (unknown)
- `odoo-cache-public-cacheable-sensitive-route` (unknown)
- `odoo-cache-public-file-download` (unknown)
- `odoo-cache-public-sensitive-render` (unknown)
- `odoo-cache-public-sensitive-response` (unknown)
- `odoo-controller-cookie-missing-security-flags` (unknown)
- `odoo-controller-cors-credentials-enabled` (unknown)
- `odoo-controller-weak-content-type-options` (unknown)
- `odoo-controller-weak-cross-origin-policy` (unknown)
- `odoo-controller-weak-csp-header` (unknown)
- `odoo-controller-weak-frame-options` (unknown)
- `odoo-controller-weak-hsts-header` (unknown)
- `odoo-controller-weak-permissions-policy` (unknown)
- ... and 30 more

### A02:2021 Cryptographic Failures

- **Shapes:** 69
- **Scanner Rules:** 36

**Example Rules:**

- `odoo-loose-python-tls-verify-disabled` (high)
- `odoo-loose-python-url-embedded-credentials` (high)
- `odoo-attachment-sensitive-filename` (unknown)
- `odoo-binary-sensitive-content-disposition-filename` (unknown)
- `odoo-binary-tokenized-web-content-redirect` (unknown)
- `odoo-config-param-base-url-embedded-credentials` (unknown)
- `odoo-controller-redirect-embedded-credentials` (unknown)
- `odoo-deploy-base-url-embedded-credentials` (unknown)
- `odoo-deploy-db-sslmode-opportunistic` (unknown)
- `odoo-deploy-oauth-endpoint-embedded-credentials` (unknown)
- `odoo-deploy-oauth-insecure-endpoint` (unknown)
- `odoo-field-sensitive-copyable` (unknown)
- `odoo-field-sensitive-indexed` (unknown)
- `odoo-field-sensitive-tracking` (unknown)
- `odoo-field-tracking-without-mail-thread` (unknown)
- ... and 21 more

### A03:2021 Injection

- **Shapes:** 65
- **Scanner Rules:** 39

**Example Rules:**

- `odoo-ai-tainted-prompt` (high)
- `odoo-ai-unsanitized-output` (high)
- `odoo-deep-getattr-setattr-tainted-name` (high)
- `odoo-deep-markup-user-input` (high)
- `odoo-loose-python-eval-exec` (critical)
- `odoo-loose-python-sql-injection` (high)
- `odoo-website-form-sanitize-disabled` (high)
- `odoo-act-url-unsafe-scheme` (unknown)
- `odoo-attachment-active-content` (unknown)
- `odoo-attachment-unsafe-url-scheme` (unknown)
- `odoo-automation-dynamic-eval` (unknown)
- `odoo-binary-active-inline-response` (unknown)
- `odoo-controller-jsonp-callback-response` (unknown)
- `odoo-deep-html-sanitize-false` (medium)
- `odoo-deep-markup-fstring` (medium)
- ... and 24 more

### A07:2021 Identification and Authentication Failures

- **Shapes:** 45
- **Scanner Rules:** 37

**Example Rules:**

- `odoo-ai-hardcoded-api-key` (critical)
- `odoo-api-key-csv-record` (unknown)
- `odoo-api-key-tainted-lookup` (unknown)
- `odoo-api-key-xml-record` (unknown)
- `odoo-attachment-tainted-access-token-write` (unknown)
- `odoo-deploy-admin-passwd-committed` (unknown)
- `odoo-deploy-oauth-client-secret-committed` (unknown)
- `odoo-deploy-oauth-missing-validation-endpoint` (unknown)
- `odoo-deploy-weak-admin-passwd` (unknown)
- `odoo-integration-hardcoded-auth-header` (unknown)
- `odoo-integration-hardcoded-http-auth` (unknown)
- `odoo-oauth-jwt-missing-algorithms` (unknown)
- `odoo-oauth-jwt-verification-disabled` (unknown)
- `odoo-oauth-request-token-decode` (unknown)
- `odoo-oauth-session-authenticate` (unknown)
- ... and 22 more

### A08:2021 Software and Data Integrity Failures

- **Shapes:** 25
- **Scanner Rules:** 1

**Example Rules:**

- `odoo-xml-function-security-model-mutation` (unknown)

### A04:2021 Insecure Design

- **Shapes:** 18
- **Scanner Rules:** 9

**Example Rules:**

- `odoo-loose-python-manual-transaction` (medium)
- `odoo-orm-context-accounting-validation-disabled` (unknown)
- `odoo-orm-context-accounting-validation-disabled-mutation` (unknown)
- `odoo-orm-context-request-accounting-validation-disabled` (unknown)
- `odoo-payment-state-without-amount-currency-check` (unknown)
- `odoo-payment-state-without-idempotency-check` (unknown)
- `odoo-qweb-fa-icon-missing-label` (low)
- `odoo-raw-sql-manual-transaction` (unknown)
- `odoo-xml-cron-doall-enabled` (unknown)

### A09:2021 Security Logging and Monitoring Failures

- **Shapes:** 8
- **Scanner Rules:** 2

**Example Rules:**

- `odoo-deploy-debug-log-handler` (unknown)
- `odoo-deploy-debug-logging` (unknown)

### A10:2021 Server-Side Request Forgery

- **Shapes:** 5
- **Scanner Rules:** 4

**Example Rules:**

- `odoo-integration-internal-url-ssrf` (unknown)
- `odoo-integration-tainted-proxy` (unknown)
- `odoo-integration-tainted-url-ssrf` (unknown)
- `odoo-oauth-tainted-validation-url` (unknown)

### A06:2021 Vulnerable and Outdated Components

- **Shapes:** 3
- **Scanner Rules:** 0

*No scanner rules directly mapped to this category.*

## Gap Analysis

Categories with fewer than 15 shapes are considered under-represented and are priority expansion targets.

### A06:2021 Vulnerable and Outdated Components (3 shapes)

**Gap:** Almost no Odoo-specific dependency/SBOM scanning. The harness detects manifest-level dependency issues but lacks deep transitive dependency analysis.

**Recommended additions:**
- Dependency version pinning checks in manifests
- Transitive dependency with known CVE (via pip-audit / osv-scanner integration)
- Odoo base module version drift detection
- Third-party JS library vulnerability in manifest remote assets
- Python wheel/sdist supply-chain integrity checks

### A10:2021 Server-Side Request Forgery (5 shapes)

**Gap:** Very thin despite massive outbound HTTP coverage. Many tainted-URL findings are mapped to A01 or A05 instead of A10.

**Recommended additions:**
- Webhook endpoints with request-derived target URLs
- Report engines fetching external data/images
- Mail servers relaying to arbitrary hosts
- Calendar/ICS sync fetching remote URLs
- Document converters (PDF, image) fetching remote resources
- Attachment URL metadata fetching remote content
- Re-map existing tainted-URL integration shapes to A10

### A09:2021 Security Logging and Monitoring Failures (8 shapes)

**Gap:** Limited to audit-metadata and debug-logging. Missing comprehensive security-event logging coverage.

**Recommended additions:**
- Failed authentication attempts not logged
- Privileged mutations (sudo writes) not logged
- Missing centralized security event logging
- Log tampering / log injection via request data
- Missing alerting thresholds on sensitive operations
- Insufficient log retention policies
