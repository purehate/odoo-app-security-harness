"""Odoo Responsible Disclosure Policy classifier.

Maps harness findings against Odoo's official disclosure criteria:
https://www.odoo.com/security-report

Usage:
    from odoo_security_harness.odoo_disclosure_mapper import classify_finding, disclosure_summary

    finding = {"rule_id": "odoo-deep-public-sudo", "severity": "high", ...}
    result = classify_finding(finding)
    # -> {"eligibility": "qualifying", "category": "broken_authentication", ...}
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DisclosureResult:
    """Classification result for a single finding."""

    eligibility: str  # qualifying | non_qualifying | borderline | unknown
    category: str
    reason: str
    odoo_policy_section: str
    recommendation: str


# ---------------------------------------------------------------------------
# Odoo qualifying categories
# ---------------------------------------------------------------------------
QUALIFYING_SHAPES: dict[str, tuple[str, str, str]] = {
    # shape_key -> (category, odoo_section, recommendation)
    "sql_injection": (
        "sql_injection",
        "SQL injection vectors in public API methods",
        "Report to Odoo Security Team with a working PoC against a public controller or JSON route.",
    ),
    "xss": (
        "xss",
        "XSS vulnerabilities working in supported browsers",
        "Confirm exploit works in current Chrome/Firefox/Safari without deprecated flags; include minimal PoC.",
    ),
    "broken_authentication": (
        "broken_authentication",
        "Broken authentication or session management, allowing unauthorized access",
        "Demonstrate session hijacking, privilege escalation, or bypass without prior account compromise.",
    ),
    "sandbox_escape": (
        "sandbox_escape",
        "Broken sandboxing of customizations, allowing arbitrary code execution or access to system resources",
        "Show arbitrary code execution via safe_eval, server actions, or QWeb template injection.",
    ),
}

# ---------------------------------------------------------------------------
# Odoo non-qualifying categories with their policy text
# ---------------------------------------------------------------------------
NON_QUALIFYING_SHAPES: dict[str, tuple[str, str, str]] = {
    "self_xss": (
        "self_xss",
        "Self-XSS attacks requiring the user to actively copy/paste malicious code",
        "Do not report to Odoo. Close or accept-risk with reason 'self-xss per Odoo policy'.",
    ),
    "admin_xss": (
        "admin_xss",
        "XSS attacks by admins, e.g. via file uploads or script injection",
        "Do not report to Odoo. Administrators are webmasters; this is a feature, not a bug.",
    ),
    "rate_limiting": (
        "rate_limiting",
        "Rate-limiting / Brute-forcing / Scripting of components working as designed",
        "Do not report to Odoo. Suggest defense-in-depth hardening in your own deployment docs instead.",
    ),
    "user_enumeration": (
        "user_enumeration",
        "User enumeration (ability to verify that a username exists)",
        "Do not report to Odoo. Per policy this does not carry much risk.",
    ),
    "file_path_disclosure": (
        "file_path_disclosure",
        "File path disclosures, which do not carry significant risk",
        "Do not report to Odoo. Accept-risk or close with 'path disclosure per Odoo policy'.",
    ),
    "clickjacking": (
        "clickjacking",
        "Clickjacking or phishing attacks using social engineering tricks",
        "Do not report to Odoo. System is working as intended per policy.",
    ),
    "tabnapping": (
        "tabnapping",
        "Tabnapping or other phishing attacks conducted by navigating other browser tabs",
        "Do not report to Odoo. Per policy this is a social-engineering vector, not a system flaw.",
    ),
    "logout_csrf": (
        "logout_csrf",
        "Logout CSRF (no plausible attack unless combined with Login CSRF)",
        "Do not report to Odoo. Per policy this is not a qualifying vulnerability.",
    ),
    "open_redirect": (
        "open_redirect",
        "Open redirectors, which are simply one vector for phishing among many others",
        "Do not report to Odoo. Odoo explicitly lists open redirects as non-qualifying.",
    ),
    "csv_injection": (
        "csv_injection",
        "CSV/XLSX injection issues that require users to explicitly bypass security warnings",
        "Do not report to Odoo. Modern spreadsheet warnings mitigate this.",
    ),
    "referer_leak": (
        "referer_leak",
        "Referer leak (including sensitive tokens) via social media links or ads/analytics requests",
        "Do not report to Odoo. Per policy this is very unlikely to be exploited within validity period.",
    ),
    "password_policy": (
        "password_policy",
        "Password policies (length, format, character classes, etc.)",
        "Do not report to Odoo. Harden in your own deployment if needed.",
    ),
    "email_verification": (
        "email_verification",
        "Missing or partial verification of email addresses, or ways to circumvent it",
        "Do not report to Odoo. Open a regular bug report instead.",
    ),
    "directory_listing": (
        "directory_listing",
        "Disclosure of public information or directory listing on downloads archive",
        "Do not report to Odoo. This is a required feature per policy.",
    ),
    "spam_policy": (
        "spam_policy",
        "Spam-fighting policies and systems such as DKIM, SPF or DMARC",
        "Do not report to Odoo. Infrastructure hardening, not a vulnerability.",
    ),
    "missing_hsts": (
        "missing_hsts",
        "Absence of HTTP Strict Transport Security (HSTS) headers, HSTS preloading, and HSTS policies",
        "Do not report to Odoo. Deploy proxy_mode and terminate TLS at your reverse proxy.",
    ),
    "weak_ssl": (
        "weak_ssl",
        "Weak ciphers or SSL deployments details",
        "Do not report to Odoo. Their benchmark is an A grade on SSLLab's test with maximal compatibility.",
    ),
    "ssrf": (
        "ssrf",
        "SSRF attacks, unless they allow access to special protocol handlers (e.g. file://)",
        "Only report SSRF to Odoo if you can read local files or hit internal cloud metadata services.",
    ),
    "default_acl": (
        "default_acl",
        "Issues in default configuration of access control rules (e.g. ACLs and record rules)",
        "Do not report to Odoo. Open a regular bug report instead.",
    ),
    "account_takeover_prerequisite": (
        "account_takeover_prerequisite",
        "Attack scenarios that include a prior takeover of the user account or an email account",
        "Do not report to Odoo. Open a regular bug report instead.",
    ),
    "social_engineering": (
        "social_engineering",
        "Attacks relying on physical or social engineering techniques",
        "Do not report to Odoo. Out of scope per responsible disclosure policy.",
    ),
    "non_persistent_dos": (
        "non_persistent_dos",
        "Non-permanent Denial of Service (DoS) and distributed DoS (DDoS)",
        "Do not report to Odoo. Rate-limit at reverse proxy/WAF layer instead.",
    ),
}

# ---------------------------------------------------------------------------
# Rule-ID-to-shape mapping
# ---------------------------------------------------------------------------
# These mappings are heuristic: a rule ID points at a *shape*, and the shape
# maps to Odoo's qualifying or non-qualifying policy text.
RULE_TO_SHAPE: dict[str, str] = {
    # --- Qualifying ---
    "odoo-raw-sql-injection": "sql_injection",
    "odoo-loose-python-sql-injection": "sql_injection",
    "odoo-deep-public-sudo": "broken_authentication",
    "odoo-deep-route-id-sudo-browse": "broken_authentication",
    "odoo-deep-empty-search-sudo": "broken_authentication",
    "odoo-route-auth-none-public-methods": "broken_authentication",
    "odoo-route-public-all-methods": "broken_authentication",
    "odoo-session-sensitive-cookie-weak-flags": "broken_authentication",
    "odoo-session-environment-tainted-user": "broken_authentication",
    "odoo-portal-route-no-auth-check": "broken_authentication",
    "odoo-portal-public-route": "broken_authentication",
    "odoo-portal-access-token-without-helper": "broken_authentication",
    "odoo-portal-token-exposed-without-check": "broken_authentication",
    "odoo-safe-eval-user-input": "sandbox_escape",
    "odoo-loose-python-eval-exec": "sandbox_escape",
    "odoo-loose-python-safe-eval": "sandbox_escape",
    "odoo-server-action-code-execution": "sandbox_escape",
    "odoo-automation-dynamic-eval": "sandbox_escape",
    "odoo-qweb-t-raw": "xss",
    "odoo-qweb-markup-escape-bypass": "xss",
    "odoo-web-owl-qweb-t-raw": "xss",
    "odoo-web-owl-unsafe-markup": "xss",
    "odoo-field-html-sanitizer-disabled": "xss",
    "odoo-deep-html-sanitize-false": "xss",
    "odoo-deep-markup-user-input": "xss",
    "odoo-ai-unsanitized-output": "xss",
    # --- Non-qualifying ---
    "odoo-web-owl-qweb-target-blank-no-noopener": "tabnapping",
    "odoo-action-url-open-redirect": "open_redirect",
    "odoo-controller-response-open-redirect": "open_redirect",
    "odoo-web-dom-open-redirect": "open_redirect",
    "odoo-web-owl-qweb-post-form-missing-csrf": "logout_csrf",  # heuristic: form CSRF without state-change is closest
    "odoo-oauth-tainted-redirect-uri": "open_redirect",
    "odoo-ssrf-generic": "ssrf",
}

# Substring-based fallbacks for rules not explicitly mapped
SHAPE_SUBSTRING_FALLBACKS: list[tuple[str, str]] = [
    # (substring, shape)
    ("sql-injection", "sql_injection"),
    ("raw-sql", "sql_injection"),
    ("cr.execute", "sql_injection"),
    ("xss", "xss"),
    ("t-raw", "xss"),
    ("markup-escape", "xss"),
    ("sanitize-false", "xss"),
    ("html-sanitizer-disabled", "xss"),
    ("safe-eval", "sandbox_escape"),
    ("eval-exec", "sandbox_escape"),
    ("server-action-code", "sandbox_escape"),
    ("automation-dynamic-eval", "sandbox_escape"),
    ("public-route", "broken_authentication"),
    ("public-sudo", "broken_authentication"),
    ("portal-route-no-auth", "broken_authentication"),
    ("session-cookie-weak", "broken_authentication"),
    ("open-redirect", "open_redirect"),
    ("logout-csrf", "logout_csrf"),
    ("user-enumeration", "user_enumeration"),
    ("rate-limit", "rate_limiting"),
    ("password-policy", "password_policy"),
    ("directory-listing", "directory_listing"),
    ("missing-hsts", "missing_hsts"),
    ("weak-cipher", "weak_ssl"),
    ("ssrf", "ssrf"),
    ("default-acl", "default_acl"),
    ("self-xss", "self_xss"),
    ("admin-xss", "admin_xss"),
    ("clickjacking", "clickjacking"),
    ("social-engineering", "social_engineering"),
    ("referer-leak", "referer_leak"),
    ("csv-injection", "csv_injection"),
    ("file-path-disclosure", "file_path_disclosure"),
    ("non-persistent-dos", "non_persistent_dos"),
]


def _resolve_shape(rule_id: str) -> str | None:
    """Map a rule_id to its disclosure shape, or None if unmapped."""
    exact = RULE_TO_SHAPE.get(rule_id)
    if exact:
        return exact
    rid = rule_id.lower()
    for substring, shape in SHAPE_SUBSTRING_FALLBACKS:
        if substring in rid:
            return shape
    return None


def classify_finding(finding: dict[str, Any]) -> DisclosureResult:
    """Classify a single finding against Odoo's disclosure policy."""
    rule_id = str(finding.get("rule_id") or finding.get("rule") or "")
    shape = _resolve_shape(rule_id)

    if shape is None:
        return DisclosureResult(
            eligibility="unknown",
            category="unknown",
            reason="This rule ID is not yet mapped to Odoo's disclosure policy.",
            odoo_policy_section="N/A",
            recommendation="Manually review against https://www.odoo.com/security-report",
        )

    if shape in QUALIFYING_SHAPES:
        category, section, recommendation = QUALIFYING_SHAPES[shape]
        return DisclosureResult(
            eligibility="qualifying",
            category=category,
            reason=f"Matches Odoo qualifying category: {section}",
            odoo_policy_section=section,
            recommendation=recommendation,
        )

    if shape in NON_QUALIFYING_SHAPES:
        category, section, recommendation = NON_QUALIFYING_SHAPES[shape]
        return DisclosureResult(
            eligibility="non_qualifying",
            category=category,
            reason=f"Matches Odoo non-qualifying category: {section}",
            odoo_policy_section=section,
            recommendation=recommendation,
        )

    return DisclosureResult(
        eligibility="borderline",
        category=shape,
        reason="Shape exists but is not explicitly categorized as qualifying or non-qualifying.",
        odoo_policy_section="Review manually",
        recommendation="Check https://www.odoo.com/security-report for latest policy updates.",
    )


def disclosure_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Produce a summary of how a findings list maps to Odoo policy."""
    buckets: dict[str, list[dict[str, Any]]] = {
        "qualifying": [],
        "non_qualifying": [],
        "borderline": [],
        "unknown": [],
    }
    for finding in findings:
        result = classify_finding(finding)
        buckets[result.eligibility].append(
            {
                "rule_id": finding.get("rule_id") or finding.get("rule"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "category": result.category,
                "reason": result.reason,
                "recommendation": result.recommendation,
            }
        )

    return {
        "total": len(findings),
        "qualifying_count": len(buckets["qualifying"]),
        "non_qualifying_count": len(buckets["non_qualifying"]),
        "borderline_count": len(buckets["borderline"]),
        "unknown_count": len(buckets["unknown"]),
        "qualifying": buckets["qualifying"],
        "non_qualifying": buckets["non_qualifying"],
        "borderline": buckets["borderline"],
        "unknown": buckets["unknown"],
    }
