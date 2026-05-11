"""QWeb Template Security Scanner - Detects XSS and injection in Odoo QWeb/OWL templates.

QWeb is Odoo's templating engine. It auto-escapes by default, but several
constructs bypass this protection:
- t-raw: renders unescaped HTML
- t-out with Markup(): renders values already marked safe
- t-att: sets attributes (can be JS URLs)
- t-call: dynamically chooses templates to render
- t-js: inline JavaScript blocks
- Markup() in Python: marks strings as safe HTML
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defusedxml import ElementTree


@dataclass
class QWebFinding:
    """Represents a QWeb template security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    element: str
    message: str
    attribute: str = ""
    sink_kind: str = "xss"


class QWebScanner:
    """Scanner for QWeb template security issues."""

    URL_BEARING_ATTRIBUTES = ("href", "src", "action", "formaction", "poster", "srcset", "ping", "xlink:href")
    URL_BEARING_ATTRIBUTE_RE = r"(?:href|src|action|formaction|poster|srcset|ping|xlink:href)"
    DANGEROUS_URL_SCHEME_RE = re.compile(
        r"^\s*(?:javascript:|vbscript:|file:|data:(?:text/html|application/(?:javascript|xhtml\+xml)))",
        re.IGNORECASE,
    )
    DANGEROUS_URL_SCHEME_LITERAL_RE = re.compile(
        r"['\"]\s*(?:javascript:|vbscript:|file:|data:(?:text/html|application/(?:javascript|xhtml\+xml)))",
        re.IGNORECASE,
    )

    # Patterns for inline JavaScript in attributes
    JS_PATTERNS = [
        DANGEROUS_URL_SCHEME_RE,
        re.compile(r"on\w+\s*=", re.IGNORECASE),  # onclick, onload, etc.
    ]

    # Dangerous HTML tags
    DANGEROUS_TAGS = {"script", "iframe", "object", "embed", "form"}
    SENSITIVE_FIELD_MARKERS = ("access_token", "api_key", "apikey", "client_secret", "password", "secret", "token")
    SENSITIVE_URL_PARAM_RE = re.compile(
        r"(?:[?#&]|%3[fF]|%26)[^'\"`\s={}]*"
        r"(?:access[_-]?token|auth[_-]?token|api[_-]?key|secret|password|session|csrf|jwt|bearer)"
        r"[^'\"`\s={}]*=",
        re.IGNORECASE,
    )
    URL_DYNAMIC_MARKER_RE = re.compile(
        r"(#\{|\{\{|%\(|%s|\+|\b(?:record|object|request|params|values|ctx|context|payload|response|token|secret)\b)",
        re.IGNORECASE,
    )
    STYLE_DYNAMIC_MARKER_RE = re.compile(
        r"(#\{|\{\{|%\(|%s|\+|\b(?:record|object|request|params|values|ctx|context|payload|response|style|css)\b)",
        re.IGNORECASE,
    )
    HTML_DYNAMIC_MARKER_RE = re.compile(
        r"(#\{|\{\{|%\(|%s|\+|\b(?:record|object|request|params|values|ctx|context|payload|response|html|markup|body)\b)",
        re.IGNORECASE,
    )
    CLASS_DYNAMIC_MARKER_RE = re.compile(
        r"(#\{|\{\{|%\(|%s|\+|\b(?:record|object|request|params|values|ctx|context|payload|response|state|status|group|role|class)\b)",
        re.IGNORECASE,
    )
    CSS_URL_RE = re.compile(r"\burl\s*\(", re.IGNORECASE)
    DYNAMIC_TEMPLATE_NAMES = {
        "context",
        "ctx",
        "env",
        "kwargs",
        "object",
        "params",
        "record",
        "request",
        "res",
        "user",
        "values",
    }

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: list[QWebFinding] = []
        self.line_map: dict[int, str] = {}
        self.markup_t_set_vars: set[str] = set()

    def scan_file(self) -> list[QWebFinding]:
        """Scan a QWeb XML file for security issues."""
        try:
            content = Path(self.file_path).read_text(encoding="utf-8")
        except Exception:
            return []

        # Build line map for accurate line numbers
        self.line_map = {i + 1: line for i, line in enumerate(content.splitlines())}
        self.markup_t_set_vars = set()

        # Parse XML
        try:
            root = ElementTree.fromstring(content)
        except ElementTree.ParseError:
            # Try with wrapping in case of multiple root elements
            try:
                root = ElementTree.fromstring(f"\u003croot\u003e{content}\u003c/root\u003e")
            except ElementTree.ParseError:
                # Fall back to regex-based scanning
                return self._regex_scan(content)
            except Exception:
                return []
        except Exception:
            return []

        self._scan_element(root, 1)
        return self._dedupe_findings(self.findings)

    def _scan_element(self, element: ElementTree.Element, depth: int) -> None:
        """Recursively scan an XML element."""
        tag = element.tag.split("}")[-1] if "}" in element.tag else element.tag

        # Check for dangerous tags
        if tag.lower() in self.DANGEROUS_TAGS:
            self._add_finding(
                rule_id="odoo-qweb-dangerous-tag",
                title=f"Dangerous HTML tag: {tag}",
                severity="medium",
                element=tag,
                message=f"QWeb template contains <{tag}> tag; verify content is trusted",
            )

        if tag.lower() == "form":
            self._check_post_form_csrf(element, tag)

        if tag.lower() == "a":
            self._check_anchor_target_blank(element, tag)

        if tag.lower() == "link":
            self._check_external_stylesheet_integrity(element, tag)
            self._check_dynamic_stylesheet_href(element, tag)

        if tag.lower() == "meta":
            self._check_meta_refresh_redirect(element, tag)

        if tag.lower() == "iframe":
            self._check_iframe_sandbox(element, tag)

        if tag.lower() == "script":
            self._check_script_qweb_expression(element, tag)
            self._check_external_script_integrity(element, tag)
            self._check_dynamic_script_src(element, tag)

        self._check_t_set_markup_value(element, tag)

        # Check attributes
        for attr, value in element.attrib.items():
            attr_name = attr.split("}")[-1] if "}" in attr else attr

            # t-raw attribute
            if attr_name == "t-raw":
                self._add_finding(
                    rule_id="odoo-qweb-t-raw",
                    title="QWeb t-raw bypasses escaping",
                    severity="medium",
                    element=tag,
                    attribute=attr_name,
                    message=f"t-raw='{value}' renders unescaped HTML; verify the expression is trusted",
                )

            if attr_name in {"t-out", "t-esc"}:
                self._check_markup_escape_bypass(tag, attr_name, value)
                self._check_t_set_markup_render(tag, attr_name, value)

            if attr_name == "t-out-mode":
                self._check_t_out_mode(tag, attr_name, value)

            if attr_name == "t-call":
                self._check_t_call(tag, attr_name, value)

            if attr_name == "t-js":
                self._add_finding(
                    rule_id="odoo-qweb-t-js-inline-script",
                    title="QWeb t-js inline JavaScript block",
                    severity="medium",
                    element=tag,
                    attribute=attr_name,
                    message=f"t-js='{value}' enables inline JavaScript in a template; verify user data cannot reach script context",
                )

            # t-att with potential JS injection
            if attr_name.startswith("t-att-"):
                self._check_t_att(tag, attr_name, value)

            # t-att mappings can dynamically set arbitrary attributes.
            if attr_name == "t-att":
                self._check_t_att_mapping(element, tag, attr_name, value)

            # t-attf formats attributes with string interpolation.
            if attr_name.startswith("t-attf-"):
                self._check_t_attf(tag, attr_name, value)

            if attr_name == "t-options":
                self._check_t_options(tag, attr_name, value)

            if attr_name in {"t-field", "t-esc", "t-out"}:
                self._check_sensitive_render(tag, attr_name, value)

            # URL-bearing attributes can execute script or leak token-bearing URLs.
            if attr_name in self.URL_BEARING_ATTRIBUTES:
                self._check_url_attr(tag, attr_name, value)

            if attr_name == "srcdoc" and self._looks_dynamic_html_value(value):
                self._check_srcdoc_html_sink(tag, attr_name, value)

            # Inline event handlers
            if attr_name.startswith("on"):
                self._add_finding(
                    rule_id="odoo-qweb-inline-event",
                    title="Inline JavaScript event handler",
                    severity="medium",
                    element=tag,
                    attribute=attr_name,
                    message=f"{attr_name}='{value}' contains inline JavaScript; potential XSS",
                )

        # Recurse into children
        for child in element:
            self._scan_element(child, depth + 1)

    def _check_t_att(self, tag: str, attr: str, value: str) -> None:
        """Check t-att-* attributes for security issues."""
        # t-att URL attributes are especially dangerous.
        base_attr = attr.replace("t-att-", "")
        if base_attr.startswith("on"):
            self._add_finding(
                rule_id="odoo-qweb-dynamic-event-handler",
                title=f"Dynamic event handler attribute: {attr}",
                severity="high",
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' dynamically builds a JavaScript event handler; verify user data cannot break out of JavaScript context",
            )
            return
        if base_attr == "style" and self._looks_dynamic_style_value(value):
            self._add_finding(
                rule_id="odoo-qweb-dynamic-style-attribute",
                title="QWeb dynamic style attribute",
                severity="medium",
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' writes dynamic CSS into a style attribute; verify untrusted data cannot hide, overlay, or restyle privileged UI",
            )
            return
        if base_attr == "class" and self._looks_dynamic_class_value(value):
            self._add_finding(
                rule_id="odoo-qweb-dynamic-class-attribute",
                title="QWeb dynamic class attribute",
                severity="low",
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' writes dynamic CSS classes; verify untrusted data cannot hide controls, spoof status, or alter privileged UI affordances",
            )
            return
        if base_attr == "srcdoc" and self._looks_dynamic_html_value(value):
            self._check_srcdoc_html_sink(tag, attr, value)
            return
        if self._looks_sensitive_attribute_render(base_attr, value):
            self._check_sensitive_render(tag, attr, value)
        if base_attr in self.URL_BEARING_ATTRIBUTES:
            self._add_finding(
                rule_id="odoo-qweb-t-att-url",
                title=f"Dynamic URL attribute: {attr}",
                severity="medium",
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' sets a URL dynamically; verify javascript: URLs cannot be injected",
            )
            self._check_sensitive_url_token(tag, attr, value)

    def _check_t_att_mapping(self, element: ElementTree.Element, tag: str, attr: str, value: str) -> None:
        """Check t-att mapping expressions for risky dynamic attributes."""
        style_value = self._mapped_attribute_value(value, "style")
        if style_value is not None and self._looks_dynamic_style_value(style_value):
            self._add_finding(
                rule_id="odoo-qweb-dynamic-style-attribute",
                title="QWeb dynamic style attribute",
                severity="medium",
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' maps dynamic CSS into a style attribute; verify untrusted data cannot hide, overlay, or restyle privileged UI",
            )

        class_value = self._mapped_attribute_value(value, "class")
        if class_value is not None and self._looks_dynamic_class_value(class_value):
            self._add_finding(
                rule_id="odoo-qweb-dynamic-class-attribute",
                title="QWeb dynamic class attribute",
                severity="low",
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' maps dynamic CSS classes; verify untrusted data cannot hide controls, spoof status, or alter privileged UI affordances",
            )

        for sensitive_attr, sensitive_value in self._mapped_sensitive_attribute_values(value):
            if self._looks_sensitive_attribute_render(sensitive_attr, sensitive_value):
                self._check_sensitive_render(tag, attr, sensitive_value)
                break

        srcdoc_value = self._mapped_attribute_value(value, "srcdoc")
        if srcdoc_value is not None and self._looks_dynamic_html_value(srcdoc_value):
            self._check_srcdoc_html_sink(tag, attr, srcdoc_value)

        src_value = self._mapped_attribute_value(value, "src")
        if tag.lower() == "script" and src_value is not None and self._looks_dynamic_asset_target(src_value):
            self._add_finding(
                rule_id="odoo-qweb-dynamic-script-src",
                title="QWeb script source uses dynamic target",
                severity="high",
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' maps script src to JavaScript imported at runtime from an external or dynamic target; restrict script URLs to reviewed bundles or strict allowlists",
            )

        href_value = self._mapped_attribute_value(value, "href")
        rel_tokens = set(_xml_attr(element, "rel").lower().split())
        mapped_rel_value = self._mapped_attribute_value(value, "rel")
        mapped_rel_tokens = set(mapped_rel_value.lower().strip("'\"").split()) if mapped_rel_value else set()
        if (
            tag.lower() == "link"
            and href_value is not None
            and self._looks_dynamic_asset_target(href_value)
            and "stylesheet" in rel_tokens | mapped_rel_tokens
        ):
            self._add_finding(
                rule_id="odoo-qweb-dynamic-stylesheet-href",
                title="QWeb stylesheet href uses dynamic target",
                severity="medium",
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' maps stylesheet href to CSS loaded from an external or dynamic target; verify untrusted data cannot choose stylesheets that hide, overlay, or restyle privileged UI",
            )

        if not self._mapping_sets_url_attribute(value):
            return
        severity = "high" if self._has_dangerous_url_scheme(value) else "medium"
        self._add_finding(
            rule_id="odoo-qweb-t-att-mapping-url",
            title="Dynamic QWeb attribute mapping sets URL",
            severity=severity,
            element=tag,
            attribute=attr,
            message=f"{attr}='{value}' can set URL-bearing attributes dynamically; verify untrusted values cannot produce javascript: URLs or unsafe destinations",
        )
        self._check_sensitive_url_token(tag, attr, value)

    def _check_t_attf(self, tag: str, attr: str, value: str) -> None:
        """Check t-attf-* formatted attributes for URL/script injection."""
        base_attr = attr.replace("t-attf-", "")
        if base_attr.startswith("on"):
            self._add_finding(
                rule_id="odoo-qweb-dynamic-event-handler",
                title=f"Formatted dynamic event handler: {attr}",
                severity="high",
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' formats a JavaScript event handler; attribute escaping is not enough for JavaScript context",
            )
            return
        if base_attr == "style" and self._looks_dynamic_style_value(value):
            self._add_finding(
                rule_id="odoo-qweb-dynamic-style-attribute",
                title="QWeb dynamic style attribute",
                severity="medium",
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' formats dynamic CSS into a style attribute; verify untrusted data cannot hide, overlay, or restyle privileged UI",
            )
            return
        if base_attr == "class" and self._looks_dynamic_class_value(value):
            self._add_finding(
                rule_id="odoo-qweb-dynamic-class-attribute",
                title="QWeb dynamic class attribute",
                severity="low",
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' formats dynamic CSS classes; verify untrusted data cannot hide controls, spoof status, or alter privileged UI affordances",
            )
            return
        if base_attr == "srcdoc" and self._looks_dynamic_html_value(value):
            self._check_srcdoc_html_sink(tag, attr, value)
            return
        if self._looks_sensitive_attribute_render(base_attr, value):
            self._check_sensitive_render(tag, attr, value)
        if base_attr in self.URL_BEARING_ATTRIBUTES:
            severity = "high" if self._has_dangerous_url_scheme(value) else "medium"
            self._add_finding(
                rule_id="odoo-qweb-t-attf-url",
                title=f"Formatted dynamic URL attribute: {attr}",
                severity=severity,
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' formats a URL dynamically; verify untrusted values cannot produce javascript: URLs",
            )
            self._check_sensitive_url_token(tag, attr, value)

    def _check_t_options(self, tag: str, attr: str, value: str) -> None:
        """Check t-options for rendering modes that bypass normal escaping."""
        if re.search(r"['\"]widget['\"]\s*:\s*['\"]html['\"]", value):
            self._add_finding(
                rule_id="odoo-qweb-html-widget",
                title="QWeb HTML widget rendering",
                severity="medium",
                element=tag,
                attribute=attr,
                message="t-options uses widget='html'; verify the field is sanitized and writers are trusted",
            )

    def _check_markup_escape_bypass(self, tag: str, attr: str, value: str) -> None:
        """Check escaped render directives for Markup() escape bypasses."""
        if not re.search(r"\bMarkup\s*\(", value):
            return
        self._add_finding(
            rule_id="odoo-qweb-markup-escape-bypass",
            title="QWeb Markup() bypasses escaping",
            severity="medium",
            element=tag,
            attribute=attr,
            message=f"{attr}='{value}' renders a Markup() value as already-safe HTML; verify the source is sanitized and trusted",
        )

    def _check_t_set_markup_value(self, element: ElementTree.Element, tag: str) -> None:
        """Track QWeb variables assigned already-safe Markup values."""
        variable = _xml_attr(element, "t-set").strip()
        value = _xml_attr(element, "t-value")
        if not variable or not re.search(r"\bMarkup\s*\(", value):
            return
        self.markup_t_set_vars.add(variable)

    def _check_t_set_markup_render(self, tag: str, attr: str, value: str) -> None:
        """Check escaped render directives that output a Markup-backed t-set variable."""
        if value.strip() not in self.markup_t_set_vars:
            return
        self._add_finding(
            rule_id="odoo-qweb-markup-escape-bypass",
            title="QWeb Markup() bypasses escaping",
            severity="medium",
            element=tag,
            attribute=attr,
            message=f"{attr}='{value}' renders a t-set variable assigned from Markup(); verify the source is sanitized and trusted",
        )

    def _check_t_out_mode(self, tag: str, attr: str, value: str) -> None:
        """Check OWL/custom raw output modes on escaped directives."""
        if value.strip().lower() != "raw":
            return
        self._add_finding(
            rule_id="odoo-qweb-raw-output-mode",
            title="QWeb raw output mode disables escaping",
            severity="high",
            element=tag,
            attribute=attr,
            message="t-out-mode='raw' disables normal t-out escaping; verify rendered data is sanitized and trusted",
        )

    def _check_t_call(self, tag: str, attr: str, value: str) -> None:
        """Check t-call for dynamic template selection."""
        if not self._looks_dynamic_t_call(value):
            return
        self._add_finding(
            rule_id="odoo-qweb-dynamic-t-call",
            title="QWeb t-call uses a dynamic template expression",
            severity="medium",
            element=tag,
            attribute=attr,
            message=f"t-call='{value}' chooses a template dynamically; verify untrusted data cannot select privileged templates",
        )

    def _looks_dynamic_t_call(self, value: str) -> bool:
        """Return True for t-call values that look expression-backed, not literal XML IDs."""
        stripped = value.strip()
        if not stripped:
            return False
        if re.search(r"(#\{|\{\{|\}\}|[\[\]\(\)\+\%])", stripped):
            return True
        first_segment = stripped.split(".", 1)[0]
        if first_segment in self.DYNAMIC_TEMPLATE_NAMES:
            return True
        return bool(re.search(r"\b(?:getattr|request|context|kwargs|params|template_name)\b", stripped))

    def _check_sensitive_render(self, tag: str, attr: str, value: str) -> None:
        """Check escaped rendering of credential-like fields."""
        lowered = value.lower()
        if any(marker in lowered for marker in self.SENSITIVE_FIELD_MARKERS):
            self._add_finding(
                rule_id="odoo-qweb-sensitive-field-render",
                title="QWeb renders sensitive-looking field",
                severity="high",
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' renders token, secret, password, or API-key-like data; verify templates cannot expose credentials",
            )

    def _looks_sensitive_attribute_render(self, attr: str, value: str) -> bool:
        """Return True when dynamic attributes expose credential-shaped values."""
        lowered_attr = attr.lower()
        if not (
            lowered_attr in {"value", "content"}
            or lowered_attr.startswith("data-")
            or any(marker in lowered_attr for marker in self.SENSITIVE_FIELD_MARKERS)
        ):
            return False
        stripped = value.strip()
        if re.fullmatch(r"""['"][^'"]*['"]""", stripped):
            return False
        lowered_value = value.lower()
        return any(marker in lowered_value for marker in self.SENSITIVE_FIELD_MARKERS)

    def _check_url_attr(self, tag: str, attr: str, value: str) -> None:
        """Check URL-bearing attributes for dangerous URL schemes."""
        if self._has_dangerous_url_scheme(value):
            self._add_finding(
                rule_id="odoo-qweb-js-url",
                title="Dangerous URL scheme detected",
                severity="high",
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' contains an executable or local-file URL scheme; XSS/navigation sink",
            )
        self._check_sensitive_url_token(tag, attr, value)

    def _has_dangerous_url_scheme(self, value: str) -> bool:
        """Return True for URL literals that execute script/HTML or expose local files."""
        return bool(self.DANGEROUS_URL_SCHEME_RE.search(value) or self.DANGEROUS_URL_SCHEME_LITERAL_RE.search(value))

    def _has_dangerous_meta_refresh_url(self, value: str) -> bool:
        """Return True when a meta refresh URL uses an executable/local scheme."""
        return bool(
            re.search(
                r"\burl\s*=\s*(?:javascript:|vbscript:|file:|data:(?:text/html|application/(?:javascript|xhtml\+xml)))",
                value,
                re.IGNORECASE,
            )
        )

    def _looks_dynamic_meta_refresh(self, value: str) -> bool:
        """Return True when meta refresh content redirects to a dynamic target."""
        return bool(re.search(r"\burl\s*=", value, re.IGNORECASE) and self.URL_DYNAMIC_MARKER_RE.search(value))

    def _check_sensitive_url_token(self, tag: str, attr: str, value: str) -> None:
        """Check URL-bearing QWeb attributes for token/secret-like parameters."""
        if not self._looks_sensitive_url_token(value):
            return
        self._add_finding(
            rule_id="odoo-qweb-sensitive-url-token",
            title="QWeb URL exposes sensitive-looking parameter",
            severity="medium",
            element=tag,
            attribute=attr,
            message=f"{attr}='{value}' places token, secret, password, or API-key-like data in a URL; verify it cannot leak through logs, referrers, browser history, or shared links",
        )

    def _looks_sensitive_url_token(self, value: str) -> bool:
        """Return True when a URL-like expression exposes secret-shaped parameters."""
        return bool(self.SENSITIVE_URL_PARAM_RE.search(value) and self.URL_DYNAMIC_MARKER_RE.search(value))

    def _looks_dynamic_style_value(self, value: str) -> bool:
        """Return True for dynamic style attributes that can restyle privileged UI."""
        return bool(self.STYLE_DYNAMIC_MARKER_RE.search(value) or self.CSS_URL_RE.search(value))

    def _looks_dynamic_html_value(self, value: str) -> bool:
        """Return True for template expressions that write dynamic HTML."""
        return bool(self.HTML_DYNAMIC_MARKER_RE.search(value))

    def _looks_dynamic_class_value(self, value: str) -> bool:
        """Return True for dynamic class attributes that can alter visible UI state."""
        return bool(self.CLASS_DYNAMIC_MARKER_RE.search(value))

    def _looks_dynamic_asset_target(self, value: str) -> bool:
        """Return True for asset URLs that are expression-backed rather than static literals."""
        stripped = value.strip()
        if not stripped:
            return False
        if re.fullmatch(r"""['"][^'"]*['"]""", stripped):
            return False
        return bool(self.URL_DYNAMIC_MARKER_RE.search(stripped) or re.search(r"\b(?:get|get_param|getlist|getattr)\s*\(", stripped))

    def _check_srcdoc_html_sink(self, tag: str, attr: str, value: str) -> None:
        """Check iframe srcdoc attributes that receive dynamic HTML."""
        self._add_finding(
            rule_id="odoo-qweb-srcdoc-html",
            title="QWeb iframe srcdoc receives dynamic HTML",
            severity="high",
            element=tag,
            attribute=attr,
            message=f"{attr}='{value}' writes dynamic HTML into iframe srcdoc; sanitize HTML and sandbox the frame before rendering untrusted template data",
        )

    def _mapped_attribute_value(self, mapping: str, key: str) -> str | None:
        """Return a best-effort value expression from a QWeb t-att mapping."""
        match = re.search(rf"['\"]{re.escape(key)}['\"]\s*:\s*([^}}]+)", mapping, re.IGNORECASE)
        if not match:
            return None
        return match.group(1).split(",", 1)[0]

    def _mapping_sets_url_attribute(self, mapping: str) -> bool:
        """Return whether a QWeb t-att mapping can set a URL-bearing attribute."""
        return bool(re.search(rf"['\"]{self.URL_BEARING_ATTRIBUTE_RE}['\"]", mapping, re.IGNORECASE))

    def _mapped_sensitive_attribute_values(self, mapping: str) -> list[tuple[str, str]]:
        """Return sensitive-looking attribute/value pairs from a QWeb t-att mapping."""
        pairs: list[tuple[str, str]] = []
        seen: set[str] = set()
        for match in re.finditer(r"['\"](?P<attr>[\w:-]+)['\"]\s*:", mapping):
            attr = match.group("attr")
            lowered_attr = attr.lower()
            if not (
                lowered_attr in {"value", "content"}
                or lowered_attr.startswith("data-")
                or any(marker in lowered_attr for marker in self.SENSITIVE_FIELD_MARKERS)
            ):
                continue
            if lowered_attr in seen:
                continue
            seen.add(lowered_attr)
            mapped_value = self._mapped_attribute_value(mapping, attr)
            if mapped_value is not None:
                pairs.append((attr, mapped_value))
        return pairs

    def _check_post_form_csrf(self, element: ElementTree.Element, tag: str) -> None:
        """Check template POST forms for a visible CSRF token field."""
        method = _xml_attr(element, "method")
        if not method or method.strip().lower() != "post":
            return
        if self._form_has_csrf_token(element):
            return
        self._add_finding(
            rule_id="odoo-qweb-post-form-missing-csrf",
            title="QWeb POST form lacks visible CSRF token",
            severity="medium",
            element=tag,
            attribute="method",
            message="QWeb template contains a POST form without a visible csrf_token field or request.csrf_token() expression; verify Odoo CSRF protection covers the target endpoint",
        )

    def _form_has_csrf_token(self, element: ElementTree.Element) -> bool:
        for node in element.iter():
            for attr, value in node.attrib.items():
                attr_name = attr.split("}")[-1] if "}" in attr else attr
                if "csrf_token" in attr_name.lower() or "csrf_token" in value.lower():
                    return True
        return False

    def _check_anchor_target_blank(self, element: ElementTree.Element, tag: str) -> None:
        """Check links opening a new tab for opener isolation."""
        target = _xml_attr(element, "target").strip().lower()
        if target != "_blank":
            return
        rel_tokens = set(_xml_attr(element, "rel").lower().split())
        if rel_tokens & {"noopener", "noreferrer"}:
            return
        self._add_finding(
            rule_id="odoo-qweb-target-blank-no-noopener",
            title="QWeb link opens new tab without opener isolation",
            severity="medium",
            element=tag,
            attribute="target",
            message="QWeb link uses target='_blank' without rel='noopener' or rel='noreferrer'; add opener isolation for external links",
        )

    def _check_iframe_sandbox(self, element: ElementTree.Element, tag: str) -> None:
        """Check embedded frames for sandbox containment."""
        if not _xml_has_attr(element, "sandbox"):
            self._add_finding(
                rule_id="odoo-qweb-iframe-missing-sandbox",
                title="QWeb iframe lacks sandbox restrictions",
                severity="medium",
                element=tag,
                attribute="sandbox",
                message="QWeb template embeds an iframe without a sandbox attribute; constrain embedded content privileges unless the frame is fully trusted",
            )
            return

        sandbox_tokens = set(_xml_attr(element, "sandbox").lower().split())
        if {"allow-scripts", "allow-same-origin"}.issubset(sandbox_tokens):
            self._add_finding(
                rule_id="odoo-qweb-iframe-sandbox-escape",
                title="QWeb iframe sandbox allows script same-origin escape",
                severity="high",
                element=tag,
                attribute="sandbox",
                message="QWeb iframe sandbox combines allow-scripts with allow-same-origin; same-origin content can remove the sandbox or access parent-origin data",
            )

    def _check_external_script_integrity(self, element: ElementTree.Element, tag: str) -> None:
        """Check third-party scripts for Subresource Integrity."""
        src = _xml_attr(element, "src").strip()
        if not _is_external_url(src) or _xml_attr(element, "integrity").strip():
            return
        self._add_finding(
            rule_id="odoo-qweb-external-script-missing-sri",
            title="QWeb external script lacks Subresource Integrity",
            severity="medium",
            element=tag,
            attribute="src",
            message="QWeb template loads an external script without an integrity attribute; pin third-party assets with SRI or serve reviewed code from trusted bundles",
        )

    def _check_dynamic_script_src(self, element: ElementTree.Element, tag: str) -> None:
        """Check script tags that import JavaScript from dynamic template expressions."""
        for attr in ("t-att-src", "t-attf-src"):
            value = _xml_attr(element, attr)
            if not value or not self._looks_dynamic_asset_target(value):
                continue
            self._add_finding(
                rule_id="odoo-qweb-dynamic-script-src",
                title="QWeb script source uses dynamic target",
                severity="high",
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' imports JavaScript at runtime from an external or dynamic target; restrict script URLs to reviewed bundles or strict allowlists",
            )
            self._check_sensitive_url_token(tag, attr, value)
            return

    def _check_script_qweb_expression(self, element: ElementTree.Element, tag: str) -> None:
        """Check QWeb output expressions rendered inside JavaScript blocks."""
        for node in element.iter():
            if node is element:
                continue
            for attr in node.attrib:
                attr_name = attr.split("}")[-1] if "}" in attr else attr
                if attr_name not in {"t-out", "t-esc", "t-raw", "t-field"}:
                    continue
                self._add_finding(
                    rule_id="odoo-qweb-script-expression-context",
                    title="QWeb expression rendered inside JavaScript block",
                    severity="high",
                    element=tag,
                    attribute=attr_name,
                    message=f"<script> contains {attr_name}; HTML escaping is not JavaScript-context escaping, so verify rendered data is JSON-encoded or otherwise safely serialized",
                )
                return

    def _check_external_stylesheet_integrity(self, element: ElementTree.Element, tag: str) -> None:
        """Check third-party stylesheets for Subresource Integrity."""
        rel_tokens = set(_xml_attr(element, "rel").lower().split())
        href = _xml_attr(element, "href").strip()
        if "stylesheet" not in rel_tokens or not _is_external_url(href) or _xml_attr(element, "integrity").strip():
            return
        self._add_finding(
            rule_id="odoo-qweb-external-stylesheet-missing-sri",
            title="QWeb external stylesheet lacks Subresource Integrity",
            severity="low",
            element=tag,
            attribute="href",
            message="QWeb template loads an external stylesheet without an integrity attribute; pin third-party CSS with SRI or serve reviewed styles from trusted bundles",
        )

    def _check_dynamic_stylesheet_href(self, element: ElementTree.Element, tag: str) -> None:
        """Check stylesheet links that load CSS from dynamic template expressions."""
        rel_tokens = set(_xml_attr(element, "rel").lower().split())
        if "stylesheet" not in rel_tokens:
            return
        for attr in ("t-att-href", "t-attf-href"):
            value = _xml_attr(element, attr)
            if not value or not self._looks_dynamic_asset_target(value):
                continue
            self._add_finding(
                rule_id="odoo-qweb-dynamic-stylesheet-href",
                title="QWeb stylesheet href uses dynamic target",
                severity="medium",
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' loads CSS from an external or dynamic target; verify untrusted data cannot choose stylesheets that hide, overlay, or restyle privileged UI",
            )
            self._check_sensitive_url_token(tag, attr, value)
            return

    def _check_meta_refresh_redirect(self, element: ElementTree.Element, tag: str) -> None:
        """Check meta refresh redirects for dynamic or executable URL targets."""
        if _xml_attr(element, "http-equiv").strip().lower() != "refresh":
            return
        for attr in ("content", "t-att-content", "t-attf-content"):
            value = _xml_attr(element, attr)
            if not value:
                continue
            dangerous = self._has_dangerous_meta_refresh_url(value)
            if not dangerous and not self._looks_dynamic_meta_refresh(value):
                continue
            self._add_finding(
                rule_id="odoo-qweb-meta-refresh-redirect",
                title="QWeb meta refresh uses dynamic redirect target",
                severity="high" if dangerous else "medium",
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' creates a client-side redirect with a dynamic target; restrict meta refresh redirects to local paths or reviewed allowlists",
            )
            self._check_sensitive_url_token(tag, attr, value)
            return

    def _regex_scan(self, content: str) -> list[QWebFinding]:
        """Fallback regex-based scanning for malformed XML."""
        findings: list[QWebFinding] = []

        # Find t-raw attributes
        for match in re.finditer(r't-raw\s*=\s*["\']([^"\']+)["\']', content):
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-t-raw",
                    title="QWeb t-raw bypasses escaping",
                    severity="medium",
                    file=self.file_path,
                    line=line,
                    element="",
                    attribute="t-raw",
                    message=f"t-raw='{match.group(1)}' renders unescaped HTML",
                )
            )

        # Find dangerous literal URL schemes.
        dangerous_url_attr_re = re.compile(
            rf"({self.URL_BEARING_ATTRIBUTE_RE})\s*=\s*([\"'])\s*"
            r"(?:javascript:|vbscript:|file:|data:(?:text/html|application/(?:javascript|xhtml\+xml)))",
            re.IGNORECASE,
        )
        for match in dangerous_url_attr_re.finditer(content):
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-js-url",
                    title="Dangerous URL scheme detected",
                    severity="high",
                    file=self.file_path,
                    line=line,
                    element="",
                    attribute=match.group(1),
                    message="Executable or local-file URL scheme in attribute; XSS/navigation sink",
                )
            )

        # Find POST forms without visible csrf_token fields.
        for match in re.finditer(r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>", content, re.IGNORECASE | re.DOTALL):
            attrs = match.group("attrs")
            body = match.group("body")
            if not re.search(r"\bmethod\s*=\s*['\"]post['\"]", attrs, re.IGNORECASE):
                continue
            if re.search(r"csrf_token", attrs + body, re.IGNORECASE):
                continue
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-post-form-missing-csrf",
                    title="QWeb POST form lacks visible CSRF token",
                    severity="medium",
                    file=self.file_path,
                    line=line,
                    element="form",
                    attribute="method",
                    message="QWeb template contains a POST form without a visible csrf_token field or request.csrf_token() expression",
                )
            )

        # Find target=_blank links without opener isolation.
        for match in re.finditer(r"<a\b(?P<attrs>[^>]*)>", content, re.IGNORECASE):
            attrs = match.group("attrs")
            if not re.search(r"\btarget\s*=\s*['\"]_blank['\"]", attrs, re.IGNORECASE):
                continue
            rel_match = re.search(r"\brel\s*=\s*['\"](?P<rel>[^'\"]*)['\"]", attrs, re.IGNORECASE)
            if rel_match and re.search(r"\b(?:noopener|noreferrer)\b", rel_match.group("rel"), re.IGNORECASE):
                continue
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-target-blank-no-noopener",
                    title="QWeb link opens new tab without opener isolation",
                    severity="medium",
                    file=self.file_path,
                    line=line,
                    element="a",
                    attribute="target",
                    message="QWeb link uses target='_blank' without rel='noopener' or rel='noreferrer'",
                )
            )

        # Find meta refresh redirects with dynamic or executable targets.
        for match in re.finditer(r"<meta\b(?P<attrs>[^>]*)>", content, re.IGNORECASE):
            attrs = match.group("attrs")
            if not re.search(r"\bhttp-equiv\s*=\s*['\"]refresh['\"]", attrs, re.IGNORECASE):
                continue
            content_match = re.search(r"\b(?P<attr>t-attf?-content|content)\s*=\s*([\"'])(?P<value>.*?)\2", attrs)
            if not content_match:
                continue
            value = content_match.group("value")
            dangerous = self._has_dangerous_meta_refresh_url(value)
            if not dangerous and not self._looks_dynamic_meta_refresh(value):
                continue
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-meta-refresh-redirect",
                    title="QWeb meta refresh uses dynamic redirect target",
                    severity="high" if dangerous else "medium",
                    file=self.file_path,
                    line=line,
                    element="meta",
                    attribute=content_match.group("attr"),
                    message=f"{content_match.group('attr')} creates a client-side redirect with a dynamic target; restrict meta refresh redirects to local paths or reviewed allowlists",
                )
            )
            if self._looks_sensitive_url_token(value):
                findings.append(
                    QWebFinding(
                        rule_id="odoo-qweb-sensitive-url-token",
                        title="QWeb URL exposes sensitive-looking parameter",
                        severity="medium",
                        file=self.file_path,
                        line=line,
                        element="meta",
                        attribute=content_match.group("attr"),
                        message=f"{content_match.group('attr')} places token, secret, password, or API-key-like data in a URL; verify it cannot leak through logs, referrers, browser history, or shared links",
                    )
                )

        # Find iframes without sandbox containment.
        for match in re.finditer(r"<iframe\b(?P<attrs>[^>]*)>", content, re.IGNORECASE):
            attrs = match.group("attrs")
            line = content[: match.start()].count("\n") + 1
            sandbox_match = re.search(r"\bsandbox\s*=\s*([\"'])(?P<sandbox>.*?)\1", attrs, re.IGNORECASE | re.DOTALL)
            if not sandbox_match:
                findings.append(
                    QWebFinding(
                        rule_id="odoo-qweb-iframe-missing-sandbox",
                        title="QWeb iframe lacks sandbox restrictions",
                        severity="medium",
                        file=self.file_path,
                        line=line,
                        element="iframe",
                        attribute="sandbox",
                        message="QWeb template embeds an iframe without a sandbox attribute",
                    )
                )
                continue
            sandbox_tokens = set(sandbox_match.group("sandbox").lower().split())
            if {"allow-scripts", "allow-same-origin"}.issubset(sandbox_tokens):
                findings.append(
                    QWebFinding(
                        rule_id="odoo-qweb-iframe-sandbox-escape",
                        title="QWeb iframe sandbox allows script same-origin escape",
                        severity="high",
                        file=self.file_path,
                        line=line,
                        element="iframe",
                        attribute="sandbox",
                        message="QWeb iframe sandbox combines allow-scripts with allow-same-origin",
                    )
                )

        # Find external scripts without SRI.
        for match in re.finditer(r"<script\b(?P<attrs>[^>]*)>", content, re.IGNORECASE):
            attrs = match.group("attrs")
            dynamic_src_match = re.search(r"\b(?P<attr>t-attf?-src)\s*=\s*([\"'])(?P<src>.*?)\2", attrs, re.IGNORECASE | re.DOTALL)
            if dynamic_src_match and self._looks_dynamic_asset_target(dynamic_src_match.group("src")):
                line = content[: match.start()].count("\n") + 1
                findings.append(
                    QWebFinding(
                        rule_id="odoo-qweb-dynamic-script-src",
                        title="QWeb script source uses dynamic target",
                        severity="high",
                        file=self.file_path,
                        line=line,
                        element="script",
                        attribute=dynamic_src_match.group("attr"),
                        message="QWeb script imports JavaScript at runtime from an external or dynamic target; restrict script URLs to reviewed bundles or strict allowlists",
                    )
                )
            src_match = re.search(r"\bsrc\s*=\s*([\"'])(?P<src>.*?)\1", attrs, re.IGNORECASE | re.DOTALL)
            if not src_match or not _is_external_url(src_match.group("src")):
                continue
            if re.search(r"\bintegrity\s*=", attrs, re.IGNORECASE):
                continue
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-external-script-missing-sri",
                    title="QWeb external script lacks Subresource Integrity",
                    severity="medium",
                    file=self.file_path,
                    line=line,
                    element="script",
                    attribute="src",
                    message="QWeb template loads an external script without an integrity attribute",
                )
            )

        # Find external stylesheets without SRI.
        for match in re.finditer(r"<link\b(?P<attrs>[^>]*)>", content, re.IGNORECASE):
            attrs = match.group("attrs")
            rel_match = re.search(r"\brel\s*=\s*([\"'])(?P<rel>.*?)\1", attrs, re.IGNORECASE | re.DOTALL)
            dynamic_href_match = re.search(r"\b(?P<attr>t-attf?-href)\s*=\s*([\"'])(?P<href>.*?)\2", attrs, re.IGNORECASE | re.DOTALL)
            if rel_match and "stylesheet" in rel_match.group("rel").lower().split():
                if dynamic_href_match and self._looks_dynamic_asset_target(dynamic_href_match.group("href")):
                    line = content[: match.start()].count("\n") + 1
                    findings.append(
                        QWebFinding(
                            rule_id="odoo-qweb-dynamic-stylesheet-href",
                            title="QWeb stylesheet href uses dynamic target",
                            severity="medium",
                            file=self.file_path,
                            line=line,
                            element="link",
                            attribute=dynamic_href_match.group("attr"),
                            message="QWeb stylesheet href loads CSS from an external or dynamic target; verify untrusted data cannot choose stylesheets that hide, overlay, or restyle privileged UI",
                        )
                    )
            href_match = re.search(r"\bhref\s*=\s*([\"'])(?P<href>.*?)\1", attrs, re.IGNORECASE | re.DOTALL)
            if not rel_match or "stylesheet" not in rel_match.group("rel").lower().split():
                continue
            if not href_match or not _is_external_url(href_match.group("href")):
                continue
            if re.search(r"\bintegrity\s*=", attrs, re.IGNORECASE):
                continue
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-external-stylesheet-missing-sri",
                    title="QWeb external stylesheet lacks Subresource Integrity",
                    severity="low",
                    file=self.file_path,
                    line=line,
                    element="link",
                    attribute="href",
                    message="QWeb template loads an external stylesheet without an integrity attribute",
                )
            )

        # Find t-js inline JavaScript blocks.
        for match in re.finditer(r't-js\s*=\s*(["\'])(.*?)\1', content, re.IGNORECASE):
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-t-js-inline-script",
                    title="QWeb t-js inline JavaScript block",
                    severity="medium",
                    file=self.file_path,
                    line=line,
                    element="",
                    attribute="t-js",
                    message=f"t-js='{match.group(2)}' enables inline JavaScript in a template; verify user data cannot reach script context",
                )
            )

        # Find QWeb output expressions embedded in JavaScript blocks.
        script_expression_re = re.compile(
            r"<script\b[^>]*>.*?(?P<attr>t-(?:out|esc|raw|field))\s*=",
            re.IGNORECASE | re.DOTALL,
        )
        for match in script_expression_re.finditer(content):
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-script-expression-context",
                    title="QWeb expression rendered inside JavaScript block",
                    severity="high",
                    file=self.file_path,
                    line=line,
                    element="script",
                    attribute=match.group("attr"),
                    message="<script> contains a QWeb output expression; HTML escaping is not JavaScript-context escaping, so verify rendered data is JSON-encoded or otherwise safely serialized",
                )
            )

        # Find formatted dynamic URL attributes.
        url_attr_re = self.URL_BEARING_ATTRIBUTE_RE
        for match in re.finditer(rf'(t-attf?-{url_attr_re})\s*=\s*["\']([^"\']+)["\']', content, re.IGNORECASE):
            line = content[: match.start()].count("\n") + 1
            severity = "high" if self._has_dangerous_url_scheme(match.group(2)) else "medium"
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-t-attf-url",
                    title=f"Formatted dynamic URL attribute: {match.group(1)}",
                    severity=severity,
                    file=self.file_path,
                    line=line,
                    element="",
                    attribute=match.group(1),
                    message=f"{match.group(1)} formats a URL dynamically; verify untrusted values cannot produce javascript: URLs",
                )
            )
            if self._looks_sensitive_url_token(match.group(2)):
                findings.append(
                    QWebFinding(
                        rule_id="odoo-qweb-sensitive-url-token",
                        title="QWeb URL exposes sensitive-looking parameter",
                        severity="medium",
                        file=self.file_path,
                        line=line,
                        element="",
                        attribute=match.group(1),
                        message=f"{match.group(1)} places token, secret, password, or API-key-like data in a URL; verify it cannot leak through logs, referrers, browser history, or shared links",
                    )
                )

        # Find dynamic event handler attributes.
        for match in re.finditer(r'(t-attf?-on[\w:-]*)\s*=\s*(["\'])(.*?)\2', content, re.IGNORECASE):
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-dynamic-event-handler",
                    title=f"Dynamic event handler attribute: {match.group(1)}",
                    severity="high",
                    file=self.file_path,
                    line=line,
                    element="",
                    attribute=match.group(1),
                    message=f"{match.group(1)} formats or builds a JavaScript event handler; verify user data cannot break out of JavaScript context",
                )
            )

        # Find dynamic style attributes.
        for match in re.finditer(r'(t-attf?-style)\s*=\s*(["\'])(.*?)\2', content, re.IGNORECASE):
            value = match.group(3)
            if not self._looks_dynamic_style_value(value):
                continue
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-dynamic-style-attribute",
                    title="QWeb dynamic style attribute",
                    severity="medium",
                    file=self.file_path,
                    line=line,
                    element="",
                    attribute=match.group(1),
                    message=f"{match.group(1)} writes dynamic CSS into a style attribute; verify untrusted data cannot hide, overlay, or restyle privileged UI",
                )
            )

        # Find iframe srcdoc attributes that receive dynamic HTML.
        for match in re.finditer(r'((?:t-attf?-)?srcdoc)\s*=\s*(["\'])(.*?)\2', content, re.IGNORECASE):
            value = match.group(3)
            if not self._looks_dynamic_html_value(value):
                continue
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-srcdoc-html",
                    title="QWeb iframe srcdoc receives dynamic HTML",
                    severity="high",
                    file=self.file_path,
                    line=line,
                    element="",
                    attribute=match.group(1),
                    message=f"{match.group(1)} writes dynamic HTML into iframe srcdoc; sanitize HTML and sandbox the frame before rendering untrusted template data",
                )
            )

        # Find dynamic class attributes.
        for match in re.finditer(r'(t-attf?-class)\s*=\s*(["\'])(.*?)\2', content, re.IGNORECASE):
            value = match.group(3)
            if not self._looks_dynamic_class_value(value):
                continue
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-dynamic-class-attribute",
                    title="QWeb dynamic class attribute",
                    severity="low",
                    file=self.file_path,
                    line=line,
                    element="",
                    attribute=match.group(1),
                    message=f"{match.group(1)} writes dynamic CSS classes; verify untrusted data cannot hide controls, spoof status, or alter privileged UI affordances",
                )
            )

        # Find Markup() values rendered through escaped directives.
        for match in re.finditer(r'(t-(?:out|esc))\s*=\s*(["\'])(.*?)\2', content, re.IGNORECASE):
            value = match.group(3)
            if not re.search(r"\bMarkup\s*\(", value):
                continue
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-markup-escape-bypass",
                    title="QWeb Markup() bypasses escaping",
                    severity="medium",
                    file=self.file_path,
                    line=line,
                    element="",
                    attribute=match.group(1),
                    message=f"{match.group(1)}='{value}' renders a Markup() value as already-safe HTML; verify the source is sanitized and trusted",
                )
            )

        markup_vars: set[str] = set()
        for match in re.finditer(r"<[^>]*\bt-set\s*=\s*([\"'])(?P<var>[^\"']+)\1[^>]*>", content, re.IGNORECASE):
            tag_text = match.group(0)
            value_match = re.search(r"\bt-value\s*=\s*([\"'])(?P<value>.*?)\1", tag_text, re.IGNORECASE)
            if value_match and re.search(r"\bMarkup\s*\(", value_match.group("value")):
                markup_vars.add(match.group("var").strip())

        if markup_vars:
            for match in re.finditer(r'(t-(?:out|esc))\s*=\s*(["\'])(.*?)\2', content, re.IGNORECASE):
                value = match.group(3).strip()
                if value not in markup_vars:
                    continue
                line = content[: match.start()].count("\n") + 1
                findings.append(
                    QWebFinding(
                        rule_id="odoo-qweb-markup-escape-bypass",
                        title="QWeb Markup() bypasses escaping",
                        severity="medium",
                        file=self.file_path,
                        line=line,
                        element="",
                        attribute=match.group(1),
                        message=f"{match.group(1)}='{value}' renders a t-set variable assigned from Markup(); verify the source is sanitized and trusted",
                    )
                )

        # Find raw t-out mode variants used by some OWL/custom builds.
        for match in re.finditer(r't-out-mode\s*=\s*(["\'])raw\1', content, re.IGNORECASE):
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-raw-output-mode",
                    title="QWeb raw output mode disables escaping",
                    severity="high",
                    file=self.file_path,
                    line=line,
                    element="",
                    attribute="t-out-mode",
                    message="t-out-mode='raw' disables normal t-out escaping; verify rendered data is sanitized and trusted",
                )
            )

        # Find generic t-att mappings that can set risky attributes.
        for match in re.finditer(r"<script\b(?P<attrs>[^>]*)>", content, re.IGNORECASE | re.DOTALL):
            attrs = match.group("attrs")
            mapping_match = re.search(r'\bt-att\s*=\s*(["\'])(?P<value>.*?)\1', attrs, re.IGNORECASE | re.DOTALL)
            if not mapping_match:
                continue
            value = mapping_match.group("value")
            src_value = self._mapped_attribute_value(value, "src")
            if src_value is None or not self._looks_dynamic_asset_target(src_value):
                continue
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-dynamic-script-src",
                    title="QWeb script source uses dynamic target",
                    severity="high",
                    file=self.file_path,
                    line=line,
                    element="script",
                    attribute="t-att",
                    message="t-att maps script src to JavaScript imported at runtime from an external or dynamic target; restrict script URLs to reviewed bundles or strict allowlists",
                )
            )

        for match in re.finditer(r"<link\b(?P<attrs>[^>]*)>", content, re.IGNORECASE | re.DOTALL):
            attrs = match.group("attrs")
            mapping_match = re.search(r'\bt-att\s*=\s*(["\'])(?P<value>.*?)\1', attrs, re.IGNORECASE | re.DOTALL)
            if not mapping_match:
                continue
            value = mapping_match.group("value")
            href_value = self._mapped_attribute_value(value, "href")
            rel_match = re.search(r"\brel\s*=\s*([\"'])(?P<rel>.*?)\1", attrs, re.IGNORECASE | re.DOTALL)
            rel_tokens = set(rel_match.group("rel").lower().split()) if rel_match else set()
            mapped_rel_value = self._mapped_attribute_value(value, "rel")
            mapped_rel_tokens = set(mapped_rel_value.lower().strip("'\"").split()) if mapped_rel_value else set()
            if (
                href_value is None
                or not self._looks_dynamic_asset_target(href_value)
                or "stylesheet" not in rel_tokens | mapped_rel_tokens
            ):
                continue
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-dynamic-stylesheet-href",
                    title="QWeb stylesheet href uses dynamic target",
                    severity="medium",
                    file=self.file_path,
                    line=line,
                    element="link",
                    attribute="t-att",
                    message="t-att maps stylesheet href to CSS loaded from an external or dynamic target; verify untrusted data cannot choose stylesheets that hide, overlay, or restyle privileged UI",
                )
            )

        for match in re.finditer(r't-att\s*=\s*(["\'])(.*?)\1', content, re.IGNORECASE):
            value = match.group(2)
            line = content[: match.start()].count("\n") + 1
            style_value = self._mapped_attribute_value(value, "style")
            if style_value is not None and self._looks_dynamic_style_value(style_value):
                findings.append(
                    QWebFinding(
                        rule_id="odoo-qweb-dynamic-style-attribute",
                        title="QWeb dynamic style attribute",
                        severity="medium",
                        file=self.file_path,
                        line=line,
                        element="",
                        attribute="t-att",
                        message="t-att maps dynamic CSS into a style attribute; verify untrusted data cannot hide, overlay, or restyle privileged UI",
                    )
                )

            class_value = self._mapped_attribute_value(value, "class")
            if class_value is not None and self._looks_dynamic_class_value(class_value):
                findings.append(
                    QWebFinding(
                        rule_id="odoo-qweb-dynamic-class-attribute",
                        title="QWeb dynamic class attribute",
                        severity="low",
                        file=self.file_path,
                        line=line,
                        element="",
                        attribute="t-att",
                        message="t-att maps dynamic CSS classes; verify untrusted data cannot hide controls, spoof status, or alter privileged UI affordances",
                    )
                )

            for sensitive_attr, sensitive_value in self._mapped_sensitive_attribute_values(value):
                if not self._looks_sensitive_attribute_render(sensitive_attr, sensitive_value):
                    continue
                findings.append(
                    QWebFinding(
                        rule_id="odoo-qweb-sensitive-field-render",
                        title="QWeb renders sensitive-looking field",
                        severity="high",
                        file=self.file_path,
                        line=line,
                        element="",
                        attribute="t-att",
                        message="t-att maps token, secret, password, or API-key-like data into an HTML attribute; verify templates cannot expose credentials",
                    )
                )
                break

            srcdoc_value = self._mapped_attribute_value(value, "srcdoc")
            if srcdoc_value is not None and self._looks_dynamic_html_value(srcdoc_value):
                findings.append(
                    QWebFinding(
                        rule_id="odoo-qweb-srcdoc-html",
                        title="QWeb iframe srcdoc receives dynamic HTML",
                        severity="high",
                        file=self.file_path,
                        line=line,
                        element="",
                        attribute="t-att",
                        message="t-att maps dynamic HTML into iframe srcdoc; sanitize HTML and sandbox the frame before rendering untrusted template data",
                    )
                )

            if not self._mapping_sets_url_attribute(value):
                continue
            severity = "high" if self._has_dangerous_url_scheme(value) else "medium"
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-t-att-mapping-url",
                    title="Dynamic QWeb attribute mapping sets URL",
                    severity=severity,
                    file=self.file_path,
                    line=line,
                    element="",
                    attribute="t-att",
                    message="t-att can set URL-bearing attributes dynamically; verify untrusted values cannot produce javascript: URLs or unsafe destinations",
                )
            )
            if self._looks_sensitive_url_token(value):
                findings.append(
                    QWebFinding(
                        rule_id="odoo-qweb-sensitive-url-token",
                        title="QWeb URL exposes sensitive-looking parameter",
                        severity="medium",
                        file=self.file_path,
                        line=line,
                        element="",
                        attribute="t-att",
                        message="t-att places token, secret, password, or API-key-like data in a URL; verify it cannot leak through logs, referrers, browser history, or shared links",
                    )
                )

        # Find dynamic t-call template names.
        for match in re.finditer(r't-call\s*=\s*(["\'])(.*?)\1', content, re.IGNORECASE):
            value = match.group(2)
            if not self._looks_dynamic_t_call(value):
                continue
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-dynamic-t-call",
                    title="QWeb t-call uses a dynamic template expression",
                    severity="medium",
                    file=self.file_path,
                    line=line,
                    element="",
                    attribute="t-call",
                    message=f"t-call='{value}' chooses a template dynamically; verify untrusted data cannot select privileged templates",
                )
            )

        # Find explicit escaped rendering of sensitive-looking fields.
        for match in re.finditer(r'(t-(?:field|esc|out))\s*=\s*["\']([^"\']+)["\']', content, re.IGNORECASE):
            value = match.group(2)
            if not any(marker in value.lower() for marker in self.SENSITIVE_FIELD_MARKERS):
                continue
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-sensitive-field-render",
                    title="QWeb renders sensitive-looking field",
                    severity="high",
                    file=self.file_path,
                    line=line,
                    element="",
                    attribute=match.group(1),
                    message=f"{match.group(1)}='{value}' renders token, secret, password, or API-key-like data",
                )
            )

        sensitive_attr_re = re.compile(r'(t-attf?-(?:value|content|data-[\w:-]+))\s*=\s*(["\'])(.*?)\2', re.IGNORECASE)
        for match in sensitive_attr_re.finditer(content):
            attr = match.group(1)
            value = match.group(3)
            base_attr = re.sub(r"^t-attf?-", "", attr, flags=re.IGNORECASE)
            if not self._looks_sensitive_attribute_render(base_attr, value):
                continue
            line = content[: match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-sensitive-field-render",
                    title="QWeb renders sensitive-looking field",
                    severity="high",
                    file=self.file_path,
                    line=line,
                    element="",
                    attribute=attr,
                    message=f"{attr}='{value}' renders token, secret, password, or API-key-like data",
                )
            )

        return findings

    def _add_finding(
        self,
        rule_id: str,
        title: str,
        severity: str,
        element: str,
        attribute: str = "",
        message: str = "",
    ) -> None:
        """Add a finding with approximate line number."""
        # Try to find the line number by searching for the element
        line = 1
        for line_num, line_content in self.line_map.items():
            if element in line_content:
                line = line_num
                break

        self.findings.append(
            QWebFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=self.file_path,
                line=line,
                element=element,
                attribute=attribute,
                message=message,
            )
        )

    def _dedupe_findings(self, findings: list[QWebFinding]) -> list[QWebFinding]:
        """Remove duplicate findings caused by parsed arch fragments and templates sharing tags."""
        seen: set[tuple[str, str, int, str, str, str]] = set()
        deduped: list[QWebFinding] = []
        for finding in findings:
            key = (
                finding.rule_id,
                finding.file,
                finding.line,
                finding.element,
                finding.attribute,
                finding.message,
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped


def scan_qweb_templates(directory: Path) -> list[QWebFinding]:
    """Scan all QWeb XML files in a directory."""
    findings: list[QWebFinding] = []

    for xml_file in directory.rglob("*.xml"):
        # Check if it's a QWeb/Odoo XML file
        try:
            content = xml_file.read_text(encoding="utf-8", errors="replace")
            if "odoo" in content or "template" in content or "t-" in content:
                scanner = QWebScanner(str(xml_file))
                findings.extend(scanner.scan_file())
        except Exception:  # noqa: S112
            continue

    return findings


def _xml_attr(element: ElementTree.Element, attr_name: str) -> str:
    for attr, value in element.attrib.items():
        local_name = attr.split("}")[-1] if "}" in attr else attr
        if local_name == attr_name:
            return value
    return ""


def _xml_has_attr(element: ElementTree.Element, attr_name: str) -> bool:
    for attr in element.attrib:
        local_name = attr.split("}")[-1] if "}" in attr else attr
        if local_name == attr_name:
            return True
    return False


def _is_external_url(value: str) -> bool:
    return bool(re.match(r"^(?:https?:)?//", value.strip(), re.IGNORECASE))


def findings_to_json(findings: list[QWebFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable format."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "element": f.element,
            "attribute": f.attribute,
            "message": f.message,
        }
        for f in findings
    ]
