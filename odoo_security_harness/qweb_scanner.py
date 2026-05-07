"""QWeb Template Security Scanner - Detects XSS and injection in Odoo QWeb/OWL templates.

QWeb is Odoo's templating engine. It auto-escapes by default, but several
constructs bypass this protection:
- t-raw: renders unescaped HTML
- t-att: sets attributes (can be JS URLs)
- t-js: inline JavaScript blocks
- Markup() in Python: marks strings as safe HTML
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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

    # Patterns for inline JavaScript in attributes
    JS_PATTERNS = [
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"on\w+\s*=", re.IGNORECASE),  # onclick, onload, etc.
    ]

    # Dangerous HTML tags
    DANGEROUS_TAGS = {"script", "iframe", "object", "embed", "form"}

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: list[QWebFinding] = []
        self.line_map: dict[int, str] = {}

    def scan_file(self) -> list[QWebFinding]:
        """Scan a QWeb XML file for security issues."""
        try:
            content = Path(self.file_path).read_text(encoding="utf-8")
        except Exception:
            return []

        # Build line map for accurate line numbers
        self.line_map = {i + 1: line for i, line in enumerate(content.splitlines())}

        # Parse XML
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            # Try with wrapping in case of multiple root elements
            try:
                root = ET.fromstring(f"\u003croot\u003e{content}\u003c/root\u003e")
            except ET.ParseError:
                # Fall back to regex-based scanning
                return self._regex_scan(content)

        self._scan_element(root, 1)
        return self.findings

    def _scan_element(self, element: ET.Element, depth: int) -> None:
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

            # t-att with potential JS injection
            if attr_name.startswith("t-att-"):
                self._check_t_att(tag, attr_name, value)

            # href/src with javascript:
            if attr_name in ("href", "src", "action"):
                self._check_url_attr(tag, attr_name, value)

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
        # t-att-href and t-att-src are especially dangerous
        base_attr = attr.replace("t-att-", "")
        if base_attr in ("href", "src", "action"):
            self._add_finding(
                rule_id="odoo-qweb-t-att-url",
                title=f"Dynamic URL attribute: {attr}",
                severity="medium",
                element=tag,
                attribute=attr,
                message=f"{attr}='{value}' sets a URL dynamically; verify javascript: URLs cannot be injected",
            )

    def _check_url_attr(self, tag: str, attr: str, value: str) -> None:
        """Check href/src attributes for javascript: URLs."""
        for pattern in self.JS_PATTERNS:
            if pattern.search(value):
                self._add_finding(
                    rule_id="odoo-qweb-js-url",
                    title="JavaScript URL detected",
                    severity="high",
                    element=tag,
                    attribute=attr,
                    message=f"{attr}='{value}' contains javascript: URL; XSS sink",
                )
                break

    def _regex_scan(self, content: str) -> list[QWebFinding]:
        """Fallback regex-based scanning for malformed XML."""
        findings: list[QWebFinding] = []

        # Find t-raw attributes
        for match in re.finditer(r't-raw\s*=\s*["\']([^"\']+)["\']', content):
            line = content[:match.start()].count("\n") + 1
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

        # Find javascript: URLs
        for match in re.finditer(r'(href|src|action)\s*=\s*["\']javascript:', content, re.IGNORECASE):
            line = content[:match.start()].count("\n") + 1
            findings.append(
                QWebFinding(
                    rule_id="odoo-qweb-js-url",
                    title="JavaScript URL detected",
                    severity="high",
                    file=self.file_path,
                    line=line,
                    element="",
                    attribute=match.group(1),
                    message="javascript: URL in attribute; XSS sink",
                )
            )

        return findings

    def _add_finding(
        self,
        rule_id: str,
        title: str,
        severity: str,
        element: str,
        attribute: str,
        message: str,
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
        except Exception:
            continue

    return findings


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
