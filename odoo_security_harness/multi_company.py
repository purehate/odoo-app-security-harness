"""Multi-Company Isolation Checker - Detects cross-company data leakage in Odoo.

Odoo supports multi-company (multi-tenant) deployments where records should
be isolated between companies. This module detects patterns that break
this isolation:

- Missing company_id filters
- sudo() without company scoping
- check_company=False on Many2one
- with_company() with user-controlled values
- Domain literals that don't filter by company
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class MultiCompanyFinding:
    """Represents a multi-company isolation security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""


class MultiCompanyChecker(ast.NodeVisitor):
    """AST-based checker for multi-company isolation issues."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: list[MultiCompanyFinding] = []
        self.current_class: str = ""
        self.has_company_id: bool = False
        self.has_check_company: bool = False

    def check_file(self) -> list[MultiCompanyFinding]:
        """Check a Python file for multi-company issues."""
        try:
            source = Path(self.file_path).read_text(encoding="utf-8")
            tree = ast.parse(source)
            self.visit(tree)
        except SyntaxError:
            pass
        except Exception as exc:
            print(f"Warning: Could not analyze {self.file_path}: {exc}")
        return self.findings

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class definitions to detect Odoo models."""
        old_class = self.current_class
        old_has_company_id = self.has_company_id
        old_has_check_company = self.has_check_company

        # Check if it's an Odoo model
        is_model = any(
            isinstance(base, ast.Attribute) and base.attr == "Model"
            for base in node.bases
        )

        if is_model:
            self.current_class = node.name
            self.has_company_id = False
            self.has_check_company = False

            # Check for _check_company_auto
            for item in node.body:
                if isinstance(item, ast.Assign):
                    for target in item.targets:
                        if isinstance(target, ast.Name):
                            if target.id == "_check_company_auto":
                                if isinstance(item.value, ast.Constant) and item.value.value is True:
                                    self.has_check_company = True
                            elif target.id == "_check_company":
                                if isinstance(item.value, ast.Constant) and item.value.value is True:
                                    self.has_check_company = True

            # Visit class body
            self.generic_visit(node)

            # Post-class analysis
            if self.has_company_id and not self.has_check_company:
                self._add_finding(
                    rule_id="odoo-mc-missing-check-company",
                    title=f"Model {node.name} has company_id without _check_company_auto",
                    severity="medium",
                    line=node.lineno,
                    message=f"Model '{node.name}' has company_id field but _check_company_auto=True is not set; cross-company access possible",
                    model=node.name,
                )

        self.current_class = old_class
        self.has_company_id = old_has_company_id
        self.has_check_company = old_has_check_company

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit assignments to detect company_id fields."""
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "company_id":
                # Check if it's a Many2one to res.company
                if isinstance(node.value, ast.Call):
                    if isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "Many2one":
                        # Check first argument
                        if node.value.args:
                            first_arg = node.value.args[0]
                            if isinstance(first_arg, ast.Constant) and first_arg.value == "res.company":
                                self.has_company_id = True

                            # Check for check_company=False
                            for kw in node.value.keywords:
                                if kw.arg == "check_company":
                                    if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                                        self._add_finding(
                                            rule_id="odoo-mc-check-company-disabled",
                                            title="Many2one with check_company=False",
                                            severity="medium",
                                            line=node.lineno,
                                            message=f"company_id Many2one has check_company=False; cross-company reference possible",
                                            model=self.current_class,
                                        )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Visit calls to detect multi-company issues."""
        # Detect sudo().search() without company filter
        if self._is_sudo_search(node):
            if not self._has_company_filter(node):
                self._add_finding(
                    rule_id="odoo-mc-sudo-search-no-company",
                    title="sudo().search() without company filter",
                    severity="high",
                    line=node.lineno,
                    message="sudo().search() doesn't filter by company_id; cross-company data read",
                )

        # Detect with_company() with user input
        if self._is_with_company_user_input(node):
            self._add_finding(
                rule_id="odoo-mc-with-company-user-input",
                title="with_company() with user-controlled value",
                severity="medium",
                line=node.lineno,
                message="with_company() called with user input; verify user belongs to target company",
            )

        # Detect domain without company filter on sensitive models
        if self._is_search_on_sensitive_model(node):
            if not self._has_company_in_domain(node):
                self._add_finding(
                    rule_id="odoo-mc-search-no-company",
                    title="Search on model without company filter",
                    severity="low",
                    line=node.lineno,
                    message="search() on multi-company model doesn't filter by company_id",
                )

        self.generic_visit(node)

    def _is_sudo_search(self, node: ast.Call) -> bool:
        """Check if call is .sudo().search(...)."""
        if isinstance(node.func, ast.Attribute) and node.func.attr == "search":
            if isinstance(node.func.value, ast.Call):
                inner = node.func.value
                if isinstance(inner.func, ast.Attribute) and inner.func.attr == "sudo":
                    return True
        return False

    def _has_company_filter(self, node: ast.Call) -> bool:
        """Check if search domain contains company_id filter."""
        if node.args:
            domain = node.args[0]
            return self._domain_has_company(domain)
        return False

    def _domain_has_company(self, node: ast.expr) -> bool:
        """Recursively check if domain contains company_id filter."""
        if isinstance(node, ast.List):
            for item in node.elts:
                if isinstance(item, ast.Tuple) and len(item.elts) >= 2:
                    first = item.elts[0]
                    if isinstance(first, ast.Constant) and "company" in str(first.value).lower():
                        return True
                elif isinstance(item, ast.List):
                    if self._domain_has_company(item):
                        return True
        return False

    def _is_with_company_user_input(self, node: ast.Call) -> bool:
        """Check if call is with_company(request.params[...])."""
        if isinstance(node.func, ast.Attribute) and node.func.attr == "with_company":
            if node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Subscript):
                    if isinstance(first_arg.value, ast.Attribute):
                        if first_arg.value.attr in ("params", "jsonrequest"):
                            return True
        return False

    def _is_search_on_sensitive_model(self, node: ast.Call) -> bool:
        """Check if call is search on a multi-company model."""
        if isinstance(node.func, ast.Attribute) and node.func.attr == "search":
            # Simplified - would need model resolution
            return False
        return False

    def _has_company_in_domain(self, node: ast.Call) -> bool:
        """Check if search domain has company filter."""
        return self._has_company_filter(node)

    def _add_finding(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        model: str = "",
    ) -> None:
        """Add a multi-company finding."""
        self.findings.append(
            MultiCompanyFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=self.file_path,
                line=line,
                message=message,
                model=model,
            )
        )


class MultiCompanyXmlChecker:
    """Check XML files for multi-company issues."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: list[MultiCompanyFinding] = []

    def check_file(self) -> list[MultiCompanyFinding]:
        """Check XML file for multi-company issues."""
        try:
            content = Path(self.file_path).read_text(encoding="utf-8")
        except Exception:
            return []

        # Check record rules for missing company filter
        self._check_record_rules(content)

        return self.findings

    def _check_record_rules(self, content: str) -> None:
        """Check ir.rule records for missing company filters."""
        # Find record rule blocks
        for match in re.finditer(
            r'<record[^\u003e]*model="ir.rule"[^\u003e]*>(.*?)\u003c/record>',
            content,
            re.DOTALL,
        ):
            rule_xml = match.group(1)

            # Check if it's a multi-company model
            model_match = re.search(r'<field name="model_id"[^\u003e]*ref="model_([^"]+)"', rule_xml)
            if model_match:
                model_name = model_match.group(1)
                if any(x in model_name for x in ["sale", "purchase", "account", "stock", "hr"]):
                    # Check for company_id in domain
                    domain_match = re.search(
                        r'<field name="domain_force"[^\u003e]*>(.*?)\u003c/field>',
                        rule_xml,
                        re.DOTALL,
                    )
                    if domain_match:
                        domain = domain_match.group(1)
                        if "company_id" not in domain and "company" not in domain:
                            line = content[: match.start()].count("\n") + 1
                            self.findings.append(
                                MultiCompanyFinding(
                                    rule_id="odoo-mc-rule-missing-company",
                                    title=f"Record rule for {model_name} missing company filter",
                                    severity="medium",
                                    file=self.file_path,
                                    line=line,
                                    message=f"ir.rule for {model_name} doesn't filter by company_id in multi-company deployment",
                                    model=model_name,
                                )
                            )


def check_multi_company_isolation(repo_path: Path) -> list[MultiCompanyFinding]:
    """Check all files in repository for multi-company isolation issues."""
    findings: list[MultiCompanyFinding] = []

    # Check Python files
    for py_file in repo_path.rglob("*.py"):
        if any(part in str(py_file) for part in ("test", "__pycache__", ".venv")):
            continue
        checker = MultiCompanyChecker(str(py_file))
        findings.extend(checker.check_file())

    # Check XML files
    for xml_file in repo_path.rglob("security/*.xml"):
        checker = MultiCompanyXmlChecker(str(xml_file))
        findings.extend(checker.check_file())

    return findings


def findings_to_json(findings: list[MultiCompanyFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable format."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
        }
        for f in findings
    ]
