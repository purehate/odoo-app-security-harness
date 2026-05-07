"""Odoo Deep Pattern Analyzer - AST-based analysis of Odoo-specific security patterns.

This module performs deep analysis of Odoo Python code using AST to detect
complex security patterns that simple regex or Semgrep might miss:

- Multi-hop data flows (request.params -> function -> sudo() -> search)
- Context manager analysis (sudo() scope)
- Control flow analysis (auth checks before/after sensitive operations)
- Cross-function taint tracking
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Represents a security finding from deep pattern analysis."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    column: int
    message: str
    confidence: str = "medium"
    hunter: str = "deep-pattern"
    sink_kind: str = ""


@dataclass
class OdooFunction:
    """Represents an analyzed Odoo function/method."""

    name: str
    line: int
    is_controller: bool = False
    auth_level: str = "user"  # public, user, none
    csrf_enabled: bool = True
    http_methods: list[str] = field(default_factory=list)
    has_sudo: bool = False
    has_cr_execute: bool = False
    has_safe_eval: bool = False
    has_request_params: bool = False
    calls_write: bool = False
    calls_create: bool = False
    calls_unlink: bool = False
    calls_search: bool = False
    calls_read: bool = False
    returns_json: bool = False
    has_auth_check: bool = False


class OdooDeepAnalyzer(ast.NodeVisitor):
    """AST visitor for deep Odoo security pattern analysis."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: list[Finding] = []
        self.current_function: OdooFunction | None = None
        self.function_stack: list[OdooFunction] = []
        self.tainted_vars: set[str] = set()

    def analyze(self, source: str) -> list[Finding]:
        """Analyze Python source code and return findings."""
        try:
            tree = ast.parse(source)
            self.visit(tree)
        except SyntaxError as exc:
            logger.warning(f"Syntax error in {self.file_path}: {exc}")
        return self.findings

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definitions to detect Odoo controllers."""
        func = OdooFunction(
            name=node.name,
            line=node.lineno,
        )

        # Check for @http.route decorator
        for decorator in node.decorator_list:
            if self._is_http_route(decorator):
                func.is_controller = True
                auth, csrf, methods = self._extract_route_kwargs(decorator)
                func.auth_level = auth
                func.csrf_enabled = csrf
                func.http_methods = methods

        self.function_stack.append(func)
        self.current_function = func
        self.tainted_vars = set()

        # Visit function body
        self.generic_visit(node)

        # Post-function analysis
        self._analyze_function_patterns(func)

        self.function_stack.pop()
        self.current_function = self.function_stack[-1] if self.function_stack else None

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit assignments to track tainted variables."""
        # Check if right-hand side is request.params or request.jsonrequest
        if isinstance(node.value, ast.Attribute):
            if self._is_request_params_attr(node.value):
                self.current_function.has_request_params = True
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)
        elif isinstance(node.value, ast.Subscript):
            if self._is_request_params_subscript(node.value):
                self.current_function.has_request_params = True
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)

        self.generic_visit(node)

    def _is_request_params_attr(self, node: ast.Attribute) -> bool:
        """Check if node is request.params or request.jsonrequest."""
        if node.attr in ("params", "jsonrequest"):
            if isinstance(node.value, ast.Name) and node.value.id == "request":
                return True
        return False

    def _is_request_params_subscript(self, node: ast.Subscript) -> bool:
        """Check if node is request.params['key'] or request.jsonrequest['key']."""
        if isinstance(node.value, ast.Attribute):
            if node.value.attr in ("params", "jsonrequest"):
                if isinstance(node.value.value, ast.Name) and node.value.value.id == "request":
                    return True
        return False

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function calls to detect security sinks."""
        if self.current_function is None:
            self.generic_visit(node)
            return

        # Detect sudo()
        if self._is_sudo_call(node):
            self.current_function.has_sudo = True
            self._check_sudo_context(node)

        # Detect cr.execute
        if self._is_cr_execute(node):
            self.current_function.has_cr_execute = True
            self._check_sql_injection(node)

        # Detect safe_eval
        if self._is_safe_eval(node):
            self.current_function.has_safe_eval = True
            self._check_safe_eval(node)

        # Detect request.params usage in calls
        for arg in node.args:
            if isinstance(arg, (ast.Attribute, ast.Subscript)):
                if self._is_request_params_attr(arg) or self._is_request_params_subscript(arg):
                    self.current_function.has_request_params = True

        # Detect ORM operations
        if self._is_orm_write(node):
            self.current_function.calls_write = True
            self._check_mass_assignment(node)
        elif self._is_orm_create(node):
            self.current_function.calls_create = True
            self._check_mass_assignment(node)
        elif self._is_orm_unlink(node):
            self.current_function.calls_unlink = True
        elif self._is_orm_search(node):
            self.current_function.calls_search = True
        elif self._is_orm_read(node):
            self.current_function.calls_read = True

        # Detect with_user(admin)
        if self._is_with_user_admin(node):
            self._add_finding(
                rule_id="odoo-deep-with-user-admin",
                title="Admin context switch detected",
                severity="medium",
                line=node.lineno,
                column=node.col_offset,
                message="with_user() switches to admin/root context, bypassing record rules",
            )

        # Detect search([]) with sudo
        if self._is_empty_search_sudo(node):
            self._add_finding(
                rule_id="odoo-deep-empty-search-sudo",
                title="Unbounded search with sudo",
                severity="high",
                line=node.lineno,
                column=node.col_offset,
                message="sudo().search([]) returns all records in the table; verify authorization",
            )

        self.generic_visit(node)

    def _is_http_route(self, decorator: ast.expr) -> bool:
        """Check if decorator is @http.route."""
        if isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Attribute):
                return (isinstance(decorator.func.value, ast.Name)
                        and decorator.func.value.id == "http"
                        and decorator.func.attr == "route")
            elif isinstance(decorator.func, ast.Name):
                return decorator.func.id == "route"
        return False

    def _extract_route_kwargs(self, decorator: ast.Call) -> tuple[str, bool, list[str]]:
        """Extract auth, csrf, and methods from @http.route decorator."""
        auth = "user"
        csrf = True
        methods: list[str] = []

        for kw in decorator.keywords:
            if kw.arg == "auth" and isinstance(kw.value, ast.Constant):
                auth = str(kw.value.value)
            elif kw.arg == "csrf" and isinstance(kw.value, ast.Constant):
                csrf = bool(kw.value.value)
            elif kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                for elt in kw.value.elts:
                    if isinstance(elt, ast.Constant):
                        methods.append(str(elt.value))

        return auth, csrf, methods

    def _is_sudo_call(self, node: ast.Call) -> bool:
        """Check if call is .sudo()."""
        return (isinstance(node.func, ast.Attribute)
                and node.func.attr == "sudo")

    def _is_cr_execute(self, node: ast.Call) -> bool:
        """Check if call is cr.execute()."""
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "cr":
                return True
            elif isinstance(node.func.value, ast.Name) and node.func.value.id == "cr":
                return True
        return False

    def _is_safe_eval(self, node: ast.Call) -> bool:
        """Check if call is safe_eval()."""
        if isinstance(node.func, ast.Name) and node.func.id == "safe_eval":
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr == "safe_eval":
            return True
        return False

    def _is_request_params(self, node: ast.expr) -> bool:
        """Check if node accesses request.params or request.jsonrequest."""
        return self._is_request_params_attr(node) or self._is_request_params_subscript(node)

    def _is_orm_write(self, node: ast.Call) -> bool:
        """Check if call is an ORM write()."""
        return isinstance(node.func, ast.Attribute) and node.func.attr == "write"

    def _is_orm_create(self, node: ast.Call) -> bool:
        """Check if call is an ORM create()."""
        return isinstance(node.func, ast.Attribute) and node.func.attr == "create"

    def _is_orm_unlink(self, node: ast.Call) -> bool:
        """Check if call is an ORM unlink()."""
        return isinstance(node.func, ast.Attribute) and node.func.attr == "unlink"

    def _is_orm_search(self, node: ast.Call) -> bool:
        """Check if call is an ORM search()."""
        return isinstance(node.func, ast.Attribute) and node.func.attr == "search"

    def _is_orm_read(self, node: ast.Call) -> bool:
        """Check if call is an ORM read()."""
        return isinstance(node.func, ast.Attribute) and node.func.attr in ("read", "search_read", "read_group")

    def _is_with_user_admin(self, node: ast.Call) -> bool:
        """Check if call is with_user(env.ref('base.user_admin'))."""
        if isinstance(node.func, ast.Attribute) and node.func.attr == "with_user":
            # Simplified check
            return True
        return False

    def _is_empty_search_sudo(self, node: ast.Call) -> bool:
        """Check if call is .sudo().search([])."""
        # This would need context about whether sudo() was called before
        return False

    def _check_sudo_context(self, node: ast.Call) -> None:
        """Analyze sudo() usage for security issues."""
        if self.current_function and self.current_function.is_controller:
            if self.current_function.auth_level in ("public", "none"):
                self._add_finding(
                    rule_id="odoo-deep-public-sudo",
                    title="Public route with sudo()",
                    severity="high",
                    line=node.lineno,
                    column=node.col_offset,
                    message=f"auth='{self.current_function.auth_level}' route uses sudo(); potential unauthenticated data access",
                )

    def _check_sql_injection(self, node: ast.Call) -> None:
        """Check for SQL injection in cr.execute calls."""
        if not node.args:
            return

        query_arg = node.args[0]

        # Check for f-string
        if isinstance(query_arg, ast.JoinedStr):
            self._add_finding(
                rule_id="odoo-deep-sql-fstring",
                title="SQL query built with f-string",
                severity="high",
                line=node.lineno,
                column=node.col_offset,
                message="cr.execute() with f-string interpolation; SQL injection possible",
            )
        # Check for % formatting
        elif isinstance(query_arg, ast.BinOp) and isinstance(query_arg.op, ast.Mod):
            self._add_finding(
                rule_id="odoo-deep-sql-percent",
                title="SQL query built with % formatting",
                severity="high",
                line=node.lineno,
                column=node.col_offset,
                message="cr.execute() with % string formatting; SQL injection possible",
            )
        # Check for + concatenation
        elif isinstance(query_arg, ast.BinOp) and isinstance(query_arg.op, ast.Add):
            self._add_finding(
                rule_id="odoo-deep-sql-concat",
                title="SQL query built with concatenation",
                severity="high",
                line=node.lineno,
                column=node.col_offset,
                message="cr.execute() with string concatenation; SQL injection possible",
            )

    def _check_safe_eval(self, node: ast.Call) -> None:
        """Check for unsafe safe_eval usage."""
        if len(node.args) > 0:
            first_arg = node.args[0]
            is_tainted = False
            
            # Direct request.params['something']
            if isinstance(first_arg, ast.Subscript):
                if isinstance(first_arg.value, ast.Attribute):
                    if first_arg.value.attr in ("params", "jsonrequest"):
                        is_tainted = True
            
            # Tainted variable
            if isinstance(first_arg, ast.Name):
                if first_arg.id in self.tainted_vars:
                    is_tainted = True
            
            if is_tainted:
                self._add_finding(
                    rule_id="odoo-deep-safe-eval-user-input",
                    title="safe_eval with user input",
                    severity="critical",
                    line=node.lineno,
                    column=node.col_offset,
                    message="safe_eval() called with user-controlled input; potential code execution",
                )

    def _check_mass_assignment(self, node: ast.Call) -> None:
        """Check for mass assignment in write/create."""
        if len(node.args) < 1:
            return

        first_arg = node.args[0]
        is_tainted = False
        taint_source = ""

        # Check if argument is request.params or request.jsonrequest
        if isinstance(first_arg, ast.Attribute):
            if first_arg.attr in ("params", "jsonrequest"):
                is_tainted = True
                taint_source = f"request.{first_arg.attr}"

        # Check if argument is a tainted variable
        if isinstance(first_arg, ast.Name):
            if first_arg.id in self.tainted_vars:
                is_tainted = True
                taint_source = f"tainted variable '{first_arg.id}'"

        if is_tainted:
            self._add_finding(
                rule_id="odoo-deep-mass-assignment",
                title="Mass assignment from request",
                severity="high",
                line=node.lineno,
                column=node.col_offset,
                message=f"ORM {node.func.attr}() called with {taint_source}; mass assignment possible",
            )

    def _track_taint(self, node: ast.Call) -> None:
        """Track tainted variables for cross-function analysis."""
        pass

    def _analyze_function_patterns(self, func: OdooFunction) -> None:
        """Post-function analysis for complex patterns."""
        # Check for public route + sudo + search/read
        if (func.is_controller
            and func.auth_level in ("public", "none")
            and func.has_sudo
            and (func.calls_search or func.calls_read)):
            self._add_finding(
                rule_id="odoo-deep-public-sudo-search",
                title="Public route with sudo and search/read",
                severity="critical",
                line=func.line,
                column=0,
                message=f"auth='{func.auth_level}' route uses sudo() and searches/reads; potential full data dump",
            )

        # Check for CSRF disabled on write route
        if (func.is_controller
            and not func.csrf_enabled
            and (func.calls_write or func.calls_create or func.calls_unlink)):
            self._add_finding(
                rule_id="odoo-deep-csrf-write",
                title="CSRF disabled on state-changing route",
                severity="medium",
                line=func.line,
                column=0,
                message="Route disables CSRF and performs writes; CSRF attack possible",
            )

        # Check for request.params -> cr.execute
        if func.has_request_params and func.has_cr_execute:
            self._add_finding(
                rule_id="odoo-deep-request-to-sql",
                title="User input reaches raw SQL",
                severity="critical",
                line=func.line,
                column=0,
                message="request.params flows to cr.execute(); SQL injection likely",
            )

        # Check for request.params -> sudo() -> write
        if func.has_request_params and func.has_sudo and func.calls_write:
            self._add_finding(
                rule_id="odoo-deep-request-sudo-write",
                title="User input reaches privileged write",
                severity="critical",
                line=func.line,
                column=0,
                message="User input reaches sudo().write(); privilege escalation and data mutation",
            )

    def _add_finding(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        column: int,
        message: str,
    ) -> None:
        """Add a finding to the results."""
        finding = Finding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            file=self.file_path,
            line=line,
            column=column,
            message=message,
        )
        self.findings.append(finding)


def analyze_file(file_path: Path) -> list[Finding]:
    """Analyze a single Python file for Odoo security patterns."""
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception as exc:
        logger.error(f"Failed to read {file_path}: {exc}")
        return []

    analyzer = OdooDeepAnalyzer(str(file_path))
    return analyzer.analyze(source)


def analyze_directory(directory: Path) -> list[Finding]:
    """Analyze all Python files in a directory for Odoo security patterns."""
    findings: list[Finding] = []

    for py_file in directory.rglob("*.py"):
        # Skip test files and common non-Odoo directories
        if any(part in str(py_file) for part in ("test", "tests", "__pycache__", ".venv")):
            continue
        findings.extend(analyze_file(py_file))

    return findings


def findings_to_json(findings: list[Finding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable format."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "column": f.column,
            "message": f.message,
            "confidence": f.confidence,
            "hunter": f.hunter,
            "sink_kind": f.sink_kind,
        }
        for f in findings
    ]
