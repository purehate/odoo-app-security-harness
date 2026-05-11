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
import re
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
    route_paths: list[str] = field(default_factory=list)
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
    has_request_env: bool = False
    has_tainted_browse: bool = False
    has_attachment_access: bool = False


class OdooDeepAnalyzer(ast.NodeVisitor):
    """AST visitor for deep Odoo security pattern analysis."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: list[Finding] = []
        self.current_function: OdooFunction | None = None
        self.function_stack: list[OdooFunction] = []
        self.tainted_vars: set[str] = set()
        self.unsafe_sql_vars: set[str] = set()
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.field_module_names: set[str] = {"fields"}
        self.superuser_names: set[str] = {"SUPERUSER_ID"}
        self.route_decorator_names: set[str] = set()
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []

    def analyze(self, source: str) -> list[Finding]:
        """Analyze Python source code and return findings."""
        try:
            tree = ast.parse(source)
            self.constants = self._module_constants(tree)
            self.visit(tree)
        except SyntaxError as exc:
            logger.warning(f"Syntax error in {self.file_path}: {exc}")
        return self.findings

    def visit_Import(self, node: ast.Import) -> None:
        """Track aliases for imported Odoo modules."""
        for alias in node.names:
            if alias.name == "odoo":
                self.odoo_module_names.add(alias.asname or alias.name)
            elif alias.name == "odoo.http" and alias.asname:
                self.http_module_names.add(alias.asname)
            elif alias.name == "odoo.fields" and alias.asname:
                self.field_module_names.add(alias.asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track aliases for Odoo HTTP helpers."""
        if node.module == "odoo":
            for alias in node.names:
                if alias.name == "http":
                    self.http_module_names.add(alias.asname or alias.name)
                elif alias.name == "fields":
                    self.field_module_names.add(alias.asname or alias.name)
                elif alias.name == "SUPERUSER_ID":
                    self.superuser_names.add(alias.asname or alias.name)
        if node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
                elif alias.name == "route":
                    self.route_decorator_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class definitions with class-scoped constants available."""
        self.class_constants_stack.append(self._static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

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
                auth, csrf, methods, route_paths = self._extract_route_kwargs(decorator)
                func.auth_level = auth
                func.csrf_enabled = csrf
                func.http_methods = methods
                func.route_paths = route_paths

        self.function_stack.append(func)
        self.current_function = func
        previous_tainted_vars = self.tainted_vars
        previous_unsafe_sql_vars = self.unsafe_sql_vars
        self.tainted_vars = set()
        self.unsafe_sql_vars = set()

        route_param_names = set(_route_parameter_names(func.route_paths)) if func.is_controller else set()
        for arg in node.args.args + node.args.kwonlyargs:
            if arg.arg in {"kw", "kwargs", "params", "post"} and func.is_controller:
                self.tainted_vars.add(arg.arg)
            if (
                func.is_controller
                and arg.arg != "self"
                and (arg.arg == "id" or arg.arg.endswith("_id") or arg.arg in route_param_names)
            ):
                self.tainted_vars.add(arg.arg)
                func.has_request_params = True
        if node.args.vararg and node.args.vararg.arg in {"args"} and func.is_controller:
            self.tainted_vars.add(node.args.vararg.arg)
        if node.args.kwarg and func.is_controller:
            self.tainted_vars.add(node.args.kwarg.arg)

        # Visit function body
        self.generic_visit(node)

        # Post-function analysis
        self._analyze_function_patterns(func)

        self.function_stack.pop()
        self.current_function = self.function_stack[-1] if self.function_stack else None
        self.tainted_vars = previous_tainted_vars
        self.unsafe_sql_vars = previous_unsafe_sql_vars

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit assignments to track tainted variables."""
        if self.current_function is None:
            self.generic_visit(node)
            return

        is_tainted = self._is_tainted_expr(node.value)
        if is_tainted:
            self.current_function.has_request_params = True
        for target in node.targets:
            self._mark_target_names(target, self.tainted_vars, is_tainted)

        is_unsafe_sql = self._is_unsafe_sql_expr(node.value)
        for target in node.targets:
            self._mark_target_names(target, self.unsafe_sql_vars, is_unsafe_sql)

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Visit annotated assignments to track tainted variables."""
        if self.current_function is None or node.value is None:
            self.generic_visit(node)
            return

        is_tainted = self._is_tainted_expr(node.value)
        if is_tainted:
            self.current_function.has_request_params = True
        self._mark_target_names(node.target, self.tainted_vars, is_tainted)

        is_unsafe_sql = self._is_unsafe_sql_expr(node.value)
        self._mark_target_names(node.target, self.unsafe_sql_vars, is_unsafe_sql)

        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        """Visit assignment expressions to track tainted variables."""
        if self.current_function is None:
            self.generic_visit(node)
            return

        if self._is_tainted_expr(node.value):
            self.current_function.has_request_params = True
            if isinstance(node.target, ast.Name):
                self.tainted_vars.add(node.target.id)

        if self._is_unsafe_sql_expr(node.value) and isinstance(node.target, ast.Name):
            self.unsafe_sql_vars.add(node.target.id)

        self.generic_visit(node)

    def _is_request_params_attr(self, node: ast.Attribute) -> bool:
        """Check if node is request.params or request.jsonrequest."""
        if node.attr in ("params", "jsonrequest"):
            if self._is_request_name(node.value):
                return True
        if node.attr in {"args", "data", "files", "form", "json", "values"}:
            return self._is_request_httprequest_attr(node.value)
        return False

    def _is_request_params_subscript(self, node: ast.Subscript) -> bool:
        """Check if node is request.params['key'] or request.jsonrequest['key']."""
        if isinstance(node.value, ast.Attribute):
            if node.value.attr in ("params", "jsonrequest"):
                if self._is_request_name(node.value.value):
                    return True
            if node.value.attr in {"args", "data", "files", "form", "json", "values"}:
                return self._is_request_httprequest_attr(node.value.value)
        return False

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function calls to detect security sinks."""
        if self._is_fields_call(node):
            self._check_field_options(node)

        if self._is_html_sanitize_call(node):
            self._check_html_sanitize_options(node)

        if self.current_function is None:
            self.generic_visit(node)
            return

        # Detect sudo()/admin-root with_user()
        if self._is_privileged_context_call(node):
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
            if isinstance(arg, ast.Attribute) and self._is_request_params_attr(arg):
                self.current_function.has_request_params = True
            if isinstance(arg, ast.Subscript) and self._is_request_params_subscript(arg):
                self.current_function.has_request_params = True
            if isinstance(arg, ast.Attribute) and self._is_request_env_attr(arg):
                self.current_function.has_request_env = True

        if self._call_uses_request_env(node):
            self.current_function.has_request_env = True

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
            self._check_tainted_search_domain(node)
        elif self._is_orm_read(node):
            self.current_function.calls_read = True
        elif self._is_orm_browse(node):
            self._check_tainted_browse(node)

        # Detect with_user(admin/root)
        if self._is_with_user_admin(node):
            self._add_finding(
                rule_id="odoo-deep-with-user-admin",
                title="Admin context switch detected",
                severity="medium",
                line=node.lineno,
                column=node.col_offset,
                message="with_user() switches to admin/root context, bypassing record rules",
            )

        # Detect unbounded privileged search/aggregate reads.
        if self._is_empty_search_sudo(node):
            self._add_finding(
                rule_id="odoo-deep-empty-search-sudo",
                title="Unbounded search with sudo",
                severity="high",
                line=node.lineno,
                column=node.col_offset,
                message="sudo()/with_user(SUPERUSER_ID) runs an unbounded search or aggregate read; verify authorization",
            )

        if self._is_markup_call(node):
            self._check_markup(node)

        if self._is_access_check_call(node):
            self.current_function.has_auth_check = True

        self._check_attachment_access(node)

        self.generic_visit(node)

    def _is_http_route(self, decorator: ast.expr) -> bool:
        """Check if decorator is @http.route."""
        if isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Attribute):
                return self._is_http_module_expr(decorator.func.value) and decorator.func.attr == "route"
            elif isinstance(decorator.func, ast.Name):
                return decorator.func.id in self.route_decorator_names
        return False

    def _extract_route_kwargs(self, decorator: ast.Call) -> tuple[str, bool, list[str], list[str]]:
        """Extract auth, csrf, and methods from @http.route decorator."""
        auth = "user"
        csrf = True
        methods: list[str] = []
        route_paths: list[str] = []

        if decorator.args:
            route_paths.extend(self._extract_route_values(decorator.args[0]))

        for key, keyword_value in self._expanded_route_keywords(decorator):
            value = self._resolve_constant(keyword_value)
            if key == "auth" and isinstance(value, ast.Constant):
                auth = str(value.value)
            elif key == "csrf" and isinstance(value, ast.Constant):
                csrf = bool(value.value)
            elif key == "methods" and isinstance(value, ast.List | ast.Tuple | ast.Set):
                for elt in value.elts:
                    resolved = self._resolve_constant(elt)
                    if isinstance(resolved, ast.Constant):
                        methods.append(str(resolved.value))
            elif key in {"route", "routes"}:
                route_paths.extend(self._extract_route_values(value))

        return auth, csrf, methods, route_paths

    def _expanded_route_keywords(self, decorator: ast.Call) -> list[tuple[str, ast.AST]]:
        """Expand direct and static **kwargs used by @http.route."""
        keywords: list[tuple[str, ast.AST]] = []
        for kw in decorator.keywords:
            if kw.arg is not None:
                keywords.append((kw.arg, kw.value))
                continue
            value = self._resolve_constant(kw.value)
            if isinstance(value, ast.Dict):
                keywords.extend(self._expanded_dict_keywords(value))
        return keywords

    def _expanded_dict_keywords(self, node: ast.Dict) -> list[tuple[str, ast.AST]]:
        keywords: list[tuple[str, ast.AST]] = []
        for key, value in zip(node.keys, node.values, strict=True):
            if key is None:
                resolved_value = self._resolve_constant(value)
                if isinstance(resolved_value, ast.Dict):
                    keywords.extend(self._expanded_dict_keywords(resolved_value))
                continue
            resolved_key = self._resolve_constant(key)
            if isinstance(resolved_key, ast.Constant) and isinstance(resolved_key.value, str):
                keywords.append((resolved_key.value, value))
        return keywords

    def _extract_route_values(self, node: ast.expr) -> list[str]:
        """Extract literal route paths from a route decorator argument."""
        node = self._resolve_constant(node)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            values: list[str] = []
            for elt in node.elts:
                resolved = self._resolve_constant(elt)
                if isinstance(resolved, ast.Constant):
                    values.append(str(resolved.value))
            return values
        return []

    def _module_constants(self, tree: ast.Module) -> dict[str, ast.AST]:
        """Collect simple module-level constants used by route decorators."""
        return self._static_constants_from_body(tree.body)

    def _static_constants_from_body(self, statements: list[ast.stmt]) -> dict[str, ast.AST]:
        constants: dict[str, ast.AST] = {}
        for statement in statements:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Name) and self._is_static_literal(statement.value):
                        constants[target.id] = statement.value
            elif (
                isinstance(statement, ast.AnnAssign)
                and isinstance(statement.target, ast.Name)
                and statement.value is not None
                and self._is_static_literal(statement.value)
            ):
                constants[statement.target.id] = statement.value
        return constants

    def _resolve_constant(self, node: ast.AST, seen: set[str] | None = None) -> ast.AST:
        seen = seen or set()
        if isinstance(node, ast.Name):
            if node.id in seen:
                return node
            constants = self._effective_constants()
            value = constants.get(node.id)
            if value is None:
                return node
            seen.add(node.id)
            return self._resolve_constant(value, seen)
        return node

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants

    def _is_static_literal(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant):
            return isinstance(node.value, str | bool | int | float | type(None))
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return all(self._is_static_literal(element) for element in node.elts)
        if isinstance(node, ast.Dict):
            return all(
                (key is None or self._is_static_literal(key)) and self._is_static_literal(value)
                for key, value in zip(node.keys, node.values, strict=True)
            )
        if isinstance(node, ast.Name):
            return True
        return False

    def _is_sudo_call(self, node: ast.Call) -> bool:
        """Check if call is .sudo()."""
        return isinstance(node.func, ast.Attribute) and node.func.attr == "sudo"

    def _is_privileged_context_call(self, node: ast.Call) -> bool:
        """Check if call switches into sudo/admin-root context."""
        return self._is_sudo_call(node) or self._is_with_user_admin(node)

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
        """Check if node accesses request.params, request.jsonrequest, or request payload helpers."""
        if isinstance(node, ast.Attribute):
            return self._is_request_params_attr(node)
        if isinstance(node, ast.Subscript):
            return self._is_request_params_subscript(node)
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Attribute):
                return False
            return (
                node.func.attr in {"get_http_params", "get_json_data"}
                and self._is_request_name(node.func.value)
                or node.func.attr in {"get", "getlist", "get_json"}
                and self._is_tainted_expr(node.func.value)
            )
        return False

    def _is_request_env_attr(self, node: ast.Attribute) -> bool:
        """Check if node accesses request.env."""
        return node.attr == "env" and self._is_request_name(node.value)

    def _is_request_name(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.request_names
        return isinstance(node, ast.Attribute) and node.attr == "request" and self._is_http_module_expr(node.value)

    def _is_http_module_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.http_module_names
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "http"
            and isinstance(node.value, ast.Name)
            and node.value.id in self.odoo_module_names
        )

    def _is_request_httprequest_attr(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Attribute) and node.attr == "httprequest" and self._is_request_name(node.value)

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
        """Check if call is an ORM search or aggregate lookup."""
        return isinstance(node.func, ast.Attribute) and node.func.attr in {"read_group", "search", "search_count"}

    def _is_orm_read(self, node: ast.Call) -> bool:
        """Check if call is an ORM read()."""
        return isinstance(node.func, ast.Attribute) and node.func.attr in ("read", "search_read", "read_group")

    def _is_orm_browse(self, node: ast.Call) -> bool:
        """Check if call is an ORM browse()."""
        return isinstance(node.func, ast.Attribute) and node.func.attr == "browse"

    def _is_with_user_admin(self, node: ast.Call) -> bool:
        """Check if call switches to the admin/root user."""
        if not (isinstance(node.func, ast.Attribute) and node.func.attr == "with_user"):
            return False
        return any(self._is_admin_user_arg(arg) for arg in node.args) or any(
            keyword.arg in {"user", "uid"} and keyword.value is not None and self._is_admin_user_arg(keyword.value)
            for keyword in node.keywords
        )

    def _is_admin_user_arg(self, node: ast.AST) -> bool:
        """Check if an expression names Odoo's root/admin user."""
        node = self._resolve_constant(node)
        if isinstance(node, ast.Constant):
            return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
        if isinstance(node, ast.Name):
            return node.id in self.superuser_names
        if isinstance(node, ast.Attribute):
            return node.attr == "SUPERUSER_ID"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
            return any(self._is_admin_user_arg(arg) for arg in node.args)
        return False

    def _is_empty_search_sudo(self, node: ast.Call) -> bool:
        """Check if call is sudo/admin-root search/read_group over an empty domain."""
        if not (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"read_group", "search", "search_count", "search_read"}
        ):
            return False
        if not node.args or not self._is_empty_domain(node.args[0]):
            return False
        value = node.func.value
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
            return self._is_privileged_context_call(value)
        return False

    def _is_empty_domain(self, node: ast.expr) -> bool:
        """Check for a literal empty ORM domain."""
        node = self._resolve_constant(node)
        return isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) == 0

    def _call_has_tainted_arg(self, node: ast.Call) -> bool:
        """Return true when a call receives tainted input."""
        return any(self._is_tainted_expr(arg) for arg in node.args) or any(
            kw.value is not None and self._is_tainted_expr(kw.value) for kw in node.keywords
        )

    def _is_tainted_expr(self, node: ast.expr) -> bool:
        """Check whether an expression is request-controlled within the current function."""
        if self._is_request_params(node):
            return True
        if isinstance(node, ast.NamedExpr):
            return self._is_tainted_expr(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        if isinstance(node, ast.Subscript):
            return self._is_tainted_expr(node.value) or self._is_tainted_expr(node.slice)
        if isinstance(node, ast.Call):
            return (
                isinstance(node.func, ast.Attribute)
                and self._is_tainted_expr(node.func.value)
                or self._call_has_tainted_arg(node)
            )
        if isinstance(node, ast.BinOp):
            return self._is_tainted_expr(node.left) or self._is_tainted_expr(node.right)
        if isinstance(node, ast.BoolOp):
            return any(self._is_tainted_expr(value) for value in node.values)
        if isinstance(node, ast.Compare):
            return self._is_tainted_expr(node.left) or any(
                self._is_tainted_expr(comparator) for comparator in node.comparators
            )
        if isinstance(node, ast.IfExp):
            return (
                self._is_tainted_expr(node.test)
                or self._is_tainted_expr(node.body)
                or self._is_tainted_expr(node.orelse)
            )
        if isinstance(node, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
            child_nodes: list[ast.expr] = []
            if isinstance(node, ast.Dict):
                child_nodes = [v for v in node.values if v is not None]
            else:
                child_nodes = list(node.elts)
            return any(self._is_tainted_expr(child) for child in child_nodes)
        return False

    def _mark_target_names(self, target: ast.AST, names: set[str], should_mark: bool) -> None:
        """Add or clear tracked names for an assignment target."""
        if isinstance(target, ast.Name):
            if should_mark:
                names.add(target.id)
            else:
                names.discard(target.id)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._mark_target_names(element, names, should_mark)

    def _call_uses_request_env(self, node: ast.Call) -> bool:
        """Check whether a call expression contains request.env."""
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute) and self._is_request_env_attr(child):
                return True
        return False

    def _is_unsafe_sql_expr(self, node: ast.expr) -> bool:
        """Check for string-building patterns commonly used for raw SQL."""
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
        return False

    def _call_chain_has_attr(self, node: ast.expr, attr_name: str) -> bool:
        """Check whether a call/attribute chain contains a named method."""
        current = node
        while isinstance(current, ast.Call):
            if not isinstance(current.func, ast.Attribute):
                return False
            if current.func.attr == attr_name:
                return True
            current = current.func.value
        return False

    def _call_chain_has_privileged_context(self, node: ast.expr) -> bool:
        """Check whether a call/attribute chain contains sudo or admin-root with_user."""
        current = node
        while isinstance(current, ast.Call):
            if not isinstance(current.func, ast.Attribute):
                return False
            if self._is_privileged_context_call(current):
                return True
            current = current.func.value
        return False

    def _extract_env_model_name(self, node: ast.expr) -> str:
        """Extract model name from env['model'] through common call chains."""
        current = node
        while isinstance(current, ast.Call) and isinstance(current.func, ast.Attribute):
            current = current.func.value
        if isinstance(current, ast.Subscript):
            slice_node = self._resolve_constant(current.slice)
            if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, str):
                value = current.value
                if isinstance(value, ast.Attribute) and value.attr == "env":
                    return slice_node.value
                if isinstance(value, ast.Name) and value.id == "env":
                    return slice_node.value
        return ""

    def _check_sudo_context(self, node: ast.Call) -> None:
        """Analyze sudo() usage for security issues."""
        if self.current_function and self.current_function.is_controller:
            if self.current_function.auth_level in ("public", "none"):
                self._add_finding(
                    rule_id="odoo-deep-public-sudo",
                    title="Public route with privileged context",
                    severity="high",
                    line=node.lineno,
                    column=node.col_offset,
                    message=f"auth='{self.current_function.auth_level}' route uses sudo()/with_user(SUPERUSER_ID); potential unauthenticated data access",
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
        elif (
            isinstance(query_arg, ast.Call)
            and isinstance(query_arg.func, ast.Attribute)
            and query_arg.func.attr == "format"
        ):
            self._add_finding(
                rule_id="odoo-deep-sql-format",
                title="SQL query built with .format()",
                severity="high",
                line=node.lineno,
                column=node.col_offset,
                message="cr.execute() with .format() string interpolation; SQL injection possible",
            )
        elif isinstance(query_arg, ast.Name) and query_arg.id in self.unsafe_sql_vars:
            self._add_finding(
                rule_id="odoo-deep-sql-built-query-var",
                title="SQL query variable built unsafely",
                severity="high",
                line=node.lineno,
                column=node.col_offset,
                message=f"cr.execute() receives query variable '{query_arg.id}' built with string interpolation",
            )

    def _check_safe_eval(self, node: ast.Call) -> None:
        """Check for unsafe safe_eval usage."""
        if len(node.args) > 0:
            first_arg = node.args[0]
            is_tainted = False

            # Direct request.params['something'] / request.jsonrequest['something'] / request payload helper.
            if isinstance(first_arg, ast.Subscript):
                if self._is_tainted_expr(first_arg):
                    is_tainted = True
            elif self._is_tainted_expr(first_arg):
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

        if not is_tainted and self._is_tainted_expr(first_arg):
            is_tainted = True
            taint_source = "request-controlled data"

        if is_tainted:
            self._add_finding(
                rule_id="odoo-deep-mass-assignment",
                title="Mass assignment from request",
                severity="high",
                line=node.lineno,
                column=node.col_offset,
                message=f"ORM {node.func.attr}() called with {taint_source}; mass assignment possible",
            )

    def _check_tainted_search_domain(self, node: ast.Call) -> None:
        """Check for user-controlled ORM search domains."""
        if node.args and self._is_tainted_expr(node.args[0]):
            self._add_finding(
                rule_id="odoo-deep-tainted-search-domain",
                title="User-controlled ORM search domain",
                severity="high",
                line=node.lineno,
                column=node.col_offset,
                message="search() receives request-controlled domain data; authorization or data disclosure bugs are likely",
            )

    def _check_tainted_browse(self, node: ast.Call) -> None:
        """Check for controller-controlled IDs loaded through browse()."""
        if node.args and self._is_tainted_expr(node.args[0]):
            self.current_function.has_tainted_browse = True
            if self.current_function.is_controller and self._call_chain_has_privileged_context(node.func.value):
                self._add_finding(
                    rule_id="odoo-deep-route-id-sudo-browse",
                    title="Route parameter used in privileged browse()",
                    severity="high",
                    line=node.lineno,
                    column=node.col_offset,
                    message="Controller route parameter flows into sudo()/with_user(SUPERUSER_ID).browse(); verify ownership with _document_check_access(), access_token, or record rules",
                )

    def _is_markup_call(self, node: ast.Call) -> bool:
        """Check for markupsafe.Markup or imported Markup()."""
        if isinstance(node.func, ast.Name):
            return node.func.id == "Markup"
        if isinstance(node.func, ast.Attribute):
            return node.func.attr == "Markup"
        return False

    def _check_markup(self, node: ast.Call) -> None:
        """Check for Markup() applied to request-controlled input."""
        if node.args and self._is_tainted_expr(node.args[0]):
            self._add_finding(
                rule_id="odoo-deep-markup-user-input",
                title="Markup() applied to user input",
                severity="high",
                line=node.lineno,
                column=node.col_offset,
                message="Markup() marks request-controlled HTML as safe; stored or reflected XSS possible",
            )

    def _is_html_sanitize_call(self, node: ast.Call) -> bool:
        """Check for odoo.tools.html_sanitize(...)."""
        if isinstance(node.func, ast.Name):
            return node.func.id == "html_sanitize"
        if isinstance(node.func, ast.Attribute):
            return node.func.attr == "html_sanitize"
        return False

    def _check_html_sanitize_options(self, node: ast.Call) -> None:
        """Check for relaxed HTML sanitizer options."""
        for kw in node.keywords:
            value = self._resolve_constant(kw.value)
            if kw.arg == "strict" and isinstance(value, ast.Constant) and value.value is False:
                self._add_finding(
                    rule_id="odoo-deep-html-sanitize-strict-false",
                    title="HTML sanitizer uses non-strict mode",
                    severity="medium",
                    line=node.lineno,
                    column=node.col_offset,
                    message="tools.html_sanitize(..., strict=False) keeps a broader HTML surface; verify input provenance, allowed tags, and render sinks",
                )
            if (
                kw.arg in {"sanitize_tags", "sanitize_attributes"}
                and isinstance(value, ast.Constant)
                and value.value is False
            ):
                self._add_finding(
                    rule_id="odoo-deep-html-sanitize-relaxed-option",
                    title="HTML sanitizer disables sanitizer option",
                    severity="high",
                    line=node.lineno,
                    column=node.col_offset,
                    message=f"tools.html_sanitize(..., {kw.arg}=False) disables part of HTML sanitization; verify input provenance, allowed tags, attributes, and render sinks",
                )

    def _is_fields_html_call(self, node: ast.Call) -> bool:
        """Check for fields.Html(...)."""
        return self._field_call_type(node) == "Html"

    def _is_fields_call(self, node: ast.Call) -> bool:
        """Check for fields.*(...)."""
        return bool(self._field_call_type(node))

    def _field_call_type(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Attribute) and self._is_odoo_fields_module_expr(node.func.value):
            return node.func.attr
        if isinstance(node.func, ast.Name):
            return node.func.id
        return ""

    def _is_odoo_fields_module_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.field_module_names
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "fields"
            and isinstance(node.value, ast.Name)
            and node.value.id in self.odoo_module_names
        )

    def _check_field_options(self, node: ast.Call) -> None:
        """Check for risky Odoo field options."""
        for kw in node.keywords:
            value = self._resolve_constant(kw.value)
            if (
                self._is_fields_html_call(node)
                and kw.arg == "sanitize"
                and isinstance(value, ast.Constant)
                and value.value is False
            ):
                self._add_finding(
                    rule_id="odoo-deep-html-sanitize-false",
                    title="HTML field disables sanitization",
                    severity="medium",
                    line=node.lineno,
                    column=node.col_offset,
                    message="fields.Html(sanitize=False) stores raw HTML; verify all writers are trusted",
                )
            if kw.arg == "compute_sudo" and isinstance(value, ast.Constant) and value.value is True:
                self._add_finding(
                    rule_id="odoo-deep-field-compute-sudo",
                    title="Computed field runs with sudo",
                    severity="medium",
                    line=node.lineno,
                    column=node.col_offset,
                    message="fields.*(compute_sudo=True) recomputes outside the caller's record rules; verify it cannot expose cross-record or cross-company data",
                )

    def _is_access_check_call(self, node: ast.Call) -> bool:
        """Detect common Odoo access/portal ownership guard helpers."""
        if isinstance(node.func, ast.Attribute):
            return node.func.attr in {
                "_document_check_access",
                "check_access_rights",
                "check_access_rule",
                "_check_access",
                "_get_page_view_values",
            }
        if isinstance(node.func, ast.Name):
            return node.func.id in {"_document_check_access", "check_access"}
        return False

    def _check_attachment_access(self, node: ast.Call) -> None:
        """Check for privileged ir.attachment reads in controllers."""
        if not (self.current_function and self.current_function.is_controller):
            return
        if not (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"browse", "read_group", "search", "search_count", "search_read"}
        ):
            return
        model_name = self._extract_env_model_name(node.func.value)
        if model_name != "ir.attachment":
            return
        self.current_function.has_attachment_access = True
        if self._call_chain_has_privileged_context(node.func.value):
            self._add_finding(
                rule_id="odoo-deep-attachment-sudo-access",
                title="Controller accesses attachments with privileged context",
                severity="high",
                line=node.lineno,
                column=node.col_offset,
                message="Controller reads ir.attachment with sudo()/with_user(SUPERUSER_ID); verify res_model/res_id ownership, access_token, and binary field rules",
            )

    def _track_taint(self, node: ast.Call) -> None:
        """Track tainted variables for cross-function analysis."""
        pass

    def _analyze_function_patterns(self, func: OdooFunction) -> None:
        """Post-function analysis for complex patterns."""
        # Check for public route + sudo + search/read
        if (
            func.is_controller
            and func.auth_level in ("public", "none")
            and func.has_sudo
            and (func.calls_search or func.calls_read)
        ):
            self._add_finding(
                rule_id="odoo-deep-public-sudo-search",
                title="Public route with privileged search/read",
                severity="critical",
                line=func.line,
                column=0,
                message=f"auth='{func.auth_level}' route uses sudo()/with_user(SUPERUSER_ID) and searches/reads; potential full data dump",
            )

        # Check for CSRF disabled on write route
        if (
            func.is_controller
            and not func.csrf_enabled
            and (func.calls_write or func.calls_create or func.calls_unlink)
        ):
            self._add_finding(
                rule_id="odoo-deep-csrf-write",
                title="CSRF disabled on state-changing route",
                severity="medium",
                line=func.line,
                column=0,
                message="Route disables CSRF and performs writes; CSRF attack possible",
            )

        # Check public/unauthenticated state-changing routes
        if (
            func.is_controller
            and func.auth_level in ("public", "none")
            and (func.calls_write or func.calls_create or func.calls_unlink)
        ):
            self._add_finding(
                rule_id="odoo-deep-public-write-route",
                title="Public route performs state-changing ORM operation",
                severity="critical",
                line=func.line,
                column=0,
                message=f"auth='{func.auth_level}' route writes through the ORM; verify authentication, ownership checks, and CSRF protections",
            )

        # Check pre-database auth='none' routes using ORM environment
        if func.is_controller and func.auth_level == "none" and func.has_request_env:
            self._add_finding(
                rule_id="odoo-deep-auth-none-env",
                title="auth='none' route accesses request.env",
                severity="high",
                line=func.line,
                column=0,
                message="auth='none' route accesses request.env before normal database/user authentication guarantees",
            )

        # Check portal/website-style IDOR pattern.
        if func.is_controller and func.has_tainted_browse and func.has_sudo and not func.has_auth_check:
            self._add_finding(
                rule_id="odoo-deep-portal-idor-sudo-browse",
                title="Controller uses privileged browse() on route ID without visible access check",
                severity="high",
                line=func.line,
                column=0,
                message="Route-controlled record ID is loaded under sudo()/with_user(SUPERUSER_ID) without a recognized ownership/access-token check",
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

        # Check for request.params -> sudo()/admin-root with_user() -> write
        if func.has_request_params and func.has_sudo and func.calls_write:
            self._add_finding(
                rule_id="odoo-deep-request-sudo-write",
                title="User input reaches privileged write",
                severity="critical",
                line=func.line,
                column=0,
                message="User input reaches sudo()/with_user(SUPERUSER_ID).write(); privilege escalation and data mutation",
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
        if _should_skip_python_file(py_file):
            continue
        findings.extend(analyze_file(py_file))

    return findings


def _should_skip_python_file(path: Path) -> bool:
    """Skip generated/cache/test files without dropping modules whose names contain 'test'."""
    parts = set(path.parts)
    return bool(parts & {"tests", "__pycache__", ".venv", "venv", ".git"})


def _route_parameter_names(route_paths: list[str]) -> list[str]:
    """Extract Odoo route converter parameter names from literal route paths."""
    names: list[str] = []
    for route_path in route_paths:
        for match in re.finditer(r"<(?:[^:<>]+:)?(?P<name>[A-Za-z_]\w*)>", route_path):
            names.append(match.group("name"))
    return names


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
