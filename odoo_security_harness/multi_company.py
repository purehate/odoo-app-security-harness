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

    MULTI_COMPANY_MODEL_PREFIXES = (
        "account.",
        "hr.",
        "mrp.",
        "purchase.",
        "sale.",
        "stock.",
    )

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: list[MultiCompanyFinding] = []
        self.current_class: str = ""
        self.has_company_id: bool = False
        self.has_check_company: bool = False
        self.tainted_vars: set[str] = set()
        self.elevated_record_vars: set[str] = set()
        self.request_names: set[str] = {"request"}
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []

    def check_file(self) -> list[MultiCompanyFinding]:
        """Check a Python file for multi-company issues."""
        try:
            source = Path(self.file_path).read_text(encoding="utf-8")
            tree = ast.parse(source)
            self.constants = _module_constants(tree)
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
            isinstance(base, ast.Attribute)
            and base.attr == "Model"
            or isinstance(base, ast.Name)
            and base.id == "Model"
            for base in node.bases
        )

        if not is_model:
            self.generic_visit(node)
            return

        self.class_constants_stack.append(_static_constants_from_body(node.body))
        constants = self._effective_constants()
        model_name = _extract_model_name(node, constants) or node.name
        self.current_class = model_name
        self.has_company_id = False
        self.has_check_company = False

        # Check for _check_company_auto
        for item in node.body:
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name):
                        if target.id == "_check_company_auto":
                            value = _resolve_constant(item.value, constants)
                            if isinstance(value, ast.Constant) and value.value is True:
                                self.has_check_company = True
                        elif target.id == "_check_company":
                            value = _resolve_constant(item.value, constants)
                            if isinstance(value, ast.Constant) and value.value is True:
                                self.has_check_company = True

        # Visit class body
        self.generic_visit(node)

        # Post-class analysis
        if self.has_company_id and not self.has_check_company:
            self._add_finding(
                rule_id="odoo-mc-missing-check-company",
                title=f"Model {model_name} has company_id without _check_company_auto",
                severity="medium",
                line=node.lineno,
                message=f"Model '{model_name}' has company_id field but _check_company_auto=True is not set; cross-company access possible",
                model=model_name,
            )

        self.class_constants_stack.pop()
        self.current_class = old_class
        self.has_company_id = old_has_company_id
        self.has_check_company = old_has_check_company

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track aliases for the Odoo HTTP request proxy."""
        if node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Seed common request wrapper names inside functions."""
        old_tainted_vars = set(self.tainted_vars)
        old_elevated_record_vars = set(self.elevated_record_vars)
        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in {"kwargs", "kw", "post", "params"}:
                self.tainted_vars.add(arg.arg)
        if node.args.vararg:
            self.tainted_vars.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_vars.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.tainted_vars = old_tainted_vars
        self.elevated_record_vars = old_elevated_record_vars

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit assignments to detect company_id fields."""
        is_request_controlled = self._is_request_controlled(node.value)
        is_elevated_record = self._is_elevated_record_expr(node.value)
        for target in node.targets:
            self._mark_target_names(target, self.tainted_vars, is_request_controlled)
            self._mark_target_names(target, self.elevated_record_vars, is_elevated_record)

        for target in node.targets:
            if isinstance(target, ast.Name):
                # Check if it's a Many2one to res.company
                if isinstance(node.value, ast.Call):
                    if self._is_many2one_call(node.value.func):
                        # Check first argument
                        if target.id == "company_id" and node.value.args:
                            first_arg = _resolve_constant(node.value.args[0], self._effective_constants())
                            if isinstance(first_arg, ast.Constant) and first_arg.value == "res.company":
                                self.has_company_id = True

                        # Check for check_company=False on relational fields.
                        for kw in node.value.keywords:
                            if kw.arg == "check_company":
                                value = _resolve_constant(kw.value, self._effective_constants())
                                if isinstance(value, ast.Constant) and value.value is False:
                                    self._add_finding(
                                        rule_id="odoo-mc-check-company-disabled",
                                        title="Many2one with check_company=False",
                                        severity="medium",
                                        line=node.lineno,
                                        message=f"Many2one field '{target.id}' has check_company=False; cross-company reference possible",
                                        model=self.current_class,
                                    )

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Visit annotated assignments to track tainted/elevated aliases."""
        if node.value is not None:
            is_request_controlled = self._is_request_controlled(node.value)
            is_elevated_record = self._is_elevated_record_expr(node.value)
            self._mark_target_names(node.target, self.tainted_vars, is_request_controlled)
            self._mark_target_names(node.target, self.elevated_record_vars, is_elevated_record)

        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        """Visit assignment expressions to track request-controlled aliases."""
        if isinstance(node.target, ast.Name):
            if self._is_request_controlled(node.value):
                self.tainted_vars.add(node.target.id)
            else:
                self.tainted_vars.discard(node.target.id)
            if self._is_elevated_record_expr(node.value):
                self.elevated_record_vars.add(node.target.id)
            else:
                self.elevated_record_vars.discard(node.target.id)
        self.generic_visit(node)

    def _is_many2one_call(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Attribute):
            return node.attr == "Many2one"
        if isinstance(node, ast.Name):
            return node.id == "Many2one"
        return False

    def visit_Call(self, node: ast.Call) -> None:
        """Visit calls to detect multi-company issues."""
        # Detect sudo()/with_user(SUPERUSER_ID).search() without company filter
        if self._is_elevated_search(node):
            if not self._has_company_filter(node):
                self._add_finding(
                    rule_id="odoo-mc-sudo-search-no-company",
                    title="Elevated search without company filter",
                    severity="high",
                    line=node.lineno,
                    message="sudo()/with_user(SUPERUSER_ID).search() doesn't filter by company_id; cross-company data read",
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

        if self._is_company_context_user_input(node):
            self._add_finding(
                rule_id="odoo-mc-company-context-user-input",
                title="Company context set from user-controlled value",
                severity="medium",
                line=node.lineno,
                message="with_context() sets force_company or allowed_company_ids from user input; verify membership first",
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

    def _is_elevated_search(self, node: ast.Call) -> bool:
        """Check if call is .sudo()/with_user(SUPERUSER_ID).search(...)."""
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            "read_group",
            "search",
            "search_count",
            "search_read",
        }:
            return self._is_elevated_record_expr(node.func.value)
        return False

    def _has_company_filter(self, node: ast.Call) -> bool:
        """Check if search domain contains company_id filter."""
        if node.args:
            domain = node.args[0]
            return self._domain_has_company(domain)
        return False

    def _domain_has_company(self, node: ast.expr) -> bool:
        """Recursively check if domain contains company_id filter."""
        if isinstance(node, (ast.List, ast.Tuple)):
            for item in node.elts:
                if isinstance(item, ast.Tuple) and len(item.elts) >= 2:
                    first = item.elts[0]
                    first = _resolve_constant(first, self._effective_constants())
                    if isinstance(first, ast.Constant) and "company" in str(first.value).lower():
                        return True
                elif isinstance(item, (ast.List, ast.Tuple)):
                    if self._domain_has_company(item):
                        return True
        return False

    def _is_with_company_user_input(self, node: ast.Call) -> bool:
        """Check if call is with_company(request.params[...])."""
        if isinstance(node.func, ast.Attribute) and node.func.attr == "with_company":
            has_tainted_arg = any(self._is_request_controlled(arg) for arg in node.args)
            has_tainted_kwarg = any(
                kw.value is not None and self._is_request_controlled(kw.value) for kw in node.keywords
            )
            return has_tainted_arg or has_tainted_kwarg
        return False

    def _is_company_context_user_input(self, node: ast.Call) -> bool:
        """Check if with_context changes company scope using request-controlled values."""
        if not (isinstance(node.func, ast.Attribute) and node.func.attr == "with_context"):
            return False
        for arg in node.args:
            if self._dict_has_tainted_company_context(arg):
                return True
        for kw in node.keywords:
            if kw.arg in {"force_company", "allowed_company_ids", "company_id"}:
                if self._is_request_controlled(kw.value):
                    return True
        return False

    def _dict_has_tainted_company_context(self, node: ast.expr) -> bool:
        """Check dict-style with_context({company_key: request_value})."""
        if not isinstance(node, ast.Dict):
            return False
        for key, value in zip(node.keys, node.values, strict=False):
            key = _resolve_constant(key, self._effective_constants())
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                continue
            if key.value in {"force_company", "allowed_company_ids", "company_id"} and value is not None:
                if self._is_request_controlled(value):
                    return True
        return False

    def _is_search_on_sensitive_model(self, node: ast.Call) -> bool:
        """Check if call is search on a multi-company model."""
        if not (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"search", "search_count", "search_read", "read_group"}
        ):
            return False
        model_name = self._extract_env_model_name(node.func.value)
        return bool(model_name and model_name.startswith(self.MULTI_COMPANY_MODEL_PREFIXES))

    def _has_company_in_domain(self, node: ast.Call) -> bool:
        """Check if search domain has company filter."""
        return self._has_company_filter(node)

    def _extract_env_model_name(self, node: ast.expr) -> str:
        """Extract model name from env['model'] or request.env['model'] call chains."""
        current = node
        while isinstance(current, ast.Call) and isinstance(current.func, ast.Attribute):
            current = current.func.value
        if isinstance(current, ast.Subscript):
            value = current.value
            if self._is_env_expr(value):
                slice_node = current.slice
                slice_node = _resolve_constant(slice_node, self._effective_constants())
                if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, str):
                    return slice_node.value
        return ""

    def _is_env_expr(self, node: ast.expr) -> bool:
        """Check for self.env, request.env, or bare env."""
        if isinstance(node, ast.Attribute) and node.attr == "env":
            return True
        return isinstance(node, ast.Name) and node.id == "env"

    def _is_elevated_record_expr(self, node: ast.AST) -> bool:
        """Check whether an expression is a recordset elevated to superuser."""
        if isinstance(node, ast.Name):
            return node.id in self.elevated_record_vars
        if isinstance(node, ast.Attribute):
            return self._is_elevated_record_expr(node.value)
        if isinstance(node, ast.Subscript):
            return self._is_elevated_record_expr(node.value)
        if isinstance(node, ast.Starred):
            return self._is_elevated_record_expr(node.value)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._is_elevated_record_expr(element) for element in node.elts)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "sudo":
                    return True
                if node.func.attr == "with_user" and _call_has_superuser_arg(
                    node, self._effective_constants()
                ):
                    return True
            return self._is_elevated_record_expr(node.func)
        return False

    def _effective_constants(self) -> dict[str, ast.AST]:
        """Return module constants overlaid with constants from active classes."""
        if not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants

    def _is_request_controlled(self, node: ast.expr) -> bool:
        """Check whether an expression is derived from request-controlled data."""
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        if isinstance(node, ast.Attribute):
            return self._is_request_controlled(node.value) or (
                node.attr in {"params", "jsonrequest"} and self._is_request_name(node.value)
            )
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                return node.value.attr in {"params", "jsonrequest"} and self._is_request_name(node.value.value)
            return self._is_request_controlled(node.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_request_controlled(item) for item in node.elts)
        if isinstance(node, ast.Dict):
            return any(value is not None and self._is_request_controlled(value) for value in node.values)
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {"get_http_params", "get_json_data"}
                and self._is_request_name(node.func.value)
            ):
                return True
            return (
                self._is_request_controlled(node.func)
                or any(self._is_request_controlled(arg) for arg in node.args)
                or any(kw.value is not None and self._is_request_controlled(kw.value) for kw in node.keywords)
            )
        return False

    def _is_request_name(self, node: ast.AST) -> bool:
        """Check whether a node is the imported Odoo request proxy name."""
        return isinstance(node, ast.Name) and node.id in self.request_names

    def _mark_target_names(self, target: ast.AST, names: set[str], should_mark: bool) -> None:
        """Add or clear tracked names for assignment targets."""
        if isinstance(target, ast.Name):
            if should_mark:
                names.add(target.id)
            else:
                names.discard(target.id)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._mark_target_names(element, names, should_mark)
        if isinstance(target, ast.Starred):
            self._mark_target_names(target.value, names, should_mark)

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
        if _should_skip_python_file(py_file):
            continue
        checker = MultiCompanyChecker(str(py_file))
        findings.extend(checker.check_file())

    # Check XML files
    for xml_file in repo_path.rglob("security/*.xml"):
        checker = MultiCompanyXmlChecker(str(xml_file))
        findings.extend(checker.check_file())

    return findings


def _should_skip_python_file(path: Path) -> bool:
    """Skip test/cache files without excluding normal Odoo modules like test_module."""
    parts = set(path.parts)
    return bool(parts & {"tests", "__pycache__", ".venv", "venv", ".git"})


def _call_has_superuser_arg(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    return any(_is_superuser_arg(arg, constants) for arg in node.args) or any(
        keyword.value is not None and _is_superuser_arg(keyword.value, constants) for keyword in node.keywords
    )


def _is_superuser_arg(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    if constants:
        node = _resolve_constant(node, constants)
    if isinstance(node, ast.Constant):
        return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
    if isinstance(node, ast.Name):
        return node.id == "SUPERUSER_ID"
    if isinstance(node, ast.Attribute):
        return node.attr == "SUPERUSER_ID"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
        return any(_is_superuser_arg(arg, constants) for arg in node.args)
    return False


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


def _resolve_constant(node: ast.AST | None, constants: dict[str, ast.AST]) -> ast.AST | None:
    return _resolve_constant_seen(node, constants, set())


def _resolve_constant_seen(
    node: ast.AST | None, constants: dict[str, ast.AST], seen: set[str]
) -> ast.AST | None:
    if isinstance(node, ast.Name):
        if node.id in seen:
            return node
        value = constants.get(node.id)
        if value is None:
            return node
        seen.add(node.id)
        return _resolve_constant_seen(value, constants, seen)
    return node


def _is_static_literal(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str | bool | int | float | type(None))
        or isinstance(node, ast.Name)
    )


def _extract_model_name(node: ast.ClassDef, constants: dict[str, ast.AST]) -> str:
    for statement in node.body:
        if not isinstance(statement, ast.Assign):
            continue
        for target in statement.targets:
            if not (isinstance(target, ast.Name) and target.id == "_name"):
                continue
            value = _resolve_constant(statement.value, constants)
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                return value.value
    return ""


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
