"""Scanner for CSV/XLSX export formula-injection risks."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ExportFinding:
    """Represents a spreadsheet/export security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    sink: str = ""


TAINTED_ARG_NAMES = {"data", "rows", "records", "kwargs", "kw", "post", "params"}
CSV_SINKS = {"to_csv", "writerow", "writerows"}
XLSX_SINKS = {"to_excel", "write", "write_column", "write_row", "write_string", "write_rich_string"}
FORMULA_SINKS = {"write_formula"}
SANITIZER_HINTS = ("sanitize", "escape_formula", "safe_csv", "neutralize", "apostrophe")
ORM_EXPORT_FIELD_SINKS = {"export_data", "search_read", "read"}
ORM_EXPORT_FIELD_KEYWORDS = {"fields", "field_names"}
SENSITIVE_EXPORT_MODELS = {
    "account.move",
    "hr.employee",
    "ir.attachment",
    "ir.config_parameter",
    "ir.cron",
    "ir.model.access",
    "ir.rule",
    "mail.message",
    "payment.provider",
    "payment.transaction",
    "res.groups",
    "res.partner",
    "res.users",
    "res.users.apikeys",
}
SENSITIVE_EXPORT_FIELDS = {
    "access_key",
    "access_token",
    "api_key",
    "auth_token",
    "bank_account_id",
    "bank_ids",
    "bearer_token",
    "client_secret",
    "company_id",
    "credit_card",
    "csrf_token",
    "groups_id",
    "hmac_secret",
    "iban",
    "jwt_secret",
    "license_key",
    "login",
    "oauth_token",
    "password",
    "password_hash",
    "private_key",
    "secret_key",
    "session_token",
    "signature_secret",
    "signup_token",
    "signing_key",
    "token",
    "totp_secret",
    "user_id",
    "webhook_secret",
}


def scan_exports(repo_path: Path) -> list[ExportFinding]:
    """Scan Python files for risky CSV/XLSX export sinks."""
    findings: list[ExportFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(ExportScanner(path).scan_file())
    return findings


class ExportScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[ExportFinding] = []
        self.tainted_names: set[str] = set()
        self.sanitized_names: set[str] = set()
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.route_decorator_names: set[str] = set()

    def scan_file(self) -> list[ExportFinding]:
        """Scan the file."""
        try:
            content = self.path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content)
        except SyntaxError:
            return []
        except Exception:
            return []

        self.visit(tree)
        return self.findings

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            if alias.name == "odoo":
                self.odoo_module_names.add(alias.asname or alias.name)
            elif alias.name == "odoo.http" and alias.asname:
                self.http_module_names.add(alias.asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module == "odoo":
            for alias in node.names:
                if alias.name == "http":
                    self.http_module_names.add(alias.asname or alias.name)
        elif node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
                elif alias.name == "route":
                    self.route_decorator_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_tainted = set(self.tainted_names)
        previous_sanitized = set(self.sanitized_names)
        is_route = _function_is_http_route(
            node,
            self.route_decorator_names,
            self.http_module_names,
            self.odoo_module_names,
        )
        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES or (is_route and arg.arg not in {"self", "cls"}):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.tainted_names = previous_tainted
        self.sanitized_names = previous_sanitized

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._track_assignment_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._track_assignment_target(node.target, node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._track_assignment_target(node.target, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        if self._expr_is_tainted(node.iter):
            self._mark_name_target(node.target, self.tainted_names)
        else:
            self.tainted_names.difference_update(_target_names(node.target))
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        attr = sink.rsplit(".", 1)[-1]
        if attr in CSV_SINKS and self._call_or_receiver_has_tainted_input(node):
            self._add(
                "odoo-export-csv-formula-injection",
                "CSV export writes unsanitized record/request data",
                "medium",
                node.lineno,
                "CSV export writes request/record-derived data without visible formula escaping; neutralize values beginning with =, +, -, @, tab, or CR",
                attr,
            )
        elif attr in XLSX_SINKS and self._call_or_receiver_has_tainted_input(node):
            self._add(
                "odoo-export-xlsx-formula-injection",
                "XLSX export writes unsanitized record/request data",
                "medium",
                node.lineno,
                "XLSX export writes request/record-derived data without visible formula escaping; force strings or neutralize formula prefixes",
                attr,
            )
        elif attr in FORMULA_SINKS and _call_has_tainted_input(node, self._expr_is_tainted):
            self._add(
                "odoo-export-tainted-formula",
                "XLSX formula uses request/record data",
                "high",
                node.lineno,
                "XLSX formula is built from request/record-derived data; verify formulas cannot execute attacker-controlled spreadsheet expressions",
                attr,
            )
        elif attr in ORM_EXPORT_FIELD_SINKS:
            self._scan_orm_export_fields(node, attr)
        self.generic_visit(node)

    def _scan_orm_export_fields(self, node: ast.Call, sink: str) -> None:
        fields_arg = _orm_export_fields_arg(node, sink)
        if fields_arg is None:
            if sink in {"read", "search_read"}:
                model = _call_receiver_sensitive_model(node)
                if model:
                    self._add(
                        "odoo-export-sensitive-model-default-fields",
                        "Sensitive model export omits field allowlist",
                        "high",
                        node.lineno,
                        f"ORM {sink} on sensitive model '{model}' omits an explicit fields allowlist; restrict returned fields before exposing data",
                        sink,
                    )
            return
        if self._expr_is_tainted(fields_arg):
            self._add(
                "odoo-export-request-controlled-fields",
                "ORM export fields are request-controlled",
                "high",
                node.lineno,
                "ORM export/read field list is request-derived; restrict exported fields to a server-side allowlist before returning data",
                sink,
            )
        sensitive_fields = sorted(_literal_sensitive_fields(fields_arg))
        if sensitive_fields:
            self._add(
                "odoo-export-sensitive-fields",
                "ORM export includes sensitive fields",
                "high",
                node.lineno,
                f"ORM export/read includes sensitive fields {sensitive_fields}; verify only authorized users can retrieve these values",
                sink,
            )

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if _is_sanitized(node):
            return False
        if self._is_request_or_record_derived(node):
            return True
        if isinstance(node, ast.Starred):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.NamedExpr):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.tainted_names and node.id not in self.sanitized_names
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Attribute):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Call):
            return (
                self._is_request_or_record_derived(node)
                or self._expr_is_tainted(node.func)
                or any(self._expr_is_tainted(arg) for arg in node.args)
                or any(keyword.value is not None and self._expr_is_tainted(keyword.value) for keyword in node.keywords)
            )
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._expr_is_tainted(element) for element in node.elts)
        if isinstance(node, ast.Dict):
            return any(self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp):
            return self._expr_is_tainted(node.elt) or any(
                self._expr_is_tainted(generator.iter)
                or any(self._expr_is_tainted(if_expr) for if_expr in generator.ifs)
                for generator in node.generators
            )
        if isinstance(node, ast.DictComp):
            return (
                self._expr_is_tainted(node.key)
                or self._expr_is_tainted(node.value)
                or any(
                    self._expr_is_tainted(generator.iter)
                    or any(self._expr_is_tainted(if_expr) for if_expr in generator.ifs)
                    for generator in node.generators
                )
            )
        if isinstance(node, ast.JoinedStr):
            return any(self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.BinOp):
            return self._expr_is_tainted(node.left) or self._expr_is_tainted(node.right)
        if isinstance(node, ast.BoolOp):
            return any(self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.Compare):
            return self._expr_is_tainted(node.left) or any(
                self._expr_is_tainted(comparator) for comparator in node.comparators
            )
        if isinstance(node, ast.IfExp):
            return (
                self._expr_is_tainted(node.test)
                or self._expr_is_tainted(node.body)
                or self._expr_is_tainted(node.orelse)
            )
        return False

    def _call_or_receiver_has_tainted_input(self, node: ast.Call) -> bool:
        if _call_has_tainted_input(node, self._expr_is_tainted):
            return True
        return isinstance(node.func, ast.Attribute) and self._expr_is_tainted(node.func.value)

    def _mark_name_target(self, target: ast.AST, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._mark_name_target(element, names)
        elif isinstance(target, ast.Starred):
            self._mark_name_target(target.value, names)

    def _track_assignment_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for child_target, child_value in _unpack_target_value_pairs(target.elts, value.elts):
                self._track_assignment_target(child_target, child_value)
            return

        target_names = _target_names(target)
        if _is_sanitized(value):
            self.sanitized_names.update(target_names)
            self.tainted_names.difference_update(target_names)
            return
        if self._is_request_or_record_derived(value) or self._expr_is_tainted(value):
            self.tainted_names.update(target_names)
            self.sanitized_names.difference_update(target_names)
            return
        self.tainted_names.difference_update(target_names)
        self.sanitized_names.difference_update(target_names)

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, sink: str) -> None:
        self.findings.append(
            ExportFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                sink=sink,
            )
        )

    def _is_request_or_record_derived(self, node: ast.AST) -> bool:
        return _is_request_or_record_derived(
            node,
            self.request_names,
            self.http_module_names,
            self.odoo_module_names,
        )


def _is_request_or_record_derived(
    node: ast.AST,
    request_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    request_names = request_names or {"request"}
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    if _is_request_expr(node, request_names, http_module_names, odoo_module_names):
        return True
    if isinstance(node, ast.Attribute):
        if node.attr in {"params", "jsonrequest", "httprequest"} and _is_request_expr(
            node.value,
            request_names,
            http_module_names,
            odoo_module_names,
        ):
            return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"get_http_params", "get_json_data"} and _is_request_expr(
            node.func.value,
            request_names,
            http_module_names,
            odoo_module_names,
        ):
            return True
    text = _safe_unparse(node)
    return any(
        marker in text
        for marker in (
            "request.params",
            "request.httprequest",
            "request.get_http_params",
            "request.get_json_data",
            "request.jsonrequest",
            "kwargs.get",
            "kw.get",
            "post.get",
            "record.",
            "records.",
            "row.",
            "line.",
        )
    )


def _is_request_expr(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in request_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "request"
        and _is_http_module_expr(node.value, http_module_names, odoo_module_names)
    )


def _is_sanitized(node: ast.AST) -> bool:
    text = _safe_unparse(node).lower()
    return any(hint in text for hint in SANITIZER_HINTS)


def _call_has_tainted_input(node: ast.Call, is_tainted: Any) -> bool:
    return any(is_tainted(arg) for arg in node.args) or any(
        keyword.value is not None and is_tainted(keyword.value) for keyword in node.keywords
    )


def _orm_export_fields_arg(node: ast.Call, sink: str) -> ast.AST | None:
    for keyword in node.keywords:
        if keyword.arg in ORM_EXPORT_FIELD_KEYWORDS:
            return keyword.value
    if sink == "export_data" and node.args:
        return node.args[0]
    if sink == "read" and node.args:
        return node.args[0]
    if sink == "search_read" and len(node.args) >= 2:
        return node.args[1]
    return None


def _literal_sensitive_fields(node: ast.AST) -> set[str]:
    fields: set[str] = set()
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if node.value in SENSITIVE_EXPORT_FIELDS:
            fields.add(node.value)
        return fields
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        for element in node.elts:
            fields.update(_literal_sensitive_fields(element))
        return fields
    if isinstance(node, ast.Dict):
        for key in node.keys:
            if key is not None:
                fields.update(_literal_sensitive_fields(key))
        for value in node.values:
            fields.update(_literal_sensitive_fields(value))
    return fields


def _call_receiver_sensitive_model(node: ast.Call) -> str:
    if not isinstance(node.func, ast.Attribute):
        return ""
    receiver = _safe_unparse(node.func.value)
    for model in SENSITIVE_EXPORT_MODELS:
        if f"'{model}'" in receiver or f'"{model}"' in receiver:
            return model
    return ""


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
    if isinstance(node, ast.Tuple | ast.List):
        names: set[str] = set()
        for element in node.elts:
            names.update(_target_names(element))
        return names
    return set()


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _function_is_http_route(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    route_decorator_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    return any(
        _is_http_route(decorator, route_decorator_names, http_module_names, odoo_module_names)
        for decorator in node.decorator_list
    )


def _is_http_route(
    node: ast.AST,
    route_decorator_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    route_decorator_names = route_decorator_names or set()
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Name):
        return target.id in route_decorator_names
    return (
        isinstance(target, ast.Attribute)
        and target.attr == "route"
        and _is_http_module_expr(target.value, http_module_names, odoo_module_names)
    )


def _is_http_module_expr(
    node: ast.AST,
    http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in http_module_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "http"
        and isinstance(node.value, ast.Name)
        and node.value.id in odoo_module_names
    )


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _unpack_target_value_pairs(
    targets: list[ast.expr],
    values: list[ast.expr],
) -> list[tuple[ast.expr, ast.AST]]:
    starred_index = next((index for index, target in enumerate(targets) if isinstance(target, ast.Starred)), None)
    if starred_index is None:
        return list(zip(targets, values, strict=False))

    tail_count = len(targets) - starred_index - 1
    if len(values) < starred_index + tail_count:
        return list(zip(targets, values, strict=False))

    pairs: list[tuple[ast.expr, ast.AST]] = []
    pairs.extend(zip(targets[:starred_index], values[:starred_index], strict=False))
    rest_values = values[starred_index : len(values) - tail_count if tail_count else len(values)]
    pairs.append((targets[starred_index], ast.List(elts=rest_values, ctx=ast.Load())))
    if tail_count:
        pairs.extend(zip(targets[-tail_count:], values[-tail_count:], strict=False))
    return pairs


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[ExportFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
        }
        for f in findings
    ]
