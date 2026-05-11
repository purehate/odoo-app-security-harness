"""Scanner for Odoo report action exposure risks."""

from __future__ import annotations

import ast
import re
from csv import DictReader
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

from defusedxml import ElementTree
from odoo_security_harness.base_scanner import _line_for, _should_skip


@dataclass
class ReportFinding:
    """Represents a risky Odoo report action finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    report: str = ""


SENSITIVE_MODELS = {
    "account.move",
    "account.payment",
    "hr.employee",
    "hr.contract",
    "ir.attachment",
    "ir.config_parameter",
    "ir.cron",
    "ir.model.access",
    "ir.rule",
    "mail.message",
    "payment.provider",
    "payment.transaction",
    "purchase.order",
    "res.groups",
    "res.partner",
    "res.users",
    "res.users.apikeys",
    "sale.order",
    "stock.picking",
}
KNOWN_MODEL_EXTERNAL_IDS = {
    "account.model_account_move": "account.move",
    "model_account_move": "account.move",
    "base.model_ir_attachment": "ir.attachment",
    "model_ir_attachment": "ir.attachment",
    "base.model_ir_config_parameter": "ir.config_parameter",
    "model_ir_config_parameter": "ir.config_parameter",
    "base.model_ir_cron": "ir.cron",
    "model_ir_cron": "ir.cron",
    "base.model_ir_model_access": "ir.model.access",
    "model_ir_model_access": "ir.model.access",
    "base.model_ir_rule": "ir.rule",
    "model_ir_rule": "ir.rule",
    "base.model_res_groups": "res.groups",
    "model_res_groups": "res.groups",
    "base.model_res_users": "res.users",
    "model_res_users": "res.users",
    "base.model_res_users_apikeys": "res.users.apikeys",
    "model_res_users_apikeys": "res.users.apikeys",
    "payment.model_payment_provider": "payment.provider",
    "model_payment_provider": "payment.provider",
    "payment.model_payment_transaction": "payment.transaction",
    "model_payment_transaction": "payment.transaction",
}
SENSITIVE_NAME_MARKERS = (
    "access_key",
    "access_link",
    "access_token",
    "access_url",
    "api_key",
    "apikey",
    "auth_token",
    "bearer_token",
    "client_secret",
    "csrf_token",
    "hmac_secret",
    "jwt_secret",
    "license_key",
    "oauth_token",
    "partner_signup_url",
    "private_key",
    "reset_password_token",
    "reset_password_url",
    "secret",
    "secret_key",
    "session_token",
    "signature_secret",
    "signup_token",
    "signup_url",
    "signing_key",
    "token",
    "totp_secret",
    "webhook_secret",
)
ROUTE_ID_ARG_RE = re.compile(r"(?:^id$|_ids?$)")
REQUEST_SOURCE_ATTRS = {"httprequest", "jsonrequest", "params"}
REQUEST_SOURCE_METHODS = {"get_http_params", "get_json_data"}
REQUEST_TEXT_MARKERS = ("kwargs.get", "kw.get", "post.get", "params.get")


def scan_reports(repo_path: Path) -> list[ReportFinding]:
    """Scan XML and Python report definitions/rendering for exposure risks."""
    findings: list[ReportFinding] = []
    for path in repo_path.rglob("*.xml"):
        if _should_skip(path):
            continue
        findings.extend(ReportScanner(path).scan_file())
    for path in repo_path.rglob("*.csv"):
        if _should_skip(path):
            continue
        findings.extend(ReportScanner(path).scan_csv_file())
    for path in repo_path.rglob("*.py"):
        if _should_skip(path) or "tests" in path.parts:
            continue
        findings.extend(ReportPythonScanner(path).scan_file())
    return findings


class ReportScanner:
    """Scanner for one XML file containing report actions."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.content = ""
        self.findings: list[ReportFinding] = []

    def scan_file(self) -> list[ReportFinding]:
        """Scan XML report actions."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            root = ElementTree.fromstring(self.content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        for record in root.iter("record"):
            if record.get("model") == "ir.actions.report":
                self._scan_report_record(record)
        for report in root.iter("report"):
            self._scan_report_tag(report)
        return self.findings

    def scan_csv_file(self) -> list[ReportFinding]:
        """Scan CSV report actions."""
        if _csv_model_name(self.path) != "ir.actions.report":
            return []
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        for fields, line in _csv_dict_rows(self.content):
            self._scan_report_values(
                fields.get("id", ""),
                _model_value(fields.get("model", "")),
                fields.get("groups_id", "") or fields.get("groups", ""),
                fields.get("report_sudo", ""),
                fields.get("attachment_use", ""),
                fields.get("attachment", ""),
                fields.get("print_report_name", ""),
                line,
            )
        return self.findings

    def _scan_report_record(self, record: ElementTree.Element) -> None:
        fields = _record_fields(record)
        report_id = record.get("id", "")
        model = _model_value(fields.get("model", ""))
        groups = fields.get("groups_id", "") or fields.get("groups", "")
        report_sudo = fields.get("report_sudo", "")
        attachment_use = fields.get("attachment_use", "")
        attachment = fields.get("attachment", "")
        print_report_name = fields.get("print_report_name", "")
        line = self._line_for_record(record)

        self._scan_report_values(
            report_id, model, groups, report_sudo, attachment_use, attachment, print_report_name, line
        )

    def _scan_report_tag(self, report: ElementTree.Element) -> None:
        report_id = report.get("id", "") or report.get("name", "")
        model = _model_value(report.get("model", ""))
        groups = report.get("groups", "")
        report_sudo = report.get("report_sudo", "")
        attachment_use = report.get("attachment_use", "")
        attachment = report.get("attachment", "")
        print_report_name = report.get("print_report_name", "")
        line = _line_for(self.content, f'id="{report_id}"') if report_id else _line_for(self.content, "<report")

        self._scan_report_values(
            report_id, model, groups, report_sudo, attachment_use, attachment, print_report_name, line
        )

    def _scan_report_values(
        self,
        report_id: str,
        model: str,
        groups: str,
        report_sudo: str,
        attachment_use: str,
        attachment: str,
        print_report_name: str,
        line: int,
    ) -> None:
        if _truthy(report_sudo):
            self._add(
                "odoo-report-sudo-enabled",
                "Report renders with sudo",
                "high",
                line,
                "Report action enables report_sudo; verify templates cannot expose records or fields beyond the caller's access",
                model,
                report_id,
            )

        if model in SENSITIVE_MODELS and not groups:
            self._add(
                "odoo-report-sensitive-no-groups",
                "Sensitive model report has no groups restriction",
                "medium",
                line,
                f"Report action for sensitive model '{model}' has no groups restriction; verify access rules and report routes are sufficient",
                model,
                report_id,
            )

        if _truthy(attachment_use) and _looks_dynamic_attachment(attachment):
            self._add(
                "odoo-report-dynamic-attachment-cache",
                "Report caches dynamic attachment names",
                "low",
                line,
                "Report caches attachments using an object-derived expression; verify cached PDFs cannot leak after record ownership/state changes",
                model,
                report_id,
            )

        if _contains_sensitive_name_marker(attachment) or _contains_sensitive_name_marker(print_report_name):
            self._add(
                "odoo-report-sensitive-filename-expression",
                "Report filename expression contains sensitive field",
                "high",
                line,
                "Report attachment or print_report_name expression references token, secret, password, or API-key-like data; avoid leaking secrets through filenames, URLs, logs, and browser history",
                model,
                report_id,
            )

    def _line_for_record(self, record: ElementTree.Element) -> int:
        record_id = record.get("id")
        if record_id:
            return _line_for(self.content, f'id="{record_id}"')
        return _line_for(self.content, 'model="ir.actions.report"')

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        model: str,
        report: str,
    ) -> None:
        self.findings.append(
            ReportFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                model=model,
                report=report,
            )
        )


class ReportPythonScanner(ast.NodeVisitor):
    """Scanner for Python report rendering/report_action call sites."""

    REPORT_RENDER_METHODS = {"report_action", "_render_qweb_pdf", "_render_qweb_html", "render_qweb_pdf"}
    TAINTED_ARG_NAMES = {"id", "ids", "docids", "record_id", "res_id", "kwargs", "kw", "post", "params"}

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[ReportFinding] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}
        self.tainted_names: set[str] = set()
        self.tainted_context_names: set[str] = set()
        self.sudo_names: set[str] = set()
        self.superuser_names: set[str] = {"SUPERUSER_ID"}
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.route_decorator_names: set[str] = set()
        self.route_stack: list[RouteContext] = []

    def scan_file(self) -> list[ReportFinding]:
        """Scan Python report rendering code."""
        try:
            source = self.path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except SyntaxError:
            return []
        except Exception:
            return []

        self.constants = _module_constants(tree)
        self.visit(tree)
        return self.findings

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_tainted = set(self.tainted_names)
        previous_tainted_context = set(self.tainted_context_names)
        previous_sudo = set(self.sudo_names)
        previous_local_constants = self.local_constants
        self.local_constants = {}
        route = _route_info(
            node,
            self._effective_constants(),
            self.route_decorator_names,
            self.http_module_names,
            self.odoo_module_names,
        ) or RouteContext(is_route=False)
        self.route_stack.append(route)

        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in self.TAINTED_ARG_NAMES or (route.is_route and _looks_route_id_arg(arg.arg)):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.route_stack.pop()
        self.tainted_names = previous_tainted
        self.tainted_context_names = previous_tainted_context
        self.sudo_names = previous_sudo
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

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
                elif alias.name == "SUPERUSER_ID":
                    self.superuser_names.add(alias.asname or alias.name)
        elif node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
                elif alias.name == "route":
                    self.route_decorator_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
            self._record_target_state(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
            self._record_target_state(node.target, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        if self._expr_is_tainted(node.iter):
            for name in _target_names(node.target):
                self.tainted_names.add(name)
        else:
            for name in _target_names(node.target):
                self.tainted_names.discard(name)
        if self._expr_has_sudo(node.iter):
            for name in _target_names(node.target):
                self.sudo_names.add(name)
        else:
            for name in _target_names(node.target):
                self.sudo_names.discard(name)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_local_constant_target(node.target, node.value)
        self._record_target_state(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        self._record_tainted_container_mutation(node)
        if self._is_report_render_call(node):
            self._scan_report_render_call(node)
        self.generic_visit(node)

    def _scan_report_render_call(self, node: ast.Call) -> None:
        route = self._current_route()
        sink = _call_name(node.func)
        if route.auth in {"public", "none"}:
            self._add(
                "odoo-report-public-render-route",
                "Public route renders report",
                "medium",
                node.lineno,
                "Public/unauthenticated controller route renders a report; verify record ownership, access tokens, and report groups before returning PDF/HTML",
                "",
                sink,
            )

        if self._call_has_tainted_input(node):
            self._add(
                "odoo-report-tainted-render-records",
                "Report render uses request-controlled records",
                "high",
                node.lineno,
                "Report rendering receives request-derived ids, records, data, or context; validate ownership and allowed model/report combinations first",
                "",
                sink,
            )

        if self._call_has_tainted_report_data(node):
            self._add(
                "odoo-report-tainted-render-data",
                "Report render uses request-controlled data or context",
                "high",
                node.lineno,
                "Report rendering receives request-derived data/context options; validate report model domains, filters, and generated output before rendering PDF/HTML",
                "",
                sink,
            )

        if self._expr_is_tainted(node.func):
            self._add(
                "odoo-report-tainted-render-action",
                "Report render uses request-controlled report action",
                "high",
                node.lineno,
                "Report rendering is invoked on a request-derived report/action object; restrict selectable reports and models before rendering PDF/HTML",
                "",
                sink,
            )

        if self._expr_has_sudo(node.func) or any(self._expr_has_sudo(arg) for arg in node.args):
            self._add(
                "odoo-report-sudo-render-call",
                "Report render uses an elevated environment",
                "high",
                node.lineno,
                "Report rendering/report_action is invoked through sudo()/with_user(SUPERUSER_ID) or receives elevated records; verify report templates cannot disclose forbidden fields or records",
                "",
                sink,
            )

    def _is_report_render_call(self, node: ast.Call) -> bool:
        if isinstance(node.func, ast.Attribute):
            return node.func.attr in self.REPORT_RENDER_METHODS
        return False

    def _call_has_tainted_input(self, node: ast.Call) -> bool:
        return any(self._expr_is_tainted(arg) for arg in node.args) or any(
            keyword.value is not None and self._expr_is_tainted(keyword.value) for keyword in node.keywords
        )

    def _call_has_tainted_report_data(self, node: ast.Call) -> bool:
        if isinstance(node.func, ast.Attribute) and self._expr_has_tainted_context(node.func.value):
            return True
        return any(
            keyword.arg in {"data", "context"} and keyword.value is not None and self._expr_is_tainted(keyword.value)
            for keyword in node.keywords
        )

    def _expr_has_tainted_context(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.tainted_context_names
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "with_context" and self._call_has_tainted_input(node):
                return True
            return self._expr_has_tainted_context(node.func.value)
        if isinstance(node, ast.Attribute):
            return self._expr_has_tainted_context(node.value)
        if isinstance(node, ast.Subscript):
            return self._expr_has_tainted_context(node.value)
        return False

    def _record_target_state(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._record_target_state(target_element, value_element)
            return

        if self._expr_is_tainted(value):
            for name in _target_names(target):
                self.tainted_names.add(name)
        else:
            for name in _target_names(target):
                self.tainted_names.discard(name)
        if self._expr_has_sudo(value):
            for name in _target_names(target):
                self.sudo_names.add(name)
        else:
            for name in _target_names(target):
                self.sudo_names.discard(name)
        if self._expr_has_tainted_context(value):
            for name in _target_names(target):
                self.tainted_context_names.add(name)
        else:
            for name in _target_names(target):
                self.tainted_context_names.discard(name)

    def _record_tainted_container_mutation(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Attribute) or node.func.attr not in {"append", "extend", "add", "update"}:
            return
        if not self._expr_is_tainted(node):
            return
        if isinstance(node.func.value, ast.Name):
            self.tainted_names.add(node.func.value.id)

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_request_derived(node):
            return True
        if isinstance(node, ast.Starred):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.tainted_names
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted(node.value) or self._expr_is_tainted(node.slice)
        if isinstance(node, ast.Attribute):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Call):
            return (
                self._is_request_derived(node)
                or self._expr_is_tainted(node.func)
                or any(self._expr_is_tainted(arg) for arg in node.args)
                or any(keyword.value is not None and self._expr_is_tainted(keyword.value) for keyword in node.keywords)
            )
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._expr_is_tainted(element) for element in node.elts)
        if isinstance(node, ast.Dict):
            return any(self._expr_is_tainted(key) for key in node.keys if key is not None) or any(
                value is not None and self._expr_is_tainted(value) for value in node.values
            )
        if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp):
            return self._expr_is_tainted(node.elt) or any(
                self._expr_is_tainted(generator.iter)
                or any(self._expr_is_tainted(condition) for condition in generator.ifs)
                for generator in node.generators
            )
        if isinstance(node, ast.DictComp):
            return (
                self._expr_is_tainted(node.key)
                or self._expr_is_tainted(node.value)
                or any(
                    self._expr_is_tainted(generator.iter)
                    or any(self._expr_is_tainted(condition) for condition in generator.ifs)
                    for generator in node.generators
                )
            )
        if isinstance(node, ast.UnaryOp):
            return self._expr_is_tainted(node.operand)
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
        if isinstance(node, ast.JoinedStr):
            return any(self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.NamedExpr):
            return self._expr_is_tainted(node.value)
        return False

    def _expr_has_sudo(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Starred):
            return self._expr_has_sudo(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.sudo_names
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and (
                node.func.attr == "sudo"
                or (
                    node.func.attr == "with_user"
                    and _call_has_superuser_arg(node, self._effective_constants(), self.superuser_names)
                )
            ):
                return True
            return (
                self._expr_has_sudo(node.func)
                or any(self._expr_has_sudo(arg) for arg in node.args)
                or any(keyword.value is not None and self._expr_has_sudo(keyword.value) for keyword in node.keywords)
            )
        if isinstance(node, ast.Attribute):
            return self._expr_has_sudo(node.value)
        if isinstance(node, ast.Subscript):
            return self._expr_has_sudo(node.value)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._expr_has_sudo(element) for element in node.elts)
        if isinstance(node, ast.Dict):
            return any(value is not None and self._expr_has_sudo(value) for value in node.values)
        if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp):
            return self._expr_has_sudo(node.elt) or any(
                self._expr_has_sudo(generator.iter) for generator in node.generators
            )
        if isinstance(node, ast.DictComp):
            return (
                self._expr_has_sudo(node.key)
                or self._expr_has_sudo(node.value)
                or any(self._expr_has_sudo(generator.iter) for generator in node.generators)
            )
        return False

    def _mark_local_constant_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_local_constant_target(target_element, value_element)
            return

        if isinstance(target, ast.Name):
            if _is_static_literal(value):
                self.local_constants[target.id] = value
            else:
                self.local_constants.pop(target.id, None)
            return

        if isinstance(target, ast.Starred):
            self._mark_local_constant_target(target.value, value)
            return

        if isinstance(target, ast.Tuple | ast.List):
            for name in _target_names(target):
                self.local_constants.pop(name, None)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack and not self.local_constants:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        constants.update(self.local_constants)
        return constants

    def _current_route(self) -> RouteContext:
        return self.route_stack[-1] if self.route_stack else RouteContext(is_route=False)

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        model: str,
        report: str,
    ) -> None:
        self.findings.append(
            ReportFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                model=model,
                report=report,
            )
        )

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(node, self.request_names, self.http_module_names, self.odoo_module_names)


@dataclass
class RouteContext:
    """Current route context for Python report render calls."""

    is_route: bool
    auth: str = "user"


def _route_info(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    constants: dict[str, ast.AST] | None = None,
    route_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> RouteContext | None:
    constants = constants or {}
    route_names = route_names or set()
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_names, http_module_names, odoo_module_names):
            continue
        auth = "user"
        if isinstance(decorator, ast.Call):
            for key, keyword_value in _expanded_keywords(decorator, constants):
                value = _resolve_constant(keyword_value, constants)
                if key == "auth" and isinstance(value, ast.Constant):
                    auth = str(value.value)
        return RouteContext(is_route=True, auth=auth)
    return None


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


def _resolve_constant(node: ast.AST, constants: dict[str, ast.AST], seen: set[str] | None = None) -> ast.AST:
    if isinstance(node, ast.Name):
        seen = seen or set()
        if node.id in seen or node.id not in constants:
            return node
        seen.add(node.id)
        return _resolve_constant(constants[node.id], constants, seen)
    return node


def _resolve_static_dict(node: ast.AST, constants: dict[str, ast.AST], seen: set[str] | None = None) -> ast.Dict | None:
    seen = seen or set()
    node = _resolve_constant(node, constants, seen)
    if isinstance(node, ast.Dict):
        return node
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _resolve_static_dict(node.left, constants, set(seen))
        right = _resolve_static_dict(node.right, constants, set(seen))
        if left is None or right is None:
            return None
        return ast.Dict(keys=[*left.keys, *right.keys], values=[*left.values, *right.values])
    return None


def _is_static_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str | bool | int | float | type(None))
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(_is_static_literal(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        keys = [key for key in node.keys if key is not None]
        return all(_is_static_literal(key) for key in keys) and all(_is_static_literal(value) for value in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_static_literal(node.left) and _is_static_literal(node.right)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd | ast.USub):
        return _is_static_literal(node.operand)
    return False


def _expanded_keywords(node: ast.Call, constants: dict[str, ast.AST]) -> list[tuple[str, ast.AST]]:
    keywords: list[tuple[str, ast.AST]] = []
    for keyword in node.keywords:
        if keyword.arg is not None:
            keywords.append((keyword.arg, keyword.value))
            continue
        value = _resolve_static_dict(keyword.value, constants)
        if value is None:
            continue
        keywords.extend(_expanded_dict_keywords(value, constants))
    return keywords


def _expanded_dict_keywords(node: ast.Dict, constants: dict[str, ast.AST]) -> list[tuple[str, ast.AST]]:
    keywords: list[tuple[str, ast.AST]] = []
    for key, item_value in zip(node.keys, node.values, strict=False):
        if key is None:
            value = _resolve_static_dict(item_value, constants)
            if value is not None:
                keywords.extend(_expanded_dict_keywords(value, constants))
            continue
        resolved_key = _resolve_constant(key, constants)
        if isinstance(resolved_key, ast.Constant) and isinstance(resolved_key.value, str):
            keywords.append((resolved_key.value, item_value))
    return keywords


def _is_http_route(
    node: ast.AST,
    route_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    route_names = route_names or set()
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    if isinstance(node, ast.Call):
        return _is_http_route(node.func, route_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.Name):
        return node.id in route_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "route"
        and _is_http_module_expr(node.value, http_module_names, odoo_module_names)
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


def _is_request_derived(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    if _is_request_source_expr(node, request_names, http_module_names, odoo_module_names):
        return True
    if isinstance(node, ast.Starred):
        return _is_request_derived(node.value, request_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(
            _is_request_derived(element, request_names, http_module_names, odoo_module_names) for element in node.elts
        )
    if isinstance(node, ast.Attribute):
        return _is_request_derived(node.value, request_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.Subscript):
        return _is_request_derived(
            node.value, request_names, http_module_names, odoo_module_names
        ) or _is_request_derived(node.slice, request_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.Call):
        return (
            _is_request_derived(node.func, request_names, http_module_names, odoo_module_names)
            or any(_is_request_derived(arg, request_names, http_module_names, odoo_module_names) for arg in node.args)
            or any(
                keyword.value is not None
                and _is_request_derived(keyword.value, request_names, http_module_names, odoo_module_names)
                for keyword in node.keywords
            )
        )
    text = _safe_unparse(node)
    return any(marker in text for marker in REQUEST_TEXT_MARKERS)


def _is_request_source_expr(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    if isinstance(node, ast.Attribute) and node.attr in REQUEST_SOURCE_ATTRS:
        return _is_request_expr(node.value, request_names, http_module_names, odoo_module_names)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in REQUEST_SOURCE_METHODS
        and _is_request_expr(node.func.value, request_names, http_module_names, odoo_module_names)
    ):
        return True
    return False


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


def _call_has_superuser_arg(
    node: ast.Call,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    constants = constants or {}
    return any(_is_superuser_arg(arg, constants, superuser_names) for arg in node.args) or any(
        keyword.value is not None and _is_superuser_arg(keyword.value, constants, superuser_names)
        for keyword in node.keywords
    )


def _is_superuser_arg(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    constants = constants or {}
    superuser_names = superuser_names or {"SUPERUSER_ID"}
    resolved = _resolve_constant(node, constants)
    if resolved is not node:
        return _is_superuser_arg(resolved, constants, superuser_names)
    node = resolved
    if isinstance(node, ast.Constant):
        return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
    if isinstance(node, ast.Name):
        return node.id in superuser_names
    if isinstance(node, ast.Attribute):
        return node.attr == "SUPERUSER_ID"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
        return any(_is_superuser_arg(arg, constants, superuser_names) for arg in node.args)
    return False


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
    return ""


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Tuple | ast.List):
        return {name for element in node.elts for name in _target_names(element)}
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
    return set()


def _looks_route_id_arg(name: str) -> bool:
    return bool(ROUTE_ID_ARG_RE.search(name))


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _unpack_target_value_pairs(
    target: ast.Tuple | ast.List, value: ast.Tuple | ast.List
) -> list[tuple[ast.AST, ast.AST]]:
    starred_index = next(
        (index for index, element in enumerate(target.elts) if isinstance(element, ast.Starred)),
        None,
    )
    if starred_index is None:
        return list(zip(target.elts, value.elts, strict=False))

    before = list(zip(target.elts[:starred_index], value.elts[:starred_index], strict=False))
    after_count = len(target.elts) - starred_index - 1
    after_values_start = max(len(value.elts) - after_count, starred_index)
    rest_values = value.elts[starred_index:after_values_start]
    after = list(zip(target.elts[starred_index + 1 :], value.elts[after_values_start:], strict=False))
    rest = ast.List(elts=list(rest_values), ctx=ast.Load())
    return [*before, (target.elts[starred_index], rest), *after]


def _record_fields(record: ElementTree.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    for field in record.iter("field"):
        name = field.get("name")
        if not name:
            continue
        values[name] = field.get("ref") or field.get("eval") or (field.text or "").strip()
    return values


def _csv_model_name(path: Path) -> str:
    stem = path.stem.strip().lower()
    aliases = {
        "ir_actions_report": "ir.actions.report",
        "ir.actions.report": "ir.actions.report",
    }
    return aliases.get(stem, stem.replace("_", "."))


def _csv_dict_rows(content: str) -> list[tuple[dict[str, str], int]]:
    try:
        reader = DictReader(StringIO(content))
    except Exception:
        return []
    if not reader.fieldnames:
        return []

    rows: list[tuple[dict[str, str], int]] = []
    try:
        for index, row in enumerate(reader, start=2):
            normalized: dict[str, str] = {}
            for key, value in row.items():
                if key is None:
                    continue
                name = str(key).strip().lower()
                text = str(value or "").strip()
                normalized[name] = text
                if "/" in name or ":" in name:
                    normalized.setdefault(re.split(r"[/:]", name, maxsplit=1)[0], text)
            rows.append((normalized, index))
    except Exception:
        return []
    return rows


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _looks_dynamic_attachment(value: str) -> bool:
    return bool(re.search(r"\b(object|record|docs?)\.", value))


def _contains_sensitive_name_marker(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in SENSITIVE_NAME_MARKERS)


def _model_value(value: str) -> str:
    normalized = value.strip().strip("'\"")
    if normalized in KNOWN_MODEL_EXTERNAL_IDS:
        return KNOWN_MODEL_EXTERNAL_IDS[normalized]
    external_id = normalized.rsplit(".", 1)[-1]
    if external_id in KNOWN_MODEL_EXTERNAL_IDS:
        return KNOWN_MODEL_EXTERNAL_IDS[external_id]
    if normalized.startswith("model_"):
        return normalized.removeprefix("model_").replace("_", ".")
    if ".model_" in normalized:
        return normalized.rsplit(".model_", 1)[1].replace("_", ".")
    return normalized


def findings_to_json(findings: list[ReportFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "report": f.report,
        }
        for f in findings
    ]
