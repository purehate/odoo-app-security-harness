"""Scanner for risky Python-returned Odoo act_window actions."""

from __future__ import annotations

import ast
import re
from csv import DictReader
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

from defusedxml import ElementTree
from odoo_security_harness.base_scanner import _record_fields, _should_skip


@dataclass
class ActionWindowFinding:
    """Represents a risky act_window finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    route: str = ""
    sink: str = ""
    flag: str = ""


TAINTED_ARG_NAMES = {"context", "domain", "kwargs", "kw", "post", "values"}
REQUEST_MARKERS = (
    "kwargs.get",
    "kw.get",
    "post.get",
)
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
PRIVILEGED_DEFAULT_FIELDS = {
    "active",
    "company_id",
    "company_ids",
    "groups_id",
    "implied_ids",
    "share",
    "user_id",
}
COMPANY_SCOPE_CONTEXT_KEYS = {"allowed_company_ids", "company_id", "force_company"}


def scan_action_windows(repo_path: Path) -> list[ActionWindowFinding]:
    """Scan Python and XML files for risky act_window declarations."""
    findings: list[ActionWindowFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        scanner = ActionWindowScanner(path)
        if path.suffix == ".py":
            findings.extend(scanner.scan_file())
        elif path.suffix == ".xml":
            findings.extend(scanner.scan_xml_file())
        elif path.suffix == ".csv":
            findings.extend(scanner.scan_csv_file())
    return findings


class ActionWindowScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[ActionWindowFinding] = []
        self.tainted_names: set[str] = set()
        self.action_window_names: set[str] = set()
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.route_names: set[str] = set()
        self.route_stack: list[RouteContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}

    def scan_file(self) -> list[ActionWindowFinding]:
        """Scan the file."""
        try:
            content = self.path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content)
        except SyntaxError:
            return []
        except Exception:
            return []

        self.constants = _module_constants(tree)
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
                    self.route_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def scan_xml_file(self) -> list[ActionWindowFinding]:
        """Scan XML act_window records."""
        try:
            content = self.path.read_text(encoding="utf-8", errors="replace")
            root = ElementTree.fromstring(content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        for record in root.iter("record"):
            if record.get("model") == "ir.actions.act_window":
                self._scan_action_window_record(record, content)
        return self.findings

    def scan_csv_file(self) -> list[ActionWindowFinding]:
        """Scan CSV act_window records."""
        if _csv_model_name(self.path) != "ir.actions.act_window":
            return []
        try:
            content = self.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        for fields, line in _csv_dict_rows(content):
            self._scan_action_window_fields(fields, fields.get("id", ""), line)
        return self.findings

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_tainted = set(self.tainted_names)
        previous_action_window_names = set(self.action_window_names)
        previous_local_constants = self.local_constants
        self.local_constants = {}
        self.route_stack.append(
            _route_info(
                node,
                self._effective_constants(),
                self.route_names,
                self.http_module_names,
                self.odoo_module_names,
            )
            or RouteContext(is_route=False)
        )
        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES:
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.route_stack.pop()
        self.tainted_names = previous_tainted
        self.action_window_names = previous_action_window_names
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
            self._mark_action_window_target(target, node.value)
            self._scan_action_window_subscript_assignment(target, node.value, node.lineno)
            self._mark_tainted_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
            self._mark_action_window_target(node.target, node.value)
            self._scan_action_window_subscript_assignment(node.target, node.value, node.lineno)
            self._mark_tainted_target(node.target, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        if self._expr_is_tainted(node.iter):
            self._mark_name_target(node.target, self.tainted_names)
        else:
            self._discard_name_target(node.target, self.tainted_names)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_local_constant_target(node.target, node.value)
        self._mark_action_window_target(node.target, node.value)
        self._scan_action_window_subscript_assignment(node.target, node.value, node.lineno)
        self._mark_tainted_target(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        self._record_tainted_container_mutation(node)
        self._scan_action_window_update_call(node)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> Any:
        fields = _dict_literal_fields(node, self._effective_constants())
        if fields.get("type") == "ir.actions.act_window":
            self._scan_action_window(node, fields)
        self.generic_visit(node)

    def _scan_action_window(self, node: ast.Dict, fields: dict[str, str]) -> None:
        constants = self._effective_constants()
        route = self._current_route()
        model = _model_value(fields.get("res_model", ""))
        model_node = _dict_value(node, "res_model", constants)
        domain_node = _dict_value(node, "domain", constants)
        context_node = _dict_value(node, "context", constants)
        groups = fields.get("groups_id", "") or fields.get("groups", "")

        if model_node is not None and self._expr_is_tainted(model_node):
            self._add(
                "odoo-act-window-tainted-res-model",
                "Action window model uses request-derived data",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "ir.actions.act_window res_model is request-derived; restrict actions to explicit models to avoid exposing unintended records or views",
                model,
                route,
                "python-dict",
                "res_model",
            )

        if domain_node is not None and self._expr_is_tainted(domain_node):
            self._add(
                "odoo-act-window-tainted-domain",
                "Action window domain uses request-derived data",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "ir.actions.act_window domain is request-derived; validate allowed fields/operators and prevent cross-record discovery",
                model,
                route,
                "python-dict",
                "domain",
            )

        if context_node is not None and self._expr_is_tainted(context_node):
            self._add(
                "odoo-act-window-tainted-context",
                "Action window context uses request-derived data",
                "high",
                node.lineno,
                "ir.actions.act_window context is request-derived; prevent forged defaults, company scope, active_test, and framework flags",
                model,
                route,
                "python-dict",
                "context",
            )

        if model in SENSITIVE_MODELS and not _has_group_restriction(groups) and _is_broad_domain(domain_node, constants):
            self._add(
                "odoo-act-window-sensitive-broad-domain",
                "Sensitive action window uses broad domain",
                "medium",
                node.lineno,
                f"Python action window opens sensitive model '{model}' with broad/no domain and no groups; verify caller authorization and record rules",
                model,
                route,
                "python-dict",
                "domain",
            )

        if model in SENSITIVE_MODELS and route.auth in {"public", "none"}:
            self._add(
                "odoo-act-window-public-sensitive-model",
                "Public route returns sensitive action window",
                "critical" if _is_broad_domain(domain_node, constants) else "high",
                node.lineno,
                (
                    f"Public route returns an ir.actions.act_window for sensitive model '{model}'; verify "
                    "unauthenticated users cannot open privileged views or enumerate records through the client action"
                ),
                model,
                route,
                "python-dict",
                "res_model",
            )

        for flag in sorted(_privileged_context_defaults(context_node, constants)):
            self._add(
                "odoo-act-window-privileged-default-context",
                "Action window seeds privilege-bearing default",
                "high",
                node.lineno,
                f"Action window context sets {flag}=...; verify create flows cannot assign users, groups, companies, share flags, or active state unexpectedly",
                model,
                route,
                "python-dict",
                flag,
            )

        if context_node is not None and _context_disables_active_test(context_node, constants):
            self._add(
                "odoo-act-window-active-test-disabled",
                "Action window disables active_test",
                "low",
                node.lineno,
                "Action window context sets active_test=False; archived/inactive records may become visible in this flow",
                model,
                route,
                "python-dict",
                "active_test",
            )

        for flag in sorted(_company_scope_context_keys(context_node, constants)):
            self._add(
                "odoo-act-window-company-scope-context",
                "Action window changes company scope",
                "medium",
                node.lineno,
                f"Action window context sets {flag}=...; verify users cannot see, create, or edit records under an unintended company scope",
                model,
                route,
                "python-dict",
                flag,
            )

    def _scan_action_window_record(self, record: ElementTree.Element, content: str) -> None:
        fields = _record_fields(record)
        record_id = record.get("id", "")
        line = (
            _line_for(content, f'id="{record_id}"')
            if record_id
            else _line_for(content, 'model="ir.actions.act_window"')
        )
        self._scan_action_window_fields(fields, record_id, line)

    def _scan_action_window_fields(self, fields: dict[str, str], record_id: str, line: int) -> None:
        model = _model_value(fields.get("res_model", ""))
        domain = fields.get("domain", "")
        context = fields.get("context", "")
        groups = fields.get("groups_id", "") or fields.get("groups", "")
        route = RouteContext(is_route=False)

        if model in SENSITIVE_MODELS and not _has_group_restriction(groups) and _is_broad_domain_text(domain):
            self._add(
                "odoo-act-window-sensitive-broad-domain",
                "Sensitive action window uses broad domain",
                "medium",
                line,
                f"XML action window '{record_id}' opens sensitive model '{model}' with broad/no domain and no groups; verify menus and bindings are not broadly reachable",
                model,
                route,
                "ir.actions.act_window",
                "domain",
            )

        for flag in sorted(_privileged_context_default_strings(context)):
            self._add(
                "odoo-act-window-privileged-default-context",
                "Action window seeds privilege-bearing default",
                "high",
                line,
                f"XML action window '{record_id}' context sets {flag}=...; verify create flows cannot assign users, groups, companies, share flags, or active state unexpectedly",
                model,
                route,
                "ir.actions.act_window",
                flag,
            )

        if "'active_test': False" in context or '"active_test": False' in context:
            self._add(
                "odoo-act-window-active-test-disabled",
                "Action window disables active_test",
                "low",
                line,
                f"XML action window '{record_id}' context sets active_test=False; archived/inactive records may become visible in this flow",
                model,
                route,
                "ir.actions.act_window",
                "active_test",
            )

        for flag in sorted(_company_scope_context_key_strings(context)):
            self._add(
                "odoo-act-window-company-scope-context",
                "Action window changes company scope",
                "medium",
                line,
                f"XML action window '{record_id}' context sets {flag}=...; verify users cannot see, create, or edit records under an unintended company scope",
                model,
                route,
                "ir.actions.act_window",
                flag,
            )

    def _scan_action_window_subscript_assignment(self, target: ast.AST, value: ast.AST, line: int) -> None:
        if not isinstance(target, ast.Subscript) or not self._expr_is_action_window(target.value):
            return
        key = _subscript_constant_key(target, self._effective_constants())
        if key in {"res_model", "domain", "context"}:
            self._scan_mutated_action_window_field(key, value, line, "python-dict-mutation")

    def _scan_action_window_update_call(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "update":
            return
        if not self._expr_is_action_window(node.func.value):
            return

        for arg in node.args:
            if not isinstance(arg, ast.Dict):
                continue
            constants = self._effective_constants()
            for key in ("res_model", "domain", "context"):
                value = _dict_value(arg, key, constants)
                if value is not None:
                    self._scan_mutated_action_window_field(key, value, node.lineno, "python-dict-update")
        for keyword in node.keywords:
            if keyword.arg in {"res_model", "domain", "context"}:
                self._scan_mutated_action_window_field(keyword.arg, keyword.value, node.lineno, "python-dict-update")

    def _scan_mutated_action_window_field(self, key: str, value: ast.AST, line: int, sink: str) -> None:
        constants = self._effective_constants()
        route = self._current_route()
        model = _model_value(_literal_string(value, constants)) if key == "res_model" else ""

        if key == "res_model" and self._expr_is_tainted(value):
            self._add(
                "odoo-act-window-tainted-res-model",
                "Action window model uses request-derived data",
                "critical" if route.auth in {"public", "none"} else "high",
                line,
                "ir.actions.act_window res_model is assigned from request-derived data; restrict actions to explicit models to avoid exposing unintended records or views",
                model,
                route,
                sink,
                "res_model",
            )
        elif key == "domain" and self._expr_is_tainted(value):
            self._add(
                "odoo-act-window-tainted-domain",
                "Action window domain uses request-derived data",
                "critical" if route.auth in {"public", "none"} else "high",
                line,
                "ir.actions.act_window domain is assigned from request-derived data; validate allowed fields/operators and prevent cross-record discovery",
                model,
                route,
                sink,
                "domain",
            )
        elif key == "context" and self._expr_is_tainted(value):
            self._add(
                "odoo-act-window-tainted-context",
                "Action window context uses request-derived data",
                "high",
                line,
                "ir.actions.act_window context is assigned from request-derived data; prevent forged defaults, company scope, active_test, and framework flags",
                model,
                route,
                sink,
                "context",
            )

        if key == "res_model" and model in SENSITIVE_MODELS and route.auth in {"public", "none"}:
            self._add(
                "odoo-act-window-public-sensitive-model",
                "Public route returns sensitive action window",
                "high",
                line,
                (
                    f"Public route assigns an ir.actions.act_window res_model to sensitive model '{model}'; verify "
                    "unauthenticated users cannot open privileged views or enumerate records through the client action"
                ),
                model,
                route,
                sink,
                "res_model",
            )

        if key == "context":
            for flag in sorted(_privileged_context_defaults(value, constants)):
                self._add(
                    "odoo-act-window-privileged-default-context",
                    "Action window seeds privilege-bearing default",
                    "high",
                    line,
                    f"Action window context sets {flag}=...; verify create flows cannot assign users, groups, companies, share flags, or active state unexpectedly",
                    model,
                    route,
                    sink,
                    flag,
                )
            if _context_disables_active_test(value, constants):
                self._add(
                    "odoo-act-window-active-test-disabled",
                    "Action window disables active_test",
                    "low",
                    line,
                    "Action window context sets active_test=False; archived/inactive records may become visible in this flow",
                    model,
                    route,
                    sink,
                    "active_test",
                )
            for flag in sorted(_company_scope_context_keys(value, constants)):
                self._add(
                    "odoo-act-window-company-scope-context",
                    "Action window changes company scope",
                    "medium",
                    line,
                    f"Action window context sets {flag}=...; verify users cannot see, create, or edit records under an unintended company scope",
                    model,
                    route,
                    sink,
                    flag,
                )

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_request_derived(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.tainted_names
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted(node.value) or self._expr_is_tainted(node.slice)
        if isinstance(node, ast.Attribute):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Call):
            return (
                self._expr_is_tainted(node.func)
                or any(self._expr_is_tainted(arg) for arg in node.args)
                or any(keyword.value is not None and self._expr_is_tainted(keyword.value) for keyword in node.keywords)
            )
        if isinstance(node, ast.JoinedStr):
            return any(self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.BinOp):
            return self._expr_is_tainted(node.left) or self._expr_is_tainted(node.right)
        if isinstance(node, ast.Dict):
            return any(self._expr_is_tainted(key) for key in node.keys if key is not None) or any(
                value is not None and self._expr_is_tainted(value) for value in node.values
            )
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._expr_is_tainted(element) for element in node.elts)
        if isinstance(node, ast.Starred):
            return self._expr_is_tainted(node.value)
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
        if isinstance(node, ast.NamedExpr):
            return self._expr_is_tainted(node.value)
        return False

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(
            node,
            self.request_names,
            self.http_module_names,
            self.odoo_module_names,
        )

    def _expr_is_action_window(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.action_window_names
        if isinstance(node, ast.Subscript):
            return _call_root_name(node) in self.action_window_names
        return False

    def _expr_creates_action_window(self, node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Dict)
            and _dict_literal_fields(node, self._effective_constants()).get("type") == "ir.actions.act_window"
            or self._expr_is_action_window(node)
            or isinstance(node, ast.List | ast.Tuple | ast.Set)
            and any(self._expr_creates_action_window(element) for element in node.elts)
        )

    def _mark_tainted_target(self, target: ast.AST, value: ast.AST) -> None:
        is_tainted = self._expr_is_tainted(value)
        if isinstance(target, ast.Name):
            if is_tainted:
                self.tainted_names.add(target.id)
            else:
                self.tainted_names.discard(target.id)
            return

        if isinstance(target, ast.Starred):
            self._mark_tainted_target(target.value, value)
            return

        if isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List):
                for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                    self._mark_tainted_target(target_element, value_element)
            elif is_tainted:
                for target_element in target.elts:
                    self._mark_name_target(target_element, self.tainted_names)
            else:
                self._discard_name_target(target, self.tainted_names)

    def _mark_action_window_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Starred):
            self._mark_action_window_target(target.value, value)
            return

        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_action_window_target(target_element, value_element)
            return

        if self._expr_creates_action_window(value):
            self._mark_name_target(target, self.action_window_names)
        else:
            self._discard_name_target(target, self.action_window_names)

    def _record_tainted_container_mutation(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Attribute) or node.func.attr not in {"append", "extend", "add", "update"}:
            return
        if not self._expr_is_tainted(node):
            return
        if isinstance(node.func.value, ast.Name):
            self.tainted_names.add(node.func.value.id)

    def _mark_name_target(self, target: ast.AST, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Starred):
            self._mark_name_target(target.value, names)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._mark_name_target(element, names)

    def _discard_name_target(self, target: ast.AST, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.discard(target.id)
        elif isinstance(target, ast.Starred):
            self._discard_name_target(target.value, names)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_name_target(element, names)

    def _mark_local_constant_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_local_constant_target(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._mark_local_constant_target(target.value, value)
            return
        if isinstance(target, ast.Name):
            if _is_static_literal(value):
                self.local_constants[target.id] = value
            else:
                self.local_constants.pop(target.id, None)
            return
        names = set(self.local_constants)
        self._discard_name_target(target, names)
        for name in set(self.local_constants) - names:
            self.local_constants.pop(name, None)

    def _current_route(self) -> RouteContext:
        return self.route_stack[-1] if self.route_stack else RouteContext(is_route=False)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack and not self.local_constants:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        constants.update(self.local_constants)
        return constants

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        model: str,
        route: RouteContext,
        sink: str,
        flag: str,
    ) -> None:
        self.findings.append(
            ActionWindowFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                model=model,
                route=route.display_path() if route.is_route else "",
                sink=sink,
                flag=flag,
            )
        )


@dataclass
class RouteContext:
    """Current route context."""

    is_route: bool
    auth: str = "user"
    paths: tuple[str, ...] = ()

    def display_path(self) -> str:
        return ",".join(self.paths) if self.paths else "<unknown>"


def _route_info(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    constants: dict[str, ast.AST] | None = None,
    route_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> RouteContext | None:
    constants = constants or {}
    route_names = route_names or set()
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_names, http_module_names, odoo_module_names):
            continue
        auth = "user"
        paths: list[str] = []
        if isinstance(decorator, ast.Call):
            if decorator.args:
                paths.extend(_route_values(decorator.args[0], constants))
            for name, keyword_value in _expanded_keywords(decorator, constants):
                value = _resolve_constant(keyword_value, constants)
                if name == "auth" and isinstance(value, ast.Constant):
                    auth = str(value.value)
                elif name in {"route", "routes"}:
                    paths.extend(_route_values(keyword_value, constants))
        return RouteContext(is_route=True, auth=auth, paths=tuple(paths))
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


def _route_values(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> list[str]:
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.List | ast.Tuple):
        values: list[str] = []
        for item in node.elts:
            value = _resolve_constant(item, constants or {})
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                values.append(value.value)
        return values
    return []


def _resolve_constant(node: ast.AST, constants: dict[str, ast.AST]) -> ast.AST:
    return _resolve_constant_seen(node, constants, set())


def _resolve_constant_seen(node: ast.AST, constants: dict[str, ast.AST], seen: set[str]) -> ast.AST:
    if isinstance(node, ast.Name):
        if node.id in seen:
            return node
        value = constants.get(node.id)
        if value is None:
            return node
        return _resolve_constant_seen(value, constants, {*seen, node.id})
    return node


def _resolve_static_dict(
    node: ast.AST, constants: dict[str, ast.AST], seen: set[str] | None = None
) -> ast.Dict | None:
    seen = seen or set()
    node = _resolve_constant_seen(node, constants, seen)
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
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str | bool | int | float | type(None))
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd | ast.USub):
        return _is_static_literal(node.operand)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(_is_static_literal(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (key is None or _is_static_literal(key)) and value is not None and _is_static_literal(value)
            for key, value in zip(node.keys, node.values, strict=False)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_static_literal(node.left) and _is_static_literal(node.right)
    return False


def _unpack_target_value_pairs(targets: list[ast.expr], values: list[ast.expr]) -> list[tuple[ast.expr, ast.AST]]:
    starred_index = next((index for index, target in enumerate(targets) if isinstance(target, ast.Starred)), None)
    if starred_index is None:
        return list(zip(targets, values, strict=False))

    before = list(zip(targets[:starred_index], values[:starred_index], strict=False))
    after_count = len(targets) - starred_index - 1
    after_values_start = max(len(values) - after_count, starred_index)
    rest_values = values[starred_index:after_values_start]
    rest_container: ast.expr = ast.List(elts=rest_values, ctx=ast.Load())
    after = list(zip(targets[starred_index + 1 :], values[after_values_start:], strict=False))
    return [*before, (targets[starred_index], rest_container), *after]


def _dict_literal_fields(node: ast.Dict, constants: dict[str, ast.AST] | None = None) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key, value in zip(node.keys, node.values, strict=False):
        resolved_key = _resolve_constant(key, constants or {}) if key is not None else None
        if isinstance(resolved_key, ast.Constant) and isinstance(resolved_key.value, str):
            fields[resolved_key.value] = _literal_string(value, constants)
    return fields


def _dict_value(node: ast.Dict, name: str, constants: dict[str, ast.AST] | None = None) -> ast.AST | None:
    for key, value in zip(node.keys, node.values, strict=False):
        resolved_key = _resolve_constant(key, constants or {}) if key is not None else None
        if isinstance(resolved_key, ast.Constant) and resolved_key.value == name:
            return value
    return None


def _subscript_constant_key(node: ast.Subscript, constants: dict[str, ast.AST] | None = None) -> str:
    value = _resolve_constant(node.slice, constants or {})
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return ""



def _csv_model_name(path: Path) -> str:
    stem = path.stem.strip().lower()
    if stem in {"ir.actions.act_window", "ir_actions_act_window"}:
        return "ir.actions.act_window"
    return stem.replace("_", ".")


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


def _literal_string(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> str:
    if node is None:
        return ""
    value = _resolve_constant(node, constants or {})
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return ""


def _is_request_derived(
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
    return any(marker in text for marker in REQUEST_MARKERS)


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


def _call_root_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _call_root_name(node.value)
    if isinstance(node, ast.Call):
        return _call_root_name(node.func)
    if isinstance(node, ast.Subscript):
        return _call_root_name(node.value)
    return ""


def _is_broad_domain(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> bool:
    if node is None:
        return True
    value = _resolve_constant(node, constants or {})
    if isinstance(value, ast.List | ast.Tuple):
        return len(value.elts) == 0
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value.strip() in {"", "[]", "[(1,'=',1)]", "[(1, '=', 1)]"}
    return False


def _is_broad_domain_text(value: str) -> bool:
    return value.strip() in {"", "[]", "[(1,'=',1)]", "[(1, '=', 1)]"}


def _has_group_restriction(value: str) -> bool:
    normalized = value.strip()
    if not normalized:
        return False
    compact = normalized.replace(" ", "").lower()
    return compact not in {"[]", "()", "false", "none", "0", "[(5,0,0)]", "[(6,0,[])]", "[(6,0,())]"}


def _privileged_context_defaults(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> set[str]:
    flags: set[str] = set()
    value = _resolve_constant(node, constants or {}) if node is not None else None
    if not isinstance(value, ast.Dict):
        return flags
    for key, item_value in zip(value.keys, value.values, strict=False):
        resolved_key = _resolve_constant(key, constants or {}) if key is not None else None
        if not isinstance(resolved_key, ast.Constant) or not isinstance(resolved_key.value, str):
            continue
        flag = resolved_key.value
        if not flag.startswith("default_") or _is_empty_or_false(item_value, constants):
            continue
        field = flag.removeprefix("default_")
        if field in PRIVILEGED_DEFAULT_FIELDS or field.startswith("sel_groups_"):
            flags.add(flag)
    return flags


def _privileged_context_default_strings(value: str) -> set[str]:
    flags: set[str] = set()
    for field in PRIVILEGED_DEFAULT_FIELDS:
        if f"default_{field}" in value:
            flags.add(f"default_{field}")
    for marker in ("default_sel_groups_", "'default_sel_groups_", '"default_sel_groups_'):
        if marker in value:
            flags.add("default_sel_groups_*")
    return flags


def _context_disables_active_test(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> bool:
    value = _resolve_constant(node, constants or {}) if node is not None else None
    if not isinstance(value, ast.Dict):
        return False
    for key, item_value in zip(value.keys, value.values, strict=False):
        resolved_key = _resolve_constant(key, constants or {}) if key is not None else None
        resolved_value = _resolve_constant(item_value, constants or {})
        if isinstance(resolved_key, ast.Constant) and resolved_key.value == "active_test":
            return isinstance(resolved_value, ast.Constant) and resolved_value.value is False
    return False


def _company_scope_context_keys(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> set[str]:
    flags: set[str] = set()
    value = _resolve_constant(node, constants or {}) if node is not None else None
    if not isinstance(value, ast.Dict):
        return flags
    for key, item_value in zip(value.keys, value.values, strict=False):
        resolved_key = _resolve_constant(key, constants or {}) if key is not None else None
        if not isinstance(resolved_key, ast.Constant) or not isinstance(resolved_key.value, str):
            continue
        if resolved_key.value in COMPANY_SCOPE_CONTEXT_KEYS and not _is_empty_or_false(item_value, constants):
            flags.add(resolved_key.value)
    return flags


def _company_scope_context_key_strings(value: str) -> set[str]:
    return {key for key in COMPANY_SCOPE_CONTEXT_KEYS if key in value}


def _is_empty_or_false(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    value = _resolve_constant(node, constants or {})
    if isinstance(value, ast.Constant):
        return value.value is False or value.value is None or value.value == "" or value.value == 0
    if isinstance(value, ast.List | ast.Tuple | ast.Set):
        return len(value.elts) == 0
    if isinstance(value, ast.Dict):
        return len(value.keys) == 0
    return False


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _line_for(content: str, needle: str) -> int:
    index = content.find(needle)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1



def findings_to_json(findings: list[ActionWindowFinding]) -> list[dict[str, Any]]:
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
            "route": f.route,
            "sink": f.sink,
            "flag": f.flag,
        }
        for f in findings
    ]
