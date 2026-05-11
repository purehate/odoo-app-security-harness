"""Scanner for risky Odoo ir.attachment metadata and mutation patterns."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from odoo_security_harness.base_scanner import _should_skip


@dataclass
class AttachmentFinding:
    """Represents an attachment metadata security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    route: str = ""
    sink: str = ""


ATTACHMENT_MODEL = "ir.attachment"
MUTATION_METHODS = {"create", "write", "unlink"}
LOOKUP_METHODS = {"browse", "read_group", "search", "search_count", "search_read"}
TAINTED_ARG_NAMES = {"attachment_id", "id", "res_id", "res_model", "model", "kwargs", "kw", "post", "params"}
ROUTE_ID_ARG_RE = re.compile(r"(?:^id$|_ids?$)")
REQUEST_MARKERS = (
    "kwargs.get",
    "kw.get",
    "post.get",
)
SENSITIVE_RES_MODELS = {
    "account.move",
    "account.payment",
    "hr.contract",
    "hr.employee",
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
    "sale.order",
    "stock.picking",
}
ATTACHMENT_VALUE_KEYS = {
    "access_token",
    "datas",
    "datas_fname",
    "db_datas",
    "mimetype",
    "name",
    "public",
    "raw",
    "res_id",
    "res_model",
    "store_fname",
    "type",
    "url",
}
ACTIVE_ATTACHMENT_MIMETYPES = {
    "application/javascript",
    "application/xhtml+xml",
    "image/svg+xml",
    "text/html",
    "text/javascript",
}
ACTIVE_ATTACHMENT_EXTENSIONS = (".htm", ".html", ".js", ".mjs", ".svg", ".xhtml")
DANGEROUS_ATTACHMENT_URL_RE = re.compile(
    r"(?i)^\s*(?:javascript:|vbscript:|file:|data:(?:text/html|image/svg\+xml|application/(?:javascript|xhtml\+xml)))"
)
SENSITIVE_ATTACHMENT_NAME_MARKERS = (
    "access_key",
    "access_token",
    "api_key",
    "apikey",
    "auth_token",
    "client_secret",
    "password",
    "private_key",
    "reset_password_token",
    "secret",
    "session_token",
    "signature",
    "signup_token",
    "token",
)


def scan_attachments(repo_path: Path) -> list[AttachmentFinding]:
    """Scan Python files for risky ir.attachment metadata handling."""
    findings: list[AttachmentFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(AttachmentScanner(path).scan_file())
    return findings


class AttachmentScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[AttachmentFinding] = []
        self.attachment_vars: set[str] = set()
        self.sudo_attachment_vars: set[str] = set()
        self.attachment_value_names: dict[str, ast.Dict] = {}
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.superuser_names: set[str] = {"SUPERUSER_ID"}
        self.route_names: set[str] = set()
        self.tainted_names: set[str] = set()
        self.route_stack: list[RouteContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}

    def scan_file(self) -> list[AttachmentFinding]:
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
                elif alias.name == "SUPERUSER_ID":
                    self.superuser_names.add(alias.asname or alias.name)
        elif node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
                elif alias.name == "route":
                    self.route_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_attachment_vars = set(self.attachment_vars)
        previous_sudo_attachment_vars = set(self.sudo_attachment_vars)
        previous_attachment_values = dict(self.attachment_value_names)
        previous_tainted = set(self.tainted_names)
        previous_local_constants = self.local_constants
        self.local_constants = {}
        route = _route_info(
            node,
            self._effective_constants(),
            self.route_names,
            self.http_module_names,
            self.odoo_module_names,
        ) or RouteContext(is_route=False)
        self.route_stack.append(route)

        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES or (route.is_route and _looks_route_id_arg(arg.arg)):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.route_stack.pop()
        self.attachment_vars = previous_attachment_vars
        self.sudo_attachment_vars = previous_sudo_attachment_vars
        self.attachment_value_names = previous_attachment_values
        self.tainted_names = previous_tainted
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
            self._mark_attachment_target(target, node.value)
            self._mark_attachment_value_target(target, node.value)
            self._mark_attachment_value_item_target(target, node.value)
            self._mark_tainted_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
            self._mark_attachment_target(node.target, node.value)
            self._mark_attachment_value_target(node.target, node.value)
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
        self._mark_attachment_target(node.target, node.value)
        self._mark_attachment_value_target(node.target, node.value)
        self._mark_attachment_value_item_target(node.target, node.value)
        self._mark_tainted_target(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        method = sink.rsplit(".", 1)[-1]
        constants = self._effective_constants()
        self._mark_attachment_value_update_call(node)
        if not _attachment_model_in_expr(node.func, self.attachment_vars, constants):
            self.generic_visit(node)
            return

        route = self._current_route()
        if method in MUTATION_METHODS:
            if route.auth in {"public", "none"}:
                self._add(
                    "odoo-attachment-public-route-mutation",
                    "Public route mutates attachments",
                    "critical",
                    node.lineno,
                    "Public/unauthenticated route mutates ir.attachment; verify upload/delete authority, record ownership, and token checks",
                    route.display_path(),
                    sink,
                )
            if _is_elevated_attachment_expr(node.func, self.sudo_attachment_vars, constants, self.superuser_names):
                self._add(
                    "odoo-attachment-sudo-mutation",
                    "Attachment mutation runs with elevated environment",
                    "high",
                    node.lineno,
                    "ir.attachment mutation runs through sudo()/with_user(SUPERUSER_ID); verify res_model/res_id binding, ownership, company scope, and auditability",
                    route.display_path(),
                    sink,
                )

        if method == "create":
            self._scan_attachment_create(node, route, sink)
        elif method == "write":
            self._scan_attachment_write(node, route, sink)
        elif method in LOOKUP_METHODS and _call_has_tainted_input(node, self._expr_is_tainted):
            self._add(
                "odoo-attachment-tainted-lookup",
                "Request-derived attachment lookup",
                "high" if route.auth in {"public", "none"} else "medium",
                node.lineno,
                "Request-derived input selects ir.attachment records; verify ownership, res_model/res_id constraints, access_token, and record-rule behavior",
                route.display_path(),
                sink,
            )

        self.generic_visit(node)

    def _scan_attachment_create(self, node: ast.Call, route: RouteContext, sink: str) -> None:
        values = self._first_dict_arg(node)
        if values is None:
            return
        res_model = values.get("res_model")
        res_id = values.get("res_id")
        public = values.get("public")
        url = values.get("url")
        constants = self._effective_constants()

        if res_model is not None and self._expr_is_tainted(res_model):
            self._add(
                "odoo-attachment-tainted-res-model",
                "Attachment res_model is request-controlled",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "ir.attachment.create uses request-derived res_model; attackers may bind uploads to unintended protected models",
                route.display_path(),
                sink,
            )
        if res_id is not None and self._expr_is_tainted(res_id):
            self._add(
                "odoo-attachment-tainted-res-id",
                "Attachment res_id is request-controlled",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "ir.attachment.create uses request-derived res_id; verify ownership before binding files to existing records",
                route.display_path(),
                sink,
            )
        if public is not None and _truthy_constant(public, constants) and (res_model is None or res_id is None):
            self._add(
                "odoo-attachment-public-orphan",
                "Public attachment lacks record binding",
                "high",
                node.lineno,
                "ir.attachment.create sets public=True without both res_model and res_id; verify the file is intended to be world-readable",
                route.display_path(),
                sink,
            )
        literal_res_model = _literal_string(res_model, constants)
        if literal_res_model in SENSITIVE_RES_MODELS and _truthy_constant(public, constants):
            self._add(
                "odoo-attachment-public-sensitive-binding",
                "Public attachment is bound to sensitive model",
                "critical",
                node.lineno,
                f"ir.attachment.create sets public=True on sensitive model '{literal_res_model}'; verify no private business document is exposed",
                route.display_path(),
                sink,
            )
        if url is not None and self._expr_is_tainted(url):
            self._add(
                "odoo-attachment-tainted-url",
                "Attachment URL is request-controlled",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "ir.attachment.create stores a request-derived URL; validate allowed schemes, trusted hosts, portal visibility, and whether users can be sent to untrusted document links",
                route.display_path(),
                sink,
            )
        unsafe_url = _dangerous_attachment_url(url, constants)
        if unsafe_url:
            self._add(
                "odoo-attachment-unsafe-url-scheme",
                "Attachment URL uses dangerous scheme",
                "high",
                node.lineno,
                f"ir.attachment.create stores URL '{unsafe_url}' with an executable or local-file scheme; restrict attachment links to safe local routes or reviewed HTTPS destinations",
                route.display_path(),
                sink,
            )
        active_content = _active_attachment_content(values, constants)
        if active_content:
            self._add(
                "odoo-attachment-active-content",
                "Attachment uses browser-active content type",
                _active_content_severity(route, public, constants),
                node.lineno,
                f"ir.attachment.create stores browser-active content ({active_content}); verify MIME allowlists, sanitization, download disposition, and public access",
                route.display_path(),
                sink,
            )
        sensitive_name = _sensitive_attachment_name_evidence(values, constants)
        if sensitive_name:
            self._add(
                "odoo-attachment-sensitive-filename",
                "Attachment filename contains sensitive marker",
                "high",
                node.lineno,
                f"ir.attachment.create stores token, secret, password, or API-key-like material in attachment filename metadata ({sensitive_name}); avoid leaking credentials through download headers, chatter, exports, logs, and shared file records",
                route.display_path(),
                sink,
            )

    def _scan_attachment_write(self, node: ast.Call, route: RouteContext, sink: str) -> None:
        values = self._first_dict_arg(node)
        if values is None:
            return
        res_model = values.get("res_model")
        res_id = values.get("res_id")
        public = values.get("public")
        access_token = values.get("access_token")
        url = values.get("url")
        constants = self._effective_constants()

        if public is not None and _truthy_constant(public, constants):
            self._add(
                "odoo-attachment-public-write",
                "Attachment write makes file public",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "ir.attachment.write sets public=True; verify the existing file, linked record, and storage object are intentionally world-readable",
                route.display_path(),
                sink,
            )
        if res_model is not None and self._expr_is_tainted(res_model):
            self._add(
                "odoo-attachment-tainted-res-model-write",
                "Attachment res_model is changed from request input",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "ir.attachment.write uses request-derived res_model; attackers may rebind files to unintended protected models",
                route.display_path(),
                sink,
            )
        if res_id is not None and self._expr_is_tainted(res_id):
            self._add(
                "odoo-attachment-tainted-res-id-write",
                "Attachment res_id is changed from request input",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "ir.attachment.write uses request-derived res_id; verify ownership before rebinding files to existing records",
                route.display_path(),
                sink,
            )
        if access_token is not None and self._expr_is_tainted(access_token):
            self._add(
                "odoo-attachment-tainted-access-token-write",
                "Attachment access_token is request-controlled",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "ir.attachment.write stores a request-derived access_token; generate attachment tokens server-side and bind them to explicit ownership checks",
                route.display_path(),
                sink,
            )
        if url is not None and self._expr_is_tainted(url):
            self._add(
                "odoo-attachment-tainted-url",
                "Attachment URL is request-controlled",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "ir.attachment.write stores a request-derived URL; validate allowed schemes, trusted hosts, portal visibility, and whether users can be sent to untrusted document links",
                route.display_path(),
                sink,
            )
        unsafe_url = _dangerous_attachment_url(url, constants)
        if unsafe_url:
            self._add(
                "odoo-attachment-unsafe-url-scheme",
                "Attachment URL uses dangerous scheme",
                "high",
                node.lineno,
                f"ir.attachment.write stores URL '{unsafe_url}' with an executable or local-file scheme; restrict attachment links to safe local routes or reviewed HTTPS destinations",
                route.display_path(),
                sink,
            )
        active_content = _active_attachment_content(values, constants)
        if active_content:
            self._add(
                "odoo-attachment-active-content",
                "Attachment uses browser-active content type",
                _active_content_severity(route, public, constants),
                node.lineno,
                f"ir.attachment.write stores browser-active content ({active_content}); verify MIME allowlists, sanitization, download disposition, and public access",
                route.display_path(),
                sink,
            )
        sensitive_name = _sensitive_attachment_name_evidence(values, constants)
        if sensitive_name:
            self._add(
                "odoo-attachment-sensitive-filename",
                "Attachment filename contains sensitive marker",
                "high",
                node.lineno,
                f"ir.attachment.write stores token, secret, password, or API-key-like material in attachment filename metadata ({sensitive_name}); avoid leaking credentials through download headers, chatter, exports, logs, and shared file records",
                route.display_path(),
                sink,
            )

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        text = _safe_unparse(node)
        if _is_request_source(
            node,
            self.request_names,
            self.http_module_names,
            self.odoo_module_names,
        ) or any(marker in text for marker in REQUEST_MARKERS):
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
        if isinstance(node, ast.Dict):
            return any(value is not None and self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._expr_is_tainted(element) for element in node.elts)
        if isinstance(node, ast.Starred):
            return self._expr_is_tainted(node.value)
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
        if isinstance(node, ast.NamedExpr):
            return self._expr_is_tainted(node.value)
        return False

    def _mark_attachment_target(self, target: ast.AST, value: ast.AST) -> None:
        constants = self._effective_constants()
        is_attachment = _attachment_model_in_expr(value, self.attachment_vars, constants)
        is_sudo = _is_elevated_attachment_expr(value, self.sudo_attachment_vars, constants, self.superuser_names)
        if isinstance(target, ast.Name):
            if is_attachment:
                self.attachment_vars.add(target.id)
                if is_sudo:
                    self.sudo_attachment_vars.add(target.id)
                else:
                    self.sudo_attachment_vars.discard(target.id)
            else:
                self.attachment_vars.discard(target.id)
                self.sudo_attachment_vars.discard(target.id)
            return

        if isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List):
                for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                    self._mark_attachment_target(target_element, value_element)
            elif is_attachment:
                self._mark_name_target(target, self.attachment_vars)
                if is_sudo:
                    self._mark_name_target(target, self.sudo_attachment_vars)
            else:
                self._discard_name_target(target, self.attachment_vars)
                self._discard_name_target(target, self.sudo_attachment_vars)
            return

        if isinstance(target, ast.Starred):
            self._mark_attachment_target(target.value, value)

    def _mark_attachment_value_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_attachment_value_target(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._mark_attachment_value_target(target.value, value)
            return
        if not isinstance(target, ast.Name):
            return
        if isinstance(value, ast.Dict) and _dict_mentions_attachment_values(value):
            self.attachment_value_names[target.id] = value
        elif isinstance(value, ast.Name) and value.id in self.attachment_value_names:
            self.attachment_value_names[target.id] = self.attachment_value_names[value.id]
        else:
            self.attachment_value_names.pop(target.id, None)

    def _mark_attachment_value_item_target(self, target: ast.AST, value: ast.AST) -> None:
        if not isinstance(target, ast.Subscript) or not isinstance(target.value, ast.Name):
            return
        name = target.value.id
        values_node = self.attachment_value_names.get(name)
        if values_node is None:
            return
        key = _literal_string(target.slice, self._effective_constants())
        if not key:
            return
        self.attachment_value_names[name] = _dict_with_field(values_node, key, value)

    def _mark_attachment_value_update_call(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "update":
            return
        if not isinstance(node.func.value, ast.Name):
            return
        name = node.func.value.id
        values_node = self.attachment_value_names.get(name)
        if values_node is None:
            return

        constants = self._effective_constants()
        merged = values_node
        for arg in node.args:
            update_node = self._attachment_values_node(arg)
            if update_node is None:
                continue
            for key, value in zip(update_node.keys, update_node.values, strict=False):
                literal_key = _literal_string(key, constants) if key is not None else ""
                if literal_key:
                    merged = _dict_with_field(merged, literal_key, value)
        for key, keyword_value in _expanded_keywords(node, constants):
            merged = _dict_with_field(merged, key, keyword_value)
        self.attachment_value_names[name] = merged

    def _first_dict_arg(self, node: ast.Call) -> dict[str, ast.AST] | None:
        values_node: ast.AST | None = node.args[0] if node.args else None
        if values_node is None:
            for key, keyword_value in _expanded_keywords(node, self._effective_constants()):
                if key in {"vals", "values"}:
                    values_node = keyword_value
                    break
        values_node = self._attachment_values_node(values_node) if values_node is not None else None
        if values_node is None:
            return None
        return _dict_fields(values_node)

    def _attachment_values_node(self, values_node: ast.AST) -> ast.Dict | None:
        if isinstance(values_node, ast.Name) and values_node.id in self.attachment_value_names:
            return self.attachment_value_names[values_node.id]
        return _resolve_static_dict(values_node, self._effective_constants())

    def _mark_tainted_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            if self._expr_is_tainted(value):
                self.tainted_names.add(target.id)
            else:
                self.tainted_names.discard(target.id)
            return

        if isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List):
                for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                    self._mark_tainted_target(target_element, value_element)
            elif self._expr_is_tainted(value):
                for target_element in target.elts:
                    self._mark_name_target(target_element, self.tainted_names)
            else:
                self._discard_name_target(target, self.tainted_names)
            return

        if isinstance(target, ast.Starred):
            self._mark_tainted_target(target.value, value)

    def _mark_name_target(self, target: ast.AST, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._mark_name_target(element, names)
        elif isinstance(target, ast.Starred):
            self._mark_name_target(target.value, names)

    def _discard_name_target(self, target: ast.AST, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.discard(target.id)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_name_target(element, names)
        elif isinstance(target, ast.Starred):
            self._discard_name_target(target.value, names)

    def _mark_local_constant_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_local_constant_target(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._mark_local_constant_target(target.value, value)
            return
        if isinstance(target, ast.Name):
            if _is_static_literal(value) or _is_static_dict_shape(value):
                self.local_constants[target.id] = value
            else:
                self.local_constants.pop(target.id, None)
            return
        if isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                if isinstance(element, ast.Name):
                    self.local_constants.pop(element.id, None)

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

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, route: str, sink: str) -> None:
        self.findings.append(
            AttachmentFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                route=route,
                sink=sink,
            )
        )


@dataclass
class RouteContext:
    """Current route context."""

    is_route: bool
    auth: str = "user"
    paths: list[str] | None = None

    def display_path(self) -> str:
        return ",".join(self.paths or []) if self.paths else "<unknown>"


def _route_info(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    constants: dict[str, ast.AST] | None = None,
    route_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> RouteContext | None:
    route_names = route_names or set()
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_names, http_module_names, odoo_module_names):
            continue
        auth = "user"
        paths: list[str] = []
        constants = constants or {}
        if isinstance(decorator, ast.Call):
            if decorator.args:
                paths.extend(_route_values(_resolve_constant(decorator.args[0], constants), constants))
            for key, keyword_value in _expanded_keywords(decorator, constants):
                value = _resolve_constant(keyword_value, constants)
                if key == "auth" and isinstance(value, ast.Constant):
                    auth = str(value.value)
                elif key in {"route", "routes"}:
                    paths.extend(_route_values(value, constants))
        return RouteContext(is_route=True, auth=auth, paths=paths)
    return None


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
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        values: list[str] = []
        for element in node.elts:
            value = _resolve_constant(element, constants or {})
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                values.append(value.value)
        return values
    return []


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


def _resolve_static_dict(node: ast.AST, constants: dict[str, ast.AST], seen: set[str] | None = None) -> ast.Dict | None:
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
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(_is_static_literal(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (key is None or _is_static_literal(key)) and _is_static_literal(value)
            for key, value in zip(node.keys, node.values, strict=True)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_static_literal(node.left) and _is_static_literal(node.right)
    return False


def _is_static_dict_shape(node: ast.AST) -> bool:
    if isinstance(node, ast.Dict):
        return all(key is None or _is_static_literal(key) for key in node.keys)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_static_dict_shape(node.left) and _is_static_dict_shape(node.right)
    return False


def _attachment_model_in_expr(
    node: ast.AST,
    attachment_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    text = _safe_unparse(node)
    if ATTACHMENT_MODEL in text:
        return True
    if isinstance(node, ast.Name):
        return node.id in attachment_vars
    if isinstance(node, ast.Attribute):
        return _attachment_model_in_expr(node.value, attachment_vars, constants)
    if isinstance(node, ast.Call):
        return _attachment_model_in_expr(node.func, attachment_vars, constants)
    if isinstance(node, ast.Subscript):
        model = _literal_string(node.slice, constants)
        return model == ATTACHMENT_MODEL or _attachment_model_in_expr(node.value, attachment_vars, constants)
    return False


def _uses_sudo_attachment_var(node: ast.AST, sudo_attachment_vars: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in sudo_attachment_vars
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_uses_sudo_attachment_var(element, sudo_attachment_vars) for element in node.elts)
    if isinstance(node, ast.Starred):
        return _uses_sudo_attachment_var(node.value, sudo_attachment_vars)
    if isinstance(node, ast.Attribute):
        return _uses_sudo_attachment_var(node.value, sudo_attachment_vars)
    if isinstance(node, ast.Call):
        return _uses_sudo_attachment_var(node.func, sudo_attachment_vars)
    if isinstance(node, ast.Subscript):
        return _uses_sudo_attachment_var(node.value, sudo_attachment_vars)
    return False


def _is_elevated_attachment_expr(
    node: ast.AST,
    sudo_attachment_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    return (
        _call_chain_has_attr(node, "sudo")
        or _call_chain_has_superuser_with_user(node, constants, superuser_names)
        or _uses_sudo_attachment_var(node, sudo_attachment_vars)
    )


def _dict_mentions_attachment_values(node: ast.Dict) -> bool:
    return any(isinstance(key, ast.Constant) and key.value in ATTACHMENT_VALUE_KEYS for key in node.keys)


def _dict_with_field(values_node: ast.Dict, key: str, value: ast.AST) -> ast.Dict:
    keys = list(values_node.keys)
    values = list(values_node.values)
    for index, existing_key in enumerate(keys):
        if isinstance(existing_key, ast.Constant) and existing_key.value == key:
            values[index] = value
            return ast.Dict(keys=keys, values=values)
    keys.append(ast.Constant(value=key))
    values.append(value)
    return ast.Dict(keys=keys, values=values)


def _dict_fields(values_node: ast.Dict) -> dict[str, ast.AST]:
    return {
        key.value: value
        for key, value in zip(values_node.keys, values_node.values)
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }


def _call_has_tainted_input(node: ast.Call, is_tainted: Any) -> bool:
    return any(is_tainted(arg) for arg in node.args) or any(
        keyword.value is not None and is_tainted(keyword.value) for keyword in node.keywords
    )


def _call_chain_has_attr(node: ast.AST, attr: str) -> bool:
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_call_chain_has_attr(element, attr) for element in node.elts)
    if isinstance(node, ast.Starred):
        return _call_chain_has_attr(node.value, attr)
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Attribute):
            if current.attr == attr:
                return True
            current = current.value
        elif isinstance(current, ast.Call):
            current = current.func
        else:
            current = current.value
    return False


def _call_chain_has_superuser_with_user(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_call_chain_has_superuser_with_user(element, constants, superuser_names) for element in node.elts)
    if isinstance(node, ast.Starred):
        return _call_chain_has_superuser_with_user(node.value, constants, superuser_names)
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Call):
            if (
                isinstance(current.func, ast.Attribute)
                and current.func.attr == "with_user"
                and (
                    any(_is_superuser_arg(arg, constants, superuser_names) for arg in current.args)
                    or any(
                        keyword.arg in {"user", "uid"}
                        and keyword.value is not None
                        and _is_superuser_arg(keyword.value, constants, superuser_names)
                        for keyword in current.keywords
                    )
                )
            ):
                return True
            current = current.func
        elif isinstance(current, ast.Attribute):
            current = current.value
        else:
            current = current.value
    return False


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


def _truthy_constant(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    value = _resolve_constant(node, constants or {})
    return isinstance(value, ast.Constant) and value.value is True


def _active_content_severity(route: RouteContext, public: ast.AST | None, constants: dict[str, ast.AST]) -> str:
    if route.auth in {"public", "none"} and public is not None and _truthy_constant(public, constants):
        return "critical"
    if route.auth in {"public", "none"} or (public is not None and _truthy_constant(public, constants)):
        return "high"
    return "medium"


def _active_attachment_content(values: dict[str, ast.AST], constants: dict[str, ast.AST]) -> str:
    evidence: list[str] = []
    mimetype = _literal_string(values.get("mimetype"), constants).strip().lower()
    if mimetype in ACTIVE_ATTACHMENT_MIMETYPES:
        evidence.append(f"mimetype={mimetype}")
    name = _literal_string(values.get("name"), constants).strip().lower()
    if name.endswith(ACTIVE_ATTACHMENT_EXTENSIONS):
        evidence.append(f"name={name}")
    return ", ".join(evidence)


def _sensitive_attachment_name_evidence(values: dict[str, ast.AST], constants: dict[str, ast.AST]) -> str:
    evidence: list[str] = []
    for field in ("name", "datas_fname", "store_fname"):
        value = values.get(field)
        if value is None:
            continue
        text = (_literal_string(value, constants) or _safe_unparse(value)).strip().lower()
        if text and any(marker in text for marker in SENSITIVE_ATTACHMENT_NAME_MARKERS):
            evidence.append(f"{field}={text}")
    return ", ".join(evidence)


def _dangerous_attachment_url(node: ast.AST | None, constants: dict[str, ast.AST]) -> str:
    value = _literal_string(node, constants).strip()
    if value and DANGEROUS_ATTACHMENT_URL_RE.match(value):
        return value
    return ""


def _looks_route_id_arg(name: str) -> bool:
    return bool(ROUTE_ID_ARG_RE.search(name))


def _is_request_source(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute) and child.attr in {"params", "jsonrequest", "httprequest"}:
            if _is_request_expr(child.value, request_names, http_module_names, odoo_module_names):
                return True
        if not isinstance(child, ast.Call) or not isinstance(child.func, ast.Attribute):
            continue
        if child.func.attr in {"get_http_params", "get_json_data"} and _is_request_expr(
            child.func.value,
            request_names,
            http_module_names,
            odoo_module_names,
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


def _unpack_target_value_pairs(
    target_elts: list[ast.expr], value_elts: list[ast.expr]
) -> list[tuple[ast.expr, ast.expr]]:
    starred_index = next(
        (index for index, element in enumerate(target_elts) if isinstance(element, ast.Starred)),
        None,
    )
    if starred_index is None:
        return list(zip(target_elts, value_elts, strict=False))

    after_count = len(target_elts) - starred_index - 1
    pairs = list(zip(target_elts[:starred_index], value_elts[:starred_index], strict=False))
    rest_end = len(value_elts) - after_count if after_count else len(value_elts)
    rest_values = value_elts[starred_index:rest_end]
    pairs.append((target_elts[starred_index], ast.List(elts=rest_values, ctx=ast.Load())))
    if after_count:
        pairs.extend(zip(target_elts[-after_count:], value_elts[-after_count:], strict=False))
    return pairs


def _literal_string(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> str:
    if node is None:
        return ""
    value = _resolve_constant(node, constants or {})
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return ""


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


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""



def findings_to_json(findings: list[AttachmentFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "route": f.route,
            "sink": f.sink,
        }
        for f in findings
    ]
