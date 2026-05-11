"""Scanner for Odoo XML data that publishes records or attachments."""

from __future__ import annotations

import ast
import re
from csv import DictReader
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

from defusedxml import ElementTree


@dataclass
class PublicationFinding:
    """Represents a public data/attachment exposure finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    record_id: str = ""


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
SENSITIVE_ATTACHMENT_HINTS = {
    "access_key",
    "access_token",
    "api_key",
    "apikey",
    "auth_token",
    "bearer_token",
    "client_secret",
    "contract",
    "csrf_token",
    "hmac_secret",
    "invoice",
    "jwt_secret",
    "license_key",
    "oauth_token",
    "passport",
    "password",
    "payslip",
    "private",
    "private_key",
    "secret",
    "secret_key",
    "session_token",
    "signature_secret",
    "signing_key",
    "token",
    "totp_secret",
    "webhook_secret",
}
PUBLICATION_FIELD_NAMES = {"is_published", "website_published"}
TAINTED_ARG_NAMES = {"is_published", "published", "value", "website_published", "kwargs", "kw", "post"}
REQUEST_MARKERS = (
    "request.params",
    "request.get_http_params",
    "request.get_json_data",
    "request.jsonrequest",
    "request.httprequest",
    "kwargs.get",
    "kw.get",
    "post.get",
)
REQUEST_SOURCE_ATTRS = {"httprequest", "jsonrequest", "params"}
REQUEST_SOURCE_METHODS = {"get_http_params", "get_json_data"}


def scan_publication(repo_path: Path) -> list[PublicationFinding]:
    """Scan data files and Python code for public publication/exposure flags."""
    findings: list[PublicationFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        if path.suffix == ".xml":
            findings.extend(PublicationScanner(path).scan_file())
        elif path.suffix == ".csv":
            findings.extend(PublicationScanner(path).scan_csv_file())
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(PublicationModelScanner(path).scan_file())
    return findings


class PublicationScanner:
    """Scanner for one XML data file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.content = ""
        self.findings: list[PublicationFinding] = []

    def scan_file(self) -> list[PublicationFinding]:
        """Scan XML records for publication flags."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            root = ElementTree.fromstring(self.content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        for record in root.iter("record"):
            fields = _record_fields(record)
            model = record.get("model", "")
            self._scan_record(model, record.get("id", ""), fields, self._line_for_record(record))
        return self.findings

    def scan_csv_file(self) -> list[PublicationFinding]:
        """Scan CSV data records for public publication/exposure flags."""
        model = _csv_model_name(self.path)
        if model not in {"ir.attachment", "portal.share", "portal.wizard", "share.wizard"} | SENSITIVE_MODELS:
            return []
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        for fields, line_number in _csv_dict_rows(self.content):
            self._scan_record(model, fields.get("id", ""), fields, line_number)
        return self.findings

    def _scan_record(self, model: str, record_id: str, fields: dict[str, str], line: int) -> None:
        if model == "ir.attachment":
            self._scan_attachment(record_id, fields, line)
        self._scan_website_publication(model, record_id, fields, line)
        self._scan_portal_share(model, record_id, fields, line)

    def _scan_attachment(self, record_id: str, fields: dict[str, str], line: int) -> None:
        if _truthy(fields.get("public", "")):
            self._add(
                "odoo-publication-public-attachment",
                "Attachment is published publicly",
                "high",
                line,
                "ir.attachment record sets public=True; verify the binary cannot expose private customer, employee, invoice, or token data",
                "ir.attachment",
                record_id,
            )
        attachment_model = _model_value(fields.get("res_model", ""))
        name_blob = " ".join(fields.get(name, "") for name in ("name", "datas_fname", "url", "res_model")).lower()
        if _truthy(fields.get("public", "")) and (
            attachment_model in SENSITIVE_MODELS or any(hint in name_blob for hint in SENSITIVE_ATTACHMENT_HINTS)
        ):
            self._add(
                "odoo-publication-sensitive-public-attachment",
                "Sensitive-looking attachment is public",
                "critical",
                line,
                "Public attachment name/model suggests sensitive content; verify it is intentionally world-readable",
                "ir.attachment",
                record_id,
            )

    def _scan_website_publication(self, model: str, record_id: str, fields: dict[str, str], line: int) -> None:
        if not _truthy(fields.get("website_published", "")) and not _truthy(fields.get("is_published", "")):
            return
        if model in SENSITIVE_MODELS:
            self._add(
                "odoo-publication-sensitive-website-published",
                "Sensitive model record is website-published",
                "high",
                line,
                f"Record for sensitive model '{model}' is marked website-published; verify portal/public routes cannot expose private fields",
                model,
                record_id,
            )

    def _scan_portal_share(self, model: str, record_id: str, fields: dict[str, str], line: int) -> None:
        if model not in {"portal.share", "portal.wizard", "share.wizard"}:
            return
        share_model = _model_value(fields.get("res_model", ""))
        if _truthy(fields.get("access_warning", "")) or share_model in SENSITIVE_MODELS:
            self._add(
                "odoo-publication-portal-share-sensitive",
                "Portal/share record targets sensitive data",
                "medium",
                line,
                "Portal/share wizard data targets sensitive records; verify generated links, recipients, and expiration behavior",
                model,
                record_id,
            )

    def _line_for_record(self, record: ElementTree.Element) -> int:
        record_id = record.get("id")
        if record_id:
            return _line_for(self.content, f'id="{record_id}"')
        return _line_for(self.content, f'model="{record.get("model", "")}"')

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        model: str,
        record_id: str,
    ) -> None:
        self.findings.append(
            PublicationFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                model=model,
                record_id=record_id,
            )
        )


class PublicationModelScanner(ast.NodeVisitor):
    """Scanner for model-level publication defaults."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[PublicationFinding] = []
        self.model_stack: list[str] = []
        self.route_stack: list[RouteContext] = []
        self.tainted_names: set[str] = set()
        self.dict_aliases: dict[str, dict[str, ast.AST]] = {}
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.route_names: set[str] = set()
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}

    def scan_file(self) -> list[PublicationFinding]:
        """Scan Python files for risky publication defaults."""
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

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_tainted = set(self.tainted_names)
        previous_dict_aliases = dict(self.dict_aliases)
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
            if arg.arg in TAINTED_ARG_NAMES or self._current_route().is_route:
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.route_stack.pop()
        self.tainted_names = previous_tainted
        self.dict_aliases = previous_dict_aliases
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
        elif node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
                elif alias.name == "route":
                    self.route_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        model = _class_model_name(node, self._effective_constants())
        self.model_stack.append(model)
        self.generic_visit(node)
        self.model_stack.pop()
        self.class_constants_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> Any:
        model = self.model_stack[-1] if self.model_stack else ""
        for target in node.targets:
            self._scan_publication_assignment(model, target, node.value, node.lineno)
            self._mark_local_constant_target(target, node.value)
            self._mark_tainted_target(target, node.value)
            self._mark_dict_alias_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        model = self.model_stack[-1] if self.model_stack else ""
        self._scan_publication_assignment(model, node.target, node.value, node.lineno)
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
            self._mark_tainted_target(node.target, node.value)
            self._mark_dict_alias_target(node.target, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        if self._expr_is_tainted(node.iter):
            self._mark_name_target(node.target, self.tainted_names)
        else:
            self._discard_name_target(node.target, self.tainted_names)
        self._discard_dict_alias_target(node.target)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_local_constant_target(node.target, node.value)
        self._mark_tainted_target(node.target, node.value)
        self._mark_dict_alias_target(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        self._scan_runtime_publication_mutation(node)
        self.generic_visit(node)

    def _scan_publication_assignment(self, model: str, target: ast.AST, value: ast.AST | None, line: int) -> None:
        field_name = _assigned_name(target)
        if model not in SENSITIVE_MODELS or field_name not in PUBLICATION_FIELD_NAMES:
            return
        if not _field_default_truthy(value, self._effective_constants()):
            return
        self.findings.append(
            PublicationFinding(
                rule_id="odoo-publication-sensitive-default-published",
                title="Sensitive model defaults records to website-published",
                severity="high",
                file=str(self.path),
                line=line,
                message=(
                    f"Sensitive model '{model}' defines '{field_name}' with a truthy default; verify records are not "
                    "published to website/public routes by default"
                ),
                model=model,
                record_id=field_name,
            )
        )

    def _scan_runtime_publication_mutation(self, node: ast.Call) -> None:
        sink = _call_name(node.func)
        method = sink.rsplit(".", 1)[-1]
        if method not in {"create", "write"}:
            return
        values = self._dict_arg(node)
        publication_values = {
            key: value
            for key, value in values.items()
            if key in PUBLICATION_FIELD_NAMES
            and (_ast_truthy(value, self._effective_constants()) or self._expr_is_tainted(value))
        }
        if not publication_values:
            return
        model = _sensitive_model_in_expr(node.func, self._effective_constants())
        if not model:
            return

        route = self._current_route()
        if route.auth in {"public", "none"}:
            self.findings.append(
                PublicationFinding(
                    rule_id="odoo-publication-public-route-mutation",
                    title="Public route changes website publication",
                    severity="critical",
                    file=str(self.path),
                    line=node.lineno,
                    message=(
                        f"Public/unauthenticated route writes publication flags on sensitive model '{model}'; "
                        "verify attackers cannot publish private records"
                    ),
                    model=model,
                    record_id=",".join(publication_values),
                )
            )

        self.findings.append(
            PublicationFinding(
                rule_id="odoo-publication-sensitive-runtime-published",
                title="Sensitive model publication flag is written at runtime",
                severity="high",
                file=str(self.path),
                line=node.lineno,
                message=(
                    f"Runtime write changes publication flags on sensitive model '{model}'; verify authorization, "
                    "record ownership, and portal/public field exposure"
                ),
                model=model,
                record_id=",".join(publication_values),
            )
        )

        if any(self._expr_is_tainted(value) for value in publication_values.values()):
            self.findings.append(
                PublicationFinding(
                    rule_id="odoo-publication-tainted-runtime-published",
                    title="Request-derived publication flag is written",
                    severity="critical" if route.auth in {"public", "none"} else "high",
                    file=str(self.path),
                    line=node.lineno,
                    message=(
                        f"Request-derived data controls publication flags on sensitive model '{model}'; "
                        "coerce booleans and require explicit publish permissions"
                    ),
                    model=model,
                    record_id=",".join(publication_values),
                )
            )

    def _dict_arg(self, node: ast.Call) -> dict[str, ast.AST]:
        values = _dict_arg(node, self._effective_constants())
        if values:
            return values
        return self._dict_from_expr(node.args[0]) if node.args else {}

    def _dict_from_expr(self, node: ast.AST) -> dict[str, ast.AST]:
        constants = self._effective_constants()
        resolved = _resolve_constant(node, constants)
        if isinstance(resolved, ast.Dict):
            return _dict_items(resolved, constants)
        if isinstance(resolved, ast.Name):
            return self.dict_aliases.get(resolved.id, {})
        if isinstance(resolved, ast.NamedExpr):
            return self._dict_from_expr(resolved.value)
        return {}

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_request_derived(node):
            return True
        text = _safe_unparse(node)
        if any(marker in text for marker in REQUEST_MARKERS):
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
        if isinstance(node, ast.NamedExpr):
            return self._expr_is_tainted(node.value)
        return False

    def _mark_tainted_target(self, target: ast.AST, value: ast.AST) -> None:
        is_tainted = self._expr_is_tainted(value)
        if isinstance(target, ast.Name):
            if is_tainted:
                self.tainted_names.add(target.id)
            else:
                self.tainted_names.discard(target.id)
            return

        if isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List):
                for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                    self._mark_tainted_target(target_element, value_element)
            elif is_tainted:
                self._mark_name_target(target, self.tainted_names)
            else:
                self._discard_name_target(target, self.tainted_names)
            return

        if isinstance(target, ast.Starred):
            self._mark_tainted_target(target.value, value)

    def _mark_dict_alias_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            values = self._dict_from_expr(value)
            if values:
                self.dict_aliases[target.id] = values
            else:
                self.dict_aliases.pop(target.id, None)
            return

        if isinstance(target, ast.Tuple | ast.List):
            self._discard_dict_alias_target(target)
            return

        if isinstance(target, ast.Starred):
            self._mark_dict_alias_target(target.value, value)

    def _mark_local_constant_target(self, target: ast.AST, value: ast.AST) -> None:
        if not self.route_stack:
            return

        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
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
            self._discard_local_constant_target(target)

    def _discard_local_constant_target(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.local_constants.pop(target.id, None)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_local_constant_target(element)
        elif isinstance(target, ast.Starred):
            self._discard_local_constant_target(target.value)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack and not self.local_constants:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        constants.update(self.local_constants)
        return constants

    def _discard_dict_alias_target(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.dict_aliases.pop(target.id, None)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_dict_alias_target(element)
        elif isinstance(target, ast.Starred):
            self._discard_dict_alias_target(target.value)

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

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(node, self.request_names, self.http_module_names, self.odoo_module_names)

    def _current_route(self) -> RouteContext:
        return self.route_stack[-1] if self.route_stack else RouteContext(is_route=False)


@dataclass
class RouteContext:
    """Current route context."""

    is_route: bool
    auth: str = "user"


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
    dotted = stem.replace("_", ".")
    if dotted in {"ir.attachment", "portal.share", "portal.wizard", "share.wizard"} | SENSITIVE_MODELS:
        return dotted
    return stem


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


def _expanded_keywords(node: ast.Call, constants: dict[str, ast.AST]) -> list[tuple[str, ast.AST]]:
    keywords: list[tuple[str, ast.AST]] = []
    for keyword in node.keywords:
        if keyword.arg is not None:
            keywords.append((keyword.arg, keyword.value))
            continue
        value = _resolve_constant(keyword.value, constants)
        if not isinstance(value, ast.Dict):
            continue
        keywords.extend(_expanded_dict_keywords(value, constants))
    return keywords


def _expanded_dict_keywords(node: ast.Dict, constants: dict[str, ast.AST]) -> list[tuple[str, ast.AST]]:
    keywords: list[tuple[str, ast.AST]] = []
    for key, item_value in zip(node.keys, node.values, strict=False):
        if key is None:
            value = _resolve_constant(item_value, constants)
            if isinstance(value, ast.Dict):
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


def _is_static_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str | bool | int | float | type(None))
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(_is_static_literal(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (key is None or _is_static_literal(key)) and _is_static_literal(value)
            for key, value in zip(node.keys, node.values, strict=True)
        )
    return False


def _dict_arg(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> dict[str, ast.AST]:
    constants = constants or {}
    if not node.args or not isinstance(node.args[0], ast.Dict):
        return {}
    return _dict_items(node.args[0], constants)


def _dict_items(node: ast.Dict, constants: dict[str, ast.AST] | None = None) -> dict[str, ast.AST]:
    constants = constants or {}
    return {
        key_value: value
        for key, value in zip(node.keys, node.values, strict=False)
        if (key_value := _constant_string(key, constants))
    }


def _sensitive_model_in_expr(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> str:
    constants = constants or {}
    for child in ast.walk(node):
        model = _constant_string(child, constants)
        if model in SENSITIVE_MODELS:
            return model
    text = _safe_unparse(node)
    for model in SENSITIVE_MODELS:
        if model in text:
            return model
    return ""


def _model_value(value: str) -> str:
    normalized = value.strip()
    if normalized in KNOWN_MODEL_EXTERNAL_IDS:
        return KNOWN_MODEL_EXTERNAL_IDS[normalized]
    external_id = (
        normalized.removeprefix("ref(")
        .removeprefix("'")
        .removeprefix('"')
        .removesuffix(")")
        .removesuffix("'")
        .removesuffix('"')
    )
    if external_id in KNOWN_MODEL_EXTERNAL_IDS:
        return KNOWN_MODEL_EXTERNAL_IDS[external_id]
    return normalized


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _class_model_name(node: ast.ClassDef, constants: dict[str, ast.AST] | None = None) -> str:
    constants = constants or {}
    model_name = ""
    inherit_name = ""
    for statement in node.body:
        if not isinstance(statement, ast.Assign):
            continue
        for target in statement.targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id == "_name":
                model_name = _constant_string(statement.value, constants)
            elif target.id == "_inherit":
                inherit_name = _constant_string(statement.value, constants)
    return model_name or inherit_name


def _assigned_name(node: ast.AST) -> str:
    return node.id if isinstance(node, ast.Name) else ""


def _is_request_derived(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    if _is_request_source_expr(node, request_names, http_module_names, odoo_module_names):
        return True
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
    return False


def _is_request_source_expr(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and _is_request_expr(node.value, request_names, http_module_names, odoo_module_names)
        and node.attr in REQUEST_SOURCE_ATTRS | REQUEST_SOURCE_METHODS
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


def _field_default_truthy(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    if isinstance(node, ast.Call) and _call_name(node.func) in {"fields.Boolean", "Boolean"}:
        for keyword in node.keywords:
            if keyword.arg == "default" and _ast_truthy(keyword.value, constants):
                return True
    return _ast_truthy(node, constants)


def _ast_truthy(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> bool:
    if node is None:
        return False
    resolved = _resolve_constant(node, constants or {})
    if isinstance(resolved, ast.Constant):
        return resolved.value is True or resolved.value == 1 or (
            isinstance(resolved.value, str) and _truthy(resolved.value)
        )
    return False


def _constant_string(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> str:
    if node is None:
        return ""
    resolved = _resolve_constant(node, constants or {})
    if isinstance(resolved, ast.Constant) and isinstance(resolved.value, str):
        return resolved.value
    return ""


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


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


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov"})


def findings_to_json(findings: list[PublicationFinding]) -> list[dict[str, Any]]:
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
            "record_id": f.record_id,
        }
        for f in findings
    ]
