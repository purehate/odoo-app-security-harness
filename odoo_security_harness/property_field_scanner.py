"""Scanner for risky Odoo property and company-dependent fields."""

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
class PropertyFieldFinding:
    """Represents a risky property/company-dependent field finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    field: str = ""
    record_id: str = ""
    sink: str = ""


@dataclass
class FieldDef:
    """Represents one Odoo field declaration."""

    name: str
    field_type: str
    line: int
    keywords: dict[str, ast.expr]


SENSITIVE_FIELD_MARKERS = (
    "access_key",
    "account",
    "api_key",
    "apikey",
    "auth_token",
    "bearer_token",
    "client_secret",
    "credential",
    "csrf_token",
    "hmac_secret",
    "journal",
    "jwt_secret",
    "license_key",
    "oauth_token",
    "payable",
    "provider",
    "private_key",
    "receivable",
    "price",
    "secret",
    "secret_key",
    "session_token",
    "signature_secret",
    "signing_key",
    "tax",
    "token",
    "totp_secret",
    "webhook_secret",
)
PROPERTY_VALUE_FIELDS = {"value_binary", "value_float", "value_integer", "value_reference", "value_text"}
PROPERTY_MUTATION_METHODS = {"create", "write"}
TAINTED_ARG_NAMES = {"field", "field_name", "kwargs", "kw", "post", "value", "values"}
ROUTE_PROPERTY_ARG_RE = re.compile(
    r"(?:^id$|_ids?$|^uid$|_uids?$|^field$|_field$|^field_name$|^value$|_value$|^model$|_model$)"
)
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


def scan_property_fields(repo_path: Path) -> list[PropertyFieldFinding]:
    """Scan Python and XML files for risky Odoo property-field behavior."""
    findings: list[PropertyFieldFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        if path.suffix == ".py":
            findings.extend(PropertyFieldScanner(path).scan_python_file())
        elif path.suffix == ".xml":
            findings.extend(PropertyFieldScanner(path).scan_xml_file())
        elif path.suffix == ".csv":
            findings.extend(PropertyFieldScanner(path).scan_csv_file())
    return findings


class PropertyFieldScanner(ast.NodeVisitor):
    """Scanner for one Python/XML file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.content = ""
        self.findings: list[PropertyFieldFinding] = []
        self.property_vars: set[str] = set()
        self.elevated_property_vars: set[str] = set()
        self.tainted_names: set[str] = set()
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.route_names: set[str] = set()
        self.route_stack: list[RouteContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []

    def scan_python_file(self) -> list[PropertyFieldFinding]:
        """Scan Python model field declarations."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(self.content)
        except SyntaxError:
            return []
        except Exception:
            return []

        self.constants = _module_constants(tree)
        self.visit(tree)
        return self.findings

    def scan_xml_file(self) -> list[PropertyFieldFinding]:
        """Scan XML ir.property data records."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            root = ElementTree.fromstring(self.content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        for record in root.iter("record"):
            if record.get("model") == "ir.property":
                self._scan_property_record(record)
        return self.findings

    def scan_csv_file(self) -> list[PropertyFieldFinding]:
        """Scan CSV ir.property data records."""
        if _csv_model_name(self.path) != "ir.property":
            return []
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        for fields, line in _csv_dict_rows(self.content):
            self._scan_property_fields(fields, fields.get("id", ""), line)
        return self.findings

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_property_vars = set(self.property_vars)
        previous_elevated_property_vars = set(self.elevated_property_vars)
        previous_tainted_names = set(self.tainted_names)
        route = _route_info(node, self._effective_constants(), self.route_names, self.http_module_names) or RouteContext(
            is_route=False
        )
        self.route_stack.append(route)

        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES or (route.is_route and _looks_route_property_arg(arg.arg)):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.route_stack.pop()
        self.property_vars = previous_property_vars
        self.elevated_property_vars = previous_elevated_property_vars
        self.tainted_names = previous_tainted_names

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

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

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._mark_property_target(target, node.value)
            self._mark_tainted_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_property_target(node.target, node.value)
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
        self._mark_property_target(node.target, node.value)
        self._mark_tainted_target(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        constants = self._effective_constants()
        if sink.rsplit(".", 1)[-1] in PROPERTY_MUTATION_METHODS and _is_ir_property_expr(
            node.func, self.property_vars, constants
        ):
            self._scan_property_mutation(node, sink)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        constants = self._effective_constants()
        if not _is_odoo_model(node):
            self.generic_visit(node)
            self.class_constants_stack.pop()
            return

        model = _extract_model_name(node, constants)
        fields = _extract_fields(node, constants)
        field_names = {field.name for field in fields}
        for field in fields:
            if not _kw_is_true(field, "company_dependent", constants):
                continue
            self._scan_company_dependent_field(model, field, field_names, constants)

        self.generic_visit(node)
        self.class_constants_stack.pop()

    def _scan_company_dependent_field(
        self, model: str, field: FieldDef, field_names: set[str], constants: dict[str, ast.AST]
    ) -> None:
        if "company_id" not in field_names and field.field_type not in {"Boolean", "Selection"}:
            self._add(
                "odoo-property-field-no-company-field",
                "Company-dependent field on model without company_id",
                "medium",
                field.line,
                f"Field '{field.name}' is company_dependent=True but model has no company_id field; review property fallback and cross-company behavior",
                model,
                field.name,
            )

        if _is_sensitive_field(field.name) and not _string_keyword(field, "groups", constants):
            self._add(
                "odoo-property-sensitive-field-no-groups",
                "Sensitive company-dependent field lacks groups",
                "high",
                field.line,
                f"Sensitive company-dependent field '{field.name}' has no groups= restriction; verify users cannot alter company-specific accounting/security values",
                model,
                field.name,
            )

        if _has_keyword(field, "default"):
            self._add(
                "odoo-property-field-default",
                "Company-dependent field defines a default",
                "low",
                field.line,
                f"Field '{field.name}' is company_dependent=True and defines default=; verify default does not mask missing company-specific properties",
                model,
                field.name,
            )

    def _scan_property_record(self, record: ElementTree.Element) -> None:
        fields = _record_fields(record)
        record_id = record.get("id", "")
        line = (
            _line_for(self.content, f'id="{record_id}"')
            if record_id
            else _line_for(self.content, 'model="ir.property"')
        )
        self._scan_property_fields(fields, record_id, line)

    def _scan_property_fields(self, fields: dict[str, str], record_id: str, line: int) -> None:
        field_ref = fields.get("fields_id", "")

        if not fields.get("company_id", ""):
            self._add(
                "odoo-property-global-default",
                "ir.property record has no company",
                "medium",
                line,
                f"ir.property '{record_id}' has no company_id and becomes a global fallback; verify this is safe for all companies",
                "ir.property",
                field_ref,
                record_id,
            )

        if not fields.get("res_id", ""):
            self._add(
                "odoo-property-no-resource-scope",
                "ir.property record has no resource scope",
                "low",
                line,
                f"ir.property '{record_id}' has no res_id and may apply broadly as a default; verify intended model/company scope",
                "ir.property",
                field_ref,
                record_id,
            )

        if _is_sensitive_field(field_ref) and any(fields.get(name, "") for name in PROPERTY_VALUE_FIELDS):
            self._add(
                "odoo-property-sensitive-value",
                "Sensitive ir.property value is preconfigured",
                "medium",
                line,
                f"ir.property '{record_id}' configures a sensitive field '{field_ref}'; verify accounting/security defaults are company-scoped",
                "ir.property",
                field_ref,
                record_id,
            )

    def _scan_property_mutation(self, node: ast.Call, sink: str) -> None:
        constants = self._effective_constants()
        values = _mutation_values(node, constants)
        route = self._current_route()
        field_ref = _literal_string(values.get("fields_id"), constants) or _literal_string(values.get("name"), constants)

        if route.auth in {"public", "none"}:
            self._add(
                "odoo-property-public-route-mutation",
                "Public route mutates ir.property",
                "critical",
                node.lineno,
                "Public route writes ir.property; verify unauthenticated users cannot alter company-specific accounting or configuration defaults",
                "ir.property",
                field_ref,
                "",
                sink,
            )

        if _is_elevated_expr(node.func, constants) or _uses_elevated_property_var(
            node.func, self.elevated_property_vars
        ):
            self._add(
                "odoo-property-sudo-mutation",
                "ir.property is mutated through privileged context",
                "high",
                node.lineno,
                "sudo()/with_user(SUPERUSER_ID) mutates ir.property; verify explicit admin checks and company scoping before changing property defaults",
                "ir.property",
                field_ref,
                "",
                sink,
            )

        if self._expr_is_tainted(node):
            self._add(
                "odoo-property-request-derived-mutation",
                "Request-derived data reaches ir.property",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "Request-derived data reaches ir.property mutation; whitelist fields and reject accounting, company, token, and security properties",
                "ir.property",
                field_ref,
                "",
                sink,
            )

        if values and "company_id" not in values:
            self._add(
                "odoo-property-runtime-global-default",
                "Runtime ir.property mutation has no company",
                "medium",
                node.lineno,
                "Runtime ir.property mutation omits company_id and may create a global fallback; verify this is safe for all companies",
                "ir.property",
                field_ref,
                "",
                sink,
            )

        if values and "res_id" not in values:
            self._add(
                "odoo-property-runtime-no-resource-scope",
                "Runtime ir.property mutation has no resource scope",
                "low",
                node.lineno,
                "Runtime ir.property mutation omits res_id and may apply broadly as a default; verify intended model/company scope",
                "ir.property",
                field_ref,
                "",
                sink,
            )

        if _is_sensitive_field(field_ref) and any(name in values for name in PROPERTY_VALUE_FIELDS):
            self._add(
                "odoo-property-runtime-sensitive-value",
                "Runtime ir.property writes sensitive value",
                "high",
                node.lineno,
                f"Runtime ir.property mutation configures sensitive field '{field_ref}'; verify accounting/security defaults are company-scoped",
                "ir.property",
                field_ref,
                "",
                sink,
            )

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_request_derived(node):
            return True
        text = _safe_unparse(node)
        if any(marker in text for marker in REQUEST_MARKERS):
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

    def _mark_property_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_property_target(target_element, value_element)
            return

        constants = self._effective_constants()
        is_property = _is_ir_property_expr(value, self.property_vars, constants)
        is_elevated_property = is_property and (
            _is_elevated_expr(value, constants)
            or _uses_elevated_property_var(value, self.elevated_property_vars)
        )
        for name in _target_names(target):
            if is_property:
                self.property_vars.add(name)
                if is_elevated_property:
                    self.elevated_property_vars.add(name)
                else:
                    self.elevated_property_vars.discard(name)
            else:
                self.property_vars.discard(name)
                self.elevated_property_vars.discard(name)

    def _mark_tainted_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_tainted_target(target_element, value_element)
            return

        if self._expr_is_tainted(value):
            self._mark_name_target(target, self.tainted_names)
        else:
            self._discard_name_target(target, self.tainted_names)

    def _mark_name_target(self, target: ast.AST, names: set[str]) -> None:
        names.update(_target_names(target))

    def _discard_name_target(self, target: ast.AST, names: set[str]) -> None:
        for name in _target_names(target):
            names.discard(name)

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(node, self.request_names)

    def _current_route(self) -> RouteContext:
        return self.route_stack[-1] if self.route_stack else RouteContext(is_route=False)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        model: str,
        field: str,
        record_id: str = "",
        sink: str = "",
    ) -> None:
        self.findings.append(
            PropertyFieldFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                model=model,
                field=field,
                record_id=record_id,
                sink=sink,
            )
        )


@dataclass
class RouteContext:
    """Current route context."""

    is_route: bool
    auth: str = "user"


def _extract_fields(node: ast.ClassDef, constants: dict[str, ast.AST] | None = None) -> list[FieldDef]:
    constants = constants or {}
    fields: list[FieldDef] = []
    for item in node.body:
        field = _field_def_from_assignment(item, constants)
        if field is not None:
            fields.append(field)
    return fields


def _field_def_from_assignment(node: ast.stmt, constants: dict[str, ast.AST]) -> FieldDef | None:
    if isinstance(node, ast.Assign):
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            return None
        target = node.targets[0]
        value = node.value
    elif isinstance(node, ast.AnnAssign):
        if not isinstance(node.target, ast.Name) or node.value is None:
            return None
        target = node.target
        value = node.value
    else:
        return None

    if not isinstance(value, ast.Call):
        return None
    call = value
    field_type = _field_call_type(call.func)
    if not field_type:
        return None
    return FieldDef(
        name=target.id,
        field_type=field_type,
        line=node.lineno,
        keywords=_call_keywords(call, constants),
    )


def _call_keywords(node: ast.Call, constants: dict[str, ast.AST]) -> dict[str, ast.AST]:
    keywords: dict[str, ast.AST] = {}
    for keyword in node.keywords:
        if keyword.arg is not None:
            keywords[keyword.arg] = keyword.value
            continue
        value = _resolve_constant(keyword.value, constants)
        if isinstance(value, ast.Dict):
            keywords.update(_dict_keywords(value, constants))
    return keywords


def _dict_keywords(node: ast.Dict, constants: dict[str, ast.AST]) -> dict[str, ast.AST]:
    keywords: dict[str, ast.AST] = {}
    for key, value in zip(node.keys, node.values, strict=False):
        if key is None:
            resolved_value = _resolve_constant(value, constants)
            if isinstance(resolved_value, ast.Dict):
                keywords.update(_dict_keywords(resolved_value, constants))
            continue
        resolved_key = _resolve_constant(key, constants)
        if isinstance(resolved_key, ast.Constant) and isinstance(resolved_key.value, str):
            keywords[resolved_key.value] = value
    return keywords


def _field_call_type(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "fields":
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _record_fields(record: ElementTree.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    for field in record.iter("field"):
        name = field.get("name")
        if not name:
            continue
        values[name] = field.get("ref") or field.get("eval") or "".join(field.itertext()).strip()
    return values


def _csv_model_name(path: Path) -> str:
    stem = path.stem.strip().lower()
    aliases = {"ir_property": "ir.property", "ir.property": "ir.property"}
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
                if "/" in name:
                    normalized.setdefault(name.split("/", 1)[0], text)
            rows.append((normalized, index))
    except Exception:
        return []
    return rows


def _route_info(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    constants: dict[str, ast.AST] | None = None,
    route_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
) -> RouteContext | None:
    constants = constants or {}
    route_names = route_names or set()
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_names, http_module_names):
            continue
        auth = "user"
        if isinstance(decorator, ast.Call):
            for name, keyword_value in _expanded_keywords(decorator, constants):
                value = _resolve_constant(keyword_value, constants)
                if name == "auth" and isinstance(value, ast.Constant):
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
) -> bool:
    route_names = route_names or set()
    http_module_names = http_module_names or {"http"}
    if isinstance(node, ast.Call):
        return _is_http_route(node.func, route_names, http_module_names)
    if isinstance(node, ast.Name):
        return node.id in route_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "route"
        and isinstance(node.value, ast.Name)
        and node.value.id in http_module_names
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
        return _resolve_constant_seen(value, constants, seen | {node.id})
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
            for key, value in zip(node.keys, node.values)
        )
    return False


def _is_odoo_model(node: ast.ClassDef) -> bool:
    return any(
        isinstance(base, ast.Attribute)
        and base.attr in {"Model", "TransientModel", "AbstractModel"}
        or isinstance(base, ast.Name)
        and base.id in {"Model", "TransientModel", "AbstractModel"}
        for base in node.bases
    )


def _extract_model_name(node: ast.ClassDef, constants: dict[str, ast.AST] | None = None) -> str:
    for item in node.body:
        if not isinstance(item, ast.Assign):
            continue
        for target in item.targets:
            if isinstance(target, ast.Name) and target.id in {"_name", "_inherit"}:
                value = _resolve_constant(item.value, constants or {})
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    return value.value
    return node.name


def _kw_is_true(field: FieldDef, keyword: str, constants: dict[str, ast.AST] | None = None) -> bool:
    value = field.keywords.get(keyword)
    if value is not None:
        value = _resolve_constant(value, constants or {})
    return isinstance(value, ast.Constant) and value.value is True


def _has_keyword(field: FieldDef, keyword: str) -> bool:
    return keyword in field.keywords


def _string_keyword(field: FieldDef, keyword: str, constants: dict[str, ast.AST] | None = None) -> str:
    value = field.keywords.get(keyword)
    if value is not None:
        value = _resolve_constant(value, constants or {})
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return ""


def _is_sensitive_field(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in SENSITIVE_FIELD_MARKERS)


def _is_ir_property_expr(
    node: ast.AST,
    property_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    if isinstance(node, ast.Starred):
        return _is_ir_property_expr(node.value, property_vars, constants)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_is_ir_property_expr(element, property_vars, constants) for element in node.elts)
    if isinstance(node, ast.Name) and node.id in property_vars:
        return True
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in property_vars:
            return True
        if isinstance(child, ast.Subscript) and _env_model_name(child, constants) == "ir.property":
            return True
    return False


def _is_elevated_expr(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    if isinstance(node, ast.Starred):
        return _is_elevated_expr(node.value, constants)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_is_elevated_expr(element, constants) for element in node.elts)
    return (
        _call_chain_has_attr(node, "sudo")
        or _call_chain_has_superuser_with_user(node, constants)
        or "SUPERUSER_ID" in _safe_unparse(node)
    )


def _call_chain_has_superuser_with_user(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        if not (isinstance(child.func, ast.Attribute) and child.func.attr == "with_user"):
            continue
        if any(_is_admin_user_arg(arg, constants) for arg in child.args):
            return True
        if any(
            keyword.arg in {"user", "uid"}
            and keyword.value is not None
            and _is_admin_user_arg(keyword.value, constants)
            for keyword in child.keywords
        ):
            return True
    return False


def _is_admin_user_arg(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant):
        return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
    if isinstance(node, ast.Name):
        return node.id == "SUPERUSER_ID"
    if isinstance(node, ast.Attribute):
        return node.attr == "SUPERUSER_ID"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
        return any(_is_admin_user_arg(arg, constants) for arg in node.args)
    return False


def _uses_elevated_property_var(node: ast.AST, elevated_property_vars: set[str]) -> bool:
    return any(isinstance(child, ast.Name) and child.id in elevated_property_vars for child in ast.walk(node))


def _env_model_name(node: ast.Subscript, constants: dict[str, ast.AST] | None = None) -> str:
    if not _call_name(node.value).endswith("env"):
        return ""
    value = _resolve_constant(node.slice, constants or {})
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return ""


def _mutation_values(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> dict[str, ast.AST]:
    constants = constants or {}
    if not node.args:
        return {}
    first_arg = node.args[0]
    if isinstance(first_arg, ast.Dict):
        return {
            str(resolved_key.value): value
            for key, value in zip(first_arg.keys, first_arg.values, strict=False)
            if key is not None
            if isinstance((resolved_key := _resolve_constant(key, constants)), ast.Constant)
            and isinstance(resolved_key.value, str)
        }
    return {}


def _literal_string(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> str:
    if node is not None:
        node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _looks_route_property_arg(name: str) -> bool:
    return bool(ROUTE_PROPERTY_ARG_RE.search(name))


def _is_request_derived(node: ast.AST, request_names: set[str]) -> bool:
    if _is_request_source_expr(node, request_names):
        return True
    if isinstance(node, ast.Starred):
        return _is_request_derived(node.value, request_names)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_is_request_derived(element, request_names) for element in node.elts)
    if isinstance(node, ast.Attribute):
        return _is_request_derived(node.value, request_names)
    if isinstance(node, ast.Subscript):
        return _is_request_derived(node.value, request_names) or _is_request_derived(node.slice, request_names)
    if isinstance(node, ast.Call):
        return (
            _is_request_derived(node.func, request_names)
            or any(_is_request_derived(arg, request_names) for arg in node.args)
            or any(
                keyword.value is not None and _is_request_derived(keyword.value, request_names)
                for keyword in node.keywords
            )
        )
    return False


def _is_request_source_expr(node: ast.AST, request_names: set[str]) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and _is_request_expr(node.value, request_names)
        and node.attr in REQUEST_SOURCE_ATTRS | REQUEST_SOURCE_METHODS
    )


def _is_request_expr(node: ast.AST, request_names: set[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in request_names


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Tuple | ast.List):
        return {name for element in node.elts for name in _target_names(element)}
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
    return set()


def _call_chain_has_attr(node: ast.AST, attr: str) -> bool:
    if isinstance(node, ast.Starred):
        return _call_chain_has_attr(node.value, attr)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_call_chain_has_attr(element, attr) for element in node.elts)
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


def _line_for(content: str, needle: str) -> int:
    if not needle:
        return 1
    index = content.find(needle)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[PropertyFieldFinding]) -> list[dict[str, Any]]:
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
            "field": f.field,
            "record_id": f.record_id,
            "sink": f.sink,
        }
        for f in findings
    ]
