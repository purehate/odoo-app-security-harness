"""Scanner for risky Odoo automated actions."""

from __future__ import annotations

import ast
import re
import textwrap
from collections.abc import Callable
from csv import DictReader
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

from defusedxml import ElementTree


@dataclass
class AutomationFinding:
    """Represents a risky automated action finding."""

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
WRITE_TRIGGERS = {"on_create", "on_write", "on_create_or_write", "on_unlink"}
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "request", "urlopen"}
HTTP_CLIENT_FACTORIES = {"AsyncClient", "Client", "ClientSession", "Session"}
MUTATION_METHODS = {"write", "create", "unlink"}
SENSITIVE_MODEL_MUTATION_METHODS = {*MUTATION_METHODS, "set", "set_param"}


def scan_automations(repo_path: Path) -> list[AutomationFinding]:
    """Scan data files for risky base.automation records."""
    findings: list[AutomationFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        scanner = AutomationScanner(path)
        if path.suffix == ".xml":
            findings.extend(scanner.scan_file())
        elif path.suffix == ".csv":
            findings.extend(scanner.scan_csv_file())
    return findings


class AutomationScanner:
    """Scanner for one data file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.content = ""
        self.findings: list[AutomationFinding] = []

    def scan_file(self) -> list[AutomationFinding]:
        """Scan the XML file."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            root = ElementTree.fromstring(self.content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        for record in root.iter("record"):
            if record.get("model") == "base.automation":
                self._scan_automation(record)
        return self.findings

    def scan_csv_file(self) -> list[AutomationFinding]:
        """Scan a CSV base.automation export/declaration file."""
        if _csv_model_name(self.path) != "base.automation":
            return []
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        for fields, line in _csv_dict_rows(self.content):
            self._scan_automation_fields(fields, fields.get("id", ""), line)
        return self.findings

    def _scan_automation(self, record: ElementTree.Element) -> None:
        fields = _record_fields(record)
        self._scan_automation_fields(fields, record.get("id", ""), self._line_for_record(record))

    def _scan_automation_fields(self, fields: dict[str, str], record_id: str, line: int) -> None:
        model = _normalize_model_ref(fields.get("model_id", ""))
        trigger = fields.get("trigger", "")
        filter_domain = fields.get("filter_domain", "") or fields.get("filter_pre_domain", "")
        code = fields.get("code", "")

        if model in SENSITIVE_MODELS and trigger in WRITE_TRIGGERS and not filter_domain.strip():
            self._add(
                "odoo-automation-broad-sensitive-trigger",
                "Broad automated action on sensitive model",
                "high",
                line,
                f"base.automation runs on '{trigger}' for sensitive model '{model}' without a filter_domain; verify it cannot mutate/expose every record",
                model,
                record_id,
            )

        code_risks = _scan_code_risks(code)

        if "dynamic_eval" in code_risks:
            self._add(
                "odoo-automation-dynamic-eval",
                "Automated action performs dynamic evaluation",
                "critical",
                line,
                "base.automation code contains eval/exec/safe_eval; verify no record or user-controlled expression reaches it",
                model,
                record_id,
            )

        if "sudo_mutation" in code_risks:
            self._add(
                "odoo-automation-sudo-mutation",
                "Automated action performs elevated mutation",
                "high",
                line,
                "base.automation code chains sudo()/with_user(SUPERUSER_ID) into write/create/unlink; verify record rules and company isolation are not bypassed",
                model,
                record_id,
            )

        if "sensitive_model_mutation" in code_risks:
            self._add(
                "odoo-automation-sensitive-model-mutation",
                "Automated action mutates sensitive model",
                "high",
                line,
                "base.automation code mutates a sensitive model; verify trigger scope, actor, idempotency, and audit trail",
                model,
                record_id,
            )

        if "http_no_timeout" in code_risks:
            self._add(
                "odoo-automation-http-no-timeout",
                "Automated action performs HTTP without timeout",
                "medium",
                line,
                "base.automation code performs outbound HTTP without timeout; review SSRF and worker exhaustion risk",
                model,
                record_id,
            )
        if "tls_verify_disabled" in code_risks:
            self._add(
                "odoo-automation-tls-verify-disabled",
                "Automated action disables TLS verification",
                "high",
                line,
                "base.automation code passes verify=False to outbound HTTP; record-triggered integrations should not permit man-in-the-middle attacks",
                model,
                record_id,
            )

    def _line_for_record(self, record: ElementTree.Element) -> int:
        record_id = record.get("id")
        if record_id:
            return _line_for(self.content, f'id="{record_id}"')
        return _line_for(self.content, 'model="base.automation"')

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
            AutomationFinding(
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
    aliases = {"base_automation": "base.automation", "base.automation": "base.automation"}
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


def _normalize_model_ref(value: str) -> str:
    value = value.strip()
    if value.startswith("model_"):
        return value.removeprefix("model_").replace("_", ".")
    if ".model_" in value:
        return value.rsplit(".model_", 1)[1].replace("_", ".")
    return value


def _scan_code_risks(code: str) -> set[str]:
    scanner = _AutomationCodeScanner()
    return scanner.scan(code)


class _AutomationCodeScanner(ast.NodeVisitor):
    def __init__(self) -> None:
        self.risks: set[str] = set()
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.sudo_vars: set[str] = set()
        self.http_module_aliases: set[str] = {"aiohttp", "requests", "httpx", "urllib"}
        self.http_function_aliases: set[str] = set()
        self.http_client_vars: set[str] = set()

    def scan(self, code: str) -> set[str]:
        try:
            tree = ast.parse(textwrap.dedent(code))
        except SyntaxError:
            return self._regex_fallback(code)
        except Exception:
            return set()
        self.constants = _module_constants(tree)
        self.visit(tree)
        return self.risks

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            if alias.name in {"aiohttp", "requests", "httpx"}:
                self.http_module_aliases.add(alias.asname or alias.name)
            elif alias.name == "urllib.request":
                self.http_module_aliases.add(alias.asname or "urllib")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module in {"aiohttp", "requests", "httpx", "urllib.request"}:
            for alias in node.names:
                if alias.name in HTTP_METHODS:
                    self.http_function_aliases.add(alias.asname or alias.name)
        elif node.module == "urllib":
            for alias in node.names:
                if alias.name == "request":
                    self.http_module_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._record_alias_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._record_alias_target(node.target, node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._record_alias_target(node.target, node.value)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> Any:
        for item in node.items:
            if item.optional_vars is not None:
                self._track_alias(
                    item.optional_vars,
                    item.context_expr,
                    self.http_client_vars,
                    lambda value: _is_http_client_expr(value, self.http_module_aliases)
                    or _call_root_name(value) in self.http_client_vars,
                )
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> Any:
        self.visit_With(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        constants = self._effective_constants()
        if _is_dynamic_eval(sink):
            self.risks.add("dynamic_eval")
        if _is_sudo_mutation(node.func, self.sudo_vars, constants):
            self.risks.add("sudo_mutation")
        if sink.rsplit(".", 1)[-1] in SENSITIVE_MODEL_MUTATION_METHODS and _call_receiver_sensitive_model(
            node, constants
        ):
            self.risks.add("sensitive_model_mutation")
        if _is_http_call(node.func, self.http_module_aliases, self.http_function_aliases, self.http_client_vars):
            if not _has_effective_timeout(node, constants):
                self.risks.add("http_no_timeout")
            if _keyword_is_false(node, "verify", constants):
                self.risks.add("tls_verify_disabled")
        self.generic_visit(node)

    def _record_alias_target(self, target: ast.AST, value: ast.AST) -> None:
        self._track_alias(
            target,
            value,
            self.sudo_vars,
            lambda node: _is_sudo_expr(node, self.sudo_vars, self._effective_constants()),
        )
        self._track_alias(
            target,
            value,
            self.http_client_vars,
            lambda node: _is_http_client_expr(node, self.http_module_aliases)
            or _call_root_name(node) in self.http_client_vars,
        )

    def _track_alias(
        self,
        target: ast.AST,
        value: ast.AST,
        aliases: set[str],
        predicate: Callable[[ast.AST], bool],
    ) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._track_alias(target_element, value_element, aliases, predicate)
            return
        if isinstance(target, ast.Tuple | ast.List):
            for target_element in target.elts:
                self._track_alias(target_element, value, aliases, predicate)
            return
        if isinstance(target, ast.Starred):
            self._track_alias(target.value, value, aliases, predicate)
            return
        if not isinstance(target, ast.Name):
            return
        if predicate(value):
            aliases.add(target.id)
        else:
            aliases.discard(target.id)

    def _regex_fallback(self, code: str) -> set[str]:
        risks: set[str] = set()
        if "safe_eval" in code or re.search(r"\b(eval|exec)\s*\(", code):
            risks.add("dynamic_eval")
        superuser_with_user = (
            r"with_user\(\s*(?:(?:user|uid)\s*=\s*)?" r"(?:SUPERUSER_ID|1|[^)]*base\.user_(?:admin|root)[^)]*)\s*\)"
        )
        if re.search(rf"\.(?:sudo\(\)|{superuser_with_user}).*?\.(write|create|unlink)\s*\(", code, re.DOTALL):
            risks.add("sudo_mutation")
        if _regex_sensitive_model_mutation(code):
            risks.add("sensitive_model_mutation")
        if (
            re.search(r"requests\.(get|post|put|patch|delete|head)\s*\(", code)
            or re.search(r"aiohttp\.(get|post|put|patch|delete|head|request)\s*\(", code)
            or re.search(r"(?:urllib\.request\.)?urlopen\s*\(", code)
        ) and ("timeout" not in code or re.search(r"\btimeout\s*=\s*None\b", code)):
            risks.add("http_no_timeout")
        if re.search(r"\bverify\s*=\s*False\b", code):
            risks.add("tls_verify_disabled")
        return risks

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants


def _is_dynamic_eval(sink: str) -> bool:
    return sink in {"eval", "exec", "safe_eval"} or sink.endswith(".safe_eval")


def _is_sudo_mutation(node: ast.AST, sudo_vars: set[str], constants: dict[str, ast.AST] | None = None) -> bool:
    sink = _call_name(node)
    if sink.rsplit(".", 1)[-1] not in MUTATION_METHODS:
        return False
    return _is_sudo_expr(node, sudo_vars, constants)


def _call_receiver_sensitive_model(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> str:
    if not isinstance(node.func, ast.Attribute):
        return ""
    model = _env_subscript_model(node.func.value, constants or {})
    if model in SENSITIVE_MODELS:
        return model
    receiver = _safe_unparse(node.func.value)
    for model in SENSITIVE_MODELS:
        if f"'{model}'" in receiver or f'"{model}"' in receiver:
            return model
    return ""


def _is_sudo_expr(node: ast.AST, sudo_vars: set[str], constants: dict[str, ast.AST] | None = None) -> bool:
    if isinstance(node, ast.Starred):
        return _is_sudo_expr(node.value, sudo_vars, constants)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_is_sudo_expr(element, sudo_vars, constants) for element in node.elts)
    return (
        _call_chain_has_attr(node, "sudo")
        or _call_chain_has_superuser_with_user(node, constants)
        or _call_root_name(node) in sudo_vars
    )


def _call_chain_has_superuser_with_user(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    if isinstance(node, ast.Starred):
        return _call_chain_has_superuser_with_user(node.value, constants)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_call_chain_has_superuser_with_user(element, constants) for element in node.elts)
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Call):
            if isinstance(current.func, ast.Attribute) and current.func.attr == "with_user":
                return any(_is_superuser_arg(arg, constants) for arg in current.args) or any(
                    keyword.value is not None and _is_superuser_arg(keyword.value, constants)
                    for keyword in current.keywords
                )
            current = current.func
        elif isinstance(current, ast.Attribute):
            current = current.value
        else:
            current = current.value
    return False


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


def _env_subscript_model(node: ast.AST, constants: dict[str, ast.AST]) -> str:
    current = node
    while isinstance(current, ast.Call | ast.Attribute):
        current = current.func if isinstance(current, ast.Call) else current.value
    if not isinstance(current, ast.Subscript):
        return ""
    if _call_name(current.value) not in {"env", "self.env"}:
        return ""
    key = _resolve_constant(current.slice, constants)
    if isinstance(key, ast.Constant) and isinstance(key.value, str):
        return key.value
    return ""


def _is_http_call(
    node: ast.AST,
    module_aliases: set[str],
    function_aliases: set[str],
    client_vars: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in function_aliases
    if not isinstance(node, ast.Attribute) or node.attr not in HTTP_METHODS:
        return False
    root = _call_root_name(node)
    return root in module_aliases or root in client_vars


def _is_http_client_expr(node: ast.AST, module_aliases: set[str]) -> bool:
    if isinstance(node, ast.Starred):
        return _is_http_client_expr(node.value, module_aliases)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_is_http_client_expr(element, module_aliases) for element in node.elts)
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr not in HTTP_CLIENT_FACTORIES:
        return False
    return _call_root_name(node.func) in module_aliases


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


def _call_chain_has_attr(node: ast.AST, attr: str) -> bool:
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


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _regex_sensitive_model_mutation(code: str) -> bool:
    model_pattern = "|".join(re.escape(model) for model in sorted(SENSITIVE_MODELS))
    method_pattern = "|".join(re.escape(method) for method in sorted(SENSITIVE_MODEL_MUTATION_METHODS))
    return bool(
        re.search(
            rf"\[['\"](?:{model_pattern})['\"]\].*?\.({method_pattern})\s*\(",
            code,
            re.DOTALL,
        )
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


def _resolve_constant(node: ast.AST, constants: dict[str, ast.AST], seen: set[str] | None = None) -> ast.AST:
    if isinstance(node, ast.Name):
        seen = seen or set()
        if node.id in seen or node.id not in constants:
            return node
        seen.add(node.id)
        return _resolve_constant(constants[node.id], constants, seen)
    return node


def _is_static_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str | bool | int | float | type(None))
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return all(_is_static_literal(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        keys = [key for key in node.keys if key is not None]
        return all(_is_static_literal(key) for key in keys) and all(
            _is_static_literal(value) for value in node.values
        )
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd | ast.USub):
        return _is_static_literal(node.operand)
    return False


def _has_keyword(node: ast.Call, name: str) -> bool:
    return any(keyword.arg == name for keyword in node.keywords)


def _has_effective_timeout(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    timeout_values = _keyword_values(node, "timeout", constants)
    return bool(timeout_values) and not any(_is_none_constant(value, constants) for value in timeout_values)


def _is_none_constant(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    value = _resolve_constant(node, constants or {})
    return isinstance(value, ast.Constant) and value.value is None


def _keyword_is_false(node: ast.Call, name: str, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    for keyword_value in _keyword_values(node, name, constants):
        value = _resolve_constant(keyword_value, constants)
        if isinstance(value, ast.Constant) and value.value is False:
            return True
    return False


def _keyword_values(node: ast.Call, name: str, constants: dict[str, ast.AST] | None = None) -> list[ast.AST]:
    constants = constants or {}
    values: list[ast.AST] = []
    for keyword in node.keywords:
        if keyword.arg == name:
            values.append(keyword.value)
            continue
        if keyword.arg is not None:
            continue
        value = _resolve_constant(keyword.value, constants)
        if isinstance(value, ast.Dict):
            values.extend(_dict_keyword_values(value, name, constants))
    return values


def _dict_keyword_values(node: ast.Dict, name: str, constants: dict[str, ast.AST]) -> list[ast.AST]:
    values: list[ast.AST] = []
    for key, item_value in zip(node.keys, node.values, strict=False):
        if key is None:
            value = _resolve_constant(item_value, constants)
            if isinstance(value, ast.Dict):
                values.extend(_dict_keyword_values(value, name, constants))
            continue
        resolved_key = _resolve_constant(key, constants)
        if isinstance(resolved_key, ast.Constant) and resolved_key.value == name:
            values.append(item_value)
    return values


def _mark_target_names(target: ast.AST, names: set[str]) -> None:
    if isinstance(target, ast.Name):
        names.add(target.id)
    elif isinstance(target, ast.Tuple | ast.List):
        for element in target.elts:
            _mark_target_names(element, names)
    elif isinstance(target, ast.Starred):
        _mark_target_names(target.value, names)


def _line_for(content: str, needle: str) -> int:
    index = content.find(needle)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov"})


def findings_to_json(findings: list[AutomationFinding]) -> list[dict[str, Any]]:
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
