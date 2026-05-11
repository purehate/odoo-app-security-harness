"""Scanner for risky Odoo scheduled-job Python methods."""

from __future__ import annotations

import ast
import re
from collections.abc import Callable
from csv import DictReader
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

from defusedxml import ElementTree


@dataclass
class ScheduledJobFinding:
    """Represents a scheduled-job security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    job: str = ""
    sink: str = ""


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "request", "urlopen"}
HTTP_CLIENT_FACTORIES = {"AsyncClient", "Client", "ClientSession", "Session"}
MUTATION_METHODS = {"create", "write", "unlink"}
SENSITIVE_MODEL_MUTATION_METHODS = {*MUTATION_METHODS, "set", "set_param"}
UNBOUNDED_READ_METHODS = {"read_group", "search", "search_count", "search_read"}
SYNC_NAME_RE = re.compile(r"(^|_)(fetch|sync|import|pull|callback|callbacks|webhook|feed|export)($|_)", re.IGNORECASE)
SENSITIVE_MUTATION_MODELS = {
    "account.move",
    "ir.attachment",
    "ir.config_parameter",
    "ir.cron",
    "ir.model.access",
    "ir.rule",
    "payment.provider",
    "payment.transaction",
    "res.groups",
    "res.users",
    "res.users.apikeys",
}


def scan_scheduled_jobs(repo_path: Path) -> list[ScheduledJobFinding]:
    """Scan cron-linked and cron-named Python methods for risky behavior."""
    cron_methods = _collect_cron_methods(repo_path)
    findings: list[ScheduledJobFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(ScheduledJobScanner(path, cron_methods).scan_file())
    return findings


class ScheduledJobScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path, cron_methods: set[str]) -> None:
        self.path = path
        self.cron_methods = cron_methods
        self.findings: list[ScheduledJobFinding] = []
        self.function_stack: list[JobContext] = []
        self.http_module_aliases: set[str] = {"aiohttp", "requests", "httpx", "urllib.request"}
        self.http_function_aliases: set[str] = set()
        self.dynamic_eval_names: set[str] = {"eval", "exec", "safe_eval"}
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []

    def scan_file(self) -> list[ScheduledJobFinding]:
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
            if alias.name in {"aiohttp", "requests", "httpx"}:
                self.http_module_aliases.add(alias.asname or alias.name)
            elif alias.name == "urllib.request":
                self.http_module_aliases.add(alias.asname or alias.name)
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
        elif node.module == "odoo.tools.safe_eval":
            for alias in node.names:
                if alias.name == "safe_eval":
                    self.dynamic_eval_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        context = JobContext(name=node.name, is_scheduled=_is_scheduled_method(node.name, self.cron_methods))
        self.function_stack.append(context)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        context = self.function_stack[-1] if self.function_stack else None
        if context and context.is_scheduled:
            for target in node.targets:
                self._record_alias_target(target, node.value, context)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        context = self.function_stack[-1] if self.function_stack else None
        if context and context.is_scheduled and node.value is not None:
            self._record_alias_target(node.target, node.value, context)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        context = self.function_stack[-1] if self.function_stack else None
        if context and context.is_scheduled:
            self._record_alias_target(node.target, node.value, context)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> Any:
        context = self.function_stack[-1] if self.function_stack else None
        if context and context.is_scheduled:
            for item in node.items:
                if item.optional_vars is not None:
                    self._track_alias(
                        item.optional_vars,
                        item.context_expr,
                        context.http_client_vars,
                        lambda value: _is_http_client_expr(value, self.http_module_aliases)
                        or _call_root_name(value) in context.http_client_vars,
                    )
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> Any:
        self.visit_With(node)

    def visit_Call(self, node: ast.Call) -> Any:
        context = self.function_stack[-1] if self.function_stack else None
        if not context or not context.is_scheduled:
            self.generic_visit(node)
            return

        sink = _call_name(node.func)
        method = sink.rsplit(".", 1)[-1]
        constants = self._effective_constants()

        if _is_sudo_mutation(node.func, context.sudo_vars, constants):
            self._add(
                "odoo-scheduled-job-sudo-mutation",
                "Scheduled job performs elevated mutation",
                "high",
                node.lineno,
                "Scheduled job mutates records through sudo()/with_user(SUPERUSER_ID); verify record rules, company isolation, input trust, and retry idempotency",
                context.name,
                sink,
            )
        elif method in SENSITIVE_MODEL_MUTATION_METHODS:
            sensitive_model = _call_receiver_sensitive_model(node, constants)
            if sensitive_model:
                self._add(
                    "odoo-scheduled-job-sensitive-model-mutation",
                    "Scheduled job mutates sensitive model",
                    "high",
                    node.lineno,
                    f"Scheduled job mutates sensitive model '{sensitive_model}'; verify the cron user, domain scope, idempotency, and audit trail",
                    context.name,
                    sink,
                )
        elif _is_dynamic_eval(sink, self.dynamic_eval_names):
            self._add(
                "odoo-scheduled-job-dynamic-eval",
                "Scheduled job performs dynamic evaluation",
                "critical",
                node.lineno,
                "Scheduled job calls eval/exec/safe_eval; verify no synchronized data, records, or config values can control evaluated code",
                context.name,
                sink,
            )
        elif _is_manual_transaction(sink):
            self._add(
                "odoo-scheduled-job-manual-transaction",
                "Scheduled job controls transactions manually",
                "medium",
                node.lineno,
                "Scheduled job calls commit()/rollback(); verify partial progress, retry behavior, and security state cannot become inconsistent",
                context.name,
                sink,
            )
        elif method in UNBOUNDED_READ_METHODS and _is_empty_domain_call(node):
            severity = "medium" if _is_sudo_expr(node.func, context.sudo_vars, constants) else "low"
            self._add(
                "odoo-scheduled-job-unbounded-search",
                "Scheduled job performs unbounded ORM search",
                severity,
                node.lineno,
                "Scheduled job searches with an empty domain and no visible limit; verify batching, locking, company scoping, and idempotency",
                context.name,
                sink,
            )

        if _is_http_call(node.func, self.http_module_aliases, self.http_function_aliases, context.http_client_vars):
            if not _has_effective_timeout(node, constants):
                self._add(
                    "odoo-scheduled-job-http-no-timeout",
                    "Scheduled job performs HTTP without timeout",
                    "medium",
                    node.lineno,
                    "Scheduled job performs outbound HTTP without timeout; slow upstreams can exhaust cron workers and cause repeated overlap",
                    context.name,
                    sink,
                )
            if _keyword_is_false(node, "verify", constants):
                self._add(
                    "odoo-scheduled-job-tls-verify-disabled",
                    "Scheduled job disables TLS verification",
                    "high",
                    node.lineno,
                    "Scheduled job passes verify=False to outbound HTTP; recurring integrations should not permit man-in-the-middle attacks",
                    context.name,
                    sink,
                )

        if (
            method in UNBOUNDED_READ_METHODS
            and SYNC_NAME_RE.search(context.name)
            and not _has_keyword(node, "limit")
        ):
            self._add(
                "odoo-scheduled-job-sync-without-limit",
                "External-sync scheduled job lacks visible batch limit",
                "low",
                node.lineno,
                "Scheduled sync/import/fetch job searches without a visible limit; verify batching, locking, timeout, and retry behavior",
                context.name,
                sink,
            )

        self.generic_visit(node)

    def _record_alias_target(self, target: ast.AST, value: ast.AST, context: JobContext) -> None:
        self._track_alias(
            target,
            value,
            context.sudo_vars,
            lambda node: _is_sudo_expr(node, context.sudo_vars, self._effective_constants()),
        )
        self._track_alias(
            target,
            value,
            context.http_client_vars,
            lambda node: _is_http_client_expr(node, self.http_module_aliases)
            or _call_root_name(node) in context.http_client_vars,
        )

    def _track_alias(
        self,
        target: ast.AST,
        value: ast.AST,
        aliases: set[str],
        predicate: Callable[[ast.AST], bool],
    ) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
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

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        job: str,
        sink: str,
    ) -> None:
        self.findings.append(
            ScheduledJobFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                job=job,
                sink=sink,
            )
        )

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants


@dataclass
class JobContext:
    """Current function context."""

    name: str
    is_scheduled: bool
    sudo_vars: set[str] = None  # type: ignore[assignment]
    http_client_vars: set[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.sudo_vars is None:
            self.sudo_vars = set()
        if self.http_client_vars is None:
            self.http_client_vars = set()


def _collect_cron_methods(repo_path: Path) -> set[str]:
    methods: set[str] = set()
    for path in repo_path.rglob("*.xml"):
        if _should_skip(path):
            continue
        try:
            root = ElementTree.fromstring(path.read_text(encoding="utf-8", errors="replace"))
        except ElementTree.ParseError:
            continue
        except Exception:  # noqa: S112
            continue
        for record in root.iter("record"):
            if record.get("model") != "ir.cron":
                continue
            fields = _record_fields(record)
            for name in ("function", "method_direct_trigger"):
                value = fields.get(name, "")
                if _is_identifier(value):
                    methods.add(value)
            code = fields.get("code", "")
            methods.update(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", code))
    for path in repo_path.rglob("*.csv"):
        if _should_skip(path) or _csv_model_name(path) != "ir.cron":
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: S112
            continue
        for fields in _csv_dict_rows(content):
            for name in ("function", "method_direct_trigger"):
                value = fields.get(name, "")
                if _is_identifier(value):
                    methods.add(value)
            code = fields.get("code", "")
            methods.update(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", code))
    return methods


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
        "ir_cron": "ir.cron",
        "ir.cron": "ir.cron",
    }
    return aliases.get(stem, stem.replace("_", "."))


def _csv_dict_rows(content: str) -> list[dict[str, str]]:
    try:
        reader = DictReader(StringIO(content))
    except Exception:
        return []
    if not reader.fieldnames:
        return []

    rows: list[dict[str, str]] = []
    try:
        for row in reader:
            normalized: dict[str, str] = {}
            for key, value in row.items():
                if key is None:
                    continue
                name = str(key).strip().lower()
                text = str(value or "").strip()
                normalized[name] = text
                if "/" in name:
                    normalized.setdefault(name.split("/", 1)[0], text)
            rows.append(normalized)
    except Exception:
        return []
    return rows


def _is_scheduled_method(name: str, cron_methods: set[str]) -> bool:
    lowered = name.lower()
    return name in cron_methods or lowered.startswith(("_cron", "cron_")) or "_cron_" in lowered


def _is_sudo_mutation(
    node: ast.AST,
    sudo_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    sink = _call_name(node)
    if sink.rsplit(".", 1)[-1] not in MUTATION_METHODS:
        return False
    return _is_sudo_expr(node, sudo_vars, constants)


def _is_sudo_expr(node: ast.AST, sudo_vars: set[str], constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
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
    constants = constants or {}
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
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant):
        return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
    if isinstance(node, ast.Name):
        return node.id == "SUPERUSER_ID"
    if isinstance(node, ast.Attribute):
        return node.attr == "SUPERUSER_ID"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
        return any(_is_superuser_arg(arg, constants) for arg in node.args)
    return False


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


def _is_dynamic_eval(sink: str, dynamic_eval_names: set[str] | None = None) -> bool:
    dynamic_eval_names = dynamic_eval_names or {"eval", "exec", "safe_eval"}
    return sink in dynamic_eval_names or sink.endswith(".safe_eval")


def _is_manual_transaction(sink: str) -> bool:
    return sink.endswith(".commit") or sink.endswith(".rollback")


def _is_empty_domain_call(node: ast.Call) -> bool:
    if not node.args or not isinstance(node.args[0], ast.List):
        return False
    return not node.args[0].elts and not _has_keyword(node, "limit")


def _call_receiver_sensitive_model(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> str:
    if not isinstance(node.func, ast.Attribute):
        return ""
    model_name = _env_subscript_model(node.func.value, constants or {})
    if model_name in SENSITIVE_MUTATION_MODELS:
        return model_name
    receiver = _safe_unparse(node.func.value)
    for model in SENSITIVE_MUTATION_MODELS:
        if f"'{model}'" in receiver or f'"{model}"' in receiver:
            return model
    return ""


def _env_subscript_model(node: ast.AST, constants: dict[str, ast.AST]) -> str:
    current = node
    while isinstance(current, ast.Call | ast.Attribute):
        if isinstance(current, ast.Call):
            current = current.func
        else:
            current = current.value
    if not isinstance(current, ast.Subscript):
        return ""
    key = _resolve_constant(current.slice, constants)
    if isinstance(key, ast.Constant) and isinstance(key.value, str) and _call_name(current.value).endswith("env"):
        return key.value
    return ""


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


def _is_identifier(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value.strip()))


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


def _mark_target_names(target: ast.AST, names: set[str]) -> None:
    if isinstance(target, ast.Name):
        names.add(target.id)
    elif isinstance(target, ast.Tuple | ast.List):
        for element in target.elts:
            _mark_target_names(element, names)
    elif isinstance(target, ast.Starred):
        _mark_target_names(target.value, names)


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[ScheduledJobFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "job": f.job,
            "sink": f.sink,
        }
        for f in findings
    ]
