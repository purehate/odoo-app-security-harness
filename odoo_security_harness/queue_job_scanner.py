"""Scanner for risky Odoo queue_job and delayed-job usage."""

from __future__ import annotations

import ast
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class QueueJobFinding:
    """Represents a queue/delayed-job finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    job: str = ""


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "request", "urlopen"}
HTTP_CLIENT_FACTORIES = {"AsyncClient", "Client", "ClientSession", "Session"}
MUTATION_METHODS = {"write", "create", "unlink"}
SENSITIVE_MODEL_MUTATION_METHODS = {*MUTATION_METHODS, "set", "set_param"}
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


def scan_queue_jobs(repo_path: Path) -> list[QueueJobFinding]:
    """Scan Python files for risky queue_job/delayed-job patterns."""
    findings: list[QueueJobFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(QueueJobScanner(path).scan_file())
    return findings


class QueueJobScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[QueueJobFinding] = []
        self.function_stack: list[FunctionContext] = []
        self.http_module_aliases: set[str] = {"aiohttp", "requests", "httpx", "urllib.request"}
        self.http_function_aliases: set[str] = set()
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.job_decorator_names: set[str] = {"job"}
        self.route_decorator_names: set[str] = {"route"}

    def scan_file(self) -> list[QueueJobFinding]:
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
        elif node.module == "odoo.addons.queue_job.job":
            for alias in node.names:
                if alias.name == "job":
                    self.job_decorator_names.add(alias.asname or alias.name)
        elif node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "route":
                    self.route_decorator_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        context = FunctionContext(
            name=node.name,
            is_job=_is_job_function(node, self.job_decorator_names),
            route_auth=_route_auth(node, self._effective_constants(), self.route_decorator_names),
        )
        self.function_stack.append(context)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> Any:
        current = self.function_stack[-1] if self.function_stack else None
        if current:
            for target in node.targets:
                self._record_alias_target(target, node.value, current)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        current = self.function_stack[-1] if self.function_stack else None
        if current and node.value is not None:
            self._record_alias_target(node.target, node.value, current)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        current = self.function_stack[-1] if self.function_stack else None
        if current:
            self._record_alias_target(node.target, node.value, current)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> Any:
        current = self.function_stack[-1] if self.function_stack else None
        if current:
            for item in node.items:
                if item.optional_vars is not None:
                    self._track_alias(
                        item.optional_vars,
                        item.context_expr,
                        current.http_client_vars,
                        lambda value: _is_http_client_expr(value, self.http_module_aliases)
                        or _call_root_name(value) in current.http_client_vars,
                    )
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> Any:
        self.visit_With(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        current = self.function_stack[-1] if self.function_stack else None

        if _is_enqueue_call(node.func):
            if not _enqueue_has_keyword(node, "identity_key"):
                self._add(
                    "odoo-queue-job-missing-identity-key",
                    "Delayed job enqueue lacks identity key",
                    "medium",
                    node.lineno,
                    "with_delay/delayable enqueue has no identity_key; repeated requests can create duplicate background jobs and side effects",
                    current.name if current else sink,
                )
            if current and current.route_auth in {"public", "none"}:
                self._add(
                    "odoo-queue-job-public-enqueue",
                    "Public route enqueues background job",
                    "high",
                    node.lineno,
                    f"auth='{current.route_auth}' route enqueues a delayed job; verify authentication, CSRF, throttling, and idempotency",
                    current.name,
                )

        if current and current.is_job:
            constants = self._effective_constants()
            if _is_sudo_mutation(node.func, current.sudo_vars, constants):
                self._add(
                    "odoo-queue-job-sudo-mutation",
                    "Queue job performs elevated mutation",
                    "high",
                    node.lineno,
                    "queue_job/delayed job mutates records through sudo()/with_user(SUPERUSER_ID); verify record rules, company isolation, and job input trust boundaries",
                    current.name,
                )
            elif sink.rsplit(".", 1)[-1] in SENSITIVE_MODEL_MUTATION_METHODS:
                sensitive_model = _call_receiver_sensitive_model(node, constants)
                if sensitive_model:
                    self._add(
                        "odoo-queue-job-sensitive-model-mutation",
                        "Queue job mutates sensitive model",
                        "high",
                        node.lineno,
                        f"queue_job/delayed job mutates sensitive model '{sensitive_model}'; verify job input trust, retry idempotency, and audit trail",
                        current.name,
                    )
            elif _is_dynamic_eval(sink):
                self._add(
                    "odoo-queue-job-dynamic-eval",
                    "Queue job performs dynamic evaluation",
                    "critical",
                    node.lineno,
                    "queue_job/delayed job calls eval/exec/safe_eval; verify no queued payload or record field can control evaluated code",
                    current.name,
                )
            elif _is_http_call(
                node.func, self.http_module_aliases, self.http_function_aliases, current.http_client_vars
            ):
                if not _has_effective_timeout(node, self._effective_constants()):
                    self._add(
                        "odoo-queue-job-http-no-timeout",
                        "Queue job performs HTTP without timeout",
                        "medium",
                        node.lineno,
                        "queue_job/delayed job performs outbound HTTP without timeout; slow upstreams can exhaust workers or stall job channels",
                        current.name,
                    )
                if _keyword_is_false(node, "verify", constants):
                    self._add(
                        "odoo-queue-job-tls-verify-disabled",
                        "Queue job disables TLS verification",
                        "high",
                        node.lineno,
                        "queue_job/delayed job passes verify=False to outbound HTTP; background integrations should not permit man-in-the-middle attacks",
                        current.name,
                    )

        self.generic_visit(node)

    def _record_alias_target(self, target: ast.AST, value: ast.AST, context: FunctionContext) -> None:
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

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, job: str) -> None:
        self.findings.append(
            QueueJobFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                job=job,
            )
        )


@dataclass
class FunctionContext:
    """Current function context."""

    name: str
    is_job: bool
    route_auth: str = ""
    sudo_vars: set[str] = None  # type: ignore[assignment]
    http_client_vars: set[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.sudo_vars is None:
            self.sudo_vars = set()
        if self.http_client_vars is None:
            self.http_client_vars = set()


def _is_job_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    job_decorator_names: set[str] | None = None,
) -> bool:
    job_decorator_names = job_decorator_names or {"job"}
    if any(_is_job_decorator(decorator, job_decorator_names) for decorator in node.decorator_list):
        return True
    return node.name.startswith(("_job_", "job_")) or "queue" in node.name.lower()


def _route_auth(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    constants: dict[str, ast.AST] | None = None,
    route_decorator_names: set[str] | None = None,
) -> str:
    constants = constants or {}
    route_decorator_names = route_decorator_names or {"route"}
    for decorator in node.decorator_list:
        if not _is_route_decorator(decorator, route_decorator_names):
            continue
        call = decorator if isinstance(decorator, ast.Call) else None
        if not call:
            continue
        for name, keyword_value in _expanded_keywords(call, constants):
            value = _resolve_constant(keyword_value, constants)
            if name == "auth" and isinstance(value, ast.Constant):
                return str(value.value)
    return ""


def _is_job_decorator(node: ast.AST, job_decorator_names: set[str]) -> bool:
    name = _decorator_name(node)
    return name in job_decorator_names or name.endswith(".job")


def _is_route_decorator(node: ast.AST, route_decorator_names: set[str]) -> bool:
    name = _decorator_name(node)
    return name in route_decorator_names or name.endswith(".route")


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
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(_is_static_literal(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        keys = [key for key in node.keys if key is not None]
        return all(_is_static_literal(key) for key in keys) and all(
            _is_static_literal(value) for value in node.values
        )
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd | ast.USub):
        return _is_static_literal(node.operand)
    return False


def _is_enqueue_call(node: ast.AST) -> bool:
    sink = _call_name(node)
    if sink.endswith(".with_delay") or sink.endswith(".delayable") or sink in {"with_delay", "delayable"}:
        return True
    return _call_chain_has_attr(node, "with_delay") or _call_chain_has_attr(node, "delayable")


def _is_sudo_mutation(
    node: ast.AST,
    sudo_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    sink = _call_name(node)
    if sink.rsplit(".", 1)[-1] not in MUTATION_METHODS:
        return False
    return _is_sudo_expr(node, sudo_vars, constants)


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


def _is_dynamic_eval(sink: str) -> bool:
    return sink in {"eval", "exec", "safe_eval"} or sink.endswith(".safe_eval")


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


def _is_sudo_expr(
    node: ast.AST,
    sudo_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
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


def _decorator_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return _call_name(node)


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


def _call_chain_has_superuser_with_user(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    if isinstance(node, ast.Starred):
        return _call_chain_has_superuser_with_user(node.value, constants)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_call_chain_has_superuser_with_user(element, constants) for element in node.elts)
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Call):
            if (
                isinstance(current.func, ast.Attribute)
                and current.func.attr == "with_user"
                and (
                    any(_is_superuser_arg(arg, constants) for arg in current.args)
                    or any(
                        keyword.arg in {"user", "uid"}
                        and keyword.value is not None
                        and _is_superuser_arg(keyword.value, constants)
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


def _is_superuser_arg(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
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


def _mark_target_names(target: ast.AST, names: set[str]) -> None:
    if isinstance(target, ast.Name):
        names.add(target.id)
    elif isinstance(target, ast.Tuple | ast.List):
        for element in target.elts:
            _mark_target_names(element, names)
    elif isinstance(target, ast.Starred):
        _mark_target_names(target.value, names)


def _has_keyword(node: ast.Call, name: str) -> bool:
    return any(keyword.arg == name for keyword in node.keywords)


def _has_effective_timeout(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    for name, keyword_value in _expanded_keywords(node, constants):
        if name != "timeout":
            continue
        value = _resolve_constant(keyword_value, constants)
        return not _is_none_constant(value)
    return False


def _is_none_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _keyword_is_false(node: ast.Call, name: str, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    for keyword_name, keyword_value in _expanded_keywords(node, constants):
        if keyword_name != name:
            continue
        value = _resolve_constant(keyword_value, constants)
        if isinstance(value, ast.Constant) and value.value is False:
            return True
    return False


def _enqueue_has_keyword(node: ast.Call, name: str) -> bool:
    if _has_keyword(node, name):
        return True
    current: ast.AST | None = node.func
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Call):
            if _has_keyword(current, name) and _is_enqueue_call(current.func):
                return True
            current = current.func
        elif isinstance(current, ast.Attribute):
            current = current.value
        else:
            current = current.value
    return False


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[QueueJobFinding]) -> list[dict[str, Any]]:
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
        }
        for f in findings
    ]
