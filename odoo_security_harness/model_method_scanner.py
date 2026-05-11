"""Scanner for risky Odoo model method behavior."""

from __future__ import annotations

import ast
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ModelMethodFinding:
    """Represents a risky model-method finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    method: str = ""


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
SUDO_MUTATION_RULES = {
    "onchange": "odoo-model-method-onchange-sudo-mutation",
    "compute": "odoo-model-method-compute-sudo-mutation",
    "constraint": "odoo-model-method-constraint-sudo-mutation",
    "inverse": "odoo-model-method-inverse-sudo-mutation",
}
SENSITIVE_MODEL_MUTATION_RULES = {
    "onchange": "odoo-model-method-onchange-sensitive-model-mutation",
    "compute": "odoo-model-method-compute-sensitive-model-mutation",
    "constraint": "odoo-model-method-constraint-sensitive-model-mutation",
    "inverse": "odoo-model-method-inverse-sensitive-model-mutation",
}
HTTP_NO_TIMEOUT_RULES = {
    "onchange": "odoo-model-method-onchange-http-no-timeout",
    "compute": "odoo-model-method-compute-http-no-timeout",
    "constraint": "odoo-model-method-constraint-http-no-timeout",
    "inverse": "odoo-model-method-inverse-http-no-timeout",
}
TLS_VERIFY_DISABLED_RULES = {
    "onchange": "odoo-model-method-onchange-tls-verify-disabled",
    "compute": "odoo-model-method-compute-tls-verify-disabled",
    "constraint": "odoo-model-method-constraint-tls-verify-disabled",
    "inverse": "odoo-model-method-inverse-tls-verify-disabled",
}
API_METHOD_DECORATORS = {"constrains", "depends", "onchange"}


def scan_model_methods(repo_path: Path) -> list[ModelMethodFinding]:
    """Scan Odoo model methods for risky side effects and dynamic behavior."""
    findings: list[ModelMethodFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(ModelMethodScanner(path).scan_file())
    return findings


class ModelMethodScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[ModelMethodFinding] = []
        self.model_stack: list[str] = []
        self.method_stack: list[MethodContext] = []
        self.http_modules = {"aiohttp", "requests", "httpx", "urllib"}
        self.http_functions: set[str] = set()
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.api_module_names: set[str] = {"api"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.api_decorator_names: dict[str, str] = {}
        self.dynamic_eval_names: set[str] = {"eval", "exec", "safe_eval"}
        self.superuser_names: set[str] = {"SUPERUSER_ID"}

    def scan_file(self) -> list[ModelMethodFinding]:
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
                self.http_modules.add(alias.asname or alias.name)
            elif alias.name == "urllib.request":
                self.http_modules.add(alias.asname or "urllib")
            elif alias.name == "odoo":
                self.odoo_module_names.add(alias.asname or alias.name)
            elif alias.name == "odoo.api":
                if alias.asname:
                    self.api_module_names.add(alias.asname)
                else:
                    self.odoo_module_names.add("odoo")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module in {"aiohttp", "requests", "httpx", "urllib.request"}:
            for alias in node.names:
                if alias.name in HTTP_METHODS:
                    self.http_functions.add(alias.asname or alias.name)
        elif node.module == "urllib":
            for alias in node.names:
                if alias.name == "request":
                    self.http_modules.add(alias.asname or alias.name)
        elif node.module == "odoo":
            for alias in node.names:
                if alias.name == "api":
                    self.api_module_names.add(alias.asname or alias.name)
                elif alias.name == "SUPERUSER_ID":
                    self.superuser_names.add(alias.asname or alias.name)
        elif node.module == "odoo.api":
            for alias in node.names:
                if alias.name in API_METHOD_DECORATORS:
                    self.api_decorator_names[alias.asname or alias.name] = alias.name
        elif node.module == "odoo.tools.safe_eval":
            for alias in node.names:
                if alias.name == "safe_eval":
                    self.dynamic_eval_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        if not _is_odoo_model(node):
            self.generic_visit(node)
            return
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.model_stack.append(_extract_model_name(node, self._effective_constants()))
        self.generic_visit(node)
        self.model_stack.pop()
        self.class_constants_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        if not self.model_stack:
            self.generic_visit(node)
            return
        context = MethodContext(
            name=node.name,
            kind=_method_kind(
                node,
                self.api_module_names,
                self.odoo_module_names,
                self.api_decorator_names,
            ),
        )
        self.method_stack.append(context)
        self.generic_visit(node)
        self.method_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        if self.method_stack:
            context = self.method_stack[-1]
            for target in node.targets:
                self._track_alias(
                    target,
                    node.value,
                    context.sudo_vars,
                    lambda value: _is_sudo_expr(
                        value, context.sudo_vars, self._effective_constants(), self.superuser_names
                    ),
                )
                self._track_alias(
                    target,
                    node.value,
                    context.http_client_vars,
                    lambda value: _is_http_client_expr(value, self.http_modules, context.http_client_vars),
                )
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if self.method_stack and node.value is not None:
            context = self.method_stack[-1]
            self._track_alias(
                node.target,
                node.value,
                context.sudo_vars,
                lambda value: _is_sudo_expr(
                    value, context.sudo_vars, self._effective_constants(), self.superuser_names
                ),
            )
            self._track_alias(
                node.target,
                node.value,
                context.http_client_vars,
                lambda value: _is_http_client_expr(value, self.http_modules, context.http_client_vars),
            )
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        if self.method_stack:
            context = self.method_stack[-1]
            self._track_alias(
                node.target,
                node.value,
                context.sudo_vars,
                lambda value: _is_sudo_expr(
                    value, context.sudo_vars, self._effective_constants(), self.superuser_names
                ),
            )
            self._track_alias(
                node.target,
                node.value,
                context.http_client_vars,
                lambda value: _is_http_client_expr(value, self.http_modules, context.http_client_vars),
            )
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> Any:
        if self.method_stack:
            context = self.method_stack[-1]
            for item in node.items:
                if item.optional_vars is not None:
                    self._track_alias(
                        item.optional_vars,
                        item.context_expr,
                        context.http_client_vars,
                        lambda value: _is_http_client_expr(value, self.http_modules, context.http_client_vars),
                    )
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> Any:
        self.visit_With(node)

    def _track_alias(
        self,
        target: ast.expr,
        value: ast.AST,
        aliases: set[str],
        predicate: Callable[[ast.AST], bool],
    ) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for child_target, child_value in _unpack_target_value_pairs(target.elts, value.elts):
                self._track_alias(child_target, child_value, aliases, predicate)
            return
        if isinstance(target, ast.Tuple | ast.List):
            for child_target in target.elts:
                self._track_alias(child_target, value, aliases, predicate)
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

    def visit_Call(self, node: ast.Call) -> Any:
        if not self.method_stack:
            self.generic_visit(node)
            return

        context = self.method_stack[-1]
        if not context.kind:
            self.generic_visit(node)
            return

        sink = _call_name(node.func)
        if _is_dynamic_eval(sink, self.dynamic_eval_names):
            self._add(
                "odoo-model-method-dynamic-eval",
                "Odoo model method performs dynamic evaluation",
                "critical",
                node.lineno,
                f"{context.kind} model method calls eval/exec/safe_eval; verify no record field or context value can control evaluated code",
                context.name,
            )
        sensitive_model = _call_receiver_sensitive_model(node.func, self._effective_constants())
        if sensitive_model and sink.rsplit(".", 1)[-1] in SENSITIVE_MODEL_MUTATION_METHODS:
            self._add(
                SENSITIVE_MODEL_MUTATION_RULES[context.kind],
                "Odoo model method mutates sensitive model",
                "high",
                node.lineno,
                f"{context.kind} model method mutates sensitive model '{sensitive_model}'; verify lifecycle side effects, caller access, and audit trail",
                context.name,
            )
        elif _is_privileged_mutation(node.func, context.sudo_vars, self._effective_constants(), self.superuser_names):
            self._add(
                SUDO_MUTATION_RULES[context.kind],
                "Odoo model method performs elevated mutation",
                "high",
                node.lineno,
                f"{context.kind} model method mutates records through sudo()/with_user(SUPERUSER_ID); verify record rules, company isolation, and form-triggered side effects",
                context.name,
            )
        elif _is_http_call(sink, self.http_modules, self.http_functions) or _is_http_client_call(
            node.func, context.http_client_vars
        ):
            constants = self._effective_constants()
            if not _has_effective_timeout(node, constants):
                self._add(
                    HTTP_NO_TIMEOUT_RULES[context.kind],
                    "Odoo model method performs HTTP without timeout",
                    "medium",
                    node.lineno,
                    f"{context.kind} model method performs outbound HTTP without timeout; form/render/background flows can block Odoo workers",
                    context.name,
                )
            if _keyword_is_false(node, "verify", constants):
                self._add(
                    TLS_VERIFY_DISABLED_RULES[context.kind],
                    "Odoo model method disables TLS verification",
                    "high",
                    node.lineno,
                    f"{context.kind} model method passes verify=False to outbound HTTP; user-triggered integrations should not permit man-in-the-middle attacks",
                    context.name,
                )

        self.generic_visit(node)

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, method: str) -> None:
        self.findings.append(
            ModelMethodFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                model=self.model_stack[-1] if self.model_stack else "",
                method=method,
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
class MethodContext:
    """Current model-method context."""

    name: str
    kind: str = ""
    sudo_vars: set[str] = None  # type: ignore[assignment]
    http_client_vars: set[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.sudo_vars is None:
            self.sudo_vars = set()
        if self.http_client_vars is None:
            self.http_client_vars = set()


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


def _method_kind(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    api_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
    api_decorator_names: dict[str, str] | None = None,
) -> str:
    api_module_names = api_module_names or {"api"}
    odoo_module_names = odoo_module_names or {"odoo"}
    api_decorator_names = api_decorator_names or {}
    decorators = {
        _api_decorator_kind(decorator, api_module_names, odoo_module_names, api_decorator_names)
        for decorator in node.decorator_list
    }
    if "onchange" in decorators or node.name.startswith("_onchange"):
        return "onchange"
    if "depends" in decorators or node.name.startswith("_compute"):
        return "compute"
    if "constrains" in decorators or node.name.startswith("_check"):
        return "constraint"
    if node.name.startswith("_inverse"):
        return "inverse"
    return ""


def _api_decorator_kind(
    node: ast.AST,
    api_module_names: set[str],
    odoo_module_names: set[str],
    api_decorator_names: dict[str, str],
) -> str:
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        if node.id in API_METHOD_DECORATORS:
            return node.id
        return api_decorator_names.get(node.id, "")
    if isinstance(node, ast.Attribute) and node.attr in API_METHOD_DECORATORS:
        if _is_odoo_api_module_expr(node.value, api_module_names, odoo_module_names):
            return node.attr
    return ""


def _is_odoo_api_module_expr(
    node: ast.AST,
    api_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in api_module_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "api"
        and isinstance(node.value, ast.Name)
        and node.value.id in odoo_module_names
    )


def _is_privileged_mutation(
    node: ast.AST,
    sudo_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    sink = _call_name(node)
    if sink.rsplit(".", 1)[-1] not in MUTATION_METHODS:
        return False
    return _is_sudo_expr(node, sudo_vars, constants, superuser_names)


def _is_sudo_expr(
    node: ast.AST,
    sudo_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    constants = constants or {}
    if isinstance(node, ast.Starred):
        return _is_sudo_expr(node.value, sudo_vars, constants, superuser_names)
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return any(_is_sudo_expr(element, sudo_vars, constants, superuser_names) for element in node.elts)
    return (
        _call_chain_has_attr(node, "sudo")
        or _call_chain_has_superuser_with_user(node, constants, superuser_names)
        or _call_root_name(node) in sudo_vars
    )


def _is_dynamic_eval(sink: str, dynamic_eval_names: set[str] | None = None) -> bool:
    dynamic_eval_names = dynamic_eval_names or {"eval", "exec", "safe_eval"}
    return sink in dynamic_eval_names or sink.endswith(".safe_eval")


def _is_http_call(sink: str, http_modules: set[str], http_functions: set[str]) -> bool:
    if sink in http_functions:
        return True
    parts = sink.split(".")
    return len(parts) >= 2 and parts[0] in http_modules and parts[-1] in HTTP_METHODS


def _is_http_client_factory(node: ast.AST, http_modules: set[str]) -> bool:
    sink = _call_name(node.func) if isinstance(node, ast.Call) else _call_name(node)
    parts = sink.split(".")
    return len(parts) >= 2 and parts[0] in http_modules and parts[-1] in HTTP_CLIENT_FACTORIES


def _is_http_client_expr(node: ast.AST, http_modules: set[str], http_client_vars: set[str]) -> bool:
    if isinstance(node, ast.Starred):
        return _is_http_client_expr(node.value, http_modules, http_client_vars)
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return any(_is_http_client_expr(element, http_modules, http_client_vars) for element in node.elts)
    return _is_http_client_factory(node, http_modules) or _call_root_name(node) in http_client_vars


def _is_http_client_call(node: ast.AST, http_client_vars: set[str]) -> bool:
    sink = _call_name(node)
    parts = sink.split(".")
    return len(parts) == 2 and _call_root_name(node) in http_client_vars and parts[-1] in HTTP_METHODS


def _call_receiver_sensitive_model(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> str | None:
    if not isinstance(node, ast.Attribute):
        return None
    current: ast.AST = node.value
    while isinstance(current, ast.Call | ast.Attribute):
        if isinstance(current, ast.Call):
            current = current.func
        else:
            current = current.value
    if not isinstance(current, ast.Subscript):
        return None
    model_name = _literal_subscript_key(current, constants)
    if model_name in SENSITIVE_MUTATION_MODELS and _call_name(current.value).endswith("env"):
        return model_name
    return None


def _literal_subscript_key(node: ast.Subscript, constants: dict[str, ast.AST] | None = None) -> str | None:
    key = _resolve_constant(node.slice, constants or {})
    if isinstance(key, ast.Constant) and isinstance(key.value, str):
        return key.value
    return None


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
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
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


def _call_chain_has_superuser_with_user(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    constants = constants or {}
    if isinstance(node, ast.Starred):
        return _call_chain_has_superuser_with_user(node.value, constants, superuser_names)
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return any(_call_chain_has_superuser_with_user(element, constants, superuser_names) for element in node.elts)
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
    superuser_names = superuser_names or {"SUPERUSER_ID"}
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant):
        return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
    if isinstance(node, ast.Name):
        return node.id in superuser_names
    if isinstance(node, ast.Attribute):
        return node.attr == "SUPERUSER_ID"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
        return any(_is_superuser_arg(arg, constants, superuser_names) for arg in node.args)
    return False


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
        resolved = constants.get(node.id)
        if resolved is None:
            return node
        return _resolve_constant_seen(resolved, constants, {*seen, node.id})
    return node


def _is_static_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Dict):
        return all(
            (key is None or _is_static_literal(key)) and _is_static_literal(value)
            for key, value in zip(node.keys, node.values, strict=False)
            if value is not None
        )
    return isinstance(node, ast.Constant) and isinstance(node.value, str | bool | int | float | type(None))


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[ModelMethodFinding]) -> list[dict[str, Any]]:
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
            "method": f.method,
        }
        for f in findings
    ]
