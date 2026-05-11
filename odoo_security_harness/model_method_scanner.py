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


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "request", "urlopen"}
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
        self.http_modules = {"requests", "httpx", "urllib"}
        self.http_functions: set[str] = set()
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []

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
            if alias.name in {"requests", "httpx"}:
                self.http_modules.add(alias.asname or alias.name)
            elif alias.name == "urllib.request":
                self.http_modules.add(alias.asname or "urllib")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module not in {"requests", "httpx", "urllib.request"}:
            self.generic_visit(node)
            return
        for alias in node.names:
            if alias.name in HTTP_METHODS:
                self.http_functions.add(alias.asname or alias.name)
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
        context = MethodContext(name=node.name, kind=_method_kind(node))
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
                    lambda value: _is_sudo_expr(value, context.sudo_vars, self._effective_constants()),
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
                lambda value: _is_sudo_expr(value, context.sudo_vars, self._effective_constants()),
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
                lambda value: _is_sudo_expr(value, context.sudo_vars, self._effective_constants()),
            )
            self._track_alias(
                node.target,
                node.value,
                context.http_client_vars,
                lambda value: _is_http_client_expr(value, self.http_modules, context.http_client_vars),
            )
        self.generic_visit(node)

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
        if _is_dynamic_eval(sink):
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
        elif _is_privileged_mutation(node.func, context.sudo_vars, self._effective_constants()):
            self._add(
                SUDO_MUTATION_RULES[context.kind],
                "Odoo model method performs elevated mutation",
                "high",
                node.lineno,
                f"{context.kind} model method mutates records through sudo()/with_user(SUPERUSER_ID); verify record rules, company isolation, and form-triggered side effects",
                context.name,
            )
        elif (
            _is_http_call(sink, self.http_modules, self.http_functions)
            or _is_http_client_call(node.func, context.http_client_vars)
        ) and not _has_keyword(node, "timeout"):
            self._add(
                HTTP_NO_TIMEOUT_RULES[context.kind],
                "Odoo model method performs HTTP without timeout",
                "medium",
                node.lineno,
                f"{context.kind} model method performs outbound HTTP without timeout; form/render/background flows can block Odoo workers",
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


def _method_kind(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    decorators = {_decorator_name(decorator) for decorator in node.decorator_list}
    if any(name.endswith(".onchange") or name == "onchange" for name in decorators) or node.name.startswith(
        "_onchange"
    ):
        return "onchange"
    if any(name.endswith(".depends") or name == "depends" for name in decorators) or node.name.startswith("_compute"):
        return "compute"
    if any(name.endswith(".constrains") or name == "constrains" for name in decorators) or node.name.startswith(
        "_check"
    ):
        return "constraint"
    if node.name.startswith("_inverse"):
        return "inverse"
    return ""


def _is_privileged_mutation(
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
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return any(_is_sudo_expr(element, sudo_vars, constants) for element in node.elts)
    return (
        _call_chain_has_attr(node, "sudo")
        or _call_chain_has_superuser_with_user(node, constants)
        or _call_root_name(node) in sudo_vars
    )


def _is_dynamic_eval(sink: str) -> bool:
    return sink in {"eval", "exec", "safe_eval"} or sink.endswith(".safe_eval")


def _is_http_call(sink: str, http_modules: set[str], http_functions: set[str]) -> bool:
    if sink in http_functions:
        return True
    parts = sink.split(".")
    return len(parts) >= 2 and parts[0] in http_modules and parts[-1] in HTTP_METHODS


def _is_http_client_factory(node: ast.AST, http_modules: set[str]) -> bool:
    sink = _call_name(node.func) if isinstance(node, ast.Call) else _call_name(node)
    parts = sink.split(".")
    return len(parts) >= 2 and parts[0] in http_modules and parts[-1] in {"Client", "Session"}


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


def _call_chain_has_superuser_with_user(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    if isinstance(node, ast.Starred):
        return _call_chain_has_superuser_with_user(node.value, constants)
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
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
