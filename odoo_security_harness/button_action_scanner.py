"""Scanner for risky Odoo button/action model methods."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ButtonActionFinding:
    """Represents a risky button/action method finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    method: str = ""


SENSITIVE_STATE_VALUES = {
    "approve",
    "approved",
    "authorize",
    "authorized",
    "cancel",
    "cancelled",
    "confirmed",
    "done",
    "paid",
    "posted",
    "sent",
    "validate",
    "validated",
}
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
ACCESS_CHECK_MARKERS = {
    "check_access_rights",
    "check_access_rule",
    "_check_access",
    "_document_check_access",
    "has_group",
    "user_has_groups",
}


def scan_button_actions(repo_path: Path) -> list[ButtonActionFinding]:
    """Scan Odoo model button/action methods for risky state changes."""
    findings: list[ButtonActionFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(ButtonActionScanner(path).scan_file())
    return findings


class ButtonActionScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[ButtonActionFinding] = []
        self.model_stack: list[str] = []
        self.method_stack: list[MethodContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.superuser_names: set[str] = {"SUPERUSER_ID"}

    def scan_file(self) -> list[ButtonActionFinding]:
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

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module == "odoo":
            for alias in node.names:
                if alias.name == "SUPERUSER_ID":
                    self.superuser_names.add(alias.asname or alias.name)
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
        if not self.model_stack or not _is_button_method(node.name):
            self.generic_visit(node)
            return
        context = MethodContext(name=node.name)
        self.method_stack.append(context)
        self.generic_visit(node)
        self._finish_method(node, context)
        self.method_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        if self.method_stack:
            context = self.method_stack[-1]
            for target in node.targets:
                self._track_sudo_alias(target, node.value, context)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if self.method_stack and node.value is not None:
            context = self.method_stack[-1]
            self._track_sudo_alias(node.target, node.value, context)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        if self.method_stack:
            context = self.method_stack[-1]
            self._track_sudo_alias(node.target, node.value, context)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        if not self.method_stack:
            self.generic_visit(node)
            return
        context = self.method_stack[-1]
        sink = _call_name(node.func)
        if any(marker in sink for marker in ACCESS_CHECK_MARKERS):
            context.has_access_check = True
        sensitive_model = _call_receiver_sensitive_model(node.func, self._effective_constants())
        if sensitive_model and sink.rsplit(".", 1)[-1] in SENSITIVE_MODEL_MUTATION_METHODS:
            self._add(
                "odoo-button-action-sensitive-model-mutation",
                "Button/action method mutates sensitive model",
                "high",
                node.lineno,
                f"Button/action method mutates sensitive model '{sensitive_model}'; verify object-button exposure, RPC access, group checks, and audit trail",
                context.name,
            )
        if (sink.endswith(".write") or sink == "write") and node.args and isinstance(node.args[0], ast.Dict):
            context.has_write = True
            if _dict_writes_sensitive_state(node.args[0], self._effective_constants()):
                context.has_sensitive_state_write = True
                self._add(
                    "odoo-button-action-sensitive-state-write",
                    "Button/action method writes sensitive workflow state",
                    "medium",
                    node.lineno,
                    "Button/action method writes approval/payment/posting-like state; verify ACLs, record rules, and groups enforce the workflow boundary",
                    context.name,
                )
        if _is_privileged_mutation(node.func, context.sudo_vars, self._effective_constants(), self.superuser_names):
            context.has_sudo_mutation = True
            self._add(
                "odoo-button-action-sudo-mutation",
                "Button/action method performs sudo mutation",
                "high",
                node.lineno,
                "Button/action method chains sudo()/with_user(SUPERUSER_ID) into write/create/unlink; verify explicit group, access, and company checks before mutation",
                context.name,
            )
        elif sink.endswith(".unlink") or sink == "unlink":
            context.has_unlink = True
        elif sink.endswith(".write") or sink == "write":
            context.has_write = True
        self.generic_visit(node)

    def _finish_method(self, node: ast.FunctionDef | ast.AsyncFunctionDef, context: MethodContext) -> None:
        if context.has_unlink and not context.has_access_check:
            self._add(
                "odoo-button-action-unlink-no-access-check",
                "Button/action method unlinks without visible access check",
                "high",
                node.lineno,
                "Button/action method deletes records without visible check_access/user_has_groups guard; verify object button exposure cannot delete unauthorized records",
                context.name,
            )
        if (context.has_sudo_mutation or context.has_sensitive_state_write) and not context.has_access_check:
            self._add(
                "odoo-button-action-mutation-no-access-check",
                "Button/action method mutates without visible access check",
                "medium",
                node.lineno,
                "Button/action method performs sensitive mutation without visible check_access/user_has_groups guard; verify UI and RPC calls cannot bypass workflow approvals",
                context.name,
            )

    def _track_sudo_alias(self, target: ast.expr, value: ast.AST, context: MethodContext) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for child_target, child_value in _unpack_target_value_pairs(target.elts, value.elts):
                self._track_sudo_alias(child_target, child_value, context)
            return
        if isinstance(target, ast.Tuple | ast.List):
            for child_target in target.elts:
                self._track_sudo_alias(child_target, value, context)
            return
        if isinstance(target, ast.Starred):
            self._track_sudo_alias(target.value, value, context)
            return
        if not isinstance(target, ast.Name):
            return
        if _is_sudo_expr(value, context.sudo_vars, self._effective_constants(), self.superuser_names):
            context.sudo_vars.add(target.id)
        else:
            context.sudo_vars.discard(target.id)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, method: str) -> None:
        self.findings.append(
            ButtonActionFinding(
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


@dataclass
class MethodContext:
    """Current action/button method context."""

    name: str
    has_access_check: bool = False
    has_sudo_mutation: bool = False
    has_sensitive_state_write: bool = False
    has_unlink: bool = False
    has_write: bool = False
    sudo_vars: set[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.sudo_vars is None:
            self.sudo_vars = set()


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


def _is_button_method(name: str) -> bool:
    return name.startswith(("action_", "button_")) or name in {"unlink", "write", "create"}


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
        return any(_is_sudo_expr(item, sudo_vars, constants, superuser_names) for item in node.elts)
    return (
        _call_chain_has_attr(node, "sudo")
        or _call_chain_has_superuser_with_user(node, constants, superuser_names)
        or _call_root_name(node) in sudo_vars
    )


def _call_chain_has_superuser_with_user(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    constants = constants or {}
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


def _dict_writes_sensitive_state(node: ast.Dict, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    for key, value in zip(node.keys, node.values):
        key = _resolve_constant(key, constants) if key is not None else None
        value = _resolve_constant(value, constants)
        if not isinstance(key, ast.Constant) or key.value not in {"state", "status", "stage_id"}:
            continue
        if isinstance(value, ast.Constant) and str(value.value).lower() in SENSITIVE_STATE_VALUES:
            return True
        if not isinstance(value, ast.Constant):
            return True
    return False


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
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return all(_is_static_literal(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (key is None or _is_static_literal(key)) and _is_static_literal(value)
            for key, value in zip(node.keys, node.values)
        )
    return False


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[ButtonActionFinding]) -> list[dict[str, Any]]:
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
