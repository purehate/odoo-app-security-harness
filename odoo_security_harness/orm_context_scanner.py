"""Scanner for risky Odoo ORM context overrides."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class OrmContextFinding:
    """Represents an ORM context security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    sink: str = ""
    flag: str = ""


FALSE_FLAGS = {"active_test"}
TRACKING_DISABLE_FLAGS = {
    "mail_create_nolog",
    "mail_create_nosubscribe",
    "mail_notrack",
    "tracking_disable",
}
NOTIFICATION_DISABLE_FLAGS = {"no_reset_password", "mail_notify_force_send"}
PRIVILEGED_MODE_FLAGS = {"install_mode", "module_uninstall", "uninstall_mode"}
PRIVILEGED_DEFAULT_FIELDS = {
    "active",
    "company_id",
    "company_ids",
    "groups_id",
    "implied_ids",
    "share",
    "user_id",
}
MUTATION_METHODS = {"create", "write", "unlink"}
READ_METHODS = {"browse", "read", "read_group", "search", "search_count", "search_read"}


def scan_orm_context(repo_path: Path) -> list[OrmContextFinding]:
    """Scan Python files for risky ORM context overrides."""
    findings: list[OrmContextFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(OrmContextScanner(path).scan_file())
    return findings


class OrmContextScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[OrmContextFinding] = []
        self.reported_context_calls: set[int] = set()
        self.scope_stack: list[ContextScope] = []
        self.request_names: set[str] = {"request"}
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []

    def scan_file(self) -> list[OrmContextFinding]:
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

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        """Track aliases for the Odoo HTTP request proxy."""
        if node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self.scope_stack.append(ContextScope())
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        if self.scope_stack:
            self._track_context_aliases(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if self.scope_stack and node.value is not None:
            self._track_context_aliases([node.target], node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        if self.scope_stack:
            self._track_context_aliases([node.target], node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        method = sink.split(".")[-1]
        scope = self.scope_stack[-1] if self.scope_stack else None

        if _is_with_context_call(node):
            self._scan_with_context_call(node, sink)
        elif _is_request_update_context_call(node, self.request_names):
            self._scan_request_update_context_call(node, sink)

        flags = _context_flags_in_chain(
            node.func,
            scope.context_vars if scope else {},
            scope.context_dict_vars if scope else {},
            self._effective_constants(),
        )
        if flags:
            if method in MUTATION_METHODS:
                self._scan_mutation_with_context(node, sink, flags)
            elif (
                method in READ_METHODS
                and _flag_is_false(flags, "active_test")
                and _is_sudo_expr(node.func, scope.sudo_vars if scope else set(), self._effective_constants())
            ):
                self._add(
                    "odoo-orm-context-sudo-active-test-read",
                    "Privileged ORM read disables active record filtering",
                    "medium",
                    node.lineno,
                    "ORM read uses sudo()/with_user(SUPERUSER_ID) with active_test=False; archived/inactive records may be exposed outside normal record visibility",
                    sink,
                    "active_test",
                )

        self.generic_visit(node)

    def _scan_with_context_call(self, node: ast.Call, sink: str) -> None:
        if id(node) in self.reported_context_calls:
            return
        self.reported_context_calls.add(id(node))

        scope = self.scope_stack[-1] if self.scope_stack else None
        flags = _context_flags(node, scope.context_dict_vars if scope else {}, self._effective_constants())
        if _flag_is_false(flags, "active_test"):
            self._add(
                "odoo-orm-context-active-test-disabled",
                "ORM context disables active record filtering",
                "low",
                node.lineno,
                "with_context(active_test=False) can include archived/inactive records in later ORM operations; verify this is intentional and access-safe",
                sink,
                "active_test",
            )

        for flag in sorted(PRIVILEGED_MODE_FLAGS & flags.keys()):
            if _flag_is_truthy(flags, flag):
                self._add(
                    "odoo-orm-context-privileged-mode",
                    "ORM context enables privileged framework mode",
                    "high",
                    node.lineno,
                    f"with_context({flag}=True) enables a framework mode normally reserved for install/uninstall flows; verify it cannot bypass normal business safeguards",
                    sink,
                    flag,
                )

        for flag in sorted(_privileged_default_flags(flags)):
            self._add(
                "odoo-orm-context-privileged-default",
                "ORM context seeds privilege-bearing default",
                "high",
                node.lineno,
                f"with_context({flag}=...) seeds a privilege-bearing default; verify create flows cannot assign user, group, company, share, or active-state fields unexpectedly",
                sink,
                flag,
            )

    def _scan_request_update_context_call(self, node: ast.Call, sink: str) -> None:
        scope = self.scope_stack[-1] if self.scope_stack else None
        flags = _context_flags(node, scope.context_dict_vars if scope else {}, self._effective_constants())
        if not flags:
            return

        if _flag_is_false(flags, "active_test"):
            self._add(
                "odoo-orm-context-request-active-test-disabled",
                "Request context disables active record filtering",
                "medium",
                node.lineno,
                "request.update_context(active_test=False) changes the current request environment; archived/inactive records may become visible or processed later in the route",
                sink,
                "active_test",
            )

        disabled_tracking = [flag for flag in TRACKING_DISABLE_FLAGS if _flag_is_truthy(flags, flag)]
        if disabled_tracking:
            self._add(
                "odoo-orm-context-request-tracking-disabled",
                "Request context disables chatter/tracking",
                "medium",
                node.lineno,
                "request.update_context disables tracking or subscription context for later ORM work in the request; verify auditability and follower notifications are preserved",
                sink,
                ",".join(sorted(disabled_tracking)),
            )

        for flag in sorted(NOTIFICATION_DISABLE_FLAGS & flags.keys()):
            if _flag_is_truthy(flags, flag):
                self._add(
                    "odoo-orm-context-request-notification-disabled",
                    "Request context disables user notifications",
                    "medium",
                    node.lineno,
                    f"request.update_context({flag}=True) suppresses later account, password, or mail notifications in the route",
                    sink,
                    flag,
                )

        for flag in sorted(PRIVILEGED_MODE_FLAGS & flags.keys()):
            if _flag_is_truthy(flags, flag):
                self._add(
                    "odoo-orm-context-request-privileged-mode",
                    "Request context enables privileged framework mode",
                    "high",
                    node.lineno,
                    f"request.update_context({flag}=True) enables a framework mode for later ORM work in the request; verify it cannot bypass normal validation or workflow controls",
                    sink,
                    flag,
                )

        for flag in sorted(_privileged_default_flags(flags)):
            self._add(
                "odoo-orm-context-request-privileged-default",
                "Request context seeds privilege-bearing default",
                "high",
                node.lineno,
                f"request.update_context({flag}=...) seeds a privileged default for later create flows in the request",
                sink,
                flag,
            )

    def _scan_mutation_with_context(self, node: ast.Call, sink: str, flags: dict[str, ast.AST]) -> None:
        disabled_tracking = [flag for flag in TRACKING_DISABLE_FLAGS if _flag_is_truthy(flags, flag)]
        if disabled_tracking:
            self._add(
                "odoo-orm-context-tracking-disabled-mutation",
                "ORM mutation disables chatter/tracking context",
                "medium",
                node.lineno,
                "ORM create/write/unlink runs with tracking or subscription context disabled; verify auditability, followers, and security notifications are not suppressed for sensitive records",
                sink,
                ",".join(sorted(disabled_tracking)),
            )

        for flag in sorted(NOTIFICATION_DISABLE_FLAGS & flags.keys()):
            if _flag_is_truthy(flags, flag):
                self._add(
                    "odoo-orm-context-notification-disabled-mutation",
                    "ORM mutation disables user notification context",
                    "medium",
                    node.lineno,
                    f"ORM create/write/unlink runs with {flag}=True; verify account, password, or mail notifications are not suppressed in a security-sensitive flow",
                    sink,
                    flag,
                )

        for flag in sorted(PRIVILEGED_MODE_FLAGS & flags.keys()):
            if _flag_is_truthy(flags, flag):
                self._add(
                    "odoo-orm-context-privileged-mode-mutation",
                    "ORM mutation runs in privileged framework mode",
                    "high",
                    node.lineno,
                    f"ORM mutation runs with {flag}=True; verify install/uninstall-only behavior cannot bypass normal validation or workflow controls",
                    sink,
                    flag,
                )

        for flag in sorted(_privileged_default_flags(flags)):
            self._add(
                "odoo-orm-context-privileged-default-mutation",
                "ORM mutation uses privilege-bearing default context",
                "high",
                node.lineno,
                f"ORM mutation runs with {flag}=... in context; verify callers cannot create records with elevated ownership, groups, companies, or visibility",
                sink,
                flag,
            )

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, sink: str, flag: str) -> None:
        self.findings.append(
            OrmContextFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                sink=sink,
                flag=flag,
            )
        )

    def _track_context_aliases(self, targets: list[ast.expr], value: ast.AST) -> None:
        scope = self.scope_stack[-1]
        constants = self._effective_constants()
        dict_flags = _dict_flags(value, constants)
        if isinstance(value, ast.Name):
            dict_flags = scope.context_dict_vars.get(value.id, {})
        flags = _context_flags_in_chain(value, scope.context_vars, scope.context_dict_vars, constants)
        is_sudo = _is_sudo_expr(value, scope.sudo_vars, constants)
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            if dict_flags:
                scope.context_dict_vars[target.id] = dict_flags
            else:
                scope.context_dict_vars.pop(target.id, None)
            if flags:
                scope.context_vars[target.id] = flags
            else:
                scope.context_vars.pop(target.id, None)
            if is_sudo:
                scope.sudo_vars.add(target.id)
            else:
                scope.sudo_vars.discard(target.id)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants


@dataclass
class ContextScope:
    """Tracks ORM context posture for local recordset aliases."""

    context_vars: dict[str, dict[str, ast.AST]] | None = None
    context_dict_vars: dict[str, dict[str, ast.AST]] | None = None
    sudo_vars: set[str] | None = None

    def __post_init__(self) -> None:
        if self.context_vars is None:
            self.context_vars = {}
        if self.context_dict_vars is None:
            self.context_dict_vars = {}
        if self.sudo_vars is None:
            self.sudo_vars = set()


def _is_with_context_call(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Attribute) and node.func.attr == "with_context"


def _is_request_update_context_call(node: ast.Call, request_names: set[str]) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "update_context"
        and _is_request_expr(node.func.value, request_names)
    )


def _is_request_expr(node: ast.AST, request_names: set[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in request_names


def _context_flags_in_chain(
    node: ast.AST,
    context_vars: dict[str, dict[str, ast.AST]] | None = None,
    context_dict_vars: dict[str, dict[str, ast.AST]] | None = None,
    constants: dict[str, ast.AST] | None = None,
) -> dict[str, ast.AST]:
    flags: dict[str, ast.AST] = {}
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Attribute):
            current = current.value
        elif isinstance(current, ast.Subscript):
            current = current.value
        elif isinstance(current, ast.Call):
            if _is_with_context_call(current):
                flags.update(_context_flags(current, context_dict_vars, constants))
            current = current.func
    if isinstance(current, ast.Name) and context_vars and current.id in context_vars:
        flags.update(context_vars[current.id])
    return flags


def _context_flags(
    node: ast.Call,
    context_dict_vars: dict[str, dict[str, ast.AST]] | None = None,
    constants: dict[str, ast.AST] | None = None,
) -> dict[str, ast.AST]:
    flags: dict[str, ast.AST] = {}
    for arg in node.args:
        flags.update(_dict_or_alias_flags(arg, context_dict_vars, constants))
    for keyword in node.keywords:
        if keyword.arg:
            flags[keyword.arg] = _resolve_constant(keyword.value, constants or {})
        else:
            flags.update(_dict_or_alias_flags(keyword.value, context_dict_vars, constants))
    return flags


def _dict_or_alias_flags(
    node: ast.AST,
    context_dict_vars: dict[str, dict[str, ast.AST]] | None = None,
    constants: dict[str, ast.AST] | None = None,
) -> dict[str, ast.AST]:
    if isinstance(node, ast.Name) and context_dict_vars:
        return context_dict_vars.get(node.id, {})
    return _dict_flags(node, constants)


def _dict_flags(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> dict[str, ast.AST]:
    node = _resolve_constant(node, constants or {})
    if not isinstance(node, ast.Dict):
        return {}
    flags: dict[str, ast.AST] = {}
    for key, value in zip(node.keys, node.values, strict=False):
        key = _resolve_constant(key, constants or {})
        value = _resolve_constant(value, constants or {})
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            flags[key.value] = value
    return flags


def _flag_is_false(flags: dict[str, ast.AST], flag: str) -> bool:
    value = flags.get(flag)
    return isinstance(value, ast.Constant) and value.value is False


def _flag_is_truthy(flags: dict[str, ast.AST], flag: str) -> bool:
    value = flags.get(flag)
    return isinstance(value, ast.Constant) and value.value is True


def _privileged_default_flags(flags: dict[str, ast.AST]) -> set[str]:
    privileged_defaults: set[str] = set()
    for flag, value in flags.items():
        if not flag.startswith("default_"):
            continue
        field = flag.removeprefix("default_")
        if field in PRIVILEGED_DEFAULT_FIELDS or field.startswith("sel_groups_"):
            if not _is_empty_or_false(value):
                privileged_defaults.add(flag)
    return privileged_defaults


def _is_empty_or_false(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return node.value is False or node.value is None or node.value == "" or node.value == 0
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return len(node.elts) == 0
    if isinstance(node, ast.Dict):
        return len(node.keys) == 0
    return False


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


def _is_sudo_expr(node: ast.AST, sudo_vars: set[str], constants: dict[str, ast.AST] | None = None) -> bool:
    return (
        _call_chain_has_attr(node, "sudo")
        or _call_chain_has_superuser_with_user(node, constants)
        or _call_root_name(node) in sudo_vars
    )


def _call_chain_has_superuser_with_user(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
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


def _call_root_name(node: ast.AST) -> str:
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Attribute):
            current = current.value
        elif isinstance(current, ast.Call):
            current = current.func
        else:
            current = current.value
    if isinstance(current, ast.Name):
        return current.id
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


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[OrmContextFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
            "flag": f.flag,
        }
        for f in findings
    ]
