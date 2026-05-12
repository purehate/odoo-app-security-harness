"""Scanner for Odoo migration scripts and lifecycle hooks."""

from __future__ import annotations

import ast
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from odoo_security_harness.base_scanner import _should_skip


@dataclass
class MigrationFinding:
    """Represents a migration/hook security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    context: str = ""


HOOK_KEYS = {"pre_init_hook", "post_init_hook", "uninstall_hook", "post_load"}
DESTRUCTIVE_SQL = re.compile(r"\b(drop|truncate|delete\s+from|alter\s+table)\b", re.IGNORECASE)
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "request", "urlopen"}
PROCESS_METHODS = {"run", "call", "check_call", "check_output", "Popen"}


def scan_migrations(repo_path: Path) -> list[MigrationFinding]:
    """Scan Odoo migration scripts and manifest-declared lifecycle hooks."""
    findings: list[MigrationFinding] = []
    for path in repo_path.rglob("migrations/**/*.py"):
        if _should_skip(path):
            continue
        findings.extend(MigrationScanner(path, "migration").scan_file())

    for manifest in [*repo_path.rglob("__manifest__.py"), *repo_path.rglob("__openerp__.py")]:
        if _should_skip(manifest):
            continue
        module_path = manifest.parent
        hooks = _manifest_hooks(manifest)
        if hooks:
            findings.extend(_scan_hook_functions(module_path, hooks, manifest))
    return findings


class MigrationScanner(ast.NodeVisitor):
    """AST scanner for migration and lifecycle-hook Python files."""

    def __init__(self, path: Path, context: str, hook_names: set[str] | None = None) -> None:
        self.path = path
        self.context = context
        self.hook_names = hook_names or set()
        self.findings: list[MigrationFinding] = []
        self.sql_vars: dict[str, ast.expr] = {}
        self.sudo_vars: set[str] = set()
        self.superuser_names: set[str] = {"SUPERUSER_ID"}
        self.http_module_aliases: set[str] = {"aiohttp", "requests", "httpx", "urllib"}
        self.http_function_aliases: set[str] = set()
        self.process_module_aliases: set[str] = {"subprocess"}
        self.process_function_aliases: set[str] = set()
        self.function_stack: list[str] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}

    def scan_file(self) -> list[MigrationFinding]:
        """Scan the file."""
        try:
            source = self.path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
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

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            if alias.name in {"aiohttp", "requests", "httpx"}:
                self.http_module_aliases.add(alias.asname or alias.name)
            elif alias.name == "urllib.request":
                self.http_module_aliases.add(alias.asname or "urllib")
            elif alias.name == "subprocess":
                self.process_module_aliases.add(alias.asname or alias.name)
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
        elif node.module == "subprocess":
            for alias in node.names:
                if alias.name in PROCESS_METHODS:
                    self.process_function_aliases.add(alias.asname or alias.name)
        elif node.module == "odoo":
            for alias in node.names:
                if alias.name == "SUPERUSER_ID":
                    self.superuser_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self.function_stack.append(node.name)
        previous_local_constants = self.local_constants
        self.local_constants = {}
        if node.name in self.hook_names:
            self._add(
                "odoo-migration-lifecycle-hook",
                "Manifest lifecycle hook requires review",
                "info",
                node.lineno,
                f"Manifest declares lifecycle hook '{node.name}'; review install/uninstall side effects and privilege assumptions",
            )
        self.generic_visit(node)
        self.local_constants = previous_local_constants
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
            self._record_alias_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
            self._record_alias_target(node.target, node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_local_constant_target(node.target, node.value)
        self._record_alias_target(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        if _is_cr_execute(node):
            self._scan_sql_execute(node)
        elif _is_sudo_mutation(node.func, self.sudo_vars, self._effective_constants(), self.superuser_names):
            self._add(
                "odoo-migration-sudo-mutation",
                "Migration/hook performs elevated mutation",
                "high",
                node.lineno,
                "Migration or lifecycle hook chains sudo()/with_user(SUPERUSER_ID) into write/create/unlink; verify it cannot corrupt records across companies or tenants",
            )
        elif _is_manual_transaction(node):
            self._add(
                "odoo-migration-manual-transaction",
                "Migration/hook controls transactions manually",
                "medium",
                node.lineno,
                "Migration or lifecycle hook calls commit()/rollback(); verify failures cannot leave partial security state",
            )
        elif _is_http_call(node.func, self.http_module_aliases, self.http_function_aliases):
            constants = self._effective_constants()
            if not _has_effective_timeout(node, constants):
                self._add(
                    "odoo-migration-http-no-timeout",
                    "Migration/hook performs HTTP without timeout",
                    "medium",
                    node.lineno,
                    "Migration or lifecycle hook performs outbound HTTP without timeout; install/upgrade can hang workers or deployment pipelines",
                )
            if _keyword_is_false(node, "verify", constants):
                self._add(
                    "odoo-migration-tls-verify-disabled",
                    "Migration/hook disables TLS verification",
                    "high",
                    node.lineno,
                    "Migration or lifecycle hook passes verify=False to outbound HTTP; install/upgrade integrations should not permit man-in-the-middle attacks",
                )
            for url_value in _http_url_values(node, _call_name(node.func), constants):
                if _is_cleartext_literal_url(url_value, constants):
                    self._add(
                        "odoo-migration-cleartext-http-url",
                        "Migration/hook uses cleartext HTTP URL",
                        "medium",
                        node.lineno,
                        "Migration or lifecycle hook outbound HTTP targets a literal http:// URL; use HTTPS to protect install/upgrade integration payloads and response data from interception or downgrade",
                    )
                if _literal_url_has_embedded_credentials(url_value, constants):
                    self._add(
                        "odoo-migration-url-embedded-credentials",
                        "Migration/hook URL embeds credentials",
                        "high",
                        node.lineno,
                        "Migration or lifecycle hook embeds username, password, or token material in an outbound HTTP URL authority; move credentials to server-side configuration",
                    )
        elif _is_process_call(node.func, self.process_module_aliases, self.process_function_aliases):
            self._add(
                "odoo-migration-process-execution",
                "Migration/hook executes a subprocess",
                "high",
                node.lineno,
                "Migration or lifecycle hook executes a subprocess; review command injection, deployment portability, timeouts, and privilege assumptions",
            )
        self.generic_visit(node)

    def _record_alias_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._record_alias_target(target_element, value_element)
            return
        sql_value = self._resolve_sql_value(value)
        if _looks_sql_expr(sql_value):
            self._record_sql_target(target, sql_value)
        self._track_sudo_alias(
            target,
            value,
            lambda node: _is_sudo_expr(node, self.sudo_vars, self._effective_constants(), self.superuser_names),
        )

    def _track_sudo_alias(
        self,
        target: ast.AST,
        value: ast.AST,
        predicate: Callable[[ast.AST], bool],
    ) -> None:
        if isinstance(target, ast.Tuple | ast.List):
            for target_element in target.elts:
                self._track_sudo_alias(target_element, value, predicate)
            return
        if isinstance(target, ast.Starred):
            self._track_sudo_alias(target.value, value, predicate)
            return
        if not isinstance(target, ast.Name):
            return
        if predicate(value):
            self.sudo_vars.add(target.id)
        else:
            self.sudo_vars.discard(target.id)

    def _record_sql_target(self, target: ast.AST, value: ast.expr) -> None:
        if isinstance(target, ast.Name):
            self.sql_vars[target.id] = value
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._record_sql_target(element, value)
        elif isinstance(target, ast.Starred):
            self._record_sql_target(target.value, value)

    def _mark_local_constant_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_local_constant_target(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._mark_local_constant_target(target.value, value)
            return
        if isinstance(target, ast.Name):
            if _is_static_literal(value):
                self.local_constants[target.id] = value
            else:
                self.local_constants.pop(target.id, None)
            return
        names: set[str] = set()
        _mark_target_names(target, names)
        for name in names:
            self.local_constants.pop(name, None)

    def _scan_sql_execute(self, node: ast.Call) -> None:
        if not node.args:
            return
        query = node.args[0]
        resolved = self._resolve_sql_value(query)
        if resolved is None:
            return

        if _is_interpolated_sql(resolved):
            self._add(
                "odoo-migration-interpolated-sql",
                "Migration SQL uses interpolation",
                "high",
                node.lineno,
                "Migration or lifecycle hook executes SQL built with interpolation/formatting; use parameters or psycopg2.sql for identifiers",
            )

        sql_literal = _literal_string(resolved)
        if sql_literal and DESTRUCTIVE_SQL.search(sql_literal):
            severity = "critical" if _destructive_without_where(sql_literal) else "high"
            self._add(
                "odoo-migration-destructive-sql",
                "Migration executes destructive SQL",
                severity,
                node.lineno,
                "Migration or lifecycle hook executes destructive SQL; verify backups, WHERE clauses, tenant filters, and rollback safety",
            )

    def _resolve_sql_value(self, value: ast.AST) -> ast.expr:
        if isinstance(value, ast.Name):
            if value.id in self.sql_vars:
                return self.sql_vars[value.id]
            resolved = _resolve_constant(value, self._effective_constants())
            return resolved if isinstance(resolved, ast.expr) else value
        if isinstance(value, ast.Subscript):
            root = _call_root_name(value)
            if root in self.sql_vars:
                return self.sql_vars[root]
        return value

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str) -> None:
        context = self.context
        if self.function_stack:
            context = f"{context}:{self.function_stack[-1]}"
        self.findings.append(
            MigrationFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                context=context,
            )
        )

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack and not self.local_constants:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        constants.update(self.local_constants)
        return constants


def _scan_hook_functions(module_path: Path, hook_names: set[str], manifest: Path) -> list[MigrationFinding]:
    findings: list[MigrationFinding] = []
    defined_hooks: set[str] = set()
    for path in module_path.rglob("*.py"):
        if _should_skip(path) or "migrations" in path.parts:
            continue
        defined_hooks.update(_defined_function_names(path) & hook_names)
        findings.extend(MigrationScanner(path, "lifecycle_hook", hook_names).scan_file())
    for missing_hook in sorted(hook_names - defined_hooks):
        findings.append(
            MigrationFinding(
                rule_id="odoo-migration-missing-lifecycle-hook",
                title="Manifest lifecycle hook function is missing",
                severity="medium",
                file=str(manifest),
                line=1,
                message=(
                    f"Manifest declares lifecycle hook '{missing_hook}', but no matching Python function was found; "
                    "verify install, upgrade, uninstall, and post-load behavior cannot fail or silently skip required security setup"
                ),
                context=f"manifest:{missing_hook}",
            )
        )
    return findings


def _defined_function_names(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return set()
    return {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)}


def _manifest_hooks(manifest: Path) -> set[str]:
    try:
        data = ast.literal_eval(manifest.read_text(encoding="utf-8"))
    except Exception:
        return set()
    if not isinstance(data, dict):
        return set()
    hooks: set[str] = set()
    for key in HOOK_KEYS:
        value = data.get(key)
        if isinstance(value, str) and value:
            hooks.add(value)
    return hooks


def _is_cr_execute(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "execute"
        and (
            isinstance(node.func.value, ast.Name)
            and node.func.value.id == "cr"
            or isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "cr"
        )
    )


def _is_sudo_mutation(
    node: ast.AST,
    sudo_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    if not (isinstance(node, ast.Attribute) and node.attr in {"write", "create", "unlink"}):
        return False
    return _is_sudo_expr(node, sudo_vars, constants, superuser_names)


def _is_sudo_expr(
    node: ast.AST,
    sudo_vars: set[str],
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    if isinstance(node, ast.Starred):
        return _is_sudo_expr(node.value, sudo_vars, constants, superuser_names)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_is_sudo_expr(element, sudo_vars, constants, superuser_names) for element in node.elts)
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
    if isinstance(node, ast.Starred):
        return _call_chain_has_superuser_with_user(node.value, constants, superuser_names)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_call_chain_has_superuser_with_user(element, constants, superuser_names) for element in node.elts)
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Call):
            if isinstance(current.func, ast.Attribute) and current.func.attr == "with_user":
                return any(_is_superuser_arg(arg, constants, superuser_names) for arg in current.args) or any(
                    keyword.value is not None and _is_superuser_arg(keyword.value, constants, superuser_names)
                    for keyword in current.keywords
                )
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


def _is_manual_transaction(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in {"commit", "rollback"}
        and (
            isinstance(node.func.value, ast.Name)
            and node.func.value.id == "cr"
            or isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "cr"
        )
    )


def _looks_sql_expr(node: ast.expr) -> bool:
    if isinstance(node, ast.Starred):
        return _looks_sql_expr(node.value)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_looks_sql_expr(element) for element in node.elts)
    literal = _literal_string(node)
    return bool(
        literal and re.search(r"\b(select|insert|update|delete|alter|drop|truncate)\b", literal, re.I)
    ) or _is_interpolated_sql(node)


def _is_interpolated_sql(node: ast.expr) -> bool:
    if isinstance(node, ast.Starred):
        return _is_interpolated_sql(node.value)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_is_interpolated_sql(element) for element in node.elts)
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return True
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"


def _literal_string(node: ast.expr) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


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
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_static_literal(node.left) and _is_static_literal(node.right)
    return False


def _http_url_values(node: ast.Call, sink: str, constants: dict[str, ast.AST]) -> list[ast.AST]:
    values: list[ast.AST] = []
    if node.args:
        method = sink.rsplit(".", 1)[-1]
        if method == "request" and len(node.args) >= 2:
            values.append(node.args[1])
        else:
            values.append(node.args[0])
    values.extend(_keyword_values(node, "url", constants))
    return values


def _is_cleartext_literal_url(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    value = _resolve_constant(node, constants)
    return (
        isinstance(value, ast.Constant)
        and isinstance(value.value, str)
        and value.value.strip().lower().startswith("http://")
    )


def _literal_url_has_embedded_credentials(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    value = _resolve_constant(node, constants)
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        return False
    parsed = urlparse(value.value.strip())
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.hostname)
        and (parsed.username is not None or parsed.password is not None)
    )


def _is_http_call(node: ast.AST, module_aliases: set[str], function_aliases: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in function_aliases
    if not isinstance(node, ast.Attribute) or node.attr not in HTTP_METHODS:
        return False
    return _call_root_name(node) in module_aliases


def _is_process_call(node: ast.AST, module_aliases: set[str], function_aliases: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in function_aliases
    if not isinstance(node, ast.Attribute) or node.attr not in PROCESS_METHODS:
        return False
    return _call_root_name(node) in module_aliases


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
        value = _resolve_static_dict(keyword.value, constants)
        if value is not None:
            values.extend(_dict_keyword_values(value, name, constants))
    return values


def _dict_keyword_values(node: ast.Dict, name: str, constants: dict[str, ast.AST]) -> list[ast.AST]:
    values: list[ast.AST] = []
    for key, item_value in zip(node.keys, node.values, strict=False):
        if key is None:
            value = _resolve_static_dict(item_value, constants)
            if value is not None:
                values.extend(_dict_keyword_values(value, name, constants))
            continue
        resolved_key = _resolve_constant(key, constants)
        if isinstance(resolved_key, ast.Constant) and resolved_key.value == name:
            values.append(item_value)
    return values


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


def _mark_target_names(target: ast.AST, names: set[str]) -> None:
    if isinstance(target, ast.Name):
        names.add(target.id)
    elif isinstance(target, ast.Tuple | ast.List):
        for element in target.elts:
            _mark_target_names(element, names)
    elif isinstance(target, ast.Starred):
        _mark_target_names(target.value, names)


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


def _destructive_without_where(sql: str) -> bool:
    lowered = sql.lower()
    if re.search(r"\b(drop|truncate|alter\s+table)\b", lowered):
        return True
    return "delete from" in lowered and " where " not in lowered


def findings_to_json(findings: list[MigrationFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "context": f.context,
        }
        for f in findings
    ]
