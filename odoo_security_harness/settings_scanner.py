"""Scanner for risky Odoo res.config.settings declarations."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from odoo_security_harness.base_scanner import _should_skip


@dataclass
class SettingsFinding:
    """Represents a settings-model security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    field: str = ""


SENSITIVE_KEY_HINTS = {
    "access_link",
    "access_key",
    "access_token",
    "access_url",
    "api_key",
    "apikey",
    "auth_token",
    "bearer_token",
    "client_secret",
    "csrf_token",
    "hmac_secret",
    "jwt",
    "jwt_secret",
    "license_key",
    "oauth_token",
    "partner_signup_url",
    "password",
    "passwd",
    "private_key",
    "refresh_token",
    "reset_password_token",
    "reset_password_url",
    "secret_key",
    "session_id",
    "session_token",
    "secret",
    "signature_secret",
    "signing_key",
    "signup_token",
    "signup_url",
    "smtp_password",
    "totp_secret",
    "token",
    "webhook_secret",
}
ADMIN_GROUP_HINTS = {"base.group_system", "base.group_erp_manager", "group_system", "group_erp_manager"}
PUBLIC_GROUP_HINTS = {"base.group_public", "base.group_portal", "group_public", "group_portal"}
SECURITY_TOGGLE_KEYS = {
    "auth.oauth.allow_signup",
    "auth.signup.allow_uninvited",
    "auth.signup.invitation_scope",
    "auth_oauth.allow_signup",
    "auth_signup.allow_uninvited",
    "auth_signup.invitation_scope",
    "database.create",
    "database.drop",
    "list_db",
    "web.base.url.freeze",
}
SECURITY_TOGGLE_UNSAFE_DEFAULTS = {
    "auth.oauth.allow_signup": {"1", "true", "yes", "y"},
    "auth.signup.allow_uninvited": {"1", "true", "yes", "y"},
    "auth.signup.invitation_scope": {"b2c"},
    "auth_oauth.allow_signup": {"1", "true", "yes", "y"},
    "auth_signup.allow_uninvited": {"1", "true", "yes", "y"},
    "auth_signup.invitation_scope": {"b2c"},
    "database.create": {"1", "true", "yes", "y"},
    "database.drop": {"1", "true", "yes", "y"},
    "list_db": {"1", "true", "yes", "y"},
    "web.base.url.freeze": {"0", "false", "no", "n"},
}


def scan_settings(repo_path: Path) -> list[SettingsFinding]:
    """Scan Python files for risky res.config.settings declarations."""
    findings: list[SettingsFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(SettingsScanner(path).scan_file())
    return findings


class SettingsScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[SettingsFinding] = []
        self.model_stack: list[str] = []
        self.settings_stack: list[bool] = []
        self.model_base_names: set[str] = {"Model", "TransientModel"}
        self.config_parameter_names: set[str] = set()
        self.sudo_config_parameter_names: set[str] = set()
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}
        self.superuser_names: set[str] = {"SUPERUSER_ID"}

    def scan_file(self) -> list[SettingsFinding]:
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
        constants = self._effective_constants()
        is_settings = _is_res_config_settings(node, constants, self.model_base_names)
        model_name = _extract_model_name(node, constants)
        self.model_stack.append(model_name)
        self.settings_stack.append(is_settings)
        if is_settings:
            self._scan_settings_fields(node, model_name)
        self.generic_visit(node)
        self.settings_stack.pop()
        self.model_stack.pop()
        self.class_constants_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_config_parameter_names = set(self.config_parameter_names)
        previous_sudo_config_parameter_names = set(self.sudo_config_parameter_names)
        previous_local_constants = self.local_constants
        self.local_constants = {}
        self.generic_visit(node)
        self.config_parameter_names = previous_config_parameter_names
        self.sudo_config_parameter_names = previous_sudo_config_parameter_names
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module == "odoo":
            for alias in node.names:
                if alias.name == "SUPERUSER_ID":
                    self.superuser_names.add(alias.asname or alias.name)
        elif node.module == "odoo.models":
            for alias in node.names:
                if alias.name in {"Model", "TransientModel"}:
                    self.model_base_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
        self._track_config_parameter_aliases(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
            self._track_config_parameter_aliases([node.target], node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_local_constant_target(node.target, node.value)
        self._track_config_parameter_aliases([node.target], node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        if not self.settings_stack or not self.settings_stack[-1]:
            self.generic_visit(node)
            return
        sink = _call_name(node.func)
        if sink.endswith(".set_param") and (
            _is_elevated_config_parameter_expr(
                node.func,
                self.sudo_config_parameter_names,
                self._effective_constants(),
                self.superuser_names,
            )
        ):
            self._add(
                "odoo-settings-sudo-set-param",
                "Settings method writes config parameter through elevated environment",
                "medium",
                node.lineno,
                "res.config.settings method calls sudo()/with_user(SUPERUSER_ID).set_param; verify only admin settings flows can alter global security, mail, auth, or integration parameters",
                self.model_stack[-1],
                _literal_string(node.args[0] if node.args else None, self._effective_constants()),
            )
        self.generic_visit(node)

    def _track_config_parameter_aliases(self, targets: list[ast.expr], value: ast.AST) -> None:
        if not self.settings_stack or not self.settings_stack[-1]:
            return
        for target in targets:
            self._track_config_parameter_alias_target(target, value)

    def _track_config_parameter_alias_target(self, target: ast.expr, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for child_target, child_value in _unpack_target_value_pairs(target, value):
                self._track_config_parameter_alias_target(child_target, child_value)
            return

        constants = self._effective_constants()
        is_config_parameter = _is_config_parameter_expr(value, self.config_parameter_names, constants)
        is_sudo_config_parameter = is_config_parameter and _is_elevated_config_parameter_expr(
            value, self.sudo_config_parameter_names, constants, self.superuser_names
        )
        for name in _target_names(target):
            if not is_config_parameter:
                self.config_parameter_names.discard(name)
                self.sudo_config_parameter_names.discard(name)
                continue
            self.config_parameter_names.add(name)
            if is_sudo_config_parameter:
                self.sudo_config_parameter_names.add(name)
            else:
                self.sudo_config_parameter_names.discard(name)

    def _mark_local_constant_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for child_target, child_value in _unpack_target_value_pairs(target, value):
                self._mark_local_constant_target(child_target, child_value)
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
        if isinstance(target, ast.Tuple | ast.List):
            for name in _target_names(target):
                self.local_constants.pop(name, None)

    def _scan_settings_fields(self, node: ast.ClassDef, model_name: str) -> None:
        for item in node.body:
            for field in _field_defs_from_assignment(item, self._effective_constants()):
                self._scan_field(field, model_name)

    def _scan_field(self, field: FieldDef, model_name: str) -> None:
        constants = self._effective_constants()
        config_key = _literal_string(field.keywords.get("config_parameter"), constants)
        groups = _literal_string(field.keywords.get("groups"), constants)
        implied_group = _literal_string(field.keywords.get("implied_group"), constants)
        default_value = _literal_value(field.keywords.get("default"), constants)

        if config_key and _is_sensitive_value(f"{field.name} {config_key}") and not _has_admin_group(groups):
            self._add(
                "odoo-settings-sensitive-config-field-no-admin-groups",
                "Sensitive settings field lacks admin-only groups",
                "high",
                field.line,
                f"Settings field '{field.name}' stores sensitive config parameter '{config_key}' without visible admin-only groups; verify only system administrators can read/write it",
                model_name,
                field.name,
            )

        if config_key and _has_public_group(groups):
            self._add(
                "odoo-settings-config-field-public-groups",
                "Settings field is exposed to public/portal groups",
                "critical",
                field.line,
                f"Settings field '{field.name}' maps to config parameter '{config_key}' and includes public/portal groups; verify it cannot expose or alter global configuration",
                model_name,
                field.name,
            )

        if config_key and _is_security_toggle_key(config_key) and not _has_admin_group(groups):
            self._add(
                "odoo-settings-security-toggle-no-admin-groups",
                "Security-sensitive setting lacks admin-only groups",
                "high",
                field.line,
                f"Settings field '{field.name}' maps to security-sensitive config parameter '{config_key}' without visible admin-only groups; verify only system administrators can alter it",
                model_name,
                field.name,
            )

        if config_key and _is_unsafe_security_toggle_default(config_key, default_value):
            self._add(
                "odoo-settings-security-toggle-unsafe-default",
                "Security-sensitive setting defaults to unsafe posture",
                "high",
                field.line,
                f"Settings field '{field.name}' maps to security-sensitive config parameter '{config_key}' and defaults to '{default_value}'; verify production installs cannot enable unsafe behavior by default",
                model_name,
                field.name,
            )

        if implied_group and _has_admin_group(implied_group):
            self._add(
                "odoo-settings-implies-admin-group",
                "Settings toggle implies administrator group",
                "high",
                field.line,
                f"Settings field '{field.name}' implies elevated group '{implied_group}'; verify only existing administrators can toggle it",
                model_name,
                field.name,
            )

        if field.name.startswith("module_") and not _has_admin_group(groups):
            self._add(
                "odoo-settings-module-toggle-no-admin-groups",
                "Module install toggle lacks admin-only groups",
                "medium",
                field.line,
                f"Settings field '{field.name}' can install/uninstall modules and has no visible admin-only groups; verify only system administrators can access it",
                model_name,
                field.name,
            )

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        model: str,
        field: str,
    ) -> None:
        self.findings.append(
            SettingsFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                model=model,
                field=field,
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


@dataclass
class FieldDef:
    """Represents a settings field declaration."""

    name: str
    line: int
    keywords: dict[str, ast.AST]


def _field_defs_from_assignment(node: ast.stmt, constants: dict[str, ast.AST] | None = None) -> list[FieldDef]:
    constants = constants or {}
    if isinstance(node, ast.Assign):
        return [
            FieldDef(
                name=target.id,
                line=node.lineno,
                keywords=_call_keywords(node.value, constants),
            )
            for target in node.targets
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Call)
        ]
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and isinstance(node.value, ast.Call):
        return [
            FieldDef(
                name=node.target.id,
                line=node.lineno,
                keywords=_call_keywords(node.value, constants),
            )
        ]
    return []


def _is_res_config_settings(
    node: ast.ClassDef,
    constants: dict[str, ast.AST] | None = None,
    model_base_names: set[str] | None = None,
) -> bool:
    model_base_names = model_base_names or {"Model", "TransientModel"}
    model_name = _extract_model_name(node, constants)
    if model_name == "res.config.settings":
        return True
    return any(
        _call_name(base) in model_base_names
        or _call_name(base).endswith(".TransientModel")
        or _call_name(base).endswith(".Model")
        for base in node.bases
    ) and ("config" in node.name.lower() and "settings" in node.name.lower())


def _extract_model_name(node: ast.ClassDef, constants: dict[str, ast.AST] | None = None) -> str:
    for item in node.body:
        if not isinstance(item, ast.Assign):
            continue
        for target in item.targets:
            if isinstance(target, ast.Name) and target.id in {"_name", "_inherit"}:
                value = _literal_string(item.value, constants)
                if value:
                    return value
    return node.name


def _is_sensitive_value(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in SENSITIVE_KEY_HINTS)


def _has_admin_group(groups: str) -> bool:
    lowered = groups.lower()
    return any(hint in lowered for hint in ADMIN_GROUP_HINTS)


def _has_public_group(groups: str) -> bool:
    lowered = groups.lower()
    return any(hint in lowered for hint in PUBLIC_GROUP_HINTS)


def _is_security_toggle_key(key: str) -> bool:
    return key.strip().lower() in SECURITY_TOGGLE_KEYS


def _is_unsafe_security_toggle_default(key: str, value: str) -> bool:
    normalized_key = key.strip().lower()
    normalized_value = value.strip().lower()
    return normalized_value in SECURITY_TOGGLE_UNSAFE_DEFAULTS.get(normalized_key, set())


def _literal_string(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> str:
    if node is not None:
        node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _literal_value(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> str:
    if node is not None:
        node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant):
        return str(node.value)
    return _literal_string(node, constants)


def _call_keywords(node: ast.Call, constants: dict[str, ast.AST]) -> dict[str, ast.AST]:
    keywords: dict[str, ast.AST] = {}
    for keyword in node.keywords:
        if keyword.arg is not None:
            keywords[keyword.arg] = keyword.value
            continue
        value = _resolve_static_dict(keyword.value, constants)
        if value is not None:
            keywords.update(_dict_keywords(value, constants))
    return keywords


def _dict_keywords(node: ast.Dict, constants: dict[str, ast.AST]) -> dict[str, ast.AST]:
    keywords: dict[str, ast.AST] = {}
    for key, value in zip(node.keys, node.values, strict=False):
        if key is None:
            resolved_value = _resolve_static_dict(value, constants)
            if resolved_value is not None:
                keywords.update(_dict_keywords(resolved_value, constants))
            continue
        resolved_key = _resolve_constant(key, constants)
        if isinstance(resolved_key, ast.Constant) and isinstance(resolved_key.value, str):
            keywords[resolved_key.value] = value
    return keywords


def _is_config_parameter_expr(
    node: ast.AST,
    config_parameter_names: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    node = _resolve_constant(node, constants)
    call_name = _call_name(node)
    if "env" in call_name and "ir.config_parameter" in ast.unparse(node):
        return True
    if isinstance(node, ast.Name):
        return node.id in config_parameter_names
    if isinstance(node, ast.Starred):
        return _is_config_parameter_expr(node.value, config_parameter_names, constants)
    if isinstance(node, ast.Attribute):
        return _is_config_parameter_expr(node.value, config_parameter_names, constants)
    if isinstance(node, ast.Call):
        return _is_config_parameter_expr(node.func, config_parameter_names, constants)
    if isinstance(node, ast.Subscript):
        model = _literal_string(node.slice, constants)
        return model == "ir.config_parameter" or _is_config_parameter_expr(
            node.value,
            config_parameter_names,
            constants,
        )
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_is_config_parameter_expr(element, config_parameter_names, constants) for element in node.elts)
    return False


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


def _is_elevated_config_parameter_expr(
    node: ast.AST,
    sudo_config_parameter_names: set[str],
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    return (
        _call_chain_has_attr(node, "sudo")
        or _call_chain_has_superuser_with_user(node, constants, superuser_names)
        or _call_root_name(node) in sudo_config_parameter_names
    )


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
    if isinstance(node, ast.Tuple | ast.List):
        names: set[str] = set()
        for element in node.elts:
            names.update(_target_names(element))
        return names
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
    return set()


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
    return [*before, (target.elts[starred_index], ast.List(elts=list(rest_values), ctx=ast.Load())), *after]


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


def _resolve_static_dict(
    node: ast.AST, constants: dict[str, ast.AST], seen: set[str] | None = None
) -> ast.Dict | None:
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


def _is_static_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str | bool | int | float | type(None))
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(_is_static_literal(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (key is None or _is_static_literal(key)) and _is_static_literal(value)
            for key, value in zip(node.keys, node.values, strict=False)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_static_literal(node.left) and _is_static_literal(node.right)
    return False



def findings_to_json(findings: list[SettingsFinding]) -> list[dict[str, Any]]:
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
        }
        for f in findings
    ]
