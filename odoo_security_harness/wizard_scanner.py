"""Scanner for risky Odoo TransientModel wizard behavior."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class WizardFinding:
    """Represents a risky Odoo wizard finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    method: str = ""


MUTATION_METHODS = {"create", "write", "unlink"}
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
PARSER_HINTS = {"base64.b64decode", "csv.reader", "openpyxl.load_workbook", "xlrd.open_workbook"}
ACCESS_CHECK_MARKERS = {
    "check_access_rights",
    "check_access_rule",
    "_check_access",
    "_document_check_access",
    "has_group",
    "user_has_groups",
}
SIZE_CHECK_HINTS = {
    "file_size",
    "max_size",
    "max_upload",
    "upload_size",
    "len(",
    "sys.getsizeof",
}
ACTIVE_RECORD_CONTEXT_KEYS = {"active_id", "active_ids"}


def scan_wizards(repo_path: Path) -> list[WizardFinding]:
    """Scan Python files for risky TransientModel wizard behavior."""
    findings: list[WizardFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(WizardScanner(path).scan_file())
    return findings


class WizardScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[WizardFinding] = []
        self.model_stack: list[WizardContext] = []
        self.method_stack: list[MethodContext] = []
        self.module_aliases: dict[str, str] = {}
        self.function_aliases: dict[str, str] = {}
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}
        self.superuser_names: set[str] = {"SUPERUSER_ID"}

    def scan_file(self) -> list[WizardFinding]:
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
            local_name = alias.asname or alias.name.split(".", 1)[0]
            if alias.name in {"base64", "csv", "openpyxl", "xlrd"}:
                self.module_aliases[local_name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module in {"base64", "csv", "openpyxl", "xlrd"}:
            for alias in node.names:
                self.function_aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif node.module == "odoo":
            for alias in node.names:
                if alias.name == "SUPERUSER_ID":
                    self.superuser_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        if not _is_transient_model(node):
            self.generic_visit(node)
            return
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        context = WizardContext(model=_extract_model_name(node, self._effective_constants()))
        self.model_stack.append(context)
        retention_hours = _numeric_class_attr(node, "_transient_max_hours", self._effective_constants())
        retention_count = _numeric_class_attr(node, "_transient_max_count", self._effective_constants())
        if _has_long_transient_retention(retention_hours, retention_count):
            self._add(
                "odoo-wizard-long-transient-retention",
                "Wizard transient records have long retention",
                "medium",
                node.lineno,
                "TransientModel wizard sets _transient_max_hours/_transient_max_count to unlimited or high retention; verify uploaded files, tokens, active_ids, and temporary decisions are not retained longer than needed",
                "",
            )
        for item in node.body:
            if _is_binary_field_assignment(item):
                self._add(
                    "odoo-wizard-binary-import-field",
                    "Wizard exposes binary upload/import field",
                    "medium",
                    getattr(item, "lineno", node.lineno),
                    "TransientModel wizard defines a Binary field; verify upload size, MIME/type validation, parsing safety, and attachment retention",
                    "",
                )
        self.generic_visit(node)
        self.model_stack.pop()
        self.class_constants_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        if not self.model_stack:
            self.generic_visit(node)
            return
        context = MethodContext(name=node.name)
        previous_local_constants = self.local_constants
        self.local_constants = {}
        self.method_stack.append(context)
        self.generic_visit(node)
        self._finish_method(node, context)
        self.method_stack.pop()
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        if not self.method_stack:
            self.generic_visit(node)
            return

        context = self.method_stack[-1]
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
        value_text = _safe_unparse(node.value)
        if "active_model" in value_text:
            for target in node.targets:
                for name in _target_names(target):
                    context.active_model_vars.add(name)
                    context.uses_active_model = True
        if _mentions_active_record_context(value_text):
            context.uses_active_ids = True
            for target in node.targets:
                for name in _target_names(target):
                    context.active_id_vars.add(name)
        for target in node.targets:
            self._track_sudo_alias(target, node.value, context)
        if _records_from_active_ids(node.value, context.active_id_vars):
            for target in node.targets:
                for name in _target_names(target):
                    context.active_record_vars.add(name)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if self.method_stack and node.value is not None:
            context = self.method_stack[-1]
            self._mark_local_constant_target(node.target, node.value)
            value_text = _safe_unparse(node.value)
            if "active_model" in value_text:
                for name in _target_names(node.target):
                    context.active_model_vars.add(name)
                    context.uses_active_model = True
            if _mentions_active_record_context(value_text):
                context.uses_active_ids = True
                for name in _target_names(node.target):
                    context.active_id_vars.add(name)
            self._track_sudo_alias(node.target, node.value, context)
            if _records_from_active_ids(node.value, context.active_id_vars):
                for name in _target_names(node.target):
                    context.active_record_vars.add(name)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        if self.method_stack:
            context = self.method_stack[-1]
            self._mark_local_constant_target(node.target, node.value)
            value_text = _safe_unparse(node.value)
            if "active_model" in value_text:
                for name in _target_names(node.target):
                    context.active_model_vars.add(name)
                    context.uses_active_model = True
            if _mentions_active_record_context(value_text):
                context.uses_active_ids = True
                for name in _target_names(node.target):
                    context.active_id_vars.add(name)
            self._track_sudo_alias(node.target, node.value, context)
            if _records_from_active_ids(node.value, context.active_id_vars):
                for name in _target_names(node.target):
                    context.active_record_vars.add(name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        if not self.model_stack:
            self.generic_visit(node)
            return
        if not self.method_stack:
            self.generic_visit(node)
            return

        context = self.method_stack[-1]
        sink = _call_name(node.func)
        canonical_sink = self._canonical_call_name(node.func)
        text = _safe_unparse(node)
        if any(marker in sink for marker in ACCESS_CHECK_MARKERS):
            context.has_access_check = True
        if _mentions_active_record_context(text):
            context.uses_active_ids = True
        if "active_model" in text:
            context.uses_active_model = True
        sensitive_model = _call_receiver_sensitive_model(node.func, self._effective_constants())
        if sensitive_model and sink.rsplit(".", 1)[-1] in SENSITIVE_MODEL_MUTATION_METHODS:
            context.has_mutation = True
            self._add(
                "odoo-wizard-sensitive-model-mutation",
                "Wizard mutates sensitive model",
                "high",
                node.lineno,
                f"TransientModel wizard mutates sensitive model '{sensitive_model}'; verify action exposure, group checks, record rules, and audit trail",
                context.name,
            )
        if _is_mutation_sink(sink):
            context.has_mutation = True
            receiver = _call_receiver(node.func)
            if (
                "sudo" in sink.split(".")[:-1]
                or _uses_name(receiver, context.sudo_vars)
                or _is_elevated_expr(receiver, self._effective_constants(), self.superuser_names)
            ):
                self._add(
                    "odoo-wizard-sudo-mutation",
                    "Wizard mutates records through an elevated environment",
                    "high",
                    node.lineno,
                    "TransientModel wizard chains sudo()/with_user(SUPERUSER_ID) into create/write/unlink; verify explicit access, group, and company checks before mutation",
                    context.name,
                )
            if _uses_name(receiver, context.active_record_vars):
                context.uses_active_ids = True
        if canonical_sink in PARSER_HINTS:
            context.has_upload_parser = True
            context.upload_parser_line = context.upload_parser_line or node.lineno
            self._add(
                "odoo-wizard-upload-parser",
                "Wizard parses uploaded file content",
                "medium",
                node.lineno,
                "TransientModel wizard parses uploaded content; verify file size, formula injection, decompression bombs, parser hardening, and per-record authorization",
                context.name,
            )
        if any(hint in text for hint in SIZE_CHECK_HINTS):
            context.has_size_check = True

        self.generic_visit(node)

    def _canonical_call_name(self, node: ast.AST) -> str:
        sink = _call_name(node)
        if sink in self.function_aliases:
            return self.function_aliases[sink]
        parts = sink.split(".")
        if parts and parts[0] in self.module_aliases:
            return ".".join([self.module_aliases[parts[0]], *parts[1:]])
        return sink

    def visit_Subscript(self, node: ast.Subscript) -> Any:
        if self.method_stack and _is_dynamic_active_model_env(node, self.method_stack[-1].active_model_vars):
            self.method_stack[-1].uses_active_model = True
            self._add(
                "odoo-wizard-dynamic-active-model",
                "Wizard uses context active_model dynamically",
                "high",
                node.lineno,
                "Wizard uses context active_model to select an env model dynamically; constrain allowed models before browsing or mutating records",
                self.method_stack[-1].name,
            )
        self.generic_visit(node)

    def _finish_method(self, node: ast.FunctionDef | ast.AsyncFunctionDef, context: MethodContext) -> None:
        if context.uses_active_ids and context.has_mutation:
            self._add(
                "odoo-wizard-active-ids-bulk-mutation",
                "Wizard mutates records selected from active_ids",
                "high",
                node.lineno,
                "Wizard mutates records selected from context active_ids; verify caller access, record rules, company scope, and batch limits",
                context.name,
            )
        if context.has_mutation and not context.has_access_check and _is_action_method(context.name):
            self._add(
                "odoo-wizard-mutation-no-access-check",
                "Wizard action mutates without visible access check",
                "medium",
                node.lineno,
                "Wizard action mutates records without visible check_access/user_has_groups guard; verify UI exposure cannot bypass workflow permissions",
                context.name,
            )
        if context.has_upload_parser and not context.has_size_check:
            self._add(
                "odoo-wizard-upload-parser-no-size-check",
                "Wizard parses uploaded content without visible size check",
                "medium",
                context.upload_parser_line or node.lineno,
                "TransientModel wizard parses uploaded content without a visible file-size guard; verify large uploads cannot exhaust memory or parser resources",
                context.name,
            )

    def _track_sudo_alias(self, target: ast.expr, value: ast.AST, context: MethodContext) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for child_target, child_value in _unpack_target_value_pairs(target, value):
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
        if _is_elevated_expr(value, self._effective_constants(), self.superuser_names) or _uses_name(
            value, context.sudo_vars
        ):
            context.sudo_vars.add(target.id)
        else:
            context.sudo_vars.discard(target.id)

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
        for name in _target_names(target):
            self.local_constants.pop(name, None)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack and not self.local_constants:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        constants.update(self.local_constants)
        return constants

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, method: str) -> None:
        self.findings.append(
            WizardFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                model=self.model_stack[-1].model if self.model_stack else "",
                method=method,
            )
        )


@dataclass
class WizardContext:
    """Current wizard model context."""

    model: str


@dataclass
class MethodContext:
    """Current wizard method context."""

    name: str
    has_access_check: bool = False
    has_mutation: bool = False
    uses_active_ids: bool = False
    uses_active_model: bool = False
    has_upload_parser: bool = False
    has_size_check: bool = False
    upload_parser_line: int = 0
    active_model_vars: set[str] = None  # type: ignore[assignment]
    active_id_vars: set[str] = None  # type: ignore[assignment]
    active_record_vars: set[str] = None  # type: ignore[assignment]
    sudo_vars: set[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.active_model_vars is None:
            self.active_model_vars = set()
        if self.active_id_vars is None:
            self.active_id_vars = set()
        if self.active_record_vars is None:
            self.active_record_vars = set()
        if self.sudo_vars is None:
            self.sudo_vars = set()


def _is_transient_model(node: ast.ClassDef) -> bool:
    return any(
        isinstance(base, ast.Attribute)
        and base.attr == "TransientModel"
        or isinstance(base, ast.Name)
        and base.id == "TransientModel"
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


def _numeric_class_attr(node: ast.ClassDef, attr: str, constants: dict[str, ast.AST]) -> int | float | None:
    for item in node.body:
        if isinstance(item, ast.Assign):
            targets = item.targets
            value = item.value
        elif isinstance(item, ast.AnnAssign):
            targets = [item.target]
            value = item.value
        else:
            continue
        if value is None:
            continue
        for target in targets:
            if not isinstance(target, ast.Name) or target.id != attr:
                continue
            resolved = _resolve_constant(value, constants)
            if isinstance(resolved, ast.Constant) and isinstance(resolved.value, int | float):
                return resolved.value
    return None


def _has_long_transient_retention(hours: int | float | None, count: int | float | None) -> bool:
    return (hours is not None and (hours == 0 or hours > 24)) or (count is not None and (count == 0 or count > 10000))


def _is_binary_field_assignment(node: ast.AST) -> bool:
    if not isinstance(node, ast.Assign | ast.AnnAssign):
        return False
    value = node.value
    return isinstance(value, ast.Call) and _call_name(value.func) in {"fields.Binary", "Binary"}


def _is_mutation_sink(sink: str) -> bool:
    return sink.split(".")[-1] in MUTATION_METHODS


def _records_from_active_ids(node: ast.AST, active_id_vars: set[str]) -> bool:
    if not isinstance(node, ast.Call):
        return False
    sink = _call_name(node.func).rsplit(".", 1)[-1]
    if sink not in {"browse", "search"}:
        return False
    text = _safe_unparse(node)
    return _mentions_active_record_context(text) or any(name in text for name in active_id_vars)


def _mentions_active_record_context(text: str) -> bool:
    return any(key in text for key in ACTIVE_RECORD_CONTEXT_KEYS)


def _is_action_method(name: str) -> bool:
    return name.startswith(("action_", "button_")) or name in {"apply", "confirm", "process"}


def _is_dynamic_active_model_env(node: ast.Subscript, active_model_vars: set[str]) -> bool:
    text = _safe_unparse(node)
    if "env[" not in text:
        return False
    if "active_model" in text:
        return True
    return any(f"[{name}]" in text for name in active_model_vars)


def _call_receiver_sensitive_model(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> str | None:
    if not isinstance(node, ast.Attribute):
        return None
    constants = constants or {}
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


def _call_receiver(node: ast.AST) -> ast.AST:
    if isinstance(node, ast.Attribute):
        return node.value
    return node


def _uses_name(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(child, ast.Name) and child.id in names for child in ast.walk(node))


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


def _call_chain_has_superuser_with_user(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    constants = constants or {}
    if isinstance(node, ast.Starred):
        return _call_chain_has_superuser_with_user(node.value, constants, superuser_names)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
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
                        keyword.value is not None and _is_superuser_arg(keyword.value, constants, superuser_names)
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
    constants = constants or {}
    superuser_names = superuser_names or {"SUPERUSER_ID"}
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Constant):
        return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
    if isinstance(node, ast.Name):
        return node.id in superuser_names
    if isinstance(node, ast.Attribute):
        return node.attr == "SUPERUSER_ID"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
        return any(_is_superuser_arg(arg, constants, superuser_names) for arg in node.args)
    return False


def _is_elevated_expr(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    return _call_chain_has_attr(node, "sudo") or _call_chain_has_superuser_with_user(node, constants, superuser_names)


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Tuple | ast.List):
        return {name for element in node.elts for name in _target_names(element)}
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
    return set()


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
        return all(_is_static_literal(key) for key in keys) and all(_is_static_literal(value) for value in node.values)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd | ast.USub):
        return _is_static_literal(node.operand)
    return False


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[WizardFinding]) -> list[dict[str, Any]]:
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
