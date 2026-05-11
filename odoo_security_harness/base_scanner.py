"""Shared base classes and utilities for Odoo security scanners.

This module extracts common patterns duplicated across ~68 scanner modules:
- Finding dataclass boilerplate
- AST traversal helpers (_module_constants, _is_odoo_model, _call_chain_has_attr, etc.)
- XML parsing helpers (_record_fields)
- File filtering (_should_skip)
- Base scanner classes to reduce per-scanner boilerplate
"""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defusedxml import ElementTree

# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class BaseFinding:
    """Unified security finding dataclass used by all scanners."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    confidence: str = "medium"
    model: str = ""
    method: str = ""
    route: str = ""
    sink: str = ""
    record_id: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to a JSON-serializable dictionary."""
        result: dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "confidence": self.confidence,
        }
        if self.model:
            result["model"] = self.model
        if self.method:
            result["method"] = self.method
        if self.route:
            result["route"] = self.route
        if self.sink:
            result["sink"] = self.sink
        if self.record_id:
            result["record_id"] = self.record_id
        if self.extra:
            result.update(self.extra)
        return result


# ---------------------------------------------------------------------------
# File filtering
# ---------------------------------------------------------------------------

_SKIP_DIRS = {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests", ".pytest_cache", ".mypy_cache", ".ruff_cache"}


def _should_skip(path: Path) -> bool:
    """Return True if *path* should be skipped during repository traversal."""
    return bool(set(path.parts) & _SKIP_DIRS)


# ---------------------------------------------------------------------------
# AST helpers (duplicated in ~40 scanners)
# ---------------------------------------------------------------------------

def _module_constants(tree: ast.Module) -> dict[str, ast.AST]:
    """Extract module-level constant assignments from an AST."""
    return _static_constants_from_body(tree.body)


def _static_constants_from_body(statements: list[ast.stmt]) -> dict[str, ast.AST]:
    """Extract constant assignments from a list of statements."""
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


def _is_static_literal(node: ast.AST) -> bool:
    """Return True if *node* is a compile-time static literal."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str | bool | int | float | type(None))
    if isinstance(node, ast.Dict):
        return all(key is None or _is_static_literal(key) for key in node.keys)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_static_literal(node.left) and _is_static_literal(node.right)
    return isinstance(node, ast.Name)


def _resolve_constant(node: ast.AST, constants: dict[str, ast.AST]) -> ast.AST:
    """Resolve a Name node through constant bindings."""
    return _resolve_constant_seen(node, constants, set())


def _resolve_constant_seen(node: ast.AST, constants: dict[str, ast.AST], seen: set[str]) -> ast.AST:
    if isinstance(node, ast.Name):
        if node.id in seen:
            return node
        resolved = constants.get(node.id)
        if resolved is None:
            return node
        seen.add(node.id)
        return _resolve_constant_seen(resolved, constants, seen)
    return node


def _literal_string(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> str:
    """Resolve a node to a string literal if possible."""
    value = _resolve_constant(node, constants or {})
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return ""


def _resolve_static_dict(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> ast.Dict | None:
    """Resolve a node to a static dict AST if possible."""
    constants = constants or {}
    resolved = _resolve_constant(node, constants)
    if resolved is not node:
        return _resolve_static_dict(resolved, constants)
    if isinstance(node, ast.Dict):
        return node
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _resolve_static_dict(node.left, constants)
        right = _resolve_static_dict(node.right, constants)
        if left is not None and right is not None:
            return _merge_static_dicts(left, right)
    return None


def _merge_static_dicts(left: ast.Dict, right: ast.Dict) -> ast.Dict:
    merged = left
    for key, value in zip(right.keys, right.values, strict=False):
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            merged = _dict_with_field(merged, key.value, value)
        else:
            merged = ast.Dict(keys=[*merged.keys, key], values=[*merged.values, value])
    return merged


def _dict_with_field(values: ast.Dict, key: str, value: ast.AST) -> ast.Dict:
    keys = list(values.keys)
    values_list = list(values.values)
    for index, existing_key in enumerate(keys):
        if isinstance(existing_key, ast.Constant) and existing_key.value == key:
            values_list[index] = value
            return ast.Dict(keys=keys, values=values_list)
    keys.append(ast.Constant(value=key))
    values_list.append(value)
    return ast.Dict(keys=keys, values=values_list)


def _expanded_keywords(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> list[ast.keyword]:
    """Expand **kwargs in a Call node into individual keyword nodes."""
    expanded: list[ast.keyword] = []
    for keyword in node.keywords:
        if keyword.arg is not None:
            expanded.append(keyword)
            continue
        expanded.extend(_expanded_dict_keywords(keyword.value, constants))
    return expanded


def _expanded_dict_keywords(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> list[ast.keyword]:
    resolved = _resolve_static_dict(node, constants)
    if resolved is None:
        return []
    keywords: list[ast.keyword] = []
    for key, value in zip(resolved.keys, resolved.values, strict=False):
        literal_key = _literal_string(key, constants) if key is not None else ""
        if literal_key:
            keywords.append(ast.keyword(arg=literal_key, value=value))
    return keywords


# ---------------------------------------------------------------------------
# Odoo-specific AST helpers
# ---------------------------------------------------------------------------

_DEFAULT_MODEL_BASES = {"Model", "TransientModel", "AbstractModel"}


def _is_odoo_model(node: ast.ClassDef, model_base_names: set[str] | None = None) -> bool:
    """Return True if a class definition inherits from an Odoo model base."""
    bases = model_base_names or _DEFAULT_MODEL_BASES
    return any(
        (isinstance(base, ast.Attribute) and base.attr in bases)
        or (isinstance(base, ast.Name) and base.id in bases)
        for base in node.bases
    )


def _extract_model_name(node: ast.ClassDef, constants: dict[str, ast.AST] | None = None) -> str:
    """Extract _name or _inherit from an Odoo model class."""
    for item in node.body:
        if not isinstance(item, ast.Assign):
            continue
        for target in item.targets:
            if isinstance(target, ast.Name) and target.id in {"_name", "_inherit"}:
                value = _resolve_constant(item.value, constants or {})
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    return value.value
    return node.name


def _call_chain_has_attr(node: ast.AST, attr: str) -> bool:
    """Check whether an AST expression chain ends with a call to *attr* (e.g. sudo)."""
    if isinstance(node, ast.Call):
        return _call_chain_has_attr(node.func, attr)
    if isinstance(node, ast.Attribute):
        return node.attr == attr or _call_chain_has_attr(node.value, attr)
    if isinstance(node, ast.Subscript):
        return _call_chain_has_attr(node.value, attr)
    return False


def _call_root_name(node: ast.AST) -> str:
    """Return the root name of a call chain (e.g. 'self' in self.env['res.users'].sudo())."""
    if isinstance(node, ast.Call):
        return _call_root_name(node.func)
    if isinstance(node, ast.Attribute):
        return _call_root_name(node.value)
    if isinstance(node, ast.Subscript):
        return _call_root_name(node.value)
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _call_chain_has_superuser_with_user(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    """Detect with_user(SUPERUSER_ID) or with_user(env.ref('base.user_admin'))."""
    constants = constants or {}
    superuser_names = superuser_names or {"SUPERUSER_ID"}
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "with_user":
            return any(_is_superuser_arg(arg, constants, superuser_names) for arg in node.args) or any(
                keyword.arg in {"user", "uid"}
                and keyword.value is not None
                and _is_superuser_arg(keyword.value, constants, superuser_names)
                for keyword in _expanded_keywords(node, constants)
            )
        return _call_chain_has_superuser_with_user(node.func, constants, superuser_names)
    if isinstance(node, ast.Attribute):
        return _call_chain_has_superuser_with_user(node.value, constants, superuser_names)
    if isinstance(node, ast.Subscript):
        return _call_chain_has_superuser_with_user(node.value, constants, superuser_names)
    return False


def _is_superuser_arg(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    """Return True when *node* statically points at Odoo's superuser identity."""
    superuser_names = superuser_names or {"SUPERUSER_ID"}
    resolved = _resolve_constant(node, constants or {})
    if isinstance(resolved, ast.Constant):
        return resolved.value == 1 or resolved.value in {"base.user_admin", "base.user_root"}
    if isinstance(resolved, ast.Name):
        return resolved.id in superuser_names
    if isinstance(resolved, ast.Attribute):
        return resolved.attr == "SUPERUSER_ID"
    if isinstance(resolved, ast.Call) and isinstance(resolved.func, ast.Attribute) and resolved.func.attr == "ref":
        return any(_is_superuser_arg(arg, constants, superuser_names) for arg in resolved.args)
    return False


def _target_names(node: ast.AST) -> set[str]:
    """Extract assigned names from an AST assignment target."""
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
    if isinstance(node, ast.Tuple | ast.List):
        names: set[str] = set()
        for element in node.elts:
            names |= _target_names(element)
        return names
    return set()


def _unpack_target_value_pairs(
    target: ast.Tuple | ast.List, value: ast.Tuple | ast.List
) -> list[tuple[ast.expr, ast.AST]]:
    """Pair elements of a multi-target assignment, handling starred targets."""
    starred_index = next((index for index, elt in enumerate(target.elts) if isinstance(elt, ast.Starred)), None)
    if starred_index is None:
        return list(zip(target.elts, value.elts, strict=False))

    before = list(zip(target.elts[:starred_index], value.elts[:starred_index], strict=False))
    after_count = len(target.elts) - starred_index - 1
    after_values_start = max(len(value.elts) - after_count, starred_index)
    rest_values = value.elts[starred_index:after_values_start]
    rest_container: ast.expr = ast.List(elts=rest_values, ctx=ast.Load())
    after = list(zip(target.elts[starred_index + 1 :], value.elts[after_values_start:], strict=False))
    return [*before, (target.elts[starred_index], rest_container), *after]


def _returns_true(node: ast.Return, constants: dict[str, ast.AST] | None = None) -> bool:
    """Return True if a return statement returns the constant True."""
    value = _resolve_constant(node.value, constants or {}) if node.value is not None else None
    return isinstance(value, ast.Constant) and value.value is True


# ---------------------------------------------------------------------------
# XML helpers (duplicated in ~20 scanners)
# ---------------------------------------------------------------------------

def _record_fields(record: ElementTree.Element) -> dict[str, str]:
    """Extract field names and values from an Odoo XML <record> element.

    Handles ``ref`` and ``eval`` attributes and collects nested text via
    :pyfunc:`itertext` so that CDATA-wrapped or multi-line values are
    preserved.
    """
    values: dict[str, str] = {}
    for field_node in record.iter("field"):
        name = field_node.get("name")
        if not name:
            continue
        values[name] = field_node.get("ref") or field_node.get("eval") or "".join(field_node.itertext()).strip()
    return values


# ---------------------------------------------------------------------------
# Base scanner classes
# ---------------------------------------------------------------------------

class BaseScanner(ABC):
    """Abstract base for all security scanners.

    Subclasses should override :pymeth:`scan_file` or :py meth:`scan_repo`
    and use :pyattr:`findings` to collect results.
    """

    def __init__(self, source_path: Path) -> None:
        self.source_path = source_path
        self.path = source_path
        self.findings: list[BaseFinding] = []

    @abstractmethod
    def scan_file(self) -> list[BaseFinding]:
        """Scan a single file and return findings."""
        ...

    def add_finding(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        **kwargs: Any,
    ) -> BaseFinding:
        """Append a finding and return it."""
        finding = BaseFinding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            file=str(self.source_path),
            line=line,
            message=message,
            **kwargs,
        )
        self.findings.append(finding)
        return finding


class AstScanner(BaseScanner, ast.NodeVisitor):
    """Base scanner for Python files using AST traversal.

    Provides shared state for:
    - Odoo model stack tracking
    - Constant resolution (module + class + local)
    - SUPERUSER_ID alias tracking
    """

    def __init__(self, source_path: Path) -> None:
        super().__init__(source_path)
        self.tree: ast.AST | None = None
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}
        self.model_stack: list[str] = []
        self.model_base_names: set[str] = set(_DEFAULT_MODEL_BASES)
        self.superuser_names: set[str] = {"SUPERUSER_ID"}
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}

    def scan_file(self) -> list[BaseFinding]:
        """Parse the file and run the AST visitor."""
        try:
            content = self.source_path.read_text(encoding="utf-8", errors="replace")
            self.tree = ast.parse(content)
        except SyntaxError:
            return []
        except Exception:
            return []

        self.constants = _module_constants(self.tree)  # type: ignore[arg-type]
        self.findings.clear()
        self.visit(self.tree)
        return self.findings

    def _effective_constants(self) -> dict[str, ast.AST]:
        """Return the merged scope of module, class, and local constants."""
        merged: dict[str, ast.AST] = dict(self.constants)
        for level in self.class_constants_stack:
            merged.update(level)
        merged.update(self.local_constants)
        return merged

    def _current_model(self) -> str:
        """Return the current Odoo model name or empty string."""
        return self.model_stack[-1] if self.model_stack else ""

    def _enter_class(self, node: ast.ClassDef) -> None:
        """Push class constants and model name onto stacks."""
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        if _is_odoo_model(node, self.model_base_names):
            self.model_stack.append(_extract_model_name(node, self._effective_constants()))
        else:
            self.model_stack.append("")

    def _exit_class(self) -> None:
        """Pop class context."""
        self.class_constants_stack.pop()
        self.model_stack.pop()

    def _enter_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Reset local constants when entering a new function scope."""
        self.local_constants = {}

    def _exit_function(self) -> None:
        """Clear local constants when leaving a function scope."""
        self.local_constants = {}

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track common Odoo import aliases."""
        if node.module == "odoo":
            for alias in node.names:
                if alias.name == "SUPERUSER_ID":
                    self.superuser_names.add(alias.asname or alias.name)
                if alias.name == "http":
                    self.http_module_names.add(alias.asname or alias.name)
        elif node.module == "odoo.models":
            for alias in node.names:
                if alias.name in _DEFAULT_MODEL_BASES:
                    self.model_base_names.add(alias.asname or alias.name)
        elif node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
        self.generic_visit(node)


class XmlScanner(BaseScanner):
    """Base scanner for Odoo XML data files.

    Parses the XML once and exposes the root element to subclasses.
    """

    def __init__(self, source_path: Path) -> None:
        super().__init__(source_path)
        self.root: ElementTree.Element | None = None
        self.content: str = ""

    def scan_file(self) -> list[BaseFinding]:
        """Parse XML and dispatch to scan_xml if successful."""
        try:
            self.content = self.source_path.read_text(encoding="utf-8", errors="replace")
            self.root = ElementTree.fromstring(self.content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        self.findings.clear()
        self.scan_xml()
        return self.findings

    @abstractmethod
    def scan_xml(self) -> None:
        """Subclasses implement their XML scanning logic here."""
        ...
