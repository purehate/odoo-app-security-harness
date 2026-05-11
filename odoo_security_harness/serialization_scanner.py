"""Scanner for unsafe deserialization and parser usage in Odoo addons."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from odoo_security_harness.base_scanner import _should_skip


@dataclass
class SerializationFinding:
    """Represents an unsafe deserialization/parser finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    sink: str = ""


UNSAFE_DESERIALIZATION_SINKS = {
    "pickle.load",
    "pickle.loads",
    "cPickle.load",
    "cPickle.loads",
    "cloudpickle.load",
    "cloudpickle.loads",
    "dill.load",
    "dill.loads",
    "joblib.load",
    "marshal.load",
    "marshal.loads",
    "jsonpickle.decode",
    "jsonpickle.loads",
    "pandas.read_pickle",
    "shelve.open",
    "torch.load",
}
TAINTED_ARG_NAMES = {"data", "payload", "body", "content", "file", "attachment", "kwargs", "kw", "post"}
SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}
YAML_LOAD_SINKS = {"yaml.load", "yaml.load_all"}
YAML_UNSAFE_LOAD_SINKS = {"yaml.unsafe_load", "yaml.unsafe_load_all"}
YAML_FULL_LOAD_SINKS = {"yaml.full_load", "yaml.full_load_all"}
LITERAL_EVAL_SINKS = {"ast.literal_eval"}
JSON_LOAD_SINKS = {"json.load", "json.loads"}
NUMPY_LOAD_SINKS = {"numpy.load"}
XML_TAINTED_PARSE_SINKS = {
    "xml.etree.ElementTree.fromstring",
    "xml.etree.ElementTree.XML",
    "lxml.etree.fromstring",
    "lxml.etree.XML",
    "xml.dom.minidom.parseString",
    "xml.sax.parseString",
}
SIZE_GUARD_HINTS = {
    "content_length",
    "Content-Length",
    "file_size",
    "len(",
    "max_length",
    "max_payload",
    "max_size",
    "max_upload",
}
REQUEST_SOURCE_ATTRS = {"httprequest", "jsonrequest", "params"}
REQUEST_SOURCE_METHODS = {"get_http_params", "get_json_data"}
SERIALIZATION_TEXT_MARKERS = (
    "kwargs.get",
    "kw.get",
    "post.get",
    ".datas",
    "attachment.",
    "response.content",
    "response.text",
)


def scan_serialization(repo_path: Path) -> list[SerializationFinding]:
    """Scan Python files for unsafe deserialization/parser calls."""
    findings: list[SerializationFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(SerializationScanner(path).scan_file())
    return findings


class SerializationScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[SerializationFinding] = []
        self.tainted_names: set[str] = set()
        self.module_aliases: dict[str, str] = {}
        self.function_aliases: dict[str, str] = {}
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.route_decorator_names: set[str] = set()
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}
        self.size_guard_stack: list[bool] = []

    def scan_file(self) -> list[SerializationFinding]:
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

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous = set(self.tainted_names)
        previous_local_constants = self.local_constants
        self.local_constants = {}
        self.size_guard_stack.append(_function_has_size_guard(node))
        is_route = _function_is_http_route(
            node, self.route_decorator_names, self.http_module_names, self.odoo_module_names
        )
        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES or (is_route and arg.arg not in {"self", "cls"}):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.size_guard_stack.pop()
        self.tainted_names = previous
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            local_name = alias.asname or alias.name.split(".", 1)[0]
            if alias.name in {
                "pickle",
                "cPickle",
                "cloudpickle",
                "dill",
                "joblib",
                "marshal",
                "jsonpickle",
                "yaml",
                "ast",
                "json",
                "numpy",
                "pandas",
                "shelve",
                "torch",
            }:
                self.module_aliases[local_name] = alias.name
            elif alias.name in {"xml.etree.ElementTree", "xml.dom.minidom", "xml.sax", "lxml.etree"}:
                self.module_aliases[alias.asname or alias.name] = alias.name
            elif alias.name == "odoo":
                self.odoo_module_names.add(alias.asname or alias.name)
            elif alias.name == "odoo.http" and alias.asname:
                self.http_module_names.add(alias.asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module in {
            "pickle",
            "cPickle",
            "cloudpickle",
            "dill",
            "joblib",
            "marshal",
            "jsonpickle",
            "yaml",
            "ast",
            "json",
            "numpy",
            "pandas",
            "shelve",
            "torch",
        }:
            for alias in node.names:
                canonical = f"{node.module}.{alias.name}"
                self.function_aliases[alias.asname or alias.name] = canonical
        elif node.module == "xml.etree.ElementTree":
            for alias in node.names:
                self.function_aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif node.module == "xml.dom":
            for alias in node.names:
                if alias.name == "minidom":
                    self.module_aliases[alias.asname or alias.name] = "xml.dom.minidom"
        elif node.module in {"xml.dom.minidom", "xml.sax"}:
            for alias in node.names:
                self.function_aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif node.module == "lxml":
            for alias in node.names:
                if alias.name == "etree":
                    self.module_aliases[alias.asname or alias.name] = "lxml.etree"
        elif node.module == "lxml.etree":
            for alias in node.names:
                self.function_aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif node.module == "odoo":
            for alias in node.names:
                if alias.name == "http":
                    self.http_module_names.add(alias.asname or alias.name)
        elif node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
                elif alias.name == "route":
                    self.route_decorator_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
            self._mark_tainted_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
            self._mark_tainted_target(node.target, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        if self._expr_is_tainted(node.iter):
            self._mark_name_target(node.target, self.tainted_names)
        else:
            self._discard_name_target(node.target, self.tainted_names)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_local_constant_target(node.target, node.value)
        self._mark_tainted_target(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        _mark_static_dict_update(node, self.local_constants)
        sink = self._canonical_call_name(node.func)
        if sink in UNSAFE_DESERIALIZATION_SINKS:
            severity = "critical" if _call_has_tainted_input(node, self._expr_is_tainted) else "high"
            self._add(
                "odoo-serialization-unsafe-deserialization",
                "Unsafe deserialization sink",
                severity,
                node.lineno,
                f"{sink} can execute code or instantiate attacker-controlled objects; never use "
                "it on request, attachment, or integration data",
                sink,
            )
        elif sink in YAML_LOAD_SINKS and not _has_safe_yaml_loader(node, self._effective_constants()):
            severity = "critical" if _call_has_tainted_input(node, self._expr_is_tainted) else "high"
            self._add(
                "odoo-serialization-unsafe-yaml-load",
                "Unsafe YAML load",
                severity,
                node.lineno,
                "yaml.load()/load_all() without SafeLoader can construct arbitrary Python "
                "objects; use safe_load()/safe_load_all() or SafeLoader",
                sink,
            )
        elif sink in YAML_UNSAFE_LOAD_SINKS:
            severity = "critical" if _call_has_tainted_input(node, self._expr_is_tainted) else "high"
            self._add(
                "odoo-serialization-unsafe-yaml-load",
                "Unsafe YAML load",
                severity,
                node.lineno,
                "yaml.unsafe_load() can construct arbitrary Python objects; never use it on "
                "request, attachment, or integration data",
                sink,
            )
        elif sink in YAML_FULL_LOAD_SINKS:
            severity = "high" if _call_has_tainted_input(node, self._expr_is_tainted) else "medium"
            self._add(
                "odoo-serialization-yaml-full-load",
                "YAML full_load on addon data",
                severity,
                node.lineno,
                "yaml.full_load() accepts a broader YAML type set than safe_load(); "
                "prefer safe_load() for request, attachment, or integration data",
                sink,
            )
        elif sink in LITERAL_EVAL_SINKS and _call_has_tainted_input(node, self._expr_is_tainted):
            self._add(
                "odoo-serialization-literal-eval-tainted",
                "Tainted data parsed with literal_eval",
                "medium",
                node.lineno,
                "ast.literal_eval() parses request, attachment, or integration data; "
                "prefer JSON/schema validation and enforce size/depth limits",
                sink,
            )
        elif (
            sink in JSON_LOAD_SINKS
            and _call_has_tainted_input(node, self._expr_is_tainted)
            and not self._current_function_has_size_guard()
        ):
            self._add(
                "odoo-serialization-json-load-no-size-check",
                "Tainted JSON parsed without visible size check",
                "medium",
                node.lineno,
                "json.load()/loads() parses request, attachment, or integration data without "
                "a visible size guard; enforce byte limits before parsing",
                sink,
            )
        elif sink in NUMPY_LOAD_SINKS and _numpy_load_allows_pickle(node, self._effective_constants()):
            severity = "critical" if _call_has_tainted_input(node, self._expr_is_tainted) else "high"
            self._add(
                "odoo-serialization-unsafe-deserialization",
                "Unsafe deserialization sink",
                severity,
                node.lineno,
                "numpy.load(..., allow_pickle=True) can load pickle object arrays; never use "
                "it on request, attachment, or integration data",
                sink,
            )
        elif sink in XML_TAINTED_PARSE_SINKS and _call_has_tainted_input(node, self._expr_is_tainted):
            self._add(
                "odoo-serialization-xml-fromstring-tainted",
                "Tainted XML parsed without hardened parser",
                "medium",
                node.lineno,
                "Request/attachment-derived XML is parsed without a hardened parser; "
                "review entity expansion, parser hardening, and size limits",
                sink,
            )
        elif sink in {"lxml.etree.XMLParser", "etree.XMLParser"} and _has_unsafe_xml_parser_option(
            node, self._effective_constants()
        ):
            self._add(
                "odoo-serialization-unsafe-xml-parser",
                "XML parser enables unsafe options",
                "high",
                node.lineno,
                "lxml XMLParser enables DTD/entity/network/huge-tree behavior; disable entity "
                "resolution, network access, and unbounded trees for imports, integrations, "
                "and attachments",
                sink,
            )
        self.generic_visit(node)

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_request_or_attachment_derived(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.tainted_names
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted(node.value) or self._expr_is_tainted(node.slice)
        if isinstance(node, ast.Attribute):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Call):
            return (
                self._is_request_or_attachment_derived(node)
                or self._expr_is_tainted(node.func)
                or any(self._expr_is_tainted(arg) for arg in node.args)
                or any(keyword.value is not None and self._expr_is_tainted(keyword.value) for keyword in node.keywords)
            )
        if isinstance(node, ast.JoinedStr):
            return any(self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.BinOp):
            return self._expr_is_tainted(node.left) or self._expr_is_tainted(node.right)
        if isinstance(node, ast.BoolOp):
            return any(self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.Compare):
            return self._expr_is_tainted(node.left) or any(
                self._expr_is_tainted(comparator) for comparator in node.comparators
            )
        if isinstance(node, ast.IfExp):
            return (
                self._expr_is_tainted(node.test)
                or self._expr_is_tainted(node.body)
                or self._expr_is_tainted(node.orelse)
            )
        if isinstance(node, ast.Dict):
            return any(value is not None and self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._expr_is_tainted(element) for element in node.elts)
        if isinstance(node, ast.Starred):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp):
            return self._expr_is_tainted(node.elt) or any(
                self._expr_is_tainted(generator.iter)
                or any(self._expr_is_tainted(condition) for condition in generator.ifs)
                for generator in node.generators
            )
        if isinstance(node, ast.DictComp):
            return (
                self._expr_is_tainted(node.key)
                or self._expr_is_tainted(node.value)
                or any(
                    self._expr_is_tainted(generator.iter)
                    or any(self._expr_is_tainted(condition) for condition in generator.ifs)
                    for generator in node.generators
                )
            )
        if isinstance(node, ast.NamedExpr):
            return self._expr_is_tainted(node.value)
        return False

    def _mark_tainted_target(self, target: ast.AST, value: ast.AST) -> None:
        is_tainted = self._is_request_or_attachment_derived(value) or self._expr_is_tainted(value)
        if isinstance(target, ast.Name):
            if is_tainted:
                self.tainted_names.add(target.id)
            else:
                self.tainted_names.discard(target.id)
            return

        if isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List):
                for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                    self._mark_tainted_target(target_element, value_element)
            elif is_tainted:
                for target_element in target.elts:
                    self._mark_name_target(target_element, self.tainted_names)
            else:
                for target_element in target.elts:
                    self._discard_name_target(target_element, self.tainted_names)
            return

        if isinstance(target, ast.Starred):
            self._mark_tainted_target(target.value, value)

    def _mark_name_target(self, target: ast.AST, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._mark_name_target(element, names)
        elif isinstance(target, ast.Starred):
            self._mark_name_target(target.value, names)

    def _discard_name_target(self, target: ast.AST, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.discard(target.id)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_name_target(element, names)
        elif isinstance(target, ast.Starred):
            self._discard_name_target(target.value, names)

    def _mark_local_constant_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_local_constant_target(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._mark_local_constant_target(target.value, value)
            return
        if isinstance(target, ast.Name):
            if _is_static_constant(value):
                self.local_constants[target.id] = value
            else:
                self.local_constants.pop(target.id, None)
            return
        for name in _target_names(target):
            self.local_constants.pop(name, None)

    def _canonical_call_name(self, node: ast.AST) -> str:
        sink = _call_name(node)
        if sink in self.function_aliases:
            return self.function_aliases[sink]
        for local_name, canonical_name in sorted(
            self.module_aliases.items(), key=lambda item: len(item[0]), reverse=True
        ):
            if sink == local_name or sink.startswith(f"{local_name}."):
                return f"{canonical_name}{sink[len(local_name):]}"
        return sink

    def _current_function_has_size_guard(self) -> bool:
        return bool(self.size_guard_stack and self.size_guard_stack[-1])

    def _is_request_or_attachment_derived(self, node: ast.AST) -> bool:
        return _is_request_or_attachment_derived(
            node, self.request_names, self.http_module_names, self.odoo_module_names
        )

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack and not self.local_constants:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        constants.update(self.local_constants)
        return constants

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, sink: str) -> None:
        self.findings.append(
            SerializationFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                sink=sink,
            )
        )


def _is_request_or_attachment_derived(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    if _is_request_source_expr(node, request_names, http_module_names, odoo_module_names):
        return True
    if isinstance(node, ast.Attribute):
        return _is_request_or_attachment_derived(node.value, request_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.Subscript):
        return _is_request_or_attachment_derived(
            node.value, request_names, http_module_names, odoo_module_names
        ) or _is_request_or_attachment_derived(node.slice, request_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.Call):
        return (
            _is_request_or_attachment_derived(node.func, request_names, http_module_names, odoo_module_names)
            or any(
                _is_request_or_attachment_derived(arg, request_names, http_module_names, odoo_module_names)
                for arg in node.args
            )
            or any(
                keyword.value is not None
                and _is_request_or_attachment_derived(
                    keyword.value, request_names, http_module_names, odoo_module_names
                )
                for keyword in node.keywords
            )
        )
    text = _safe_unparse(node)
    return any(marker in text for marker in SERIALIZATION_TEXT_MARKERS)


def _is_request_source_expr(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and _is_request_expr(node.value, request_names, http_module_names, odoo_module_names)
        and node.attr in REQUEST_SOURCE_ATTRS | REQUEST_SOURCE_METHODS
    )


def _is_request_expr(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in request_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "request"
        and _is_http_module_expr(node.value, http_module_names, odoo_module_names)
    )


def _unpack_target_value_pairs(
    target_elts: list[ast.expr], value_elts: list[ast.expr]
) -> list[tuple[ast.expr, ast.expr]]:
    starred_index = next(
        (index for index, element in enumerate(target_elts) if isinstance(element, ast.Starred)),
        None,
    )
    if starred_index is None:
        return list(zip(target_elts, value_elts, strict=False))

    after_count = len(target_elts) - starred_index - 1
    pairs = list(zip(target_elts[:starred_index], value_elts[:starred_index], strict=False))
    rest_end = len(value_elts) - after_count if after_count else len(value_elts)
    rest_values = value_elts[starred_index:rest_end]
    pairs.append((target_elts[starred_index], ast.List(elts=rest_values, ctx=ast.Load())))
    if after_count:
        pairs.extend(zip(target_elts[-after_count:], value_elts[-after_count:], strict=False))
    return pairs


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


def _call_has_tainted_input(node: ast.Call, is_tainted: Any) -> bool:
    return any(is_tainted(arg) for arg in node.args) or any(
        keyword.value is not None and is_tainted(keyword.value) for keyword in node.keywords
    )


def _has_safe_yaml_loader(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    for keyword in _expanded_keywords(node, constants):
        if (
            keyword.arg in {"Loader", "loader"}
            and _loader_name(_resolve_constant(keyword.value, constants)) in SAFE_YAML_LOADERS
        ):
            return True
    return False


def _has_unsafe_xml_parser_option(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    unsafe_true = {"resolve_entities", "load_dtd", "huge_tree"}
    for keyword in _expanded_keywords(node, constants or {}):
        if keyword.arg in unsafe_true and _keyword_value_is(keyword, True, constants):
            return True
        if keyword.arg == "no_network" and _keyword_value_is(keyword, False, constants):
            return True
    return False


def _numpy_load_allows_pickle(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    for keyword in _expanded_keywords(node, constants or {}):
        if keyword.arg == "allow_pickle" and _keyword_value_is(keyword, True, constants):
            return True
    return False


def _function_has_size_guard(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for statement in node.body:
        if any(hint in _safe_unparse(child) for child in ast.walk(statement) for hint in SIZE_GUARD_HINTS):
            return True
    return False


def _function_is_http_route(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    route_decorator_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    return any(
        _is_http_route(decorator, route_decorator_names, http_module_names, odoo_module_names)
        for decorator in node.decorator_list
    )


def _is_http_route(
    node: ast.AST,
    route_decorator_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    route_decorator_names = route_decorator_names or set()
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    target = node.func if isinstance(node, ast.Call) else node
    return (
        isinstance(target, ast.Attribute)
        and target.attr == "route"
        and _is_http_module_expr(target.value, http_module_names, odoo_module_names)
    ) or (isinstance(target, ast.Name) and target.id in route_decorator_names)


def _is_http_module_expr(
    node: ast.AST,
    http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in http_module_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "http"
        and isinstance(node.value, ast.Name)
        and node.value.id in odoo_module_names
    )


def _keyword_value_is(keyword: ast.keyword, expected: bool, constants: dict[str, ast.AST] | None = None) -> bool:
    value = _resolve_constant(keyword.value, constants or {})
    return isinstance(value, ast.Constant) and value.value is expected


def _loader_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _module_constants(tree: ast.Module) -> dict[str, ast.AST]:
    return _static_constants_from_body(tree.body)


def _static_constants_from_body(statements: list[ast.stmt]) -> dict[str, ast.AST]:
    constants: dict[str, ast.AST] = {}
    for statement in statements:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name) and _is_static_constant(statement.value):
                    constants[target.id] = statement.value
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.value is not None
            and _is_static_constant(statement.value)
        ):
            constants[statement.target.id] = statement.value
        elif isinstance(statement, ast.Expr):
            _mark_static_dict_update(statement.value, constants)
    return constants


def _expanded_keywords(node: ast.Call, constants: dict[str, ast.AST]) -> list[ast.keyword]:
    keywords: list[ast.keyword] = []
    for keyword in node.keywords:
        if keyword.arg is not None:
            keywords.append(keyword)
            continue
        value = _resolve_static_dict(keyword.value, constants)
        if value is not None:
            keywords.extend(_expanded_dict_keywords(value, constants))
    return keywords


def _expanded_dict_keywords(node: ast.Dict, constants: dict[str, ast.AST]) -> list[ast.keyword]:
    keywords: list[ast.keyword] = []
    for key, dict_value in zip(node.keys, node.values, strict=False):
        if key is None:
            value = _resolve_static_dict(dict_value, constants)
            if value is not None:
                keywords.extend(_expanded_dict_keywords(value, constants))
            continue
        resolved_key = _resolve_constant(key, constants)
        if isinstance(resolved_key, ast.Constant) and isinstance(resolved_key.value, str):
            keywords.append(ast.keyword(arg=resolved_key.value, value=dict_value))
    return keywords


def _resolve_constant(node: ast.AST, constants: dict[str, ast.AST], seen: set[str] | None = None) -> ast.AST:
    seen = seen or set()
    if isinstance(node, ast.Name):
        if node.id in seen:
            return node
        if node.id in constants:
            return _resolve_constant(constants[node.id], constants, seen | {node.id})
    return node


def _resolve_static_dict(
    node: ast.AST, constants: dict[str, ast.AST], seen: set[str] | None = None
) -> ast.Dict | None:
    seen = seen or set()
    node = _resolve_constant(node, constants, seen)
    if isinstance(node, ast.Dict):
        return node
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _resolve_static_dict(node.left, constants, set(seen))
        right = _resolve_static_dict(node.right, constants, set(seen))
        if left is None or right is None:
            return None
        return ast.Dict(keys=[*left.keys, *right.keys], values=[*left.values, *right.values])
    return None


def _mark_static_dict_update(node: ast.AST, constants: dict[str, ast.AST]) -> None:
    if not isinstance(node, ast.Call):
        return
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "update":
        return
    if not isinstance(node.func.value, ast.Name):
        return
    name = node.func.value.id
    values_node = _resolve_static_dict(ast.Name(id=name, ctx=ast.Load()), constants)
    if values_node is None:
        return
    for arg in node.args:
        arg_values = _resolve_static_dict(arg, constants)
        if arg_values is not None:
            for key, value in _dict_items(arg_values, constants):
                values_node = _dict_with_field(values_node, key, value)
    for keyword in node.keywords:
        if keyword.arg is not None:
            values_node = _dict_with_field(values_node, keyword.arg, keyword.value)
            continue
        keyword_values = _resolve_static_dict(keyword.value, constants)
        if keyword_values is not None:
            for key, value in _dict_items(keyword_values, constants):
                values_node = _dict_with_field(values_node, key, value)
    constants[name] = values_node


def _dict_items(node: ast.Dict, constants: dict[str, ast.AST]) -> list[tuple[str, ast.AST]]:
    items: list[tuple[str, ast.AST]] = []
    for key, value in zip(node.keys, node.values, strict=False):
        if key is None:
            nested = _resolve_static_dict(value, constants)
            if nested is not None:
                items.extend(_dict_items(nested, constants))
            continue
        resolved_key = _resolve_constant(key, constants)
        if isinstance(resolved_key, ast.Constant) and isinstance(resolved_key.value, str):
            items.append((resolved_key.value, value))
    return items


def _dict_with_field(values_node: ast.Dict, key: str, value: ast.AST) -> ast.Dict:
    keys = list(values_node.keys)
    values = list(values_node.values)
    for index, existing_key in enumerate(keys):
        if isinstance(existing_key, ast.Constant) and existing_key.value == key:
            values[index] = value
            return ast.Dict(keys=keys, values=values)
    keys.append(ast.Constant(value=key))
    values.append(value)
    return ast.Dict(keys=keys, values=values)


def _is_static_constant(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant | ast.Attribute | ast.Name):
        return True
    if isinstance(node, ast.Dict):
        return all(
            (key is None or (isinstance(key, ast.Constant) and isinstance(key.value, str)))
            and _is_static_constant(value)
            for key, value in zip(node.keys, node.values, strict=False)
        )
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(_is_static_constant(element) for element in node.elts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_static_constant(node.left) and _is_static_constant(node.right)
    return False


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""



def findings_to_json(findings: list[SerializationFinding]) -> list[dict[str, Any]]:
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
        }
        for f in findings
    ]
