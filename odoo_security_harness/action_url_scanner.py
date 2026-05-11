"""Scanner for risky Odoo ir.actions.act_url usage."""

from __future__ import annotations

import ast
import re
from csv import DictReader
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

from defusedxml import ElementTree


@dataclass
class ActionUrlFinding:
    """Represents a risky URL action finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    url: str = ""
    route: str = ""
    sink: str = ""
    record_id: str = ""


TAINTED_ARG_NAMES = {
    "callback_url",
    "kwargs",
    "kw",
    "next",
    "next_url",
    "post",
    "redirect_url",
    "return_url",
    "success_url",
    "target_url",
    "url",
}
ROUTE_ID_ARG_RE = re.compile(r"(?:^id$|_ids?$)")
REQUEST_MARKERS = (
    "kwargs.get",
    "kw.get",
    "post.get",
)
SENSITIVE_URL_MARKERS = ("access_token", "api_key", "apikey", "password", "secret", "token")


def scan_action_urls(repo_path: Path) -> list[ActionUrlFinding]:
    """Scan Python and XML files for risky act_url behavior."""
    findings: list[ActionUrlFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        if path.suffix == ".py":
            findings.extend(ActionUrlScanner(path).scan_python_file())
        elif path.suffix == ".xml":
            findings.extend(ActionUrlScanner(path).scan_xml_file())
        elif path.suffix == ".csv":
            findings.extend(ActionUrlScanner(path).scan_csv_file())
    return findings


class ActionUrlScanner(ast.NodeVisitor):
    """Scanner for one Python/XML file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.content = ""
        self.findings: list[ActionUrlFinding] = []
        self.tainted_names: set[str] = set()
        self.action_url_names: set[str] = set()
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.route_names: set[str] = set()
        self.route_stack: list[RouteContext] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}

    def scan_python_file(self) -> list[ActionUrlFinding]:
        """Scan Python code for returned act_url dictionaries."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(self.content)
        except SyntaxError:
            return []
        except Exception:
            return []

        self.constants = _module_constants(tree)
        self.visit(tree)
        return self.findings

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            if alias.name == "odoo":
                self.odoo_module_names.add(alias.asname or alias.name)
            elif alias.name == "odoo.http" and alias.asname:
                self.http_module_names.add(alias.asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module == "odoo":
            for alias in node.names:
                if alias.name == "http":
                    self.http_module_names.add(alias.asname or alias.name)
        elif node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
                elif alias.name == "route":
                    self.route_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def scan_xml_file(self) -> list[ActionUrlFinding]:
        """Scan XML records for ir.actions.act_url declarations."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            root = ElementTree.fromstring(self.content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        for record in root.iter("record"):
            if record.get("model") == "ir.actions.act_url":
                self._scan_action_url_record(record)
        return self.findings

    def scan_csv_file(self) -> list[ActionUrlFinding]:
        """Scan CSV records for ir.actions.act_url declarations."""
        if _csv_model_name(self.path) != "ir.actions.act.url":
            return []
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        for fields, line in _csv_dict_rows(self.content):
            self._scan_action_url_fields(fields, fields.get("id", ""), line)
        return self.findings

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_tainted = set(self.tainted_names)
        previous_action_url_names = set(self.action_url_names)
        previous_local_constants = self.local_constants
        self.local_constants = {}
        route = _route_info(
            node,
            self._effective_constants(),
            self.route_names,
            self.http_module_names,
            self.odoo_module_names,
        ) or RouteContext(is_route=False)
        self.route_stack.append(route)
        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES or (route.is_route and _looks_route_id_arg(arg.arg)):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.route_stack.pop()
        self.tainted_names = previous_tainted
        self.action_url_names = previous_action_url_names
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
            self._mark_action_url_target(target, node.value)
            self._scan_action_url_subscript_assignment(target, node.value, node.lineno)
            self._mark_tainted_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
            self._mark_action_url_target(node.target, node.value)
            self._scan_action_url_subscript_assignment(node.target, node.value, node.lineno)
            self._mark_tainted_target(node.target, node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_local_constant_target(node.target, node.value)
        self._mark_action_url_target(node.target, node.value)
        self._mark_tainted_target(node.target, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        self._mark_tainted_target(node.target, node.iter)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_Call(self, node: ast.Call) -> Any:
        self._scan_action_url_update_call(node)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> Any:
        fields = _dict_fields(node, self._effective_constants())
        if fields.get("type") == "ir.actions.act_url":
            self._scan_python_action_dict(node, fields)
        self.generic_visit(node)

    def _scan_python_action_dict(self, node: ast.Dict, fields: dict[str, str]) -> None:
        route = self._current_route()
        url_node = _dict_value(node, "url", self._effective_constants())
        url = fields.get("url", "")
        target = fields.get("target", "")

        if url_node is not None and self._expr_is_tainted(url_node):
            self._add(
                "odoo-act-url-tainted-url",
                "URL action uses request-controlled URL",
                "critical" if route.auth in {"public", "none"} else "high",
                node.lineno,
                "Returned ir.actions.act_url uses a request-derived URL; restrict to local paths or allowlisted hosts to prevent open redirect/navigation abuse",
                url,
                route,
                "python-dict",
            )

        if route.auth in {"public", "none"} and (
            _is_external_url(url) or url_node is not None and self._expr_is_tainted(url_node)
        ):
            self._add(
                "odoo-act-url-public-route",
                "Public route returns URL action",
                "high",
                node.lineno,
                "Public route returns ir.actions.act_url; verify unauthenticated users cannot drive external navigation or consume one-time links",
                url,
                route,
                "python-dict",
            )

        if target == "new" and _is_external_url(url):
            self._add(
                "odoo-act-url-external-new-window",
                "URL action opens external URL in new window",
                "medium",
                node.lineno,
                f"ir.actions.act_url opens external URL '{url}' with target='new'; review phishing, tabnabbing, and allowlist expectations",
                url,
                route,
                "python-dict",
            )

        if _has_unsafe_url_scheme(url):
            self._add(
                "odoo-act-url-unsafe-scheme",
                "URL action uses unsafe URL scheme",
                "high",
                node.lineno,
                f"ir.actions.act_url uses URL '{url}' with an unsafe scheme; restrict actions to local paths or allowlisted HTTPS destinations",
                url,
                route,
                "python-dict",
            )

        if _contains_sensitive_url_marker(url) or (
            url_node is not None and _expr_contains_sensitive_url_marker(url_node)
        ):
            self._add(
                "odoo-act-url-sensitive-url",
                "URL action contains sensitive parameter",
                "high",
                node.lineno,
                "ir.actions.act_url URL appears to contain token, secret, password, or API-key material; avoid exposing secrets in browser history and referrers",
                url,
                route,
                "python-dict",
            )

    def _scan_action_url_record(self, record: ElementTree.Element) -> None:
        fields = _record_fields(record)
        record_id = record.get("id", "")
        line = (
            _line_for(self.content, f'id="{record_id}"')
            if record_id
            else _line_for(self.content, 'model="ir.actions.act_url"')
        )
        self._scan_action_url_fields(fields, record_id, line)

    def _scan_action_url_fields(self, fields: dict[str, str], record_id: str, line: int) -> None:
        url = fields.get("url", "")
        groups = fields.get("groups_id", "") or fields.get("groups", "")
        target = fields.get("target", "")

        if _is_external_url(url) and not _has_group_restriction(groups):
            self._add(
                "odoo-act-url-external-no-groups",
                "External URL action has no groups",
                "medium",
                line,
                f"ir.actions.act_url '{record_id}' opens external URL '{url}' without groups; verify only intended users can trigger this navigation",
                url,
                RouteContext(is_route=False),
                "ir.actions.act_url",
                record_id,
            )

        if target == "new" and _is_external_url(url):
            self._add(
                "odoo-act-url-external-new-window",
                "URL action opens external URL in new window",
                "medium",
                line,
                f"ir.actions.act_url '{record_id}' opens external URL in a new window; review phishing, tabnabbing, and allowlist expectations",
                url,
                RouteContext(is_route=False),
                "ir.actions.act_url",
                record_id,
            )

        if _has_unsafe_url_scheme(url):
            self._add(
                "odoo-act-url-unsafe-scheme",
                "URL action uses unsafe URL scheme",
                "high",
                line,
                f"ir.actions.act_url '{record_id}' uses URL '{url}' with an unsafe scheme; restrict actions to local paths or allowlisted HTTPS destinations",
                url,
                RouteContext(is_route=False),
                "ir.actions.act_url",
                record_id,
            )

        if _contains_sensitive_url_marker(url):
            self._add(
                "odoo-act-url-sensitive-url",
                "URL action contains sensitive parameter",
                "high",
                line,
                f"ir.actions.act_url '{record_id}' URL appears to contain token, secret, password, or API-key material",
                url,
                RouteContext(is_route=False),
                "ir.actions.act_url",
                record_id,
            )

    def _scan_action_url_subscript_assignment(self, target: ast.AST, value: ast.AST, line: int) -> None:
        if not _is_subscript_key(target, "url", self._effective_constants()) or not isinstance(target, ast.Subscript):
            return
        if not self._expr_is_action_url(target.value):
            return
        self._scan_mutated_action_url(value, line, "python-dict-mutation")

    def _scan_action_url_update_call(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "update":
            return
        if not self._expr_is_action_url(node.func.value):
            return

        for arg in node.args:
            if isinstance(arg, ast.Dict):
                url_node = _dict_value(arg, "url", self._effective_constants())
                if url_node is not None:
                    self._scan_mutated_action_url(url_node, node.lineno, "python-dict-update")
        for keyword in node.keywords:
            if keyword.arg == "url":
                self._scan_mutated_action_url(keyword.value, node.lineno, "python-dict-update")

    def _scan_mutated_action_url(self, url_node: ast.AST, line: int, sink: str) -> None:
        route = self._current_route()
        url = _literal_string(url_node, self._effective_constants())

        if self._expr_is_tainted(url_node):
            self._add(
                "odoo-act-url-tainted-url",
                "URL action uses request-controlled URL",
                "critical" if route.auth in {"public", "none"} else "high",
                line,
                "ir.actions.act_url URL is assigned from request-derived data; restrict to local paths or allowlisted hosts to prevent open redirect/navigation abuse",
                url,
                route,
                sink,
            )

        if route.auth in {"public", "none"} and (_is_external_url(url) or self._expr_is_tainted(url_node)):
            self._add(
                "odoo-act-url-public-route",
                "Public route returns URL action",
                "high",
                line,
                "Public route mutates ir.actions.act_url; verify unauthenticated users cannot drive external navigation or consume one-time links",
                url,
                route,
                sink,
            )

        if _has_unsafe_url_scheme(url):
            self._add(
                "odoo-act-url-unsafe-scheme",
                "URL action uses unsafe URL scheme",
                "high",
                line,
                f"ir.actions.act_url uses URL '{url}' with an unsafe scheme; restrict actions to local paths or allowlisted HTTPS destinations",
                url,
                route,
                sink,
            )

        if _contains_sensitive_url_marker(url) or _expr_contains_sensitive_url_marker(url_node):
            self._add(
                "odoo-act-url-sensitive-url",
                "URL action contains sensitive parameter",
                "high",
                line,
                "ir.actions.act_url URL appears to contain token, secret, password, or API-key material; avoid exposing secrets in browser history and referrers",
                url,
                route,
                sink,
            )

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_request_derived(node):
            return True
        if isinstance(node, ast.NamedExpr):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.tainted_names
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted(node.value) or self._expr_is_tainted(node.slice)
        if isinstance(node, ast.Attribute):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Call):
            return (
                self._expr_is_tainted(node.func)
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
        return False

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(node, self.request_names, self.http_module_names, self.odoo_module_names)

    def _expr_is_action_url(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.action_url_names
        if isinstance(node, ast.Subscript):
            return _call_root_name(node) in self.action_url_names
        return False

    def _expr_creates_action_url(self, node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Dict)
            and _dict_fields(node, self._effective_constants()).get("type") == "ir.actions.act_url"
            or self._expr_is_action_url(node)
            or isinstance(node, ast.List | ast.Tuple | ast.Set)
            and any(self._expr_creates_action_url(element) for element in node.elts)
        )

    def _mark_tainted_target(self, target: ast.AST, value: ast.AST) -> None:
        is_tainted = self._expr_is_tainted(value)
        if isinstance(target, ast.Name):
            if is_tainted:
                self.tainted_names.add(target.id)
            else:
                self.tainted_names.discard(target.id)
            return

        if isinstance(target, ast.Starred):
            self._mark_tainted_target(target.value, value)
            return

        if isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List):
                for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                    self._mark_tainted_target(target_element, value_element)
            elif is_tainted:
                for target_element in target.elts:
                    self._mark_name_target(target_element, self.tainted_names)
            else:
                self._discard_name_target(target, self.tainted_names)

    def _mark_action_url_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Starred):
            self._mark_action_url_target(target.value, value)
            return

        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_action_url_target(target_element, value_element)
            return

        if self._expr_creates_action_url(value):
            self._mark_name_target(target, self.action_url_names)
        else:
            self._discard_name_target(target, self.action_url_names)

    def _mark_local_constant_target(self, target: ast.AST, value: ast.AST) -> None:
        if not self.route_stack:
            return

        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_local_constant_target(target_element, value_element)
            return

        if isinstance(target, ast.Name):
            if _is_static_literal(value):
                self.local_constants[target.id] = value
            else:
                self.local_constants.pop(target.id, None)
            return

        if isinstance(target, ast.Starred):
            self._mark_local_constant_target(target.value, value)
            return

        if isinstance(target, ast.Tuple | ast.List):
            self._discard_local_constant_target(target)

    def _discard_local_constant_target(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.local_constants.pop(target.id, None)
        elif isinstance(target, ast.Starred):
            self._discard_local_constant_target(target.value)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_local_constant_target(element)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.local_constants and not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        constants.update(self.local_constants)
        return constants

    def _mark_name_target(self, target: ast.AST, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Starred):
            self._mark_name_target(target.value, names)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._mark_name_target(element, names)

    def _discard_name_target(self, target: ast.AST, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.discard(target.id)
        elif isinstance(target, ast.Starred):
            self._discard_name_target(target.value, names)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_name_target(element, names)

    def _current_route(self) -> RouteContext:
        return self.route_stack[-1] if self.route_stack else RouteContext(is_route=False)

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        url: str,
        route: RouteContext,
        sink: str,
        record_id: str = "",
    ) -> None:
        self.findings.append(
            ActionUrlFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                url=url,
                route=route.display_path() if route.is_route else "",
                sink=sink,
                record_id=record_id,
            )
        )


@dataclass
class RouteContext:
    """Current route context."""

    is_route: bool
    auth: str = "user"
    paths: tuple[str, ...] = ()

    def display_path(self) -> str:
        return ",".join(self.paths) if self.paths else "<unknown>"


def _route_info(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    constants: dict[str, ast.AST] | None = None,
    route_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> RouteContext | None:
    constants = constants or {}
    route_names = route_names or set()
    for decorator in node.decorator_list:
        if not _is_http_route(decorator, route_names, http_module_names, odoo_module_names):
            continue
        auth = "user"
        paths: list[str] = []
        if isinstance(decorator, ast.Call):
            if decorator.args:
                paths.extend(_route_values(decorator.args[0], constants))
            for name, keyword_value in _expanded_keywords(decorator, constants):
                value = _resolve_constant(keyword_value, constants)
                if name == "auth" and isinstance(value, ast.Constant):
                    auth = str(value.value)
                elif name in {"route", "routes"}:
                    paths.extend(_route_values(keyword_value, constants))
        return RouteContext(is_route=True, auth=auth, paths=tuple(paths))
    return None


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


def _is_http_route(
    node: ast.AST,
    route_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    route_names = route_names or set()
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    if isinstance(node, ast.Call):
        return _is_http_route(node.func, route_names, http_module_names, odoo_module_names)
    if isinstance(node, ast.Name):
        return node.id in route_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "route"
        and _is_http_module_expr(node.value, http_module_names, odoo_module_names)
    )


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


def _route_values(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> list[str]:
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.List | ast.Tuple):
        return [
            str(value.value)
            for item in node.elts
            if isinstance((value := _resolve_constant(item, constants or {})), ast.Constant)
            and isinstance(value.value, str)
        ]
    return []


def _resolve_constant(node: ast.AST, constants: dict[str, ast.AST]) -> ast.AST:
    return _resolve_constant_seen(node, constants, set())


def _resolve_constant_seen(node: ast.AST, constants: dict[str, ast.AST], seen: set[str]) -> ast.AST:
    if isinstance(node, ast.Name):
        if node.id in seen:
            return node
        value = constants.get(node.id)
        if value is None:
            return node
        return _resolve_constant_seen(value, constants, {*seen, node.id})
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
            for key, value in zip(node.keys, node.values, strict=True)
        )
    return False


def _unpack_target_value_pairs(targets: list[ast.expr], values: list[ast.expr]) -> list[tuple[ast.expr, ast.AST]]:
    starred_index = next((index for index, target in enumerate(targets) if isinstance(target, ast.Starred)), None)
    if starred_index is None:
        return list(zip(targets, values, strict=False))

    before = list(zip(targets[:starred_index], values[:starred_index], strict=False))
    after_count = len(targets) - starred_index - 1
    after_values_start = max(len(values) - after_count, starred_index)
    rest_values = values[starred_index:after_values_start]
    rest_container: ast.expr = ast.List(elts=rest_values, ctx=ast.Load())
    after = list(zip(targets[starred_index + 1 :], values[after_values_start:], strict=False))
    return [*before, (targets[starred_index], rest_container), *after]


def _dict_fields(node: ast.Dict, constants: dict[str, ast.AST] | None = None) -> dict[str, str]:
    constants = constants or {}
    fields: dict[str, str] = {}
    for key, value in zip(node.keys, node.values, strict=False):
        key_value = _literal_string(key, constants)
        if key_value:
            fields[key_value] = _literal_string(value, constants)
    return fields


def _dict_value(node: ast.Dict, name: str, constants: dict[str, ast.AST] | None = None) -> ast.AST | None:
    constants = constants or {}
    for key, value in zip(node.keys, node.values, strict=False):
        if _literal_string(key, constants) == name:
            return value
    return None


def _is_subscript_key(node: ast.AST, key: str, constants: dict[str, ast.AST] | None = None) -> bool:
    if not isinstance(node, ast.Subscript):
        return False
    return _literal_string(node.slice, constants or {}) == key


def _record_fields(record: ElementTree.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    for field in record.iter("field"):
        name = field.get("name")
        if not name:
            continue
        values[name] = field.get("ref") or field.get("eval") or "".join(field.itertext()).strip()
    return values


def _csv_model_name(path: Path) -> str:
    return path.stem.strip().lower().replace("_", ".")


def _csv_dict_rows(content: str) -> list[tuple[dict[str, str], int]]:
    try:
        reader = DictReader(StringIO(content))
    except Exception:
        return []
    if not reader.fieldnames:
        return []

    rows: list[tuple[dict[str, str], int]] = []
    try:
        for index, row in enumerate(reader, start=2):
            normalized: dict[str, str] = {}
            for key, value in row.items():
                if key is None:
                    continue
                name = str(key).strip().lower()
                text = str(value or "").strip()
                normalized[name] = text
                if "/" in name:
                    normalized.setdefault(name.split("/", 1)[0], text)
            rows.append((normalized, index))
    except Exception:
        return []
    return rows


def _literal_string(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> str:
    if node is None:
        return ""
    resolved = _resolve_constant(node, constants or {})
    if isinstance(resolved, ast.Constant) and isinstance(resolved.value, str):
        return resolved.value
    return ""


def _is_external_url(url: str) -> bool:
    stripped = url.strip()
    return bool(re.match(r"(?i)^(https?:)?//", stripped)) and not re.match(
        r"(?i)^(https?:)?//[^/]*(localhost|127\\.0\\.0\\.1)", stripped
    )


def _has_group_restriction(value: str) -> bool:
    compact = re.sub(r"\s+", "", value).strip("'\"").lower()
    return compact not in {"", "[]", "()", "false", "none", "0", "[(5,0,0)]", "[(6,0,[])]", "[(6,0,())]"}


def _has_unsafe_url_scheme(url: str) -> bool:
    return bool(re.match(r"(?i)^\s*(javascript|vbscript|data|file):", url))


def _contains_sensitive_url_marker(url: str) -> bool:
    lowered = url.lower()
    return any(marker in lowered for marker in SENSITIVE_URL_MARKERS)


def _expr_contains_sensitive_url_marker(node: ast.AST) -> bool:
    return _contains_sensitive_url_marker(_safe_unparse(node))


def _looks_route_id_arg(name: str) -> bool:
    return bool(ROUTE_ID_ARG_RE.search(name))


def _is_request_derived(
    node: ast.AST,
    request_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    request_names = request_names or {"request"}
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    if _is_request_expr(node, request_names, http_module_names, odoo_module_names):
        return True
    if isinstance(node, ast.Attribute):
        if node.attr in {"params", "jsonrequest", "httprequest"} and _is_request_expr(
            node.value,
            request_names,
            http_module_names,
            odoo_module_names,
        ):
            return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"get_http_params", "get_json_data"} and _is_request_expr(
            node.func.value,
            request_names,
            http_module_names,
            odoo_module_names,
        ):
            return True
    text = _safe_unparse(node)
    return any(marker in text for marker in REQUEST_MARKERS)


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


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _line_for(content: str, needle: str) -> int:
    index = content.find(needle)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[ActionUrlFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "url": f.url,
            "route": f.route,
            "sink": f.sink,
            "record_id": f.record_id,
        }
        for f in findings
    ]
