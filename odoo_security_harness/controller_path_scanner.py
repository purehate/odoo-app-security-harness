"""Scanner for path traversal vulnerabilities in Odoo controllers.

Detects unsafe file path construction in controller methods where user-controlled
input flows into path operations without visible sanitization.

CVE coverage:
- CVE-2024-45840: Arbitrary source code download via asset path manipulation
- CVE-2021-44475: Local file read via asset file generation path abuse
- CVE-2021-44476: Sandbox escape → local file read
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ControllerPathFinding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    sink: str


@dataclass
class _RouteContext:
    is_route: bool = False
    auth: str = "user"


@dataclass
class _ScannerState:
    route_stack: list[_RouteContext] = field(default_factory=lambda: [_RouteContext()])
    tainted_vars: set[str] = field(default_factory=set)
    has_basename_sanitization: bool = False
    has_traversal_check: bool = False


class ControllerPathScanner(ast.NodeVisitor):
    """AST scanner for path traversal in controllers."""

    PATH_SINK_METHODS = {
        "open",
        "os.path.join",
        "os.path.abspath",
        "os.path.realpath",
        "os.path.normpath",
        "os.path.expanduser",
        "os.listdir",
        "os.walk",
        "os.remove",
        "os.unlink",
        "os.rename",
        "os.replace",
        "shutil.copy",
        "shutil.copy2",
        "shutil.move",
        "shutil.rmtree",
        "pathlib.Path",
        "Path",
    }

    SEND_FILE_METHODS = {
        "send_file",
        "send_from_directory",
        "send_static_file",
    }

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[ControllerPathFinding] = []
        self.state = _ScannerState()
        self._constants: dict[str, ast.AST] = {}
        self._route_names: set[str] = set()
        self._http_module_names: set[str] = set()

    def scan_file(self) -> list[ControllerPathFinding]:
        try:
            source = self.path.read_text(encoding="utf-8")
        except Exception:
            return []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        self._collect_imports(tree)
        self._constants = self._module_constants(tree)
        self.visit(tree)
        return self.findings

    def _collect_imports(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "odoo":
                        self._http_module_names.add("odoo")
            elif isinstance(node, ast.ImportFrom):
                if node.module == "odoo" and node.names:
                    for alias in node.names:
                        if alias.name == "http":
                            self._http_module_names.add("http")
                if node.module in {"odoo.http", "odoo", "http"}:
                    for alias in node.names:
                        if alias.name == "route":
                            self._route_names.add(alias.asname or alias.name)

    def _module_constants(self, tree: ast.Module) -> dict[str, ast.AST]:
        constants: dict[str, ast.AST] = {}
        for statement in tree.body:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Name) and self._is_static_literal(statement.value):
                        constants[target.id] = statement.value
            elif (
                isinstance(statement, ast.AnnAssign)
                and isinstance(statement.target, ast.Name)
                and statement.value is not None
                and self._is_static_literal(statement.value)
            ):
                constants[statement.target.id] = statement.value
        return constants

    def _is_static_literal(self, node: ast.AST) -> bool:
        return isinstance(node, (ast.Constant, ast.List, ast.Tuple, ast.Dict, ast.Set))

    def _current_route(self) -> _RouteContext:
        return self.state.route_stack[-1]

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> Any:
        route = self._route_info(node)
        self.state.route_stack.append(route)
        self.state.tainted_vars = set()
        self.state.has_basename_sanitization = False
        self.state.has_traversal_check = False
        self.generic_visit(node)
        self.state.route_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        self._track_tainted_assignment(node)
        self._track_path_sanitization(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._check_path_traversal_sink(node)
        self._check_unsafe_send_file(node)
        self.generic_visit(node)

    def _track_tainted_assignment(self, node: ast.Assign) -> None:
        if not self._current_route().is_route:
            return
        is_tainted = self._expr_is_tainted(node.value)
        if not is_tainted:
            return
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.state.tainted_vars.add(target.id)

    def _track_path_sanitization(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            func_name = self._call_name(node.value.func)
            if func_name in {"os.path.basename", "basename", "pathlib.Path.resolve", "Path.resolve", "os.path.realpath", "realpath"}:
                self.state.has_basename_sanitization = True
            if func_name in {"os.path.commonprefix", "os.path.abspath"}:
                self.state.has_traversal_check = True

    def _check_path_traversal_sink(self, node: ast.Call) -> None:
        route = self._current_route()
        if not route.is_route:
            return
        func_name = self._call_name(node.func)
        if not self._is_path_sink(node.func, func_name):
            return
        has_tainted_arg = any(self._expr_is_tainted(arg) for arg in node.args)
        has_tainted_kwarg = any(
            self._expr_is_tainted(kw.value) for kw in node.keywords
        )
        if not has_tainted_arg and not has_tainted_kwarg:
            return
        if self.state.has_basename_sanitization or self.state.has_traversal_check:
            return
        severity = "high" if route.auth in {"public", "none"} else "medium"
        self._add(
            "odoo-controller-path-traversal",
            "Controller constructs file path with user input",
            severity,
            node.lineno,
            f"Controller calls {func_name} with request-controlled path component; "
            "validate with os.path.basename(), restrict to allowlisted directory, "
            "and block traversal sequences (../, ..\\)",
            func_name,
        )

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Detect Path() / tainted_var (pathlib path joining)."""
        route = self._current_route()
        if not route.is_route:
            self.generic_visit(node)
            return
        # Check for Path(...) / something or something / Path(...)
        if not isinstance(node.op, ast.Div):
            self.generic_visit(node)
            return
        left_is_path = self._is_path_constructor(node.left)
        right_is_path = self._is_path_constructor(node.right)
        has_tainted = self._expr_is_tainted(node.left) or self._expr_is_tainted(node.right)
        if (left_is_path or right_is_path) and has_tainted:
            if not (self.state.has_basename_sanitization or self.state.has_traversal_check):
                severity = "high" if route.auth in {"public", "none"} else "medium"
                self._add(
                    "odoo-controller-path-traversal",
                    "Controller constructs file path with user input",
                    severity,
                    node.lineno,
                    "Controller joins Path with request-controlled component using / operator; "
                    "validate with os.path.basename(), restrict to allowlisted directory, "
                    "and block traversal sequences (../, ..\\)",
                    "Path /",
                )
        self.generic_visit(node)

    def _is_path_constructor(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Call):
            name = self._call_name(node.func)
            return name in {"Path", "pathlib.Path", "PosixPath", "WindowsPath", "PurePath"}
        return False

    def _check_unsafe_send_file(self, node: ast.Call) -> None:
        route = self._current_route()
        if not route.is_route:
            return
        func_name = self._call_name(node.func)
        base = func_name.rsplit(".", 1)[-1]
        if base not in self.SEND_FILE_METHODS:
            return
        if not node.args:
            return
        first_arg = node.args[0]
        if not self._expr_is_tainted(first_arg):
            return
        if self.state.has_basename_sanitization:
            return
        severity = "high" if route.auth in {"public", "none"} else "medium"
        self._add(
            "odoo-controller-unsafe-send-file",
            "Controller sends file from request-controlled path",
            severity,
            node.lineno,
            f"Controller calls {func_name} with request-controlled path; "
            "validate attachment ownership, basename, traversal, and storage root",
            func_name,
        )

    def _is_path_sink(self, func: ast.expr, func_name: str) -> bool:
        if func_name in self.PATH_SINK_METHODS:
            return True
        if isinstance(func, ast.Attribute) and func.attr in {
            "join", "resolve", "absolute", "relative_to", "with_name", "with_suffix"
        }:
            return True
        return False

    def _expr_is_tainted(self, node: ast.expr | None) -> bool:
        if node is None:
            return False
        if self._is_request_params(node) or self._is_request_params_subscript(node):
            return True
        if isinstance(node, ast.Name) and node.id in self.state.tainted_vars:
            return True
        if isinstance(node, ast.BinOp):
            return self._expr_is_tainted(node.left) or self._expr_is_tainted(node.right)
        if isinstance(node, ast.JoinedStr):
            return any(
                self._expr_is_tainted(v.value)
                for v in node.values
                if isinstance(v, ast.FormattedValue)
            )
        if isinstance(node, ast.Call):
            # Method calls on tainted objects are tainted (e.g. request.params.get('file'))
            if isinstance(node.func, ast.Attribute) and self._expr_is_tainted(node.func.value):
                return True
            return any(self._expr_is_tainted(arg) for arg in node.args)
        if isinstance(node, ast.Attribute) and self._expr_is_tainted(node.value):
            return True
        return False

    def _is_request_params(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Attribute):
            if node.attr == "params":
                if isinstance(node.value, ast.Name) and node.value.id == "request":
                    return True
                if isinstance(node.value, ast.Attribute) and node.value.attr == "http":
                    if isinstance(node.value.value, ast.Name) and node.value.value.id == "request":
                        return True
        return False

    def _is_request_params_subscript(self, node: ast.expr) -> bool:
        if not isinstance(node, ast.Subscript):
            return False
        if not isinstance(node.value, ast.Attribute):
            return False
        return self._is_request_params(node.value)

    def _call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{self._call_name(node.value)}.{node.attr}"
        return ""

    def _route_info(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> _RouteContext:
        for decorator in node.decorator_list:
            if self._is_http_route(decorator):
                auth = "user"
                if isinstance(decorator, ast.Call):
                    for kw in decorator.keywords:
                        if kw.arg == "auth" and isinstance(kw.value, ast.Constant):
                            auth = str(kw.value.value)
                return _RouteContext(is_route=True, auth=auth)
        return _RouteContext()

    def _is_http_route(self, decorator: ast.expr) -> bool:
        if isinstance(decorator, ast.Call):
            func = decorator.func
            if isinstance(func, ast.Attribute) and func.attr == "route":
                if isinstance(func.value, ast.Name) and func.value.id in self._route_names:
                    return True
                if isinstance(func.value, ast.Name) and func.value.id in self._http_module_names:
                    return True
                if isinstance(func.value, ast.Attribute) and func.value.attr == "http":
                    return True
            if isinstance(func, ast.Name) and func.id in self._route_names:
                return True
        elif isinstance(decorator, ast.Attribute) and decorator.attr == "route":
            return True
        return False

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        sink: str,
    ) -> None:
        self.findings.append(
            ControllerPathFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                sink=sink,
            )
        )


def scan_controller_paths(repo_path: Path) -> list[ControllerPathFinding]:
    findings: list[ControllerPathFinding] = []
    for path in repo_path.rglob("*.py"):
        if path.name.startswith(".") or "__pycache__" in str(path):
            continue
        findings.extend(ControllerPathScanner(path).scan_file())
    return findings
