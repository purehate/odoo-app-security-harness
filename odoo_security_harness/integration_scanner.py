"""Scanner for risky outbound integrations in Odoo Python code."""

from __future__ import annotations

import ast
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


@dataclass
class IntegrationFinding:
    """Represents an outbound integration/security boundary finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    sink: str = ""


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "request", "head", "urlopen"}
REQUEST_MODULES = {"aiohttp", "requests", "httpx", "urllib.request"}
HTTP_CLIENT_FACTORIES = {"AsyncClient", "Client", "ClientSession", "Session"}
TAINTED_ARG_NAMES = {
    "args",
    "cmd",
    "command",
    "endpoint",
    "path",
    "script",
    "target",
    "uri",
    "url",
    "callback",
    "callback_url",
    "webhook_url",
}
COMMAND_TIMEOUT_SINKS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}
REPORT_COMMAND_HINTS = {"wkhtmltopdf", "libreoffice", "soffice", "unoconv", "convert"}
SENSITIVE_OUTBOUND_HEADER_NAMES = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-forwarded-authorization",
}
LOW_VALUE_SECRET_PLACEHOLDERS = {"changeme", "change_me", "example", "dummy", "password", "secret", "token", "admin"}
METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
}
REQUEST_SOURCE_ATTRS = {"httprequest", "jsonrequest", "params"}
REQUEST_SOURCE_METHODS = {"get_http_params", "get_json_data"}
REQUEST_TEXT_MARKERS = ("kwargs.get", "kw.get", "post.get")


def scan_integrations(repo_path: Path) -> list[IntegrationFinding]:
    """Scan Python files for risky outbound HTTP and command execution."""
    findings: list[IntegrationFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(IntegrationScanner(path).scan_file())
    return findings


class IntegrationScanner(ast.NodeVisitor):
    """AST visitor for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[IntegrationFinding] = []
        self.tainted_names: set[str] = set()
        self.http_module_names: dict[str, str] = {module: module for module in REQUEST_MODULES}
        self.http_function_names: dict[str, str] = {}
        self.http_client_names: set[str] = set()
        self.tainted_auth_header_names: set[str] = set()
        self.hardcoded_auth_header_names: set[str] = set()
        self.hardcoded_http_auth_names: set[str] = set()
        self.command_module_names: dict[str, str] = {"os": "os", "subprocess": "subprocess"}
        self.command_function_names: dict[str, str] = {}
        self.request_names: set[str] = {"request"}
        self.odoo_http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.constants: dict[str, ast.AST] = {}
        self.local_constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []

    def scan_file(self) -> list[IntegrationFinding]:
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
        previous_tainted = set(self.tainted_names)
        previous_http_clients = set(self.http_client_names)
        previous_tainted_auth_headers = set(self.tainted_auth_header_names)
        previous_hardcoded_auth_headers = set(self.hardcoded_auth_header_names)
        previous_hardcoded_http_auth_names = set(self.hardcoded_http_auth_names)
        previous_local_constants = self.local_constants
        self.local_constants = {}
        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES or arg.arg in {"kwargs", "kw", "post"}:
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.tainted_names = previous_tainted
        self.http_client_names = previous_http_clients
        self.tainted_auth_header_names = previous_tainted_auth_headers
        self.hardcoded_auth_header_names = previous_hardcoded_auth_headers
        self.hardcoded_http_auth_names = previous_hardcoded_http_auth_names
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            local_name = alias.asname or alias.name.split(".", 1)[0]
            if alias.name in REQUEST_MODULES:
                self.http_module_names[local_name] = alias.name
            elif alias.name in {"os", "subprocess"}:
                self.command_module_names[local_name] = alias.name
            elif alias.name == "odoo":
                self.odoo_module_names.add(alias.asname or alias.name)
            elif alias.name == "odoo.http" and alias.asname:
                self.odoo_http_module_names.add(alias.asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module in REQUEST_MODULES:
            for alias in node.names:
                if alias.name in HTTP_METHODS:
                    self.http_function_names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
                elif alias.name in HTTP_CLIENT_FACTORIES:
                    self.http_function_names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif node.module == "urllib":
            for alias in node.names:
                if alias.name == "request":
                    self.http_module_names[alias.asname or alias.name] = "urllib.request"
        elif node.module == "odoo":
            for alias in node.names:
                if alias.name == "http":
                    self.odoo_http_module_names.add(alias.asname or alias.name)
        elif node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
        elif node.module in {"os", "subprocess"}:
            for alias in node.names:
                canonical = f"{node.module}.{alias.name}"
                if _is_command_call(canonical):
                    self.command_function_names[alias.asname or alias.name] = canonical
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        previous_http_clients = set(self.http_client_names)
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
            self._mark_tainted_target(target, node.value)
            self._mark_http_client_target(target, node.value, previous_http_clients)
            self._mark_tainted_auth_header_target(target, node.value)
            self._mark_hardcoded_auth_header_target(target, node.value)
            self._mark_hardcoded_http_auth_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            previous_http_clients = set(self.http_client_names)
            self._mark_local_constant_target(node.target, node.value)
            self._mark_tainted_target(node.target, node.value)
            self._mark_http_client_target(node.target, node.value, previous_http_clients)
            self._mark_tainted_auth_header_target(node.target, node.value)
            self._mark_hardcoded_auth_header_target(node.target, node.value)
            self._mark_hardcoded_http_auth_target(node.target, node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        previous_http_clients = set(self.http_client_names)
        self._mark_local_constant_target(node.target, node.value)
        self._mark_tainted_target(node.target, node.value)
        self._mark_http_client_target(node.target, node.value, previous_http_clients)
        self._mark_tainted_auth_header_target(node.target, node.value)
        self._mark_hardcoded_auth_header_target(node.target, node.value)
        self._mark_hardcoded_http_auth_target(node.target, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        if self._expr_is_tainted(node.iter):
            self._mark_name_target(node.target, self.tainted_names)
        else:
            self._discard_name_target(node.target, self.tainted_names)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_With(self, node: ast.With) -> Any:
        previous_http_clients = set(self.http_client_names)
        for item in node.items:
            if item.optional_vars is not None:
                self._mark_http_client_target(item.optional_vars, item.context_expr, previous_http_clients)
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> Any:
        self.visit_With(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        canonical_sink = self._canonical_sink(sink)
        if self._is_http_call(canonical_sink):
            self._scan_http_call(node, sink, canonical_sink)
        elif _is_command_call(canonical_sink):
            self._scan_command_call(node, sink, canonical_sink)
        self.generic_visit(node)

    def _scan_http_call(self, node: ast.Call, sink: str, canonical_sink: str) -> None:
        if not _has_effective_timeout(node, self._effective_constants()):
            self._add(
                "odoo-integration-http-no-timeout",
                "Outbound HTTP call has no timeout",
                "medium",
                node.lineno,
                "Outbound HTTP call lacks a timeout; a slow upstream can exhaust Odoo workers",
                sink,
            )
        if any(
            _value_is(value, False, self._effective_constants())
            for value in _keyword_values(node, "verify", self._effective_constants())
        ):
            self._add(
                "odoo-integration-tls-verify-disabled",
                "Outbound HTTP disables TLS verification",
                "high",
                node.lineno,
                "Outbound HTTP call passes verify=False; this permits man-in-the-middle attacks against integration traffic",
                sink,
            )
        for url_arg in _positional_http_url_args(node, canonical_sink):
            if self._expr_is_tainted(url_arg):
                self._add(
                    "odoo-integration-tainted-url-ssrf",
                    "Outbound HTTP URL is request-controlled",
                    "high",
                    node.lineno,
                    "Outbound HTTP URL is derived from request/controller input; validate scheme, host, and private-network reachability to prevent SSRF",
                    sink,
                )
            if _is_internal_literal_url(url_arg, self._effective_constants()):
                self._add(
                    "odoo-integration-internal-url-ssrf",
                    "Outbound HTTP targets internal URL",
                    "high",
                    node.lineno,
                    "Outbound HTTP call targets a literal loopback, private, link-local, or metadata URL; verify the integration cannot expose cloud metadata or internal Odoo/admin services",
                    sink,
                )
            if _is_cleartext_literal_url(url_arg, self._effective_constants()):
                self._add(
                    "odoo-integration-cleartext-http-url",
                    "Outbound integration uses cleartext HTTP URL",
                    "medium",
                    node.lineno,
                    "Outbound HTTP call targets a literal http:// URL; use HTTPS to protect integration payloads and response data from interception or downgrade",
                    sink,
                )
        for url_value in _keyword_values(node, "url", self._effective_constants()):
            if self._expr_is_tainted(url_value):
                self._add(
                    "odoo-integration-tainted-url-ssrf",
                    "Outbound HTTP URL is request-controlled",
                    "high",
                    node.lineno,
                    "Outbound HTTP url= value is derived from request/controller input; validate scheme, host, and private-network reachability to prevent SSRF",
                    sink,
                )
            if _is_internal_literal_url(url_value, self._effective_constants()):
                self._add(
                    "odoo-integration-internal-url-ssrf",
                    "Outbound HTTP targets internal URL",
                    "high",
                    node.lineno,
                    "Outbound HTTP url= targets a literal loopback, private, link-local, or metadata URL; verify the integration cannot expose cloud metadata or internal Odoo/admin services",
                    sink,
                )
            if _is_cleartext_literal_url(url_value, self._effective_constants()):
                self._add(
                    "odoo-integration-cleartext-http-url",
                    "Outbound integration uses cleartext HTTP URL",
                    "medium",
                    node.lineno,
                    "Outbound HTTP url= targets a literal http:// URL; use HTTPS to protect integration payloads and response data from interception or downgrade",
                    sink,
                )
        for proxy_keyword_name in ("proxy", "proxies"):
            if any(self._expr_is_tainted(value) for value in _keyword_values(node, proxy_keyword_name, self._effective_constants())):
                self._add(
                    "odoo-integration-tainted-proxy",
                    "Outbound HTTP proxy is request-controlled",
                    "high",
                    node.lineno,
                    "Outbound HTTP proxy configuration is derived from request/controller input; ensure attackers cannot redirect integration traffic through controlled proxies",
                    sink,
                )
        self._scan_auth_material(node, sink)

    def _scan_auth_material(self, node: ast.Call, sink: str) -> None:
        header_values = _keyword_values(node, "headers", self._effective_constants())
        if any(self._expr_contains_tainted_sensitive_header(value) for value in header_values):
            self._add(
                "odoo-integration-tainted-auth-header",
                "Outbound HTTP auth header uses request-controlled value",
                "high",
                node.lineno,
                "Outbound HTTP forwards request-derived Authorization, Cookie, API key, or token header material; ensure credentials come from trusted server-side configuration and cannot be attacker supplied",
                sink,
            )
        if any(self._expr_contains_hardcoded_sensitive_header(value) for value in header_values):
            self._add(
                "odoo-integration-hardcoded-auth-header",
                "Outbound HTTP auth header is hardcoded",
                "high",
                node.lineno,
                "Outbound HTTP sends literal Authorization, Cookie, API key, or token header material; move integration credentials to trusted server-side configuration and rotate any value committed to source",
                sink,
            )
        auth_values = _keyword_values(node, "auth", self._effective_constants())
        if any(self._expr_is_tainted(value) for value in auth_values):
            self._add(
                "odoo-integration-tainted-http-auth",
                "Outbound HTTP auth parameter uses request-controlled value",
                "high",
                node.lineno,
                "Outbound HTTP auth= material is request-derived; ensure upstream credentials come from trusted server-side configuration and cannot be attacker supplied",
                sink,
            )
        if any(self._expr_contains_hardcoded_http_auth(value) for value in auth_values):
            self._add(
                "odoo-integration-hardcoded-http-auth",
                "Outbound HTTP auth parameter is hardcoded",
                "high",
                node.lineno,
                "Outbound HTTP auth= material contains literal credential-like values; move integration credentials to trusted server-side configuration and rotate any value committed to source",
                sink,
            )

    def _scan_command_call(self, node: ast.Call, sink: str, canonical_sink: str) -> None:
        command = node.args[0] if node.args else None
        command_is_tainted = command is not None and self._expr_is_tainted(command)

        if any(_value_is(value, True, self._effective_constants()) for value in _keyword_values(node, "shell", self._effective_constants())):
            severity = "high" if command_is_tainted else "medium"
            self._add(
                "odoo-integration-subprocess-shell-true",
                "Subprocess uses shell=True",
                severity,
                node.lineno,
                "subprocess call uses shell=True; verify no user-controlled command text can reach this sink",
                sink,
            )

        if canonical_sink in {"os.system", "os.popen"}:
            severity = "critical" if command_is_tainted else "high"
            self._add(
                "odoo-integration-os-command-execution",
                "OS command execution sink",
                severity,
                node.lineno,
                f"{sink} executes through the shell; replace with bounded subprocess argument lists and validate command inputs",
                sink,
            )

        if command_is_tainted:
            self._add(
                "odoo-integration-tainted-command-args",
                "Process command uses request-controlled input",
                "high",
                node.lineno,
                "Process command or arguments are derived from request/controller input; validate allowlisted commands, arguments, paths, and environment",
                sink,
            )

        if canonical_sink in COMMAND_TIMEOUT_SINKS and not _has_effective_timeout(node, self._effective_constants()):
            self._add(
                "odoo-integration-process-no-timeout",
                "Process execution has no timeout",
                "medium",
                node.lineno,
                "Process execution lacks timeout; external converters and commands can hang Odoo workers",
                sink,
            )

        if command is not None and _contains_report_command(command):
            self._add(
                "odoo-integration-report-command-review",
                "External report/document converter command",
                "medium",
                node.lineno,
                "Command invokes an external report/document converter; verify input file control, output path safety, timeout, and sandboxing",
                sink,
            )

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_request_derived(node):
            return True
        if isinstance(node, ast.Starred):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.NamedExpr):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.tainted_names
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted(node.value) or self._expr_is_tainted(node.slice)
        if isinstance(node, ast.Call):
            return (
                self._is_request_derived(node)
                or self._expr_is_tainted(node.func)
                or any(self._expr_is_tainted(arg) for arg in node.args)
                or any(keyword.value is not None and self._expr_is_tainted(keyword.value) for keyword in node.keywords)
            )
        if isinstance(node, ast.Attribute):
            return self._expr_is_tainted(node.value)
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

    def _mark_tainted_target(self, target: ast.AST, value: ast.AST) -> None:
        is_tainted = self._is_request_derived(value) or self._expr_is_tainted(value)
        if isinstance(target, ast.Starred):
            self._mark_tainted_target(target.value, value)
            return
        if isinstance(target, ast.Name):
            if is_tainted:
                self.tainted_names.add(target.id)
            else:
                self.tainted_names.discard(target.id)
            return

        if isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List):
                for target_element, value_element in _unpack_target_value_pairs(target, value):
                    self._mark_tainted_target(target_element, value_element)
            elif is_tainted:
                for target_element in target.elts:
                    self._mark_name_target(target_element, self.tainted_names)
            else:
                self._discard_name_target(target, self.tainted_names)

    def _mark_http_client_target(self, target: ast.AST, value: ast.AST, http_client_names: set[str]) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_http_client_target(target_element, value_element, http_client_names)
            return

        if self._is_http_client_expr(value, http_client_names):
            self._mark_name_target(target, self.http_client_names)
        else:
            self._discard_name_target(target, self.http_client_names)

    def _mark_tainted_auth_header_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_tainted_auth_header_target(target_element, value_element)
            return

        if self._expr_contains_tainted_sensitive_header(value):
            self._mark_name_target(target, self.tainted_auth_header_names)
        else:
            self._discard_name_target(target, self.tainted_auth_header_names)

    def _mark_hardcoded_auth_header_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_hardcoded_auth_header_target(target_element, value_element)
            return

        if self._expr_contains_hardcoded_sensitive_header(value):
            self._mark_name_target(target, self.hardcoded_auth_header_names)
        else:
            self._discard_name_target(target, self.hardcoded_auth_header_names)

    def _expr_contains_tainted_sensitive_header(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Starred):
            return self._expr_contains_tainted_sensitive_header(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.tainted_auth_header_names
        if isinstance(node, ast.Subscript):
            return self._expr_contains_tainted_sensitive_header(node.value)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            if any(self._expr_contains_tainted_sensitive_header(element) for element in node.elts):
                return True
        for header_name, value in _literal_header_pairs_with_constants(node, self._effective_constants()):
            if _is_sensitive_outbound_header(header_name) and self._expr_is_tainted(value):
                return True
        return False

    def _expr_contains_hardcoded_sensitive_header(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Starred):
            return self._expr_contains_hardcoded_sensitive_header(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.hardcoded_auth_header_names
        if isinstance(node, ast.Subscript):
            return self._expr_contains_hardcoded_sensitive_header(node.value)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            if any(self._expr_contains_hardcoded_sensitive_header(element) for element in node.elts):
                return True
        for header_name, value in _literal_header_pairs_with_constants(node, self._effective_constants()):
            if _is_sensitive_outbound_header(header_name) and _is_hardcoded_secret_value(value, self._effective_constants()):
                return True
        return False

    def _expr_contains_hardcoded_http_auth(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Starred):
            return self._expr_contains_hardcoded_http_auth(node.value)
        if isinstance(node, ast.Name) and node.id in self.hardcoded_http_auth_names:
            return True
        if isinstance(node, ast.Subscript):
            return self._expr_contains_hardcoded_http_auth(node.value)
        return _expr_contains_hardcoded_secret_value(node, self._effective_constants())

    def _mark_hardcoded_http_auth_target(self, target: ast.AST, value: ast.AST) -> None:
        if self._expr_contains_hardcoded_http_auth(value):
            self._mark_name_target(target, self.hardcoded_http_auth_names)
        else:
            self._discard_name_target(target, self.hardcoded_http_auth_names)

    def _mark_local_constant_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
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

    def _effective_constants(self) -> dict[str, ast.AST]:
        constants = self.constants
        if self.class_constants_stack:
            constants = dict(constants)
            for class_constants in self.class_constants_stack:
                constants.update(class_constants)
        if self.local_constants:
            constants = {**constants, **self.local_constants}
        return constants

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

    def _canonical_sink(self, sink: str) -> str:
        if sink in self.http_function_names:
            return self.http_function_names[sink]
        if sink in self.command_function_names:
            return self.command_function_names[sink]

        parts = sink.split(".")
        if not parts:
            return sink
        if parts[0] in self.http_module_names:
            return ".".join([self.http_module_names[parts[0]], *parts[1:]])
        if parts[0] in self.command_module_names:
            return ".".join([self.command_module_names[parts[0]], *parts[1:]])
        return sink

    def _is_http_call(self, sink: str) -> bool:
        parts = sink.split(".")
        module = ".".join(parts[:-1])
        if len(parts) >= 2 and module in REQUEST_MODULES and parts[-1] in HTTP_METHODS:
            return True
        return (
            len(parts) >= 2
            and parts[-1] in HTTP_METHODS
            and parts[-2] in self.http_client_names | HTTP_CLIENT_FACTORIES
        )

    def _is_http_client_factory(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        sink = self._canonical_sink(_call_name(node.func))
        parts = sink.split(".")
        return len(parts) >= 2 and ".".join(parts[:-1]) in REQUEST_MODULES and parts[-1] in HTTP_CLIENT_FACTORIES

    def _is_http_client_expr(self, node: ast.AST, http_client_names: set[str]) -> bool:
        if isinstance(node, ast.Starred):
            return self._is_http_client_expr(node.value, http_client_names)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._is_http_client_expr(element, http_client_names) for element in node.elts)
        if isinstance(node, ast.Subscript):
            return self._is_http_client_expr(node.value, http_client_names)
        return self._is_http_client_factory(node) or isinstance(node, ast.Name) and node.id in http_client_names

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(
            node, self.request_names, self.odoo_http_module_names, self.odoo_module_names
        )

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
            IntegrationFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                sink=sink,
            )
        )


def _is_request_derived(
    node: ast.AST,
    request_names: set[str],
    odoo_http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    odoo_http_module_names = odoo_http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    if _is_request_source_expr(node, request_names, odoo_http_module_names, odoo_module_names):
        return True
    if isinstance(node, ast.Attribute):
        return _is_request_derived(node.value, request_names, odoo_http_module_names, odoo_module_names)
    if isinstance(node, ast.Subscript):
        return _is_request_derived(
            node.value, request_names, odoo_http_module_names, odoo_module_names
        ) or _is_request_derived(node.slice, request_names, odoo_http_module_names, odoo_module_names)
    if isinstance(node, ast.Call):
        return (
            _is_request_derived(node.func, request_names, odoo_http_module_names, odoo_module_names)
            or any(_is_request_derived(arg, request_names, odoo_http_module_names, odoo_module_names) for arg in node.args)
            or any(
                keyword.value is not None
                and _is_request_derived(keyword.value, request_names, odoo_http_module_names, odoo_module_names)
                for keyword in node.keywords
            )
        )
    text = _safe_unparse(node)
    return any(marker in text for marker in REQUEST_TEXT_MARKERS)


def _positional_http_url_args(node: ast.Call, canonical_sink: str) -> list[ast.AST]:
    """Return positional URL expressions for common HTTP client call signatures."""
    if not node.args:
        return []
    if canonical_sink.endswith(".request") and len(node.args) >= 2:
        return [node.args[1]]
    return [node.args[0]]


def _is_request_source_expr(
    node: ast.AST,
    request_names: set[str],
    odoo_http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and _is_request_expr(node.value, request_names, odoo_http_module_names, odoo_module_names)
        and node.attr in REQUEST_SOURCE_ATTRS | REQUEST_SOURCE_METHODS
    )


def _is_request_expr(
    node: ast.AST,
    request_names: set[str],
    odoo_http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in request_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "request"
        and _is_odoo_http_module_expr(node.value, odoo_http_module_names, odoo_module_names)
    )


def _is_odoo_http_module_expr(
    node: ast.AST,
    odoo_http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in odoo_http_module_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "http"
        and isinstance(node.value, ast.Name)
        and node.value.id in odoo_module_names
    )


def _is_http_call(sink: str) -> bool:
    parts = sink.split(".")
    module = ".".join(parts[:-1])
    if len(parts) >= 2 and module in REQUEST_MODULES and parts[-1] in HTTP_METHODS:
        return True
    return len(parts) >= 2 and parts[-1] in HTTP_METHODS and parts[-2] in {"Session", "Client"}


def _is_command_call(sink: str) -> bool:
    return sink in {
        "os.popen",
        "os.system",
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
    }


def _contains_report_command(node: ast.AST) -> bool:
    text = _safe_unparse(node).lower()
    return any(hint in text for hint in REPORT_COMMAND_HINTS)


def _literal_header_pairs(node: ast.AST) -> list[tuple[str, ast.AST]]:
    return _literal_header_pairs_with_constants(node, {})


def _literal_header_pairs_with_constants(node: ast.AST, constants: dict[str, ast.AST]) -> list[tuple[str, ast.AST]]:
    if isinstance(node, ast.Starred):
        return _literal_header_pairs_with_constants(node.value, constants)
    if isinstance(node, ast.Dict):
        pairs: list[tuple[str, ast.AST]] = []
        for key, value in zip(node.keys, node.values, strict=False):
            if value is None:
                continue
            header_name = _constant_string(key, constants)
            if header_name:
                pairs.append((header_name, value))
        return pairs
    if isinstance(node, ast.List | ast.Tuple):
        pairs = []
        for element in node.elts:
            if not isinstance(element, ast.Tuple | ast.List) or len(element.elts) < 2:
                continue
            header_name = _constant_string(element.elts[0], constants)
            if header_name:
                pairs.append((header_name, element.elts[1]))
        return pairs
    return []


def _is_sensitive_outbound_header(name: str) -> bool:
    return name.strip().lower() in SENSITIVE_OUTBOUND_HEADER_NAMES


def _is_hardcoded_secret_value(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    value = _constant_string(node, constants).strip()
    if not value:
        return False
    lowered = value.lower()
    for prefix in ("bearer ", "basic ", "token "):
        if lowered.startswith(prefix):
            value = value[len(prefix) :].strip()
            lowered = value.lower()
            break
    if _looks_low_value_secret_placeholder(lowered):
        return False
    return len(value) >= 12 or any(marker in lowered for marker in ("sk_live", "ghp_", "xoxb-", "eyj"))


def _expr_contains_hardcoded_secret_value(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Starred):
        return _expr_contains_hardcoded_secret_value(node.value, constants)
    if _is_hardcoded_secret_value(node, constants):
        return True
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_expr_contains_hardcoded_secret_value(element, constants) for element in node.elts)
    if isinstance(node, ast.Dict):
        return any(_expr_contains_hardcoded_secret_value(value, constants) for value in node.values)
    if isinstance(node, ast.Call):
        return any(_expr_contains_hardcoded_secret_value(arg, constants) for arg in node.args) or any(
            keyword.value is not None and _expr_contains_hardcoded_secret_value(keyword.value, constants)
            for keyword in node.keywords
        )
    return False


def _looks_low_value_secret_placeholder(value: str) -> bool:
    return (
        value in LOW_VALUE_SECRET_PLACEHOLDERS
        or value.startswith(("example_", "dummy_", "test_"))
        or value.endswith(("_example", "_dummy", "_test"))
    )


def _is_internal_literal_url(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    url = _constant_string(node, constants).strip()
    if not url:
        return False
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    host = parsed.hostname.strip().lower().rstrip(".")
    if host in METADATA_HOSTS or host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_reserved
    )


def _is_cleartext_literal_url(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    url = _constant_string(node, constants).strip()
    if not url:
        return False
    parsed = urlparse(url)
    return parsed.scheme == "http" and bool(parsed.hostname)


def _constant_string(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> str:
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
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


def _keyword(node: ast.Call, name: str) -> ast.keyword | None:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword
    return None


def _has_keyword(node: ast.Call, name: str) -> bool:
    return _keyword(node, name) is not None


def _has_effective_timeout(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    timeout_values = _keyword_values(node, "timeout", constants)
    return bool(timeout_values) and not any(_value_is(value, None, constants) for value in timeout_values)


def _keyword_value_is(keyword: ast.keyword, expected: object, constants: dict[str, ast.AST] | None = None) -> bool:
    return _value_is(keyword.value, expected, constants)


def _value_is(node: ast.AST, expected: object, constants: dict[str, ast.AST] | None = None) -> bool:
    value = _resolve_constant(node, constants or {})
    return isinstance(value, ast.Constant) and value.value is expected


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


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _unpack_target_value_pairs(
    target: ast.Tuple | ast.List,
    value: ast.Tuple | ast.List,
) -> list[tuple[ast.AST, ast.AST]]:
    starred_index = next(
        (index for index, element in enumerate(target.elts) if isinstance(element, ast.Starred)),
        None,
    )
    if starred_index is None:
        return list(zip(target.elts, value.elts, strict=False))

    before = list(zip(target.elts[:starred_index], value.elts[:starred_index], strict=False))
    trailing_target_count = len(target.elts) - starred_index - 1
    after_values_start = max(len(value.elts) - trailing_target_count, starred_index)
    rest_value = ast.List(elts=value.elts[starred_index:after_values_start], ctx=ast.Load())
    after = list(zip(target.elts[starred_index + 1 :], value.elts[after_values_start:], strict=False))
    return [*before, (target.elts[starred_index], rest_value), *after]


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[IntegrationFinding]) -> list[dict[str, Any]]:
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
