"""Loose Python and server-action scanner for Odoo review contexts.

Server actions, migration helpers, and admin scripts often run with an
ambient Odoo environment. They deserve different review questions than normal
models/controllers because `env`, `record`, and `records` may already be in
scope and are commonly executed by privileged users.
"""

from __future__ import annotations

import ast
import textwrap
from csv import DictReader
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

from defusedxml import ElementTree


@dataclass
class LoosePythonFinding:
    """Represents a finding from loose Python/server-action scanning."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    context: str = ""


class LoosePythonScanner(ast.NodeVisitor):
    """AST scanner for server actions and loose Python helper scripts."""

    HTTP_METHODS = {
        "aiohttp.delete",
        "aiohttp.get",
        "aiohttp.head",
        "aiohttp.patch",
        "aiohttp.post",
        "aiohttp.put",
        "aiohttp.request",
        "requests.delete",
        "requests.get",
        "requests.head",
        "requests.patch",
        "requests.post",
        "requests.put",
    }
    HTTP_CLIENT_METHODS = {"delete", "get", "head", "patch", "post", "put", "request"}
    HTTP_CLIENT_CONSTRUCTORS = {"aiohttp.ClientSession", "httpx.AsyncClient", "httpx.Client", "requests.Session"}
    SENSITIVE_MUTATION_METHODS = {"create", "set", "set_param", "unlink", "write"}
    ELEVATED_BUSINESS_METHOD_PREFIXES = ("_action_", "_button_", "action_", "button_", "do_", "post_", "run_", "send_")
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

    def __init__(self, file_path: str, context: str) -> None:
        self.file_path = file_path
        self.context = context
        self.findings: list[LoosePythonFinding] = []
        self.unsafe_sql_vars: set[str] = set()
        self.http_client_names: set[str] = set()
        self.elevated_record_names: set[str] = set()
        self.superuser_names: set[str] = {"SUPERUSER_ID"}
        self.module_aliases: dict[str, str] = {}
        self.function_aliases: dict[str, str] = {}
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []

    def scan_file(self) -> list[LoosePythonFinding]:
        """Scan one Python file."""
        try:
            source = Path(self.file_path).read_text(encoding="utf-8")
        except SyntaxError:
            return []
        except Exception:
            return []
        return self.scan_source(source)

    def scan_source(self, source: str, line_offset: int = 0) -> list[LoosePythonFinding]:
        """Scan a Python source string."""
        try:
            tree = ast.parse(textwrap.dedent(source))
        except SyntaxError:
            return []
        except Exception:
            return []
        self.line_offset = line_offset
        self.constants = _module_constants(tree)
        self.visit(tree)
        return self.findings

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "urllib.request" and alias.asname is None:
                continue
            local_name = alias.asname or alias.name.split(".", 1)[0]
            if alias.name in {"aiohttp", "requests", "httpx", "urllib.request", "odoo.tools.safe_eval"}:
                self.module_aliases[local_name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module in {"aiohttp", "requests", "httpx", "urllib.request", "odoo.tools.safe_eval"}:
            for alias in node.names:
                self.function_aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif node.module == "urllib":
            for alias in node.names:
                if alias.name == "request":
                    self.module_aliases[alias.asname or alias.name] = "urllib.request"
        elif node.module == "odoo":
            for alias in node.names:
                if alias.name == "SUPERUSER_ID":
                    self.superuser_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track query variables built through string interpolation."""
        for target in node.targets:
            self._mark_unsafe_sql_target(target, node.value)
            self._mark_http_client_target(target, node.value)
            self._mark_elevated_record_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Track annotated aliases for loose Python sinks."""
        if node.value is not None:
            self._mark_unsafe_sql_target(node.target, node.value)
            self._mark_http_client_target(node.target, node.value)
            self._mark_elevated_record_target(node.target, node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        """Track assignment-expression aliases for loose Python sinks."""
        self._mark_unsafe_sql_target(node.target, node.value)
        self._mark_http_client_target(node.target, node.value)
        self._mark_elevated_record_target(node.target, node.value)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        """Track HTTP client aliases introduced by context managers."""
        for item in node.items:
            if item.optional_vars is not None:
                self._mark_http_client_target(item.optional_vars, item.context_expr)
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.visit_With(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect high-risk calls in loose Python contexts."""
        if self._is_cr_execute(node):
            self._check_sql(node)

        if self._is_eval_or_exec(node):
            self._add_finding(
                rule_id="odoo-loose-python-eval-exec",
                title="Dynamic Python execution in loose script",
                severity="critical",
                line=node.lineno,
                message="eval()/exec() in server actions or loose scripts can become code execution if inputs are not strictly controlled",
            )

        if self._is_safe_eval(node):
            self._add_finding(
                rule_id="odoo-loose-python-safe-eval",
                title="safe_eval in loose script",
                severity="high",
                line=node.lineno,
                message="safe_eval() in server actions/scripts needs strict input provenance review and sandbox assumptions",
            )

        if self._is_sudo_write(node):
            self._add_finding(
                rule_id="odoo-loose-python-sudo-write",
                title="Privileged mutation in loose script",
                severity="high",
                line=node.lineno,
                message="sudo()/with_user(SUPERUSER_ID) is chained into write/create/unlink; verify this cannot bypass intended record rules or company isolation",
            )

        if self._is_elevated_business_method_call(node):
            self._add_finding(
                rule_id="odoo-loose-python-sudo-method-call",
                title="Privileged business method call in loose script",
                severity="high",
                line=node.lineno,
                message="sudo()/with_user(SUPERUSER_ID) is used to call a business/action method; verify workflow side effects cannot bypass record rules, approvals, audit, or company isolation",
            )

        sensitive_model = self._sensitive_mutation_model(node)
        if sensitive_model:
            self._add_finding(
                rule_id="odoo-loose-python-sensitive-model-mutation",
                title="Sensitive model mutation in loose script",
                severity="high",
                line=node.lineno,
                message=f"Server action or loose script mutates sensitive model '{sensitive_model}'; verify actor, trigger scope, idempotency, and audit trail",
            )

        if self._is_commit_or_rollback(node):
            self._add_finding(
                rule_id="odoo-loose-python-manual-transaction",
                title="Manual transaction control",
                severity="medium",
                line=node.lineno,
                message="Manual commit()/rollback() can leave partial state and bypass Odoo transaction expectations",
            )

        if self._is_http_call_without_timeout(node):
            self._add_finding(
                rule_id="odoo-loose-python-http-no-timeout",
                title="Outbound HTTP without timeout in loose script",
                severity="medium",
                line=node.lineno,
                message="Server actions or loose scripts perform outbound HTTP without timeout; review SSRF, retry behavior, and worker exhaustion risk",
            )

        if self._is_http_call(node) and _keyword_is_false(node, "verify", self._effective_constants()):
            self._add_finding(
                rule_id="odoo-loose-python-tls-verify-disabled",
                title="Loose script disables TLS verification",
                severity="high",
                line=node.lineno,
                message="Server actions or loose scripts pass verify=False to outbound HTTP; privileged automation should not permit man-in-the-middle attacks",
            )

        self.generic_visit(node)

    def _is_cr_execute(self, node: ast.Call) -> bool:
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

    def _check_sql(self, node: ast.Call) -> None:
        if not node.args:
            return
        query = node.args[0]
        if self._is_unsafe_sql_expr(query) or (isinstance(query, ast.Name) and query.id in self.unsafe_sql_vars):
            self._add_finding(
                rule_id="odoo-loose-python-sql-injection",
                title="Raw SQL built with string interpolation",
                severity="high",
                line=node.lineno,
                message="cr.execute() receives SQL built with interpolation/concatenation; use parameters or psycopg2.sql for identifiers",
            )

    def _is_unsafe_sql_expr(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Starred):
            return self._is_unsafe_sql_expr(node.value)
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._is_unsafe_sql_expr(element) for element in node.elts)
        return False

    def _is_unsafe_sql_value(self, node: ast.AST) -> bool:
        if self._is_unsafe_sql_expr(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.unsafe_sql_vars
        if isinstance(node, ast.Starred):
            return self._is_unsafe_sql_value(node.value)
        if isinstance(node, ast.Subscript):
            return self._is_unsafe_sql_value(node.value)
        if isinstance(node, ast.Attribute):
            return self._is_unsafe_sql_value(node.value)
        return False

    def _is_eval_or_exec(self, node: ast.Call) -> bool:
        return isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}

    def _is_safe_eval(self, node: ast.Call) -> bool:
        sink = self._canonical_call_name(node.func)
        return sink in {"safe_eval", "odoo.tools.safe_eval.safe_eval"} or sink.endswith(".safe_eval")

    def _is_sudo_write(self, node: ast.Call) -> bool:
        if not (isinstance(node.func, ast.Attribute) and node.func.attr in {"write", "create", "unlink"}):
            return False
        return self._expr_has_elevated_record(node.func.value)

    def _is_elevated_business_method_call(self, node: ast.Call) -> bool:
        if not isinstance(node.func, ast.Attribute):
            return False
        method = node.func.attr
        if not method.startswith(self.ELEVATED_BUSINESS_METHOD_PREFIXES):
            return False
        return self._expr_has_elevated_record(node.func.value)

    def _sensitive_mutation_model(self, node: ast.Call) -> str:
        if not isinstance(node.func, ast.Attribute) or node.func.attr not in self.SENSITIVE_MUTATION_METHODS:
            return ""
        model = self._env_subscript_model(node.func.value)
        if model in self.SENSITIVE_MUTATION_MODELS:
            return model
        receiver = _safe_unparse(node.func.value)
        for model in self.SENSITIVE_MUTATION_MODELS:
            if f"'{model}'" in receiver or f'"{model}"' in receiver:
                return model
        return ""

    def _env_subscript_model(self, node: ast.AST) -> str:
        current = node
        while isinstance(current, ast.Call | ast.Attribute):
            current = current.func if isinstance(current, ast.Call) else current.value
        if not isinstance(current, ast.Subscript):
            return ""
        if _call_name(current.value) not in {"env", "self.env"}:
            return ""
        key = _resolve_constant(current.slice, self._effective_constants())
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value
        return ""

    def _is_commit_or_rollback(self, node: ast.Call) -> bool:
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"commit", "rollback"}
            and (
                isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "cr"
                or isinstance(node.func.value, ast.Name)
                and node.func.value.id == "cr"
            )
        )

    def _is_http_call_without_timeout(self, node: ast.Call) -> bool:
        return self._is_http_call(node) and not _has_effective_timeout(node, self._effective_constants())

    def _is_http_call(self, node: ast.Call) -> bool:
        sink = self._canonical_call_name(node.func)
        if sink in self.HTTP_METHODS or sink in {"requests.request", "httpx.request", "urllib.request.urlopen"}:
            return True
        if sink.startswith(("aiohttp.", "httpx.")) and sink.rsplit(".", maxsplit=1)[-1] in self.HTTP_CLIENT_METHODS:
            return True
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in self.HTTP_CLIENT_METHODS
            and _call_name(node.func.value).endswith(("Client", "ClientSession"))
        ):
            return True
        return (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.http_client_names
            and node.func.attr in self.HTTP_CLIENT_METHODS
        )

    def _add_finding(self, rule_id: str, title: str, severity: str, line: int, message: str) -> None:
        self.findings.append(
            LoosePythonFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=self.file_path,
                line=line + getattr(self, "line_offset", 0),
                message=message,
                context=self.context,
            )
        )

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

    def _mark_unsafe_sql_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_unsafe_sql_target(target_element, value_element)
            return
        if self._is_unsafe_sql_value(value):
            self._mark_name_target(target, self.unsafe_sql_vars)
        else:
            self._discard_name_target(target, self.unsafe_sql_vars)

    def _mark_http_client_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_http_client_target(target_element, value_element)
            return
        if self._is_http_client_expr(value):
            self._mark_name_target(target, self.http_client_names)
        else:
            self._discard_name_target(target, self.http_client_names)

    def _mark_elevated_record_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_elevated_record_target(target_element, value_element)
            return
        if self._expr_has_elevated_record(value):
            self._mark_name_target(target, self.elevated_record_names)
        else:
            self._discard_name_target(target, self.elevated_record_names)

    def _expr_has_elevated_record(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Starred):
            return self._expr_has_elevated_record(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.elevated_record_names
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and (
                node.func.attr == "sudo"
                or (
                    node.func.attr == "with_user"
                    and _call_has_superuser_arg(node, self._effective_constants(), self.superuser_names)
                )
            ):
                return True
            return self._expr_has_elevated_record(node.func)
        if isinstance(node, ast.Attribute):
            return self._expr_has_elevated_record(node.value)
        if isinstance(node, ast.Subscript):
            return self._expr_has_elevated_record(node.value)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._expr_has_elevated_record(element) for element in node.elts)
        return False

    def _is_http_client_expr(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.http_client_names
        if isinstance(node, ast.Starred):
            return self._is_http_client_expr(node.value)
        if isinstance(node, ast.Subscript):
            return self._is_http_client_expr(node.value)
        if isinstance(node, ast.Attribute):
            return self._is_http_client_expr(node.value)
        if isinstance(node, ast.Call):
            return self._canonical_call_name(node.func) in self.HTTP_CLIENT_CONSTRUCTORS
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._is_http_client_expr(element) for element in node.elts)
        return False

    def _canonical_call_name(self, node: ast.AST) -> str:
        sink = _call_name(node)
        if sink in self.function_aliases:
            return self.function_aliases[sink]
        parts = sink.split(".")
        if parts and parts[0] in self.module_aliases:
            return ".".join([self.module_aliases[parts[0]], *parts[1:]])
        return sink

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants


def scan_loose_python(repo_path: Path) -> list[LoosePythonFinding]:
    """Scan docs/server_actions/*.py and scripts/*.py files in a repository."""
    findings: list[LoosePythonFinding] = []
    targets = [
        (repo_path / "docs" / "server_actions", "server_action"),
        (repo_path / "scripts", "script"),
    ]
    for root, context in targets:
        if not root.exists():
            continue
        for py_file in root.rglob("*.py"):
            if "__pycache__" in py_file.parts:
                continue
            findings.extend(LoosePythonScanner(str(py_file), context).scan_file())
    for xml_file in repo_path.rglob("*.xml"):
        if _should_skip(xml_file):
            continue
        findings.extend(_scan_xml_server_actions(xml_file))
    for csv_file in repo_path.rglob("*.csv"):
        if _should_skip(csv_file):
            continue
        findings.extend(_scan_csv_server_actions(csv_file))
    return findings


def _scan_xml_server_actions(xml_file: Path) -> list[LoosePythonFinding]:
    findings: list[LoosePythonFinding] = []
    try:
        content = xml_file.read_text(encoding="utf-8", errors="replace")
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        return []
    except Exception:
        return []

    for record in root.iter("record"):
        if record.get("model") != "ir.actions.server":
            continue
        fields = _record_fields(record)
        if fields.get("state") != "code" or not fields.get("code", "").strip():
            continue
        line = _line_for_record(content, record)
        scanner = LoosePythonScanner(str(xml_file), "server_action_xml")
        findings.extend(scanner.scan_source(fields["code"], line_offset=line - 1))
    return findings


def _scan_csv_server_actions(csv_file: Path) -> list[LoosePythonFinding]:
    findings: list[LoosePythonFinding] = []
    if _csv_model_name(csv_file) != "ir.actions.server":
        return findings
    try:
        content = csv_file.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    for fields, line in _csv_dict_rows(content):
        if fields.get("state") != "code" or not fields.get("code", "").strip():
            continue
        scanner = LoosePythonScanner(str(csv_file), "server_action_csv")
        findings.extend(scanner.scan_source(fields["code"], line_offset=line - 1))
    return findings


def _record_fields(record: ElementTree.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    for field in record.iter("field"):
        name = field.get("name")
        if not name:
            continue
        values[name] = field.get("eval") or field.get("ref") or "".join(field.itertext()).strip()
    return values


def _csv_model_name(path: Path) -> str:
    stem = path.stem.strip().lower()
    aliases = {
        "ir_actions_server": "ir.actions.server",
        "ir.actions.server": "ir.actions.server",
    }
    return aliases.get(stem, stem.replace("_", "."))


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


def _line_for_record(content: str, record: ElementTree.Element) -> int:
    record_id = record.get("id")
    if record_id:
        return _line_for(content, f'id="{record_id}"')
    return _line_for(content, 'model="ir.actions.server"')


def _line_for(content: str, needle: str) -> int:
    index = content.find(needle)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1


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


def _call_has_superuser_arg(
    node: ast.Call,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    return any(_is_superuser_arg(arg, constants, superuser_names) for arg in node.args) or any(
        keyword.value is not None and _is_superuser_arg(keyword.value, constants, superuser_names)
        for keyword in node.keywords
    )


def _keyword_is_false(node: ast.Call, name: str, constants: dict[str, ast.AST] | None = None) -> bool:
    constants = constants or {}
    for keyword_value in _keyword_values(node, name, constants):
        value = _resolve_constant(keyword_value, constants)
        if isinstance(value, ast.Constant) and value.value is False:
            return True
    return False


def _has_effective_timeout(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    timeout_values = _keyword_values(node, "timeout", constants)
    return bool(timeout_values) and not any(_is_none_constant(value, constants or {}) for value in timeout_values)


def _is_none_constant(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    value = _resolve_constant(node, constants)
    return isinstance(value, ast.Constant) and value.value is None


def _keyword_values(node: ast.Call, name: str, constants: dict[str, ast.AST] | None = None) -> list[ast.AST]:
    constants = constants or {}
    values: list[ast.AST] = []
    for keyword in node.keywords:
        if keyword.arg == name:
            values.append(keyword.value)
            continue
        if keyword.arg is not None:
            continue
        value = _resolve_constant(keyword.value, constants)
        if isinstance(value, ast.Dict):
            values.extend(_dict_keyword_values(value, name, constants))
    return values


def _dict_keyword_values(node: ast.Dict, name: str, constants: dict[str, ast.AST]) -> list[ast.AST]:
    values: list[ast.AST] = []
    for key, value in zip(node.keys, node.values, strict=True):
        if key is None:
            resolved_value = _resolve_constant(value, constants)
            if isinstance(resolved_value, ast.Dict):
                values.extend(_dict_keyword_values(resolved_value, name, constants))
            continue
        resolved_key = _resolve_constant(key, constants)
        if isinstance(resolved_key, ast.Constant) and resolved_key.value == name:
            values.append(value)
    return values


def _is_superuser_arg(
    node: ast.AST,
    constants: dict[str, ast.AST] | None = None,
    superuser_names: set[str] | None = None,
) -> bool:
    superuser_names = superuser_names or {"SUPERUSER_ID"}
    if constants:
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


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[LoosePythonFinding]) -> list[dict[str, Any]]:
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
