"""Scanner for risky Odoo runtime raw SQL usage."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class RawSqlFinding:
    """Represents a raw SQL security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    sink: str = ""


DESTRUCTIVE_SQL = re.compile(r"\b(delete\s+from|update|drop|truncate|alter\s+table)\b", re.IGNORECASE)
WRITE_SQL = re.compile(r"\b(delete\s+from|update)\b", re.IGNORECASE)
SQL_START = re.compile(r"\b(select|insert|update|delete|alter|drop|truncate)\b", re.IGNORECASE)
REQUEST_MARKERS = (
    "kwargs.get",
    "post.get",
    "kw.get",
)
EXECUTE_QUERY_KEYWORDS = {"operation", "query", "sql", "statement"}
EXECUTE_PARAMS_KEYWORDS = {"args", "parameters", "params", "vars"}
BULK_SQL_HELPERS = {"execute_batch", "execute_values"}
CURSOR_SQL_METHODS = {"copy_expert", "execute"}


def scan_raw_sql(repo_path: Path) -> list[RawSqlFinding]:
    """Scan Python files for risky raw SQL cursor usage."""
    findings: list[RawSqlFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(RawSqlScanner(path).scan_file())
    return findings


class RawSqlScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[RawSqlFinding] = []
        self.request_names: set[str] = {"request"}
        self.unsafe_sql_vars: set[str] = set()
        self.sql_literal_vars: dict[str, str] = {}
        self.tainted_vars: set[str] = set()
        self.cursor_vars: set[str] = {"cr"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.route_decorator_names: set[str] = set()
        self.constants: dict[str, ast.AST] = {}
        self.local_constants: dict[str, ast.AST] = {}

    def scan_file(self) -> list[RawSqlFinding]:
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
                    self.route_decorator_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_tainted = set(self.tainted_vars)
        previous_local_constants = self.local_constants
        self.local_constants = {}
        if _function_is_http_route(
            node,
            self.route_decorator_names,
            self.http_module_names,
            self.odoo_module_names,
        ):
            for arg in [*node.args.args, *node.args.kwonlyargs]:
                if arg.arg not in {"self", "cls"}:
                    self.tainted_vars.add(arg.arg)
            if node.args.vararg:
                self.tainted_vars.add(node.args.vararg.arg)
            if node.args.kwarg:
                self.tainted_vars.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.tainted_vars = previous_tainted
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        previous_cursor_vars = set(self.cursor_vars)
        previous_unsafe_sql_vars = set(self.unsafe_sql_vars)
        previous_sql_literal_vars = dict(self.sql_literal_vars)
        is_tainted = self._expr_is_tainted(node.value)
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
            self._mark_cursor_target(target, node.value, previous_cursor_vars)
            self._mark_unsafe_sql_target(target, node.value, previous_unsafe_sql_vars)
            self._mark_sql_literal_target(target, node.value, previous_sql_literal_vars)
            self._mark_tainted_target(target, is_tainted)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
            self._mark_cursor_target(node.target, node.value, set(self.cursor_vars))
            self._mark_unsafe_sql_target(node.target, node.value, set(self.unsafe_sql_vars))
            self._mark_sql_literal_target(node.target, node.value, dict(self.sql_literal_vars))
            self._mark_tainted_target(node.target, self._expr_is_tainted(node.value))
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        self._mark_tainted_target(node.target, self._expr_is_tainted(node.iter))
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_local_constant_target(node.target, node.value)
        self._mark_cursor_target(node.target, node.value, set(self.cursor_vars))
        self._mark_unsafe_sql_target(node.target, node.value, set(self.unsafe_sql_vars))
        self._mark_sql_literal_target(node.target, node.value, dict(self.sql_literal_vars))
        self._mark_tainted_target(node.target, self._expr_is_tainted(node.value))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = _call_name(node.func)
        if self._is_raw_sql_call(node):
            self._scan_execute(node, sink)
        elif self._is_manual_transaction(node):
            self._add(
                "odoo-raw-sql-manual-transaction",
                "Manual transaction control in runtime code",
                "medium",
                node.lineno,
                "Runtime code calls commit()/rollback(); verify partial writes cannot bypass Odoo request, ORM, and security transaction expectations",
                sink,
            )
        self.generic_visit(node)

    def _scan_execute(self, node: ast.Call, sink: str) -> None:
        query = _execute_query_arg(node, self._effective_constants())
        if query is None:
            return

        if self._expr_is_unsafe_sql(query):
            self._add(
                "odoo-raw-sql-interpolated-query",
                "Raw SQL query is built with interpolation",
                "high",
                node.lineno,
                "cr.execute() receives SQL built through f-strings, %, .format(), or concatenation; use bound parameters and psycopg2.sql for identifiers",
                sink,
            )

        if self._expr_is_tainted(query) or any(
            self._expr_is_tainted(arg) for arg in _execute_param_args(node, self._effective_constants())
        ):
            self._add(
                "odoo-raw-sql-request-derived-input",
                "Request-derived value reaches raw SQL",
                "high",
                node.lineno,
                "Request-derived data reaches cr.execute(); verify parameter binding, allowed identifiers, and domain-equivalent access checks",
                sink,
            )

        sql_literal = self._literal_sql(query)
        if sql_literal and DESTRUCTIVE_SQL.search(sql_literal):
            if _destructive_without_where(sql_literal):
                self._add(
                    "odoo-raw-sql-broad-destructive-query",
                    "Raw SQL performs broad destructive operation",
                    "critical" if re.search(r"\b(drop|truncate|alter\s+table)\b", sql_literal, re.I) else "high",
                    node.lineno,
                    "Runtime cr.execute() performs destructive SQL without an obvious WHERE clause; verify tenant scoping, backups, and ORM invariants",
                    sink,
                )
            elif WRITE_SQL.search(sql_literal) and "company" not in sql_literal.lower():
                self._add(
                    "odoo-raw-sql-write-no-company-scope",
                    "Raw SQL write lacks company scoping",
                    "medium",
                    node.lineno,
                    "Runtime UPDATE/DELETE SQL has a WHERE clause but no visible company filter; verify multi-company isolation and record rule equivalence",
                    sink,
                )

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        text = _safe_unparse(node)
        if _is_request_source(
            node,
            self.request_names,
            self.http_module_names,
            self.odoo_module_names,
        ) or any(marker in text for marker in REQUEST_MARKERS):
            return True
        if isinstance(node, ast.Starred):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted(node.value) or self._expr_is_tainted(node.slice)
        if isinstance(node, ast.Attribute):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Call):
            return (
                self._expr_is_tainted(node.func)
                or any(self._expr_is_tainted(arg) for arg in node.args)
                or any(
                    keyword.value is not None and self._expr_is_tainted(keyword.value)
                    for keyword in _expanded_keywords(node, self._effective_constants())
                )
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

    def _expr_is_unsafe_sql(self, node: ast.AST) -> bool:
        if _is_unsafe_sql_expr(node):
            return True
        if isinstance(node, ast.Starred):
            return self._expr_is_unsafe_sql(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.unsafe_sql_vars
        if isinstance(node, ast.Subscript):
            return self._expr_is_unsafe_sql(node.value)
        if isinstance(node, ast.Tuple | ast.List | ast.Set):
            return any(self._expr_is_unsafe_sql(element) for element in node.elts)
        return False

    def _is_raw_sql_call(self, node: ast.Call) -> bool:
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in CURSOR_SQL_METHODS
            and self._is_cursor_expr(node.func.value)
        ):
            return True
        return _call_name(node.func).split(".")[-1] in BULK_SQL_HELPERS and bool(
            node.args and self._is_cursor_expr(node.args[0])
        )

    def _is_manual_transaction(self, node: ast.Call) -> bool:
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"commit", "rollback"}
            and self._is_cursor_expr(node.func.value)
        )

    def _is_cursor_expr(self, node: ast.AST, cursor_vars: set[str] | None = None) -> bool:
        cursor_vars = self.cursor_vars if cursor_vars is None else cursor_vars
        if isinstance(node, ast.Starred):
            return self._is_cursor_expr(node.value, cursor_vars)
        if isinstance(node, ast.Tuple | ast.List | ast.Set):
            return any(self._is_cursor_expr(element, cursor_vars) for element in node.elts)
        if isinstance(node, ast.Name):
            return node.id in cursor_vars
        if isinstance(node, ast.Subscript):
            return self._is_cursor_expr(node.value, cursor_vars)
        return isinstance(node, ast.Attribute) and node.attr == "cr"

    def _mark_cursor_target(self, target: ast.AST, value: ast.AST, cursor_vars: set[str]) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_cursor_target(target_element, value_element, cursor_vars)
            return
        if self._is_cursor_expr(value, cursor_vars):
            self._mark_name_target(target, self.cursor_vars)
        else:
            self._discard_name_target(target, self.cursor_vars)

    def _mark_unsafe_sql_target(self, target: ast.AST, value: ast.AST, unsafe_sql_vars: set[str]) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_unsafe_sql_target(target_element, value_element, unsafe_sql_vars)
            return
        if self._expr_is_unsafe_sql_with_vars(value, unsafe_sql_vars):
            self._mark_name_target(target, self.unsafe_sql_vars)
        else:
            self._discard_name_target(target, self.unsafe_sql_vars)

    def _expr_is_unsafe_sql_with_vars(self, node: ast.AST, unsafe_sql_vars: set[str]) -> bool:
        if _is_unsafe_sql_expr(node):
            return True
        if isinstance(node, ast.Starred):
            return self._expr_is_unsafe_sql_with_vars(node.value, unsafe_sql_vars)
        if isinstance(node, ast.Name):
            return node.id in unsafe_sql_vars
        if isinstance(node, ast.Subscript):
            return self._expr_is_unsafe_sql_with_vars(node.value, unsafe_sql_vars)
        if isinstance(node, ast.Tuple | ast.List | ast.Set):
            return any(self._expr_is_unsafe_sql_with_vars(element, unsafe_sql_vars) for element in node.elts)
        return False

    def _mark_sql_literal_target(
        self,
        target: ast.AST,
        value: ast.AST,
        sql_literal_vars: dict[str, str],
    ) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
                self._mark_sql_literal_target(target_element, value_element, sql_literal_vars)
            return
        if isinstance(target, ast.Starred):
            self._mark_sql_literal_target(target.value, value, sql_literal_vars)
            return
        if not isinstance(target, ast.Name):
            return
        literal = self._literal_sql_with_vars(value, sql_literal_vars)
        if literal and SQL_START.search(literal):
            self.sql_literal_vars[target.id] = literal
        else:
            self.sql_literal_vars.pop(target.id, None)

    def _literal_sql(self, node: ast.AST) -> str:
        return self._literal_sql_with_vars(node, self.sql_literal_vars)

    def _literal_sql_with_vars(self, node: ast.AST, sql_literal_vars: dict[str, str]) -> str:
        literal = _literal_string(node, self._effective_constants())
        if literal:
            return literal
        if isinstance(node, ast.Name):
            return sql_literal_vars.get(node.id, "")
        if isinstance(node, ast.Subscript):
            return self._literal_sql_with_vars(node.value, sql_literal_vars)
        return ""

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

    def _mark_tainted_target(self, target: ast.AST, is_tainted: bool) -> None:
        if is_tainted:
            self._mark_name_target(target, self.tainted_vars)
        else:
            self._discard_name_target(target, self.tainted_vars)

    def _mark_local_constant_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target.elts, value.elts):
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
        if isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_local_constant_target(element)

    def _discard_local_constant_target(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.local_constants.pop(target.id, None)
        elif isinstance(target, ast.Starred):
            self._discard_local_constant_target(target.value)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_local_constant_target(element)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.local_constants:
            return self.constants
        return {**self.constants, **self.local_constants}

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, sink: str) -> None:
        self.findings.append(
            RawSqlFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                sink=sink,
            )
        )


def _is_unsafe_sql_expr(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def _is_request_source(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute) and child.attr in {"params", "jsonrequest", "httprequest"}:
            if _is_request_expr(child.value, request_names, http_module_names, odoo_module_names):
                return True
        if not isinstance(child, ast.Call) or not isinstance(child.func, ast.Attribute):
            continue
        if child.func.attr in {"get_http_params", "get_json_data"} and _is_request_expr(
            child.func.value,
            request_names,
            http_module_names,
            odoo_module_names,
        ):
            return True
    return False


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


def _literal_string(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> str:
    value = _resolve_constant(node, constants or {})
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return ""


def _execute_query_arg(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> ast.AST | None:
    if _call_name(node.func).split(".")[-1] in BULK_SQL_HELPERS and node.args:
        if len(node.args) >= 2:
            return node.args[1]
        for keyword in _expanded_keywords(node, constants):
            if keyword.arg in EXECUTE_QUERY_KEYWORDS:
                return keyword.value
        return None
    if node.args:
        return node.args[0]
    for keyword in _expanded_keywords(node, constants):
        if keyword.arg in EXECUTE_QUERY_KEYWORDS:
            return keyword.value
    return None


def _execute_param_args(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> list[ast.AST]:
    if _call_name(node.func).split(".")[-1] in BULK_SQL_HELPERS and node.args:
        params = list(node.args[2:])
        params.extend(
            keyword.value for keyword in _expanded_keywords(node, constants) if keyword.arg in EXECUTE_PARAMS_KEYWORDS
        )
        return params
    params = list(node.args[1:])
    params.extend(
        keyword.value for keyword in _expanded_keywords(node, constants) if keyword.arg in EXECUTE_PARAMS_KEYWORDS
    )
    return params


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
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str | bool | int | float | type(None))
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return all(_is_static_literal(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(key is None or _is_static_literal(key) for key in node.keys)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_static_literal(node.left) and _is_static_literal(node.right)
    return False


def _resolve_static_dict(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> ast.Dict | None:
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


def _destructive_without_where(sql: str) -> bool:
    lowered = sql.lower()
    if re.search(r"\b(drop|truncate|alter\s+table)\b", lowered):
        return True
    return bool(re.search(r"\b(delete\s+from|update)\b", lowered) and " where " not in f" {lowered} ")


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
    if isinstance(target, ast.Name):
        return target.id in route_decorator_names
    return (
        isinstance(target, ast.Attribute)
        and target.attr == "route"
        and _is_http_module_expr(target.value, http_module_names, odoo_module_names)
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


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _unpack_target_value_pairs(
    targets: list[ast.expr],
    values: list[ast.expr],
) -> list[tuple[ast.expr, ast.AST]]:
    starred_index = next((index for index, target in enumerate(targets) if isinstance(target, ast.Starred)), None)
    if starred_index is None:
        return list(zip(targets, values, strict=False))

    tail_count = len(targets) - starred_index - 1
    if len(values) < starred_index + tail_count:
        return list(zip(targets, values, strict=False))

    pairs: list[tuple[ast.expr, ast.AST]] = []
    pairs.extend(zip(targets[:starred_index], values[:starred_index], strict=False))
    rest_values = values[starred_index : len(values) - tail_count if tail_count else len(values)]
    pairs.append((targets[starred_index], ast.List(elts=rest_values, ctx=ast.Load())))
    if tail_count:
        pairs.extend(zip(targets[-tail_count:], values[-tail_count:], strict=False))
    return pairs


def _should_skip(path: Path) -> bool:
    parts = set(path.parts)
    return bool(parts & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests", "migrations"})


def findings_to_json(findings: list[RawSqlFinding]) -> list[dict[str, Any]]:
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
