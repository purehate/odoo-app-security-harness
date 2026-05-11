"""Scanner for executable/risky Odoo XML data records."""

from __future__ import annotations

import ast
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defusedxml import ElementTree

ADMIN_GROUP_RE = re.compile(r"\bbase\.(group_system|group_erp_manager)\b")
INTERNAL_GROUP_RE = re.compile(r"\bbase\.group_user\b")
SECURITY_FUNCTION_MODELS = {
    "account.move",
    "ir.attachment",
    "ir.config_parameter",
    "ir.cron",
    "ir.model.access",
    "ir.model.fields",
    "ir.property",
    "ir.rule",
    "payment.provider",
    "payment.transaction",
    "res.groups",
    "res.users",
    "res.users.apikeys",
}
SECURITY_MUTATION_FUNCTIONS = {"create", "set", "set_param", "unlink", "write"}
KNOWN_MODEL_EXTERNAL_IDS = {
    "account.model_account_move": "account.move",
    "model_account_move": "account.move",
    "base.model_ir_attachment": "ir.attachment",
    "model_ir_attachment": "ir.attachment",
    "base.model_ir_config_parameter": "ir.config_parameter",
    "model_ir_config_parameter": "ir.config_parameter",
    "base.model_ir_cron": "ir.cron",
    "model_ir_cron": "ir.cron",
    "base.model_ir_model_access": "ir.model.access",
    "model_ir_model_access": "ir.model.access",
    "base.model_ir_rule": "ir.rule",
    "model_ir_rule": "ir.rule",
    "base.model_res_groups": "res.groups",
    "model_res_groups": "res.groups",
    "base.model_res_users": "res.users",
    "model_res_users": "res.users",
    "base.model_res_users_apikeys": "res.users.apikeys",
    "model_res_users_apikeys": "res.users.apikeys",
    "payment.model_payment_provider": "payment.provider",
    "model_payment_provider": "payment.provider",
    "payment.model_payment_transaction": "payment.transaction",
    "model_payment_transaction": "payment.transaction",
}


@dataclass
class XmlDataFinding:
    """Represents a risky XML data record finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    record_id: str = ""


def scan_xml_data(repo_path: Path) -> list[XmlDataFinding]:
    """Scan Odoo XML data files for executable/security-sensitive records."""
    findings: list[XmlDataFinding] = []
    for path in repo_path.rglob("*.xml"):
        if _should_skip(path):
            continue
        findings.extend(XmlDataScanner(path).scan_file())
    return findings


class XmlDataScanner:
    """Scanner for one XML data file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[XmlDataFinding] = []
        self.content = ""

    def scan_file(self) -> list[XmlDataFinding]:
        """Scan the XML file."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            root = ElementTree.fromstring(self.content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        for record in root.iter("record"):
            model = record.get("model", "")
            if model == "ir.actions.server":
                self._scan_server_action(record)
            elif model == "ir.cron":
                self._scan_cron(record)
            elif model in {"mail.channel", "discuss.channel"}:
                self._scan_mail_channel(record)
            elif model == "res.users":
                self._scan_user_record(record)
            elif model == "res.groups":
                self._scan_group_record(record)
        for function in root.iter("function"):
            self._scan_function(function)

        return self.findings

    def _scan_server_action(self, record: ElementTree.Element) -> None:
        fields = self._fields(record)
        if fields.get("state") != "code":
            return
        code = fields.get("code", "")
        groups = fields.get("groups_id", "") + " " + fields.get("groups", "")
        target_model = _first_model_name(
            fields.get(name, "") for name in ("model_id", "binding_model_id", "crud_model_id")
        )
        record_id = record.get("id", "")

        if "base.group_user" in groups or "base.group_portal" in groups or not groups.strip():
            self._add(
                "odoo-xml-server-action-code-user-reachable",
                "Executable server action is broadly reachable",
                "high",
                self._line_for_record(record),
                "ir.actions.server uses state='code' and is reachable by broad/no groups; verify buttons/menus cannot expose arbitrary Python execution",
                "ir.actions.server",
                record_id,
            )

        if target_model in SECURITY_FUNCTION_MODELS:
            self._add(
                "odoo-xml-server-action-sensitive-model-code",
                "Executable server action targets sensitive model",
                "high",
                self._line_for_record(record),
                f"ir.actions.server uses state='code' on sensitive model '{target_model}'; verify action bindings, groups, and record-rule boundaries",
                "ir.actions.server",
                record_id,
            )

        code_risks = _server_action_code_risks(code)
        sensitive_mutation_model = code_risks.sensitive_model or _sensitive_env_mutation_model(code)
        if sensitive_mutation_model:
            self._add(
                "odoo-xml-server-action-sensitive-model-mutation",
                "Server action mutates sensitive model",
                "high",
                self._line_for_record(record),
                f"ir.actions.server code mutates sensitive model '{sensitive_mutation_model}'; verify actor, groups, trigger scope, and audit trail",
                "ir.actions.server",
                record_id,
            )

        if "safe_eval" in code or re.search(r"\b(eval|exec)\s*\(", code):
            self._add(
                "odoo-xml-server-action-dynamic-eval",
                "Server action code performs dynamic evaluation",
                "critical",
                self._line_for_record(record),
                "ir.actions.server code contains eval/exec/safe_eval; verify no user-controlled expression can reach it",
                "ir.actions.server",
                record_id,
            )

        if code_risks.sudo_mutation or _regex_sudo_mutation(code):
            self._add(
                "odoo-xml-server-action-sudo-mutation",
                "Server action performs sudo mutation",
                "high",
                self._line_for_record(record),
                "ir.actions.server code chains sudo()/with_user(SUPERUSER_ID) into write/create/unlink; verify record rules and company isolation are not bypassed",
                "ir.actions.server",
                record_id,
            )

        if _http_call_without_timeout(code):
            self._add(
                "odoo-xml-server-action-http-no-timeout",
                "Server action performs HTTP request without timeout",
                "medium",
                self._line_for_record(record),
                "ir.actions.server code performs outbound HTTP without timeout; review SSRF, retry, and worker exhaustion risk",
                "ir.actions.server",
                record_id,
            )

        if code_risks.tls_verify_disabled:
            self._add(
                "odoo-xml-server-action-tls-verify-disabled",
                "Server action disables TLS verification",
                "high",
                self._line_for_record(record),
                "ir.actions.server code passes verify=False to outbound HTTP; install/update automation should not permit man-in-the-middle attacks",
                "ir.actions.server",
                record_id,
            )

    def _scan_cron(self, record: ElementTree.Element) -> None:
        fields = self._fields(record)
        state = fields.get("state", "")
        code = fields.get("code", "")
        callable_text = " ".join(
            fields.get(name, "") for name in ("code", "function", "method_direct_trigger", "args", "model_id", "name")
        )
        user_ref = fields.get("user_id", "")
        record_id = record.get("id", "")
        code_risks = _server_action_code_risks(code) if state == "code" else _ServerActionCodeRisks()

        if "base.user_root" in user_ref or "base.user_admin" in user_ref:
            self._add(
                "odoo-xml-cron-admin-user",
                "Cron executes as admin/root user",
                "high",
                self._line_for_record(record),
                "ir.cron runs under admin/root user; verify the scheduled job cannot process attacker-controlled records or external input with elevated privileges",
                "ir.cron",
                record_id,
            )
            if state == "code":
                self._add(
                    "odoo-xml-cron-root-code",
                    "Cron executes Python as admin/root",
                    "high",
                    self._line_for_record(record),
                    "ir.cron uses state='code' under admin/root user; verify it cannot process attacker-controlled records or external input",
                    "ir.cron",
                    record_id,
                )

        if state == "code" and _http_call_without_timeout(code):
            self._add(
                "odoo-xml-cron-http-no-timeout",
                "Cron performs HTTP request without visible timeout",
                "medium",
                self._line_for_record(record),
                "Cron code performs outbound HTTP without timeout; review SSRF and worker exhaustion risk",
                "ir.cron",
                record_id,
            )

        if code_risks.tls_verify_disabled:
            self._add(
                "odoo-xml-cron-tls-verify-disabled",
                "Cron disables TLS verification",
                "high",
                self._line_for_record(record),
                "ir.cron code passes verify=False to outbound HTTP; scheduled integrations should not permit man-in-the-middle attacks",
                "ir.cron",
                record_id,
            )

        if _is_truthy(fields.get("doall", "")):
            self._add(
                "odoo-xml-cron-doall-enabled",
                "Cron catches up missed executions",
                "medium",
                self._line_for_record(record),
                "ir.cron has doall=True; after downtime it may replay missed jobs in bulk, causing duplicate side effects or load spikes",
                "ir.cron",
                record_id,
            )

        interval_number = _int_value(fields.get("interval_number", ""))
        interval_type = fields.get("interval_type", "").strip("'\"").lower()
        if interval_number > 0 and _interval_minutes(interval_number, interval_type) <= 5:
            self._add(
                "odoo-xml-cron-short-interval",
                "Cron runs at a very short interval",
                "low",
                self._line_for_record(record),
                "ir.cron runs every five minutes or less; review idempotency, locking, and external side effects",
                "ir.cron",
                record_id,
            )

        if re.search(r"\b(fetch|sync|import|pull|webhook|callback|http|url|request)\b", callable_text, re.IGNORECASE):
            if not re.search(r"\b(limit|batch|lock|timeout|commit)\b", callable_text, re.IGNORECASE):
                self._add(
                    "odoo-xml-cron-external-sync-review",
                    "Cron appears to perform external sync without visible guardrails",
                    "low",
                    self._line_for_record(record),
                    "ir.cron name/function/model suggests external import or sync; verify timeouts, batching, locking, and retry safety",
                    "ir.cron",
                    record_id,
                )

    def _scan_mail_channel(self, record: ElementTree.Element) -> None:
        fields = self._fields(record)
        if fields.get("allow_public_users") in {"1", "True", "true"}:
            self._add(
                "odoo-xml-public-mail-channel",
                "Mail/discuss channel allows public users",
                "medium",
                self._line_for_record(record),
                "Channel allows public users; verify this is intentional and cannot expose internal messages or metadata",
                record.get("model", ""),
                record.get("id", ""),
            )

    def _scan_user_record(self, record: ElementTree.Element) -> None:
        fields = self._fields(record)
        groups = fields.get("groups_id", "") + " " + fields.get("groups", "")
        if ADMIN_GROUP_RE.search(groups):
            self._add(
                "odoo-xml-user-admin-group-assignment",
                "XML data assigns user to administrator group",
                "critical",
                self._line_for_record(record),
                "res.users XML data assigns groups_id/groups to base.group_system or base.group_erp_manager; verify module install/update cannot grant unintended administrator access",
                "res.users",
                record.get("id", ""),
            )

    def _scan_group_record(self, record: ElementTree.Element) -> None:
        fields = self._fields(record)
        implied_groups = fields.get("implied_ids", "")
        if not implied_groups or not _mentions_privileged_group(implied_groups):
            return

        self._add(
            "odoo-xml-group-implies-privilege",
            "XML data changes implied group privileges",
            "critical" if ADMIN_GROUP_RE.search(implied_groups) else "high",
            self._line_for_record(record),
            "res.groups XML data writes implied_ids toward internal/administrator groups; verify no public, portal, or signup-assigned group inherits unintended privileges",
            "res.groups",
            record.get("id", ""),
        )

    def _scan_function(self, function: ElementTree.Element) -> None:
        model = function.get("model", "")
        name = function.get("name", "")
        text = _function_text(function)
        line = self._line_for_function(function)

        if model in SECURITY_FUNCTION_MODELS and name in SECURITY_MUTATION_FUNCTIONS:
            self._add(
                "odoo-xml-function-security-model-mutation",
                "XML function mutates security-sensitive model",
                "high",
                line,
                f"XML <function> calls {model}.{name} during data loading; verify module install/update cannot silently alter security metadata or sensitive defaults",
                model,
                "",
            )

        if model == "res.users" and name in {"create", "write"} and _mentions_user_groups(text):
            self._add(
                "odoo-xml-function-user-group-assignment",
                "XML function assigns user groups",
                "critical" if ADMIN_GROUP_RE.search(text) else "high",
                line,
                "XML <function> creates or writes res.users group assignments; verify module install/update cannot grant administrator or internal access unexpectedly",
                model,
                "",
            )

        if (
            model == "res.groups"
            and name in {"create", "write"}
            and "implied_ids" in text
            and _mentions_privileged_group(text)
        ):
            self._add(
                "odoo-xml-function-group-implies-privilege",
                "XML function changes implied group privileges",
                "high",
                line,
                "XML <function> creates or writes res.groups implied_ids toward internal/administrator groups; verify no public, portal, or signup-assigned group inherits unintended privileges",
                model,
                "",
            )

    def _fields(self, record: ElementTree.Element) -> dict[str, str]:
        values: dict[str, str] = {}
        for field in record.iter("field"):
            name = field.get("name")
            if not name:
                continue
            values[name] = field.get("ref") or field.get("eval") or (field.text or "").strip()
        return values

    def _line_for_record(self, record: ElementTree.Element) -> int:
        record_id = record.get("id")
        if record_id:
            return _line_for(self.content, f'id="{record_id}"')
        model = record.get("model", "")
        return _line_for(self.content, f'model="{model}"')

    def _line_for_function(self, function: ElementTree.Element) -> int:
        model = function.get("model", "")
        name = function.get("name", "")
        for needle in (f'<function model="{model}" name="{name}"', f'<function name="{name}" model="{model}"'):
            line = _line_for(self.content, needle)
            if line != 1:
                return line
        return _line_for(self.content, "<function")

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        model: str,
        record_id: str,
    ) -> None:
        self.findings.append(
            XmlDataFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                model=model,
                record_id=record_id,
            )
        )


def _line_for(content: str, needle: str) -> int:
    index = content.find(needle)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1


def _is_truthy(value: str) -> bool:
    return value.strip().strip("'\"").lower() in {"1", "true", "yes"}


def _int_value(value: str) -> int:
    match = re.search(r"-?\d+", value)
    if not match:
        return 0
    return int(match.group())


def _interval_minutes(number: int, interval_type: str) -> int:
    if interval_type in {"seconds", "second"}:
        return 0
    if interval_type in {"minutes", "minute"}:
        return number
    if interval_type in {"hours", "hour"}:
        return number * 60
    if interval_type in {"days", "day"}:
        return number * 60 * 24
    if interval_type in {"weeks", "week"}:
        return number * 60 * 24 * 7
    if interval_type in {"months", "month"}:
        return number * 60 * 24 * 30
    return 60 * 24


def _function_text(function: ElementTree.Element) -> str:
    values = []
    for element in function.iter():
        values.extend(str(value) for value in element.attrib.values())
        if element.text:
            values.append(element.text)
    return " ".join(values)


def _first_model_name(values: Any) -> str:
    for value in values:
        model_name = _model_name(value)
        if model_name:
            return model_name
    return ""


def _model_name(value: str) -> str:
    normalized = value.strip().strip("'\"")
    if not normalized:
        return ""
    if normalized in SECURITY_FUNCTION_MODELS:
        return normalized
    if normalized in KNOWN_MODEL_EXTERNAL_IDS:
        return KNOWN_MODEL_EXTERNAL_IDS[normalized]
    external_id = normalized.rsplit(".", 1)[-1]
    if external_id in KNOWN_MODEL_EXTERNAL_IDS:
        return KNOWN_MODEL_EXTERNAL_IDS[external_id]
    if external_id.startswith("model_"):
        return external_id.removeprefix("model_").replace("_", ".")
    return ""


def _sensitive_env_mutation_model(code: str) -> str:
    for match in re.finditer(
        r"(?:env|self\.env)\[['\"](?P<model>[^'\"]+)['\"]\][\s\S]{0,160}?\."
        r"(?P<method>create|set|set_param|unlink|write)\s*\(",
        code,
    ):
        model_name = match.group("model")
        if model_name in SECURITY_FUNCTION_MODELS:
            return model_name
    return ""


@dataclass
class _ServerActionCodeRisks:
    sudo_mutation: bool = False
    sensitive_model: str = ""
    tls_verify_disabled: bool = False


def _server_action_code_risks(code: str) -> _ServerActionCodeRisks:
    try:
        tree = ast.parse(textwrap.dedent(code))
    except SyntaxError:
        return _ServerActionCodeRisks()
    except Exception:
        return _ServerActionCodeRisks()
    scanner = _ServerActionCodeScanner(_module_constants(tree))
    scanner.visit(tree)
    return scanner.risks


class _ServerActionCodeScanner(ast.NodeVisitor):
    def __init__(self, constants: dict[str, ast.AST]) -> None:
        self.constants = constants
        self.risks = _ServerActionCodeRisks()
        self.elevated_names: set[str] = set()

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._track_elevated_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._track_elevated_target(node.target, node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._track_elevated_target(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        method = _call_name(node.func).rsplit(".", 1)[-1]
        if method in {"write", "create", "unlink"} and _is_elevated_expr(node.func, self.elevated_names, self.constants):
            self.risks.sudo_mutation = True
        if method in SECURITY_MUTATION_FUNCTIONS:
            model = _call_receiver_env_model(node.func, self.constants)
            if model in SECURITY_FUNCTION_MODELS:
                self.risks.sensitive_model = model
        if _is_http_call(node.func) and _keyword_is_false(node, "verify", self.constants):
            self.risks.tls_verify_disabled = True
        self.generic_visit(node)

    def _track_elevated_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in zip(target.elts, value.elts, strict=False):
                self._track_elevated_target(target_element, value_element)
            return
        if isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._track_elevated_target(element, value)
            return
        if isinstance(target, ast.Starred):
            self._track_elevated_target(target.value, value)
            return
        if not isinstance(target, ast.Name):
            return
        if _is_elevated_expr(value, self.elevated_names, self.constants):
            self.elevated_names.add(target.id)
        else:
            self.elevated_names.discard(target.id)


def _regex_sudo_mutation(code: str) -> bool:
    superuser_with_user = (
        r"with_user\(\s*(?:(?:user|uid)\s*=\s*)?"
        r"(?:SUPERUSER_ID|1|[^)]*base\.user_(?:admin|root)[^)]*)\s*\)"
    )
    return bool(re.search(rf"\.(?:sudo\(\)|{superuser_with_user}).*?\.(write|create|unlink)\s*\(", code, re.DOTALL))


def _is_elevated_expr(node: ast.AST, elevated_names: set[str], constants: dict[str, ast.AST]) -> bool:
    if isinstance(node, ast.Starred):
        return _is_elevated_expr(node.value, elevated_names, constants)
    if isinstance(node, ast.Name):
        return node.id in elevated_names
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_is_elevated_expr(element, elevated_names, constants) for element in node.elts)
    return (
        _call_root_name(node) in elevated_names
        or _call_chain_has_attr(node, "sudo")
        or _call_chain_has_superuser_with_user(node, constants)
    )


def _call_chain_has_attr(node: ast.AST, attr: str) -> bool:
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


def _call_chain_has_superuser_with_user(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Call):
            if isinstance(current.func, ast.Attribute) and current.func.attr == "with_user":
                return any(_is_superuser_arg(arg, constants) for arg in current.args) or any(
                    keyword.value is not None and _is_superuser_arg(keyword.value, constants)
                    for keyword in current.keywords
                )
            current = current.func
        elif isinstance(current, ast.Attribute):
            current = current.value
        else:
            current = current.value
    return False


def _is_superuser_arg(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    node = _resolve_constant(node, constants)
    if isinstance(node, ast.Constant):
        return node.value == 1 or node.value in {"base.user_admin", "base.user_root"}
    if isinstance(node, ast.Name):
        return node.id == "SUPERUSER_ID"
    if isinstance(node, ast.Attribute):
        return node.attr == "SUPERUSER_ID"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "ref":
        return any(_is_superuser_arg(arg, constants) for arg in node.args)
    return False


def _call_receiver_env_model(node: ast.AST, constants: dict[str, ast.AST]) -> str:
    if not isinstance(node, ast.Attribute):
        return ""
    current = node.value
    while isinstance(current, ast.Call | ast.Attribute):
        current = current.func if isinstance(current, ast.Call) else current.value
    if not isinstance(current, ast.Subscript):
        return ""
    if _call_name(current.value) not in {"env", "self.env"}:
        return ""
    key = _resolve_constant(current.slice, constants)
    if isinstance(key, ast.Constant) and isinstance(key.value, str):
        return key.value
    return ""


def _is_http_call(node: ast.AST) -> bool:
    call_name = _call_name(node)
    if call_name in {
        "requests.delete",
        "requests.get",
        "requests.head",
        "requests.patch",
        "requests.post",
        "requests.put",
        "requests.request",
        "httpx.delete",
        "httpx.get",
        "httpx.head",
        "httpx.patch",
        "httpx.post",
        "httpx.put",
        "httpx.request",
        "aiohttp.delete",
        "aiohttp.get",
        "aiohttp.head",
        "aiohttp.patch",
        "aiohttp.post",
        "aiohttp.put",
        "aiohttp.request",
    }:
        return True
    return call_name.endswith(
        (
            ".delete",
            ".get",
            ".head",
            ".patch",
            ".post",
            ".put",
            ".request",
        )
    ) and _call_root_name(node) in {"client", "session"}


def _keyword_is_false(node: ast.Call, name: str, constants: dict[str, ast.AST]) -> bool:
    for keyword in node.keywords:
        if keyword.arg != name:
            continue
        value = _resolve_constant(keyword.value, constants)
        if isinstance(value, ast.Constant) and value.value is False:
            return True
    return False


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


def _module_constants(tree: ast.Module) -> dict[str, ast.AST]:
    constants: dict[str, ast.AST] = {}
    for statement in tree.body:
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
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd | ast.USub):
        return _is_static_literal(node.operand)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(_is_static_literal(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (key is None or _is_static_literal(key)) and _is_static_literal(value)
            for key, value in zip(node.keys, node.values, strict=True)
        )
    return False


def _http_call_without_timeout(code: str) -> bool:
    return any(
        "timeout" not in match.group("args")
        for match in re.finditer(
            r"(?:(?:aiohttp|requests|httpx)\.(?:get|post|put|patch|delete|head|request)|(?:urllib\.request\.)?urlopen)"
            r"\s*\((?P<args>[^)]*)\)",
            code,
        )
    )


def _mentions_user_groups(value: str) -> bool:
    return ("groups_id" in value or "groups" in value) and _mentions_privileged_group(value)


def _mentions_privileged_group(value: str) -> bool:
    return bool(ADMIN_GROUP_RE.search(value) or INTERNAL_GROUP_RE.search(value))


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov"})


def findings_to_json(findings: list[XmlDataFinding]) -> list[dict[str, Any]]:
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
            "record_id": f.record_id,
        }
        for f in findings
    ]
