"""Scanner for executable/risky Odoo XML data records."""

from __future__ import annotations

import ast
import re
import textwrap
from csv import DictReader
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from defusedxml import ElementTree

from odoo_security_harness.base_scanner import _line_for, _should_skip

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
CONFIG_PARAMETER_MODELS = {"ir.config_parameter", "ir.config.parameter"}
MAIL_SERVER_MODELS = {"ir.mail_server", "ir.mail.server"}
LOCAL_BASE_URL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}  # noqa: S104
SECURITY_TOGGLE_UNSAFE_VALUES = {
    "auth.signup.allow_uninvited": {"1", "true", "yes", "y"},
    "auth_signup.allow_uninvited": {"1", "true", "yes", "y"},
    "auth_signup.invitation_scope": {"b2c", "public"},
    "database.create": {"1", "true", "yes", "y"},
    "database.drop": {"1", "true", "yes", "y"},
    "list_db": {"1", "true", "yes", "y"},
    "web.base.url.freeze": {"0", "false", "no", "n"},
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
    """Scan Odoo data files for executable/security-sensitive records."""
    findings: list[XmlDataFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        scanner = XmlDataScanner(path)
        if path.suffix == ".xml":
            findings.extend(scanner.scan_file())
        elif path.suffix == ".csv":
            findings.extend(scanner.scan_csv_file())
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
            elif model in CONFIG_PARAMETER_MODELS:
                self._scan_config_parameter_record(record)
            elif model in MAIL_SERVER_MODELS:
                self._scan_mail_server_record(record)
        for function in root.iter("function"):
            self._scan_function(function)

        return self.findings

    def scan_csv_file(self) -> list[XmlDataFinding]:
        """Scan CSV data records for security-sensitive declarations."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        model = _csv_model_name(self.path)
        for fields, line in _csv_dict_rows(self.content):
            record_id = fields.get("id", "")
            if model == "ir.cron":
                self._scan_cron_fields(fields, line, record_id)
            elif model in {"mail.channel", "discuss.channel"}:
                self._scan_mail_channel_fields(model, fields, line, record_id)
            elif model == "res.users":
                self._scan_user_fields(fields, line, record_id)
            elif model == "res.groups":
                self._scan_group_fields(fields, line, record_id)
            elif model in CONFIG_PARAMETER_MODELS:
                self._scan_config_parameter_fields(fields, line, record_id)
            elif model in MAIL_SERVER_MODELS:
                self._scan_mail_server_fields(fields, line, record_id)
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
                "ir.actions.server uses state='code' and is reachable by broad/no groups; "
                "verify buttons/menus cannot expose arbitrary Python execution",
                "ir.actions.server",
                record_id,
            )

        if target_model in SECURITY_FUNCTION_MODELS:
            self._add(
                "odoo-xml-server-action-sensitive-model-code",
                "Executable server action targets sensitive model",
                "high",
                self._line_for_record(record),
                f"ir.actions.server uses state='code' on sensitive model '{target_model}'; "
                "verify action bindings, groups, and record-rule boundaries",
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
                f"ir.actions.server code mutates sensitive model '{sensitive_mutation_model}'; "
                "verify actor, groups, trigger scope, and audit trail",
                "ir.actions.server",
                record_id,
            )

        if "safe_eval" in code or re.search(r"\b(eval|exec)\s*\(", code):
            self._add(
                "odoo-xml-server-action-dynamic-eval",
                "Server action code performs dynamic evaluation",
                "critical",
                self._line_for_record(record),
                "ir.actions.server code contains eval/exec/safe_eval; "
                "verify no user-controlled expression can reach it",
                "ir.actions.server",
                record_id,
            )

        if code_risks.sudo_mutation or _regex_sudo_mutation(code):
            self._add(
                "odoo-xml-server-action-sudo-mutation",
                "Server action performs sudo mutation",
                "high",
                self._line_for_record(record),
                "ir.actions.server code chains sudo()/with_user(SUPERUSER_ID) into write/create/unlink; "
                "verify record rules and company isolation are not bypassed",
                "ir.actions.server",
                record_id,
            )

        if _http_call_without_timeout(code):
            self._add(
                "odoo-xml-server-action-http-no-timeout",
                "Server action performs HTTP request without timeout",
                "medium",
                self._line_for_record(record),
                "ir.actions.server code performs outbound HTTP without timeout; "
                "review SSRF, retry, and worker exhaustion risk",
                "ir.actions.server",
                record_id,
            )

        if code_risks.tls_verify_disabled:
            self._add(
                "odoo-xml-server-action-tls-verify-disabled",
                "Server action disables TLS verification",
                "high",
                self._line_for_record(record),
                "ir.actions.server code passes verify=False to outbound HTTP; "
                "install/update automation should not permit man-in-the-middle attacks",
                "ir.actions.server",
                record_id,
            )

        if code_risks.cleartext_http_url:
            self._add(
                "odoo-xml-server-action-cleartext-http-url",
                "Server action uses cleartext HTTP URL",
                "medium",
                self._line_for_record(record),
                "ir.actions.server code targets a literal http:// URL; use HTTPS to protect "
                "automation payloads and response data from interception or downgrade",
                "ir.actions.server",
                record_id,
            )
        if code_risks.url_embedded_credentials:
            self._add(
                "odoo-xml-server-action-url-embedded-credentials",
                "Server action URL embeds credentials",
                "high",
                self._line_for_record(record),
                "ir.actions.server code embeds username, password, or token material in an "
                "outbound HTTP URL authority; move credentials to server-side configuration",
                "ir.actions.server",
                record_id,
            )

    def _scan_cron(self, record: ElementTree.Element) -> None:
        fields = self._fields(record)
        self._scan_cron_fields(fields, self._line_for_record(record), record.get("id", ""))

    def _scan_cron_fields(self, fields: dict[str, str], line: int, record_id: str) -> None:
        state = fields.get("state", "")
        code = fields.get("code", "")
        callable_text = " ".join(
            fields.get(name, "") for name in ("code", "function", "method_direct_trigger", "args", "model_id", "name")
        )
        user_ref = fields.get("user_id", "")
        code_risks = _server_action_code_risks(code) if state == "code" else _ServerActionCodeRisks()

        if "base.user_root" in user_ref or "base.user_admin" in user_ref:
            self._add(
                "odoo-xml-cron-admin-user",
                "Cron executes as admin/root user",
                "high",
                line,
                "ir.cron runs under admin/root user; verify the scheduled job cannot process "
                "attacker-controlled records or external input with elevated privileges",
                "ir.cron",
                record_id,
            )
            if state == "code":
                self._add(
                    "odoo-xml-cron-root-code",
                    "Cron executes Python as admin/root",
                    "high",
                    line,
                    "ir.cron uses state='code' under admin/root user; verify it cannot process "
                    "attacker-controlled records or external input",
                    "ir.cron",
                    record_id,
                )

        if state == "code" and _http_call_without_timeout(code):
            self._add(
                "odoo-xml-cron-http-no-timeout",
                "Cron performs HTTP request without visible timeout",
                "medium",
                line,
                "Cron code performs outbound HTTP without timeout; review SSRF and worker exhaustion risk",
                "ir.cron",
                record_id,
            )

        if code_risks.tls_verify_disabled:
            self._add(
                "odoo-xml-cron-tls-verify-disabled",
                "Cron disables TLS verification",
                "high",
                line,
                "ir.cron code passes verify=False to outbound HTTP; "
                "scheduled integrations should not permit man-in-the-middle attacks",
                "ir.cron",
                record_id,
            )

        if code_risks.cleartext_http_url:
            self._add(
                "odoo-xml-cron-cleartext-http-url",
                "Cron uses cleartext HTTP URL",
                "medium",
                line,
                "ir.cron code targets a literal http:// URL; use HTTPS to protect scheduled "
                "integration payloads and response data from interception or downgrade",
                "ir.cron",
                record_id,
            )
        if code_risks.url_embedded_credentials:
            self._add(
                "odoo-xml-cron-url-embedded-credentials",
                "Cron URL embeds credentials",
                "high",
                line,
                "ir.cron code embeds username, password, or token material in an outbound HTTP "
                "URL authority; move credentials to server-side configuration",
                "ir.cron",
                record_id,
            )

        if _is_truthy(fields.get("doall", "")):
            self._add(
                "odoo-xml-cron-doall-enabled",
                "Cron catches up missed executions",
                "medium",
                line,
                "ir.cron has doall=True; after downtime it may replay missed jobs in bulk, "
                "causing duplicate side effects or load spikes",
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
                line,
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
                    line,
                    "ir.cron name/function/model suggests external import or sync; "
                    "verify timeouts, batching, locking, and retry safety",
                    "ir.cron",
                    record_id,
                )

    def _scan_mail_channel(self, record: ElementTree.Element) -> None:
        fields = self._fields(record)
        self._scan_mail_channel_fields(
            record.get("model", ""), fields, self._line_for_record(record), record.get("id", "")
        )

    def _scan_mail_channel_fields(self, model: str, fields: dict[str, str], line: int, record_id: str) -> None:
        if fields.get("allow_public_users") in {"1", "True", "true"}:
            self._add(
                "odoo-xml-public-mail-channel",
                "Mail/discuss channel allows public users",
                "medium",
                line,
                "Channel allows public users; verify this is intentional and cannot expose "
                "internal messages or metadata",
                model,
                record_id,
            )

    def _scan_user_record(self, record: ElementTree.Element) -> None:
        fields = self._fields(record)
        self._scan_user_fields(fields, self._line_for_record(record), record.get("id", ""))

    def _scan_user_fields(self, fields: dict[str, str], line: int, record_id: str) -> None:
        groups = fields.get("groups_id", "") + " " + fields.get("groups", "")
        if ADMIN_GROUP_RE.search(groups):
            self._add(
                "odoo-xml-user-admin-group-assignment",
                "XML data assigns user to administrator group",
                "critical",
                line,
                "res.users XML data assigns groups_id/groups to base.group_system or "
                "base.group_erp_manager; verify module install/update cannot grant unintended "
                "administrator access",
                "res.users",
                record_id,
            )

    def _scan_group_record(self, record: ElementTree.Element) -> None:
        fields = self._fields(record)
        self._scan_group_fields(fields, self._line_for_record(record), record.get("id", ""))

    def _scan_group_fields(self, fields: dict[str, str], line: int, record_id: str) -> None:
        implied_groups = fields.get("implied_ids", "")
        if not implied_groups or not _mentions_privileged_group(implied_groups):
            return

        self._add(
            "odoo-xml-group-implies-privilege",
            "XML data changes implied group privileges",
            "critical" if ADMIN_GROUP_RE.search(implied_groups) else "high",
            line,
            "res.groups XML data writes implied_ids toward internal/administrator groups; "
            "verify no public, portal, or signup-assigned group inherits unintended privileges",
            "res.groups",
            record_id,
        )

    def _scan_config_parameter_record(self, record: ElementTree.Element) -> None:
        fields = self._fields(record)
        self._scan_config_parameter_fields(fields, self._line_for_record(record), record.get("id", ""))

    def _scan_config_parameter_fields(self, fields: dict[str, str], line: int, record_id: str) -> None:
        key = fields.get("key", "").strip().strip("'\"")
        value = fields.get("value", "").strip().strip("'\"")
        if key in SECURITY_TOGGLE_UNSAFE_VALUES and value.lower() in SECURITY_TOGGLE_UNSAFE_VALUES[key]:
            self._add(
                "odoo-xml-config-param-security-toggle-enabled",
                "XML data enables security-sensitive config parameter",
                "high",
                line,
                f"Module data sets ir.config_parameter '{key}' to '{value}'; verify "
                "install/update cannot silently weaken signup, database manager, or "
                "generated-link security posture",
                "ir.config_parameter",
                record_id,
            )
        if key.lower() == "web.base.url" and _is_insecure_base_url(value):
            self._add(
                "odoo-xml-config-param-insecure-base-url",
                "XML data sets insecure base URL",
                "medium",
                line,
                "Module data sets web.base.url to HTTP or a local host; generated portal, OAuth, "
                "payment, and password-reset links should use the public HTTPS origin",
                "ir.config_parameter",
                record_id,
            )
        if key.lower() == "web.base.url" and _url_has_embedded_credentials(value):
            self._add(
                "odoo-xml-config-param-base-url-embedded-credentials",
                "XML data base URL embeds credentials",
                "high",
                line,
                "Module data sets web.base.url with username, password, or token material; "
                "generated portal, OAuth, payment, and password-reset links can leak those credentials",
                "ir.config_parameter",
                record_id,
            )

    def _scan_mail_server_record(self, record: ElementTree.Element) -> None:
        fields = self._fields(record)
        self._scan_mail_server_fields(fields, self._line_for_record(record), record.get("id", ""))

    def _scan_mail_server_fields(self, fields: dict[str, str], line: int, record_id: str) -> None:
        host = fields.get("smtp_host", "").strip().strip("'\"")
        password = fields.get("smtp_pass", fields.get("smtp_password", "")).strip().strip("'\"")
        encryption = fields.get("smtp_encryption", "").strip().strip("'\"").lower()
        port = fields.get("smtp_port", "").strip().strip("'\"")
        if password:
            self._add(
                "odoo-xml-mail-server-hardcoded-credential",
                "XML mail server commits SMTP credentials",
                "high",
                line,
                "ir.mail_server data includes a literal SMTP password; move outbound mail "
                "credentials to deployment secrets or administrator-managed configuration",
                "ir.mail_server",
                record_id,
            )
        if _mail_server_tls_disabled(host, encryption, port):
            self._add(
                "odoo-xml-mail-server-no-tls",
                "XML mail server does not require TLS",
                "medium",
                line,
                "ir.mail_server data configures outbound SMTP without TLS; credentials and "
                "notification content may cross the network in cleartext",
                "ir.mail_server",
                record_id,
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
                f"XML <function> calls {model}.{name} during data loading; verify module "
                "install/update cannot silently alter security metadata or sensitive defaults",
                model,
                "",
            )

        if model == "res.users" and name in {"create", "write"} and _mentions_user_groups(text):
            self._add(
                "odoo-xml-function-user-group-assignment",
                "XML function assigns user groups",
                "critical" if ADMIN_GROUP_RE.search(text) else "high",
                line,
                "XML <function> creates or writes res.users group assignments; verify module "
                "install/update cannot grant administrator or internal access unexpectedly",
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
                "XML <function> creates or writes res.groups implied_ids toward internal/"
                "administrator groups; verify no public, portal, or signup-assigned group "
                "inherits unintended privileges",
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


def _is_truthy(value: str) -> bool:
    return value.strip().strip("'\"").lower() in {"1", "true", "yes"}


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
                if "/" in name or ":" in name:
                    normalized.setdefault(re.split(r"[/:]", name, maxsplit=1)[0], text)
            rows.append((normalized, index))
    except Exception:
        return []
    return rows


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
    http_no_timeout: bool = False
    tls_verify_disabled: bool = False
    cleartext_http_url: bool = False
    url_embedded_credentials: bool = False


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
        self.superuser_names: set[str] = {"SUPERUSER_ID"}
        self.module_aliases: dict[str, str] = {}
        self.function_aliases: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            if alias.name == "urllib.request" and alias.asname is None:
                continue
            local_name = alias.asname or alias.name.split(".", 1)[0]
            if alias.name in {"aiohttp", "requests", "httpx", "urllib.request"}:
                self.module_aliases[local_name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module in {"aiohttp", "requests", "httpx", "urllib.request"}:
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
        _mark_static_dict_update(node, self.constants)
        method = _call_name(node.func).rsplit(".", 1)[-1]
        if method in {"write", "create", "unlink"} and _is_elevated_expr(
            node.func, self.elevated_names, self.constants, self.superuser_names
        ):
            self.risks.sudo_mutation = True
        if method in SECURITY_MUTATION_FUNCTIONS:
            model = _call_receiver_env_model(node.func, self.constants)
            if model in SECURITY_FUNCTION_MODELS:
                self.risks.sensitive_model = model
        if self._is_http_call(node.func):
            if not _has_effective_timeout(node, self.constants):
                self.risks.http_no_timeout = True
            if _keyword_is_false(node, "verify", self.constants):
                self.risks.tls_verify_disabled = True
            for url_value in _http_url_values(node, self._canonical_call_name(node.func), self.constants):
                if _is_cleartext_literal_url(url_value, self.constants):
                    self.risks.cleartext_http_url = True
                if _literal_url_has_embedded_credentials(url_value, self.constants):
                    self.risks.url_embedded_credentials = True
        self.generic_visit(node)

    def _is_http_call(self, node: ast.AST) -> bool:
        call_name = self._canonical_call_name(node)
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
            "urllib.request.urlopen",
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

    def _canonical_call_name(self, node: ast.AST) -> str:
        call_name = _call_name(node)
        if call_name in self.function_aliases:
            return self.function_aliases[call_name]
        parts = call_name.split(".")
        if parts and parts[0] in self.module_aliases:
            return ".".join([self.module_aliases[parts[0]], *parts[1:]])
        return call_name

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
        if _is_elevated_expr(value, self.elevated_names, self.constants, self.superuser_names):
            self.elevated_names.add(target.id)
        else:
            self.elevated_names.discard(target.id)


def _regex_sudo_mutation(code: str) -> bool:
    superuser_with_user = (
        r"with_user\(\s*(?:(?:user|uid)\s*=\s*)?" r"(?:SUPERUSER_ID|1|[^)]*base\.user_(?:admin|root)[^)]*)\s*\)"
    )
    return bool(re.search(rf"\.(?:sudo\(\)|{superuser_with_user}).*?\.(write|create|unlink)\s*\(", code, re.DOTALL))


def _is_elevated_expr(
    node: ast.AST,
    elevated_names: set[str],
    constants: dict[str, ast.AST],
    superuser_names: set[str] | None = None,
) -> bool:
    if isinstance(node, ast.Starred):
        return _is_elevated_expr(node.value, elevated_names, constants, superuser_names)
    if isinstance(node, ast.Name):
        return node.id in elevated_names
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_is_elevated_expr(element, elevated_names, constants, superuser_names) for element in node.elts)
    return (
        _call_root_name(node) in elevated_names
        or _call_chain_has_attr(node, "sudo")
        or _call_chain_has_superuser_with_user(node, constants, superuser_names)
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


def _call_chain_has_superuser_with_user(
    node: ast.AST,
    constants: dict[str, ast.AST],
    superuser_names: set[str] | None = None,
) -> bool:
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute | ast.Call | ast.Subscript):
        if isinstance(current, ast.Call):
            if isinstance(current.func, ast.Attribute) and current.func.attr == "with_user":
                return any(_is_superuser_arg(arg, constants, superuser_names) for arg in current.args) or any(
                    keyword.value is not None and _is_superuser_arg(keyword.value, constants, superuser_names)
                    for keyword in current.keywords
                )
            current = current.func
        elif isinstance(current, ast.Attribute):
            current = current.value
        else:
            current = current.value
    return False


def _is_superuser_arg(
    node: ast.AST,
    constants: dict[str, ast.AST],
    superuser_names: set[str] | None = None,
) -> bool:
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
    ) and _call_root_name(
        node
    ) in {"client", "session"}


def _keyword_is_false(node: ast.Call, name: str, constants: dict[str, ast.AST]) -> bool:
    for keyword_value in _keyword_values(node, name, constants):
        value = _resolve_constant(keyword_value, constants)
        if isinstance(value, ast.Constant) and value.value is False:
            return True
    return False


def _has_effective_timeout(node: ast.Call, constants: dict[str, ast.AST]) -> bool:
    timeout_values = _keyword_values(node, "timeout", constants)
    return bool(timeout_values) and not any(_is_none_constant(value, constants) for value in timeout_values)


def _is_none_constant(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    value = _resolve_constant(node, constants)
    return isinstance(value, ast.Constant) and value.value is None


def _http_url_values(node: ast.Call, sink: str, constants: dict[str, ast.AST]) -> list[ast.AST]:
    values: list[ast.AST] = []
    if node.args:
        method = sink.rsplit(".", 1)[-1]
        if method == "request" and len(node.args) >= 2:
            values.append(node.args[1])
        else:
            values.append(node.args[0])
    values.extend(_keyword_values(node, "url", constants))
    return values


def _is_cleartext_literal_url(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    value = _resolve_constant(node, constants)
    return (
        isinstance(value, ast.Constant)
        and isinstance(value.value, str)
        and value.value.strip().lower().startswith("http://")
    )


def _literal_url_has_embedded_credentials(node: ast.AST, constants: dict[str, ast.AST]) -> bool:
    value = _resolve_constant(node, constants)
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        return False
    parsed = urlparse(value.value.strip())
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.hostname)
        and (parsed.username is not None or parsed.password is not None)
    )


def _keyword_values(node: ast.Call, name: str, constants: dict[str, ast.AST]) -> list[ast.AST]:
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
    for key, value in zip(node.keys, node.values, strict=True):
        if key is None:
            resolved_value = _resolve_static_dict(value, constants)
            if resolved_value is not None:
                values.extend(_dict_keyword_values(resolved_value, name, constants))
            continue
        resolved_key = _resolve_constant(key, constants)
        if isinstance(resolved_key, ast.Constant) and resolved_key.value == name:
            values.append(value)
    return values


def _resolve_static_dict(node: ast.AST, constants: dict[str, ast.AST], seen: set[str] | None = None) -> ast.Dict | None:
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
    for key, value in zip(node.keys, node.values, strict=True):
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
        elif isinstance(statement, ast.Expr):
            _mark_static_dict_update(statement.value, constants)
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
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_static_literal(node.left) and _is_static_literal(node.right)
    return False


def _http_call_without_timeout(code: str) -> bool:
    try:
        ast.parse(textwrap.dedent(code))
    except SyntaxError:
        return any(
            "timeout" not in match.group("args")
            for match in re.finditer(
                r"(?:(?:aiohttp|requests|httpx)\.(?:get|post|put|patch|delete|head|request)|(?:[\w.]+\.)?urlopen)"
                r"\s*\((?P<args>[^)]*)\)",
                code,
            )
        )
    except Exception:
        return False
    return _server_action_code_risks(code).http_no_timeout


def _mentions_user_groups(value: str) -> bool:
    return ("groups_id" in value or "groups" in value) and _mentions_privileged_group(value)


def _mentions_privileged_group(value: str) -> bool:
    return bool(ADMIN_GROUP_RE.search(value) or INTERNAL_GROUP_RE.search(value))


def _is_insecure_base_url(value: str) -> bool:
    normalized = value.strip().strip("'\"").lower()
    if normalized.startswith("http://"):
        return True
    parsed = urlparse(normalized)
    return (parsed.hostname or "") in LOCAL_BASE_URL_HOSTS


def _url_has_embedded_credentials(value: str) -> bool:
    normalized = value.strip().strip("'\"")
    if not normalized:
        return False
    parsed = urlparse(normalized)
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.hostname)
        and (parsed.username is not None or parsed.password is not None)
    )


def _mail_server_tls_disabled(host: str, encryption: str, port: str) -> bool:
    if not host:
        return False
    host_name = host.lower()
    if host_name in LOCAL_BASE_URL_HOSTS:
        return False
    if encryption in {"ssl", "starttls", "tls"}:
        return False
    return encryption in {"", "none", "false", "0"} or port == "25"


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
