"""Scanner for risky Odoo mail template records."""

from __future__ import annotations

import re
from csv import DictReader
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

from defusedxml import ElementTree


@dataclass
class MailTemplateFinding:
    """Represents a risky mail template finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    template: str = ""
    field: str = ""


SENSITIVE_MODELS = {
    "account.move",
    "account.payment",
    "hr.employee",
    "hr.contract",
    "ir.config_parameter",
    "ir.cron",
    "ir.model.access",
    "ir.rule",
    "payment.provider",
    "payment.transaction",
    "res.groups",
    "res.partner",
    "res.users",
    "res.users.apikeys",
    "sale.order",
}
KNOWN_MODEL_EXTERNAL_IDS = {
    "account.model_account_move": "account.move",
    "model_account_move": "account.move",
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
SENSITIVE_FIELDS = {
    "access_key",
    "api_key",
    "apikey",
    "auth_token",
    "bearer_token",
    "client_secret",
    "csrf_token",
    "hmac_secret",
    "jwt_secret",
    "license_key",
    "oauth_token",
    "private_key",
    "secret",
    "secret_key",
    "session_token",
    "signature_secret",
    "signing_key",
    "totp_secret",
    "webhook_secret",
    "access_token",
    "access_url",
    "access_link",
    "partner_signup_url",
    "signup_token",
    "signup_url",
    "reset_password_token",
    "reset_password_url",
    "password",
    "new_password",
    "get_access_action",
    "get_portal_url",
    "portal_url",
}
TOKEN_EXPRESSION_FIELDS = (
    "body_html",
    "subject",
    "email_to",
    "email_cc",
    "partner_to",
    "reply_to",
    "email_from",
    "report_name",
)
PRIVILEGED_EXPRESSION_FIELDS = (*TOKEN_EXPRESSION_FIELDS, "lang", "scheduled_date")
EXTERNAL_URL_RE = re.compile(r"\bhttps?://|//[a-zA-Z0-9.-]+")
DANGEROUS_URL_SCHEME_RE = re.compile(
    r"(?:javascript|vbscript)\s*:|file\s*:|data\s*:\s*(?:text/html|image/svg\+xml|application/(?:javascript|xhtml\+xml))",
    re.IGNORECASE,
)
SUPERUSER_WITH_USER_RE = re.compile(
    r"\.with_user\(\s*(?:(?:user|uid)\s*=\s*)?"
    r"(?:SUPERUSER_ID|1|['\"]base\.user_(?:admin|root)['\"]|(?:[\w.]+\.)?ref\(\s*['\"]base\.user_(?:admin|root)['\"]\s*\))",
    re.DOTALL,
)


def scan_mail_templates(repo_path: Path) -> list[MailTemplateFinding]:
    """Scan data files for risky mail.template records."""
    findings: list[MailTemplateFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        scanner = MailTemplateScanner(path)
        if path.suffix == ".xml":
            findings.extend(scanner.scan_file())
        elif path.suffix == ".csv":
            findings.extend(scanner.scan_csv_file())
    return findings


class MailTemplateScanner:
    """Scanner for one XML file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.content = ""
        self.findings: list[MailTemplateFinding] = []

    def scan_file(self) -> list[MailTemplateFinding]:
        """Scan the XML file."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            root = ElementTree.fromstring(self.content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        for record in root.iter("record"):
            if record.get("model") == "mail.template":
                self._scan_template(record)
        return self.findings

    def scan_csv_file(self) -> list[MailTemplateFinding]:
        """Scan CSV mail.template records."""
        if _csv_model_name(self.path) != "mail.template":
            return []
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        for fields, line in _csv_dict_rows(self.content):
            self._scan_template_values(fields.get("id", ""), fields, line)
        return self.findings

    def _scan_template(self, record: ElementTree.Element) -> None:
        fields = _record_fields(record)
        template_id = record.get("id", "")
        line = self._line_for_record(record)
        self._scan_template_values(template_id, fields, line)

    def _scan_template_values(self, template_id: str, fields: dict[str, str], line: int) -> None:
        model = _normalize_model_ref(fields.get("model_id", "") or fields.get("model", ""))
        body = fields.get("body_html", "")
        recipients = " ".join(fields.get(name, "") for name in ("email_to", "email_cc", "partner_to", "reply_to"))
        sender_fields = " ".join(fields.get(name, "") for name in ("email_from", "reply_to"))

        if body and _contains_raw_html_rendering(body):
            self._add(
                "odoo-mail-template-raw-html",
                "Mail template renders raw HTML",
                "medium",
                line,
                "mail.template body_html uses raw/unsafe rendering; verify writers cannot inject scriptable HTML into outbound mail",
                template_id,
                "body_html",
            )

        if _contains_dangerous_url_scheme(body):
            self._add(
                "odoo-mail-template-dangerous-url-scheme",
                "Mail template contains dangerous URL scheme",
                "high",
                line,
                "mail.template body_html contains javascript:, data:text/html, vbscript:, or file: URLs; restrict outbound email links to safe local routes or reviewed HTTPS destinations",
                template_id,
                "body_html",
            )

        if _contains_insecure_http_url(body):
            self._add(
                "odoo-mail-template-insecure-url",
                "Mail template contains insecure HTTP URL",
                "medium",
                line,
                "mail.template body_html contains a literal http:// URL; use HTTPS or same-origin links to avoid downgrade, interception, and referrer leakage risk",
                template_id,
                "body_html",
            )

        token_text = _join_fields(fields, TOKEN_EXPRESSION_FIELDS)
        if _references_sensitive_value(token_text):
            token_field = _first_sensitive_field(fields, TOKEN_EXPRESSION_FIELDS) or "body_html"
            self._add(
                "odoo-mail-template-sensitive-token",
                "Mail template includes token/access fields",
                "high",
                line,
                "Mail template references access/password/signup token fields; verify recipients are constrained and links expire appropriately",
                template_id,
                token_field,
            )

            if not _is_truthy(fields.get("auto_delete", "")):
                self._add(
                    "odoo-mail-template-token-not-auto-deleted",
                    "Token-bearing mail template is retained",
                    "medium",
                    line,
                    "Mail template references access/password/signup token fields without auto_delete=True; verify generated mail records and logs do not retain usable secrets longer than necessary",
                    template_id,
                    "auto_delete",
                )

            if _looks_dynamic_recipient(recipients):
                self._add(
                    "odoo-mail-template-token-dynamic-recipient",
                    "Token-bearing mail template uses dynamic recipients",
                    "high",
                    line,
                    "Mail template references access/password/signup token fields while deriving recipients from expressions; verify attacker-controlled records cannot redirect capability links",
                    template_id,
                    "email_to",
                )

        expression_text = _join_fields(fields, PRIVILEGED_EXPRESSION_FIELDS)
        if _contains_privileged_expression(expression_text):
            self._add(
                "odoo-mail-template-sudo-expression",
                "Mail template expression uses privileged context",
                "high",
                line,
                "mail.template expression calls sudo()/with_user(SUPERUSER_ID); verify rendered content cannot disclose fields outside the recipient's access",
                template_id,
                "expression",
            )

        if model in SENSITIVE_MODELS and _looks_dynamic_recipient(recipients):
            self._add(
                "odoo-mail-template-dynamic-sensitive-recipient",
                "Sensitive template uses dynamic recipients",
                "medium",
                line,
                f"Mail template for sensitive model '{model}' derives recipients from expressions; verify attacker-controlled records cannot redirect private mail",
                template_id,
                "email_to",
            )

        if model in SENSITIVE_MODELS and _looks_dynamic_recipient(sender_fields):
            self._add(
                "odoo-mail-template-dynamic-sender",
                "Sensitive template uses dynamic sender or reply-to",
                "medium",
                line,
                f"Mail template for sensitive model '{model}' derives email_from/reply_to from expressions; verify attackers cannot spoof senders or redirect replies",
                template_id,
                "email_from",
            )

        if model in SENSITIVE_MODELS and _contains_external_link(body):
            self._add(
                "odoo-mail-template-external-link-sensitive",
                "Sensitive template contains external link",
                "medium",
                line,
                f"Mail template for sensitive model '{model}' includes an external URL; verify links cannot leak tokens, record identifiers, or private workflow context",
                template_id,
                "body_html",
            )

    def _line_for_record(self, record: ElementTree.Element) -> int:
        record_id = record.get("id")
        if record_id:
            return _line_for(self.content, f'id="{record_id}"')
        return _line_for(self.content, 'model="mail.template"')

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        template: str,
        field: str,
    ) -> None:
        self.findings.append(
            MailTemplateFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                template=template,
                field=field,
            )
        )


def _record_fields(record: ElementTree.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    for field in record.iter("field"):
        name = field.get("name")
        if not name:
            continue
        values[name] = field.get("ref") or field.get("eval") or "".join(field.itertext()).strip()
    return values


def _csv_model_name(path: Path) -> str:
    stem = path.stem.strip().lower()
    aliases = {
        "mail_template": "mail.template",
        "mail.template": "mail.template",
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
                if "/" in name or ":" in name:
                    normalized.setdefault(re.split(r"[/:]", name, maxsplit=1)[0], text)
            rows.append((normalized, index))
    except Exception:
        return []
    return rows


def _contains_raw_html_rendering(value: str) -> bool:
    lowered = value.lower()
    return bool("t-raw" in lowered or re.search(r"\|\s*safe\b", lowered) or re.search(r"\bmarkup\s*\(", lowered))


def _references_sensitive_value(value: str) -> bool:
    lowered = value.lower()
    return any(field in lowered for field in SENSITIVE_FIELDS)


def _join_fields(fields: dict[str, str], names: tuple[str, ...]) -> str:
    return " ".join(fields.get(name, "") for name in names)


def _first_sensitive_field(fields: dict[str, str], names: tuple[str, ...]) -> str:
    for name in names:
        if _references_sensitive_value(fields.get(name, "")):
            return name
    return ""


def _looks_dynamic_recipient(value: str) -> bool:
    return bool(re.search(r"\$\{|{{|object\.|record\.", value))


def _contains_external_link(value: str) -> bool:
    return bool(EXTERNAL_URL_RE.search(value))


def _contains_dangerous_url_scheme(value: str) -> bool:
    return bool(DANGEROUS_URL_SCHEME_RE.search(value))


def _contains_insecure_http_url(value: str) -> bool:
    return bool(re.search(r"\bhttp://", value, re.IGNORECASE))


def _contains_privileged_expression(value: str) -> bool:
    return "sudo(" in value or bool(SUPERUSER_WITH_USER_RE.search(value))


def _is_truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes"}


def _normalize_model_ref(value: str) -> str:
    normalized = value.strip().strip("'\"")
    ref_match = re.fullmatch(r"ref\(\s*['\"]([^'\"]+)['\"]\s*\)", normalized)
    if ref_match:
        normalized = ref_match.group(1)
    if normalized in KNOWN_MODEL_EXTERNAL_IDS:
        return KNOWN_MODEL_EXTERNAL_IDS[normalized]
    external_id = normalized.rsplit(".", 1)[-1]
    if external_id in KNOWN_MODEL_EXTERNAL_IDS:
        return KNOWN_MODEL_EXTERNAL_IDS[external_id]
    if normalized.startswith("model_"):
        return normalized.removeprefix("model_").replace("_", ".")
    if ".model_" in normalized:
        return normalized.rsplit(".model_", 1)[1].replace("_", ".")
    return normalized


def _line_for(content: str, needle: str) -> int:
    index = content.find(needle)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov"})


def findings_to_json(findings: list[MailTemplateFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "template": f.template,
            "field": f.field,
        }
        for f in findings
    ]
