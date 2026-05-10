"""Scanner for risky Odoo translation catalog entries."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class TranslationFinding:
    """Represents an i18n/translation catalog finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    msgid: str = ""
    locale: str = ""


DANGEROUS_HTML_RE = re.compile(
    r"<\s*script\b|(?:javascript|vbscript)\s*:|file\s*:|data\s*:\s*(?:text/html|application/(?:javascript|xhtml\+xml))|on[a-z]+\s*=|<\s*iframe\b|<\s*object\b|<\s*embed\b",
    re.IGNORECASE,
)
QWEB_RAW_RE = re.compile(r"\bt-raw\s*=|\bt-out\s*=", re.IGNORECASE)
TEMPLATE_EXPR_RE = re.compile(
    r"\$\{[^}]+\}|\{\{[^}]+\}\}|<\s*t\b[^>]*\bt-(?:call|foreach|if|set|att|attf)-?", re.IGNORECASE
)
PRINTF_NAMED_RE = re.compile(r"%\(([^)]+)\)[#0 +\-]*\d*(?:\.\d+)?[bcdeEfFgGnosxXr]")
PRINTF_POSITIONAL_RE = re.compile(r"(?<!%)%(?!%)[#0 +\-]*\d*(?:\.\d+)?[bcdeEfFgGnosxXr]")
BRACE_RE = re.compile(r"(?<!{){([A-Za-z_][A-Za-z0-9_]*|\d+)(?:![rsa])?(?::[^{}]*)?}(?!})")


def scan_translations(repo_path: Path) -> list[TranslationFinding]:
    """Scan .po translation files for risky translated markup and placeholder drift."""
    findings: list[TranslationFinding] = []
    for path in repo_path.rglob("*.po"):
        if _should_skip(path):
            continue
        findings.extend(TranslationScanner(path).scan_file())
    return findings


class TranslationScanner:
    """Scanner for one gettext catalog."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[TranslationFinding] = []

    def scan_file(self) -> list[TranslationFinding]:
        """Scan the file."""
        try:
            lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return []

        for entry in _parse_po_entries(lines):
            if not entry.msgid or not entry.msgstr:
                continue
            self._scan_entry(entry)
        return self.findings

    def _scan_entry(self, entry: PoEntry) -> None:
        if DANGEROUS_HTML_RE.search(entry.msgstr):
            self._add(
                "odoo-i18n-dangerous-html",
                "Translation injects dangerous HTML or scriptable URL",
                "high",
                entry.msgstr_line,
                "Translated msgstr contains scriptable HTML, event handlers, or dangerous URL schemes such as javascript:, data:text/html, vbscript:, or file:; translated catalogs can bypass reviewed template text",
                entry.msgid,
            )
        if QWEB_RAW_RE.search(entry.msgstr):
            self._add(
                "odoo-i18n-qweb-raw-output",
                "Translation injects raw QWeb output directive",
                "high",
                entry.msgstr_line,
                "Translated msgstr contains raw QWeb output directives; verify translations cannot disable escaping",
                entry.msgid,
            )
        if TEMPLATE_EXPR_RE.search(entry.msgstr) and not TEMPLATE_EXPR_RE.search(entry.msgid):
            self._add(
                "odoo-i18n-template-expression-injection",
                "Translation injects template expression",
                "high",
                entry.msgstr_line,
                "Translated msgstr introduces template expressions or QWeb control directives absent from the source string; verify translators cannot execute template logic or expose object/request data",
                entry.msgid,
            )

        id_placeholders = _extract_placeholders(entry.msgid)
        str_placeholders = _extract_placeholders(entry.msgstr)
        if id_placeholders != str_placeholders:
            self._add(
                "odoo-i18n-placeholder-mismatch",
                "Translation changes interpolation placeholders",
                "medium",
                entry.msgstr_line,
                f"Translated msgstr placeholders {sorted(str_placeholders)} do not match msgid placeholders {sorted(id_placeholders)}; placeholder drift can drop escaped values or break rendering",
                entry.msgid,
            )

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        msgid: str,
    ) -> None:
        self.findings.append(
            TranslationFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                msgid=msgid[:120],
                locale=_locale_for(self.path),
            )
        )


@dataclass
class PoEntry:
    """Parsed gettext entry."""

    msgid: str
    msgstr: str
    msgid_line: int
    msgstr_line: int


def _parse_po_entries(lines: list[str]) -> list[PoEntry]:
    entries: list[PoEntry] = []
    msgid_parts: list[str] = []
    msgstr_parts: list[str] = []
    msgid_line = 0
    msgstr_line = 0
    current: str | None = None

    def flush() -> None:
        nonlocal msgid_parts, msgstr_parts, msgid_line, msgstr_line, current
        if msgid_parts or msgstr_parts:
            entries.append(
                PoEntry(
                    msgid="".join(msgid_parts),
                    msgstr="".join(msgstr_parts),
                    msgid_line=msgid_line,
                    msgstr_line=msgstr_line or msgid_line,
                )
            )
        msgid_parts = []
        msgstr_parts = []
        msgid_line = 0
        msgstr_line = 0
        current = None

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            flush()
            continue
        if line.startswith("#"):
            continue
        if line.startswith("msgid "):
            if msgid_parts or msgstr_parts:
                flush()
            current = "msgid"
            msgid_line = line_number
            msgid_parts.append(_po_string_value(line[6:]))
        elif line.startswith("msgstr "):
            current = "msgstr"
            msgstr_line = line_number
            msgstr_parts.append(_po_string_value(line[7:]))
        elif line.startswith('"') and current == "msgid":
            msgid_parts.append(_po_string_value(line))
        elif line.startswith('"') and current == "msgstr":
            msgstr_parts.append(_po_string_value(line))

    flush()
    return entries


def _po_string_value(token: str) -> str:
    token = token.strip()
    if len(token) < 2 or not token.startswith('"') or not token.endswith('"'):
        return ""
    try:
        return bytes(token[1:-1], "utf-8").decode("unicode_escape")
    except Exception:
        return token[1:-1]


def _extract_placeholders(text: str) -> set[str]:
    placeholders = {f"%({match})" for match in PRINTF_NAMED_RE.findall(text)}
    placeholders.update("%" for _ in PRINTF_POSITIONAL_RE.findall(text))
    placeholders.update(f"{{{match}}}" for match in BRACE_RE.findall(text))
    return placeholders


def _locale_for(path: Path) -> str:
    return path.stem


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[TranslationFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "msgid": f.msgid,
            "locale": f.locale,
        }
        for f in findings
    ]
