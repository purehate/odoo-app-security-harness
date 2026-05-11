"""Tests for translation catalog security scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.translation_scanner import scan_translations


def write_po(path: Path, content: str) -> None:
    """Write a PO file fixture."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_flags_dangerous_translated_html(tmp_path: Path) -> None:
    """Scriptable translated markup should be reported."""
    write_po(
        tmp_path / "module" / "i18n" / "fr.po",
        """
msgid "Open"
msgstr "<a href=\\"javascript:alert(1)\\">Ouvrir</a>"
""",
    )

    findings = scan_translations(tmp_path)

    assert {finding.rule_id for finding in findings} == {"odoo-i18n-dangerous-html"}
    assert findings[0].locale == "fr"


def test_flags_data_html_translated_url(tmp_path: Path) -> None:
    """Translated links should not introduce executable data-document URLs."""
    write_po(
        tmp_path / "module" / "i18n" / "fr.po",
        """
msgid "Open"
msgstr "<a href=\\"data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;\\">Ouvrir</a>"
""",
    )

    findings = scan_translations(tmp_path)

    assert {finding.rule_id for finding in findings} == {"odoo-i18n-dangerous-html"}


def test_flags_file_translated_url(tmp_path: Path) -> None:
    """Translated links should not point users at local-file URLs."""
    write_po(
        tmp_path / "module" / "i18n" / "fr.po",
        """
msgid "Open"
msgstr "<a href=\\"file:///etc/passwd\\">Ouvrir</a>"
""",
    )

    findings = scan_translations(tmp_path)

    assert {finding.rule_id for finding in findings} == {"odoo-i18n-dangerous-html"}


def test_flags_insecure_translated_http_url(tmp_path: Path) -> None:
    """Translated links should not downgrade users to cleartext HTTP."""
    write_po(
        tmp_path / "module" / "i18n" / "fr.po",
        """
msgid "Pay now"
msgstr "<a href=\\"http://portal.example.com/pay\\">Payer</a>"
""",
    )

    findings = scan_translations(tmp_path)

    assert any(
        finding.rule_id == "odoo-i18n-insecure-url"
        and finding.severity == "medium"
        and finding.locale == "fr"
        for finding in findings
    )


def test_ignores_https_translated_url_for_insecure_url_rule(tmp_path: Path) -> None:
    """HTTPS translated links should not create cleartext URL findings."""
    write_po(
        tmp_path / "module" / "i18n" / "fr.po",
        """
msgid "Pay now"
msgstr "<a href=\\"https://portal.example.com/pay\\">Payer</a>"
""",
    )

    findings = scan_translations(tmp_path)

    assert not any(finding.rule_id == "odoo-i18n-insecure-url" for finding in findings)


def test_flags_qweb_raw_output_in_translation(tmp_path: Path) -> None:
    """Translations should not be able to introduce raw QWeb output."""
    write_po(
        tmp_path / "module" / "i18n" / "de.po",
        """
msgid "Name"
msgstr "<span t-raw=\\"object.name\\"></span>"
""",
    )

    findings = scan_translations(tmp_path)

    assert "odoo-i18n-qweb-raw-output" in {finding.rule_id for finding in findings}


def test_flags_printf_placeholder_mismatch(tmp_path: Path) -> None:
    """Named printf placeholders should remain stable between source and translation."""
    write_po(
        tmp_path / "module" / "i18n" / "es.po",
        """
msgid "Order %(name)s for %(partner)s"
msgstr "Pedido %(name)s"
""",
    )

    findings = scan_translations(tmp_path)

    assert {finding.rule_id for finding in findings} == {"odoo-i18n-placeholder-mismatch"}


def test_flags_brace_placeholder_mismatch(tmp_path: Path) -> None:
    """Brace format placeholders should remain stable between source and translation."""
    write_po(
        tmp_path / "module" / "i18n" / "it.po",
        """
msgid "Invoice {number} for {partner}"
msgstr "Fattura {number}"
""",
    )

    findings = scan_translations(tmp_path)

    assert {finding.rule_id for finding in findings} == {"odoo-i18n-placeholder-mismatch"}


def test_flags_template_expression_added_by_translation(tmp_path: Path) -> None:
    """Translations should not introduce template expressions into plain source strings."""
    write_po(
        tmp_path / "module" / "i18n" / "pt.po",
        """
msgid "Your account is ready"
msgstr "Sua conta esta pronta ${object.password}"
""",
    )

    findings = scan_translations(tmp_path)

    assert "odoo-i18n-template-expression-injection" in {finding.rule_id for finding in findings}


def test_flags_qweb_control_directive_added_by_translation(tmp_path: Path) -> None:
    """Translations should not introduce QWeb control flow or attribute directives."""
    write_po(
        tmp_path / "module" / "i18n" / "pl.po",
        """
msgid "Continue"
msgstr "<t t-call=\\"web.login_layout\\">Continue</t>"
""",
    )

    findings = scan_translations(tmp_path)

    assert "odoo-i18n-template-expression-injection" in {finding.rule_id for finding in findings}


def test_flags_dangerous_plural_translation(tmp_path: Path) -> None:
    """Plural msgstr entries should be scanned like normal translated strings."""
    write_po(
        tmp_path / "module" / "i18n" / "fr.po",
        """
msgid "%(count)s record"
msgid_plural "%(count)s records"
msgstr[0] "%(count)s enregistrement"
msgstr[1] "<a href=\\"javascript:alert(1)\\">%(count)s enregistrements</a>"
""",
    )

    findings = scan_translations(tmp_path)

    assert "odoo-i18n-dangerous-html" in {finding.rule_id for finding in findings}


def test_plural_placeholder_sets_are_compared(tmp_path: Path) -> None:
    """Plural source placeholders should be considered when checking msgstr drift."""
    write_po(
        tmp_path / "module" / "i18n" / "es.po",
        """
msgid "%(count)s order"
msgid_plural "%(count)s orders for %(partner)s"
msgstr[0] "%(count)s pedido"
msgstr[1] "%(count)s pedidos"
""",
    )

    findings = scan_translations(tmp_path)

    assert "odoo-i18n-placeholder-mismatch" in {finding.rule_id for finding in findings}


def test_accepts_multiline_safe_translation(tmp_path: Path) -> None:
    """Multiline entries with matching placeholders should not be reported."""
    write_po(
        tmp_path / "module" / "i18n" / "nl.po",
        """
msgid ""
"Hello %(name)s, "
"your order {number} is ready"
msgstr ""
"Hallo %(name)s, "
"uw order {number} is klaar"
""",
    )

    findings = scan_translations(tmp_path)

    assert findings == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Fixture translation catalogs under tests should not affect repository scans."""
    write_po(
        tmp_path / "tests" / "i18n" / "fr.po",
        """
msgid "Open"
msgstr "<script>alert(1)</script>"
""",
    )

    assert scan_translations(tmp_path) == []
