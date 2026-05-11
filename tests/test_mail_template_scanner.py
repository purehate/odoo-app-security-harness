"""Tests for Odoo mail template scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.mail_template_scanner import MailTemplateScanner, scan_mail_templates


def test_raw_html_rendering_is_reported(tmp_path: Path) -> None:
    """Unsafe HTML rendering inside email templates should be flagged."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_raw" model="mail.template">
    <field name="body_html"><![CDATA[<div t-raw="object.note"/></div>]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-mail-template-raw-html" for f in findings)


def test_sensitive_access_tokens_are_reported(tmp_path: Path) -> None:
    """Templates that include access/reset tokens should be review leads."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_token" model="mail.template">
    <field name="body_html">Click ${object.access_url}?token=${object.access_token}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-mail-template-sensitive-token" for f in findings)


def test_integration_credential_fields_are_reported(tmp_path: Path) -> None:
    """Templates that include integration credential fields should be review leads."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_connector_credentials" model="mail.template">
    <field name="body_html">${object.access_key} ${object.license_key} ${object.client_secret}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-mail-template-sensitive-token" for f in findings)


def test_sensitive_access_tokens_in_csv_are_reported(tmp_path: Path) -> None:
    """CSV mail.template rows should be scanned like XML records."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "mail_template.csv").write_text(
        "id,name,body_html\ntemplate_token,Token,Open ${object.access_url}\n",
        encoding="utf-8",
    )

    findings = scan_mail_templates(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-template-sensitive-token" in rule_ids
    assert "odoo-mail-template-token-not-auto-deleted" in rule_ids


def test_csv_token_template_with_auto_delete_is_ignored(tmp_path: Path) -> None:
    """CSV auto_delete=True should suppress token-retention findings."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "mail.template.csv").write_text(
        "id,name,body_html,auto_delete\ntemplate_token,Token,Open ${object.access_url},True\n",
        encoding="utf-8",
    )

    findings = scan_mail_templates(tmp_path)

    assert any(f.rule_id == "odoo-mail-template-sensitive-token" for f in findings)
    assert not any(f.rule_id == "odoo-mail-template-token-not-auto-deleted" for f in findings)


def test_sensitive_csv_template_model_external_id_is_normalized(tmp_path: Path) -> None:
    """CSV model relation columns should normalize sensitive model external IDs."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "mail_template.csv").write_text(
        "id,name,model_id/id,email_to,body_html\n"
        "template_invoice,Invoice,account.model_account_move,${object.partner_id.email},Invoice ready\n",
        encoding="utf-8",
    )

    findings = scan_mail_templates(tmp_path)

    assert any(
        finding.rule_id == "odoo-mail-template-dynamic-sensitive-recipient" and finding.template == "template_invoice"
        for finding in findings
    )


def test_sensitive_csv_template_colon_model_external_id_is_normalized(tmp_path: Path) -> None:
    """CSV model refs exported with colon headers should drive sensitive-template checks."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "mail_template.csv").write_text(
        "id,name,model_id:id,email_to,body_html\n"
        "template_invoice,Invoice,account.model_account_move,${object.partner_id.email},Invoice ready\n",
        encoding="utf-8",
    )

    findings = scan_mail_templates(tmp_path)

    assert any(
        finding.rule_id == "odoo-mail-template-dynamic-sensitive-recipient" and finding.template == "template_invoice"
        for finding in findings
    )


def test_sensitive_signup_url_helpers_are_reported(tmp_path: Path) -> None:
    """Odoo signup URL helper fields carry tokenized account-access links."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_signup_url" model="mail.template">
    <field name="body_html">Activate ${object.partner_signup_url}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-template-sensitive-token" in rule_ids
    assert "odoo-mail-template-token-not-auto-deleted" in rule_ids


def test_portal_url_helpers_are_reported(tmp_path: Path) -> None:
    """Portal URL helpers often carry tokenized or capability-style links."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_portal_url" model="mail.template">
    <field name="body_html">Open ${object.get_portal_url()}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-template-sensitive-token" in rule_ids
    assert "odoo-mail-template-token-not-auto-deleted" in rule_ids


def test_sensitive_reset_url_in_subject_is_reported(tmp_path: Path) -> None:
    """Reset URL helpers in subjects should be treated like token references."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_reset_url" model="mail.template">
    <field name="subject">Reset link ${object.reset_password_url}</field>
    <field name="body_html">Use the reset link</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-mail-template-sensitive-token" for f in findings)


def test_sensitive_token_in_report_name_is_reported(tmp_path: Path) -> None:
    """Generated report names can retain tokenized values in attachments and logs."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_report_token" model="mail.template">
    <field name="report_name">Invoice-${object.access_token}</field>
    <field name="body_html">Invoice attached</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(
        f.rule_id == "odoo-mail-template-sensitive-token"
        and f.field == "report_name"
        and f.template == "template_report_token"
        for f in findings
    )
    assert any(f.rule_id == "odoo-mail-template-token-not-auto-deleted" for f in findings)


def test_token_template_without_auto_delete_is_reported(tmp_path: Path) -> None:
    """Token-bearing generated email should not be retained by default."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_token_retained" model="mail.template">
    <field name="body_html">Click ${object.access_url}?token=${object.access_token}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-mail-template-token-not-auto-deleted" for f in findings)


def test_token_template_with_auto_delete_is_ignored(tmp_path: Path) -> None:
    """auto_delete=True should suppress the token-retention finding."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_token_auto_delete" model="mail.template">
    <field name="auto_delete" eval="True"/>
    <field name="body_html">Click ${object.access_url}?token=${object.access_token}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert not any(f.rule_id == "odoo-mail-template-token-not-auto-deleted" for f in findings)


def test_token_template_dynamic_recipient_is_reported(tmp_path: Path) -> None:
    """Token-bearing templates should not route capability links through record-controlled emails."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_token_dynamic_recipient" model="mail.template">
    <field name="model">project.task</field>
    <field name="email_to">${object.partner_email}</field>
    <field name="body_html">Open ${object.access_url}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(
        f.rule_id == "odoo-mail-template-token-dynamic-recipient"
        and f.template == "template_token_dynamic_recipient"
        and f.severity == "high"
        for f in findings
    )


def test_sudo_expression_is_reported(tmp_path: Path) -> None:
    """Template expressions should not silently elevate record access."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_sudo" model="mail.template">
    <field name="body_html">${object.sudo().secret_note}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-mail-template-sudo-expression" for f in findings)


def test_superuser_with_user_expression_is_reported(tmp_path: Path) -> None:
    """Template expressions using admin-root with_user should be treated like sudo."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_superuser" model="mail.template">
    <field name="body_html">${object.with_user(user=SUPERUSER_ID).secret_note}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-mail-template-sudo-expression" for f in findings)


def test_env_ref_superuser_with_user_expression_is_reported(tmp_path: Path) -> None:
    """Template expressions using admin XML-ID with_user should be treated like sudo."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_env_ref_superuser" model="mail.template">
    <field name="body_html">${object.with_user(object.env.ref('base.user_admin')).secret_note}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-mail-template-sudo-expression" for f in findings)


def test_csv_ref_superuser_with_user_expression_is_reported(tmp_path: Path) -> None:
    """CSV mail.template rows should catch admin XML-ID with_user expressions."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "mail_template.csv").write_text(
        "id,name,body_html\n"
        "template_ref_superuser,Ref Superuser,${object.with_user(ref('base.user_root')).secret_note}\n",
        encoding="utf-8",
    )

    findings = scan_mail_templates(tmp_path)

    assert any(f.rule_id == "odoo-mail-template-sudo-expression" for f in findings)


def test_regular_with_user_expression_is_not_sudo(tmp_path: Path) -> None:
    """Regular with_user expressions should not be reported as privileged rendering."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_regular_user" model="mail.template">
    <field name="body_html">${object.with_user(object.user_id).name}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert not any(f.rule_id == "odoo-mail-template-sudo-expression" for f in findings)


def test_sudo_sender_expression_is_reported(tmp_path: Path) -> None:
    """Privileged expressions in email_from/reply_to can disclose or spoof context."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_sudo_sender" model="mail.template">
    <field name="email_from">${object.sudo().user_id.email}</field>
    <field name="body_html">Updated</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-mail-template-sudo-expression" for f in findings)


def test_sudo_report_name_expression_is_reported(tmp_path: Path) -> None:
    """Privileged template expressions outside the body can still disclose values."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_sudo_report_name" model="mail.template">
    <field name="report_name">${object.sudo().secret_note}</field>
    <field name="body_html">Attached</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(
        f.rule_id == "odoo-mail-template-sudo-expression" and f.template == "template_sudo_report_name"
        for f in findings
    )


def test_sensitive_template_dynamic_recipient_is_reported(tmp_path: Path) -> None:
    """Sensitive templates with expression-derived recipients can leak private mail."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_invoice" model="mail.template">
    <field name="model_id" ref="account.model_account_move"/>
    <field name="email_to">${object.partner_id.email}</field>
    <field name="body_html">Invoice ready</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-mail-template-dynamic-sensitive-recipient" for f in findings)


def test_sensitive_template_dynamic_sender_is_reported(tmp_path: Path) -> None:
    """Sender/reply-to expressions on sensitive mail deserve spoofing review."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_invoice_sender" model="mail.template">
    <field name="model_id" ref="account.model_account_move"/>
    <field name="email_from">${object.user_id.email}</field>
    <field name="reply_to">${object.partner_id.email}</field>
    <field name="body_html">Invoice ready</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-mail-template-dynamic-sender" for f in findings)


def test_sensitive_template_external_link_is_reported(tmp_path: Path) -> None:
    """External links in sensitive templates can leak workflow context."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_invoice_link" model="mail.template">
    <field name="model_id" ref="account.model_account_move"/>
    <field name="body_html">Review https://billing.example.com/invoice/${object.id}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-mail-template-external-link-sensitive" for f in findings)


def test_dangerous_url_scheme_is_reported(tmp_path: Path) -> None:
    """Email template links should not use executable URL schemes."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_dangerous_link" model="mail.template">
    <field name="body_html"><![CDATA[<a href="javascript:alert(document.domain)">Open</a>]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(
        f.rule_id == "odoo-mail-template-dangerous-url-scheme" and f.field == "body_html" and f.severity == "high"
        for f in findings
    )


def test_data_html_url_scheme_is_reported(tmp_path: Path) -> None:
    """Email template links should not embed executable data documents."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_data_link" model="mail.template">
    <field name="body_html"><![CDATA[<a href="data:text/html,<script>alert(1)</script>">Open</a>]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-mail-template-dangerous-url-scheme" for f in findings)


def test_sensitive_model_external_ids_are_normalized(tmp_path: Path) -> None:
    """Core model external IDs should not evade sensitive template checks."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_params" model="mail.template">
    <field name="model_id" ref="base.model_ir_config_parameter"/>
    <field name="email_to">${object.user_id.email}</field>
    <field name="body_html">Parameter changed</field>
  </record>
  <record id="template_payment_provider" model="mail.template">
    <field name="model_id" ref="payment.model_payment_provider"/>
    <field name="body_html">Review https://pay.example.com/provider/${object.id}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()
    templates = {
        finding.template
        for finding in findings
        if finding.rule_id
        in {
            "odoo-mail-template-dynamic-sensitive-recipient",
            "odoo-mail-template-external-link-sensitive",
        }
    }

    assert {"template_params", "template_payment_provider"} <= templates


def test_eval_ref_model_external_ids_are_normalized(tmp_path: Path) -> None:
    """eval=ref(...) model IDs should still drive sensitive template checks."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_eval_ref" model="mail.template">
    <field name="model_id" eval="ref('account.model_account_move')"/>
    <field name="email_to">${object.partner_id.email}</field>
    <field name="body_html">Invoice ready</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-mail-template-dynamic-sensitive-recipient" for f in findings)


def test_direct_model_field_is_normalized(tmp_path: Path) -> None:
    """Legacy/direct model fields should still classify sensitive templates."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="template_direct_model" model="mail.template">
    <field name="model">sale.order</field>
    <field name="body_html">Review https://sales.example.com/order/${object.id}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-mail-template-external-link-sensitive" for f in findings)


def test_mail_template_xml_entities_are_not_expanded(tmp_path: Path) -> None:
    """Mail template XML parsing should reject entities instead of expanding them into findings."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<!DOCTYPE odoo [
<!ENTITY sensitive_body "Click ${object.access_token}">
]>
<odoo>
  <record id="template_entity" model="mail.template">
    <field name="body_html">&sensitive_body;</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MailTemplateScanner(xml).scan_file()

    assert not findings


def test_repository_scan_finds_mail_templates(tmp_path: Path) -> None:
    """Repository scan should include XML mail template data files."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "mail.xml").write_text(
        """<odoo><record id="template_token" model="mail.template">
<field name="body_html">${object.signup_token}</field>
</record></odoo>""",
        encoding="utf-8",
    )

    findings = scan_mail_templates(tmp_path)

    assert any(f.rule_id == "odoo-mail-template-sensitive-token" for f in findings)
