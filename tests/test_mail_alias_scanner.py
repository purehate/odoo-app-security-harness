"""Tests for inbound mail alias scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.mail_alias_scanner import scan_mail_aliases


def test_flags_public_alias_to_sensitive_model(tmp_path: Path) -> None:
    """Public aliases targeting sensitive models should be review leads."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "aliases.xml").write_text(
        """<odoo>
  <record id="alias_sale" model="mail.alias">
    <field name="alias_name">orders</field>
    <field name="alias_model_id" ref="sale.model_sale_order"/>
    <field name="alias_contact">everyone</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_mail_aliases(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-alias-public-sensitive-model" in rule_ids
    assert "odoo-mail-alias-broad-contact-policy" in rule_ids


def test_flags_public_alias_to_sensitive_model_in_csv(tmp_path: Path) -> None:
    """Public mail.alias CSV rows should get the same review coverage as XML."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "mail.alias.csv").write_text(
        "id,alias_name,alias_model_id/id,alias_contact\nalias_sale,orders,sale.model_sale_order,everyone\n",
        encoding="utf-8",
    )

    findings = scan_mail_aliases(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-alias-public-sensitive-model" in rule_ids
    assert "odoo-mail-alias-broad-contact-policy" in rule_ids


def test_flags_public_alias_with_colon_csv_ref(tmp_path: Path) -> None:
    """Colon-style alias model relation headers should normalize like slash-style headers."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "mail.alias.csv").write_text(
        "id,alias_name,alias_model_id:id,alias_contact\nalias_sale,orders,sale.model_sale_order,everyone\n",
        encoding="utf-8",
    )

    findings = scan_mail_aliases(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-alias-public-sensitive-model" in rule_ids
    assert "odoo-mail-alias-broad-contact-policy" in rule_ids


def test_flags_partners_alias_as_broad_sender_policy(tmp_path: Path) -> None:
    """Partner-wide aliases are still broad ingress compared with followers-only aliases."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "aliases.xml").write_text(
        """<odoo>
  <record id="alias_partner_cases" model="mail.alias">
    <field name="alias_name">cases</field>
    <field name="alias_model">helpdesk.ticket</field>
    <field name="alias_contact">partners</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_mail_aliases(tmp_path)

    assert any(f.rule_id == "odoo-mail-alias-broad-contact-policy" for f in findings)


def test_flags_csv_privileged_alias_owner_and_defaults(tmp_path: Path) -> None:
    """CSV aliases should expose privileged owners and default assignments."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "mail_alias.csv").write_text(
        "id,alias_name,alias_model,alias_contact,alias_user_id/id,alias_defaults\n"
        "alias_admin,admin-create,project.task,followers,base.user_admin,\"{'user_id': 1}\"\n",
        encoding="utf-8",
    )

    findings = scan_mail_aliases(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-alias-privileged-owner" in rule_ids
    assert "odoo-mail-alias-elevated-defaults" in rule_ids


def test_sensitive_alias_model_external_ids_are_normalized(tmp_path: Path) -> None:
    """Core model external IDs should not hide public aliases to sensitive models."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "aliases.xml").write_text(
        """<odoo>
  <record id="alias_params" model="mail.alias">
    <field name="alias_name">params</field>
    <field name="alias_model_id" ref="base.model_ir_config_parameter"/>
    <field name="alias_contact">everyone</field>
  </record>
  <record id="alias_payment_provider" model="mail.alias">
    <field name="alias_name">payment-provider</field>
    <field name="alias_model_id" ref="payment.model_payment_provider"/>
    <field name="alias_contact">partners</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_mail_aliases(tmp_path)
    models = {finding.model for finding in findings if finding.rule_id == "odoo-mail-alias-public-sensitive-model"}

    assert {"ir.config_parameter", "payment.provider"} <= models


def test_flags_elevated_and_dynamic_alias_defaults(tmp_path: Path) -> None:
    """Alias defaults should not assign privileged ownership or evaluate code."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "aliases.xml").write_text(
        """<odoo>
  <record id="alias_users" model="mail.alias">
    <field name="alias_name">users</field>
    <field name="alias_model">res.users</field>
    <field name="alias_contact">followers</field>
    <field name="alias_defaults">{'user_id': 1, 'groups_id': [(4, ref('base.group_system'))], 'x': safe_eval(ctx)}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_mail_aliases(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-alias-elevated-defaults" in rule_ids
    assert "odoo-mail-alias-dynamic-defaults" in rule_ids


def test_flags_privileged_alias_owner(tmp_path: Path) -> None:
    """Inbound aliases should not create or route records as admin/root users."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "aliases.xml").write_text(
        """<odoo>
  <record id="alias_admin" model="mail.alias">
    <field name="alias_name">admin-create</field>
    <field name="alias_model">project.task</field>
    <field name="alias_contact">followers</field>
    <field name="alias_user_id" ref="base.user_admin"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_mail_aliases(tmp_path)

    assert any(f.rule_id == "odoo-mail-alias-privileged-owner" for f in findings)


def test_flags_public_force_thread_alias(tmp_path: Path) -> None:
    """Broad aliases forced into an existing thread can permit external record injection."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "aliases.xml").write_text(
        """<odoo>
  <record id="alias_forced_thread" model="mail.alias">
    <field name="alias_name">case</field>
    <field name="alias_model">helpdesk.ticket</field>
    <field name="alias_contact">everyone</field>
    <field name="alias_force_thread_id" eval="42"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_mail_aliases(tmp_path)

    assert any(f.rule_id == "odoo-mail-alias-public-force-thread" for f in findings)


def test_flags_partners_force_thread_alias(tmp_path: Path) -> None:
    """Partner-wide forced-thread aliases can still permit external thread injection."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "aliases.xml").write_text(
        """<odoo>
  <record id="alias_forced_partner_thread" model="mail.alias">
    <field name="alias_name">case</field>
    <field name="alias_model">helpdesk.ticket</field>
    <field name="alias_contact">partners</field>
    <field name="alias_force_thread_id" eval="42"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_mail_aliases(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-alias-broad-contact-policy" in rule_ids
    assert "odoo-mail-alias-public-force-thread" in rule_ids


def test_safe_restricted_alias_is_ignored(tmp_path: Path) -> None:
    """Restricted aliases to low-risk models should avoid findings."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "aliases.xml").write_text(
        """<odoo>
  <record id="alias_help" model="mail.alias">
    <field name="alias_name">help</field>
    <field name="alias_model">project.task</field>
    <field name="alias_contact">followers</field>
    <field name="alias_defaults">{'priority': '0'}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_mail_aliases(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Alias fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "aliases.xml").write_text(
        """<odoo>
  <record id="alias_sale" model="mail.alias">
    <field name="alias_model">sale.order</field>
    <field name="alias_contact">everyone</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_mail_aliases(tmp_path) == []
