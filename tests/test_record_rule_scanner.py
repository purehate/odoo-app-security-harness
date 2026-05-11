"""Tests for risky Odoo record-rule domain scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.record_rule_scanner import scan_record_rules


def test_flags_public_sensitive_rule_without_owner_scope(tmp_path: Path) -> None:
    """Portal/public rules on sensitive models need an owner, token, or company scope."""
    security = tmp_path / "module" / "security"
    security.mkdir(parents=True)
    (security / "rules.xml").write_text(
        """<odoo>
  <record id="portal_sale_state" model="ir.rule">
    <field name="model_id" ref="sale.model_sale_order"/>
    <field name="groups" eval="[(4, ref('base.group_portal'))]"/>
    <field name="domain_force">[('state', '=', 'sale')]</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_record_rules(tmp_path)

    assert any(f.rule_id == "odoo-record-rule-public-sensitive-no-owner-scope" for f in findings)


def test_flags_portal_write_on_sensitive_model(tmp_path: Path) -> None:
    """Record rules should not grant portal/public mutation on sensitive models."""
    security = tmp_path / "module" / "security"
    security.mkdir(parents=True)
    (security / "rules.xml").write_text(
        """<odoo>
  <record id="portal_invoice_write" model="ir.rule">
    <field name="model_id" ref="account.model_account_move"/>
    <field name="groups" eval="[(4, ref('base.group_portal'))]"/>
    <field name="domain_force">[('partner_id', '=', user.partner_id.id)]</field>
    <field name="perm_write" eval="True"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_record_rules(tmp_path)

    assert any(f.rule_id == "odoo-record-rule-portal-write-sensitive" for f in findings)


def test_flags_global_sensitive_mutation_rule(tmp_path: Path) -> None:
    """Sensitive mutation rules without groups apply too broadly."""
    security = tmp_path / "module" / "security"
    security.mkdir(parents=True)
    (security / "rules.xml").write_text(
        """<odoo>
  <record id="global_invoice_write" model="ir.rule">
    <field name="model_id" ref="account.model_account_move"/>
    <field name="domain_force">[('company_id', 'in', user.company_ids.ids)]</field>
    <field name="perm_write" eval="True"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_record_rules(tmp_path)

    assert any(f.rule_id == "odoo-record-rule-global-sensitive-mutation" for f in findings)


def test_flags_public_security_rule_without_owner_scope_and_mutation(tmp_path: Path) -> None:
    """Security metadata rules should get the same public mutation scrutiny."""
    security = tmp_path / "module" / "security"
    security.mkdir(parents=True)
    (security / "rules.xml").write_text(
        """<odoo>
  <record id="portal_params_write" model="ir.rule">
    <field name="model_id" ref="base.model_ir_config_parameter"/>
    <field name="groups" eval="[(4, ref('base.group_portal'))]"/>
    <field name="domain_force">[('key', '!=', False)]</field>
    <field name="perm_write" eval="True"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_record_rules(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-record-rule-public-sensitive-no-owner-scope" in rule_ids
    assert "odoo-record-rule-portal-write-sensitive" in rule_ids


def test_flags_public_sensitive_rule_without_owner_scope_in_csv(tmp_path: Path) -> None:
    """CSV ir.rule declarations should be scanned like XML records."""
    security = tmp_path / "module" / "security"
    security.mkdir(parents=True)
    (security / "ir_rule.csv").write_text(
        "id,model_id/id,groups/id,domain_force\n"
        "portal_sale_state,sale.model_sale_order,base.group_portal,\"[('state', '=', 'sale')]\"\n",
        encoding="utf-8",
    )

    findings = scan_record_rules(tmp_path)

    assert any(f.rule_id == "odoo-record-rule-public-sensitive-no-owner-scope" for f in findings)


def test_flags_portal_write_on_sensitive_model_in_csv(tmp_path: Path) -> None:
    """CSV record rules can grant public/portal mutation permissions."""
    security = tmp_path / "module" / "security"
    security.mkdir(parents=True)
    (security / "ir.rule.csv").write_text(
        "id,model_id,groups,domain_force,perm_write\n"
        "portal_invoice_write,account.model_account_move,base.group_portal,"
        "\"[('partner_id', '=', user.partner_id.id)]\",1\n",
        encoding="utf-8",
    )

    findings = scan_record_rules(tmp_path)

    assert any(f.rule_id == "odoo-record-rule-portal-write-sensitive" for f in findings)


def test_flags_portal_scope_inside_multi_group_csv_rule(tmp_path: Path) -> None:
    """CSV rules with multiple external-id groups should still detect portal scope."""
    security = tmp_path / "module" / "security"
    security.mkdir(parents=True)
    (security / "ir_rule.csv").write_text(
        "id,model_id/id,groups/id,domain_force,perm_write\n"
        "mixed_portal_invoice,account.model_account_move,\"base.group_user,base.group_portal\","
        "\"[('partner_id', '=', user.partner_id.id)]\",1\n",
        encoding="utf-8",
    )

    findings = scan_record_rules(tmp_path)

    assert any(
        f.rule_id == "odoo-record-rule-portal-write-sensitive" and f.group == "base.group_user,base.group_portal"
        for f in findings
    )


def test_flags_record_rule_domain_logic_in_csv(tmp_path: Path) -> None:
    """CSV domains should still surface group, context, hierarchy, and disabled-perm risks."""
    security = tmp_path / "module" / "security"
    security.mkdir(parents=True)
    (security / "ir_rule.csv").write_text(
        "id,model_id,domain_force,perm_read,perm_write,perm_create,perm_unlink\n"
        "stock_hierarchy,stock.model_stock_picking,"
        "\"['|', ('company_id', 'child_of', user.company_ids.ids), ('id', '=', user.has_group('base.group_system'))]\",1,0,0,0\n"
        "context_company,sale.model_sale_order,"
        "\"[('company_id', 'in', context.get('allowed_company_ids', []))]\",1,0,0,0\n"
        "disabled_rule,sale.model_sale_order,\"[('partner_id', '=', user.partner_id.id)]\",0,0,0,0\n",
        encoding="utf-8",
    )

    findings = scan_record_rules(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-record-rule-domain-has-group" in rule_ids
    assert "odoo-record-rule-company-child-of" in rule_ids
    assert "odoo-record-rule-context-dependent-domain" in rule_ids
    assert "odoo-record-rule-empty-permissions" in rule_ids


def test_flags_global_payment_provider_mutation_rule(tmp_path: Path) -> None:
    """Payment provider rules should normalize and be treated as strict-scope."""
    security = tmp_path / "module" / "security"
    security.mkdir(parents=True)
    (security / "rules.xml").write_text(
        """<odoo>
  <record id="global_payment_provider_write" model="ir.rule">
    <field name="model_id" ref="payment.model_payment_provider"/>
    <field name="domain_force">[('company_id', 'in', user.company_ids.ids)]</field>
    <field name="perm_write" eval="True"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_record_rules(tmp_path)

    assert any(
        finding.rule_id == "odoo-record-rule-global-sensitive-mutation" and finding.model == "payment.provider"
        for finding in findings
    )


def test_flags_group_checks_and_company_child_of_domains(tmp_path: Path) -> None:
    """Dynamic group checks and company hierarchy expansion deserve review."""
    security = tmp_path / "module" / "security"
    security.mkdir(parents=True)
    (security / "rules.xml").write_text(
        """<odoo>
  <record id="stock_hierarchy" model="ir.rule">
    <field name="model_id" ref="stock.model_stock_picking"/>
    <field name="domain_force">['|', ('company_id', 'child_of', user.company_ids.ids), ('id', '=', user.has_group('base.group_system'))]</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_record_rules(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-record-rule-domain-has-group" in rule_ids
    assert "odoo-record-rule-company-child-of" in rule_ids


def test_flags_universal_domain_on_sensitive_model(tmp_path: Path) -> None:
    """Empty or tautological domains on sensitive models should be explicit leads."""
    security = tmp_path / "module" / "security"
    security.mkdir(parents=True)
    (security / "rules.xml").write_text(
        """<odoo>
  <record id="all_users" model="ir.rule">
    <field name="model_id" ref="base.model_res_users"/>
    <field name="groups" eval="[(4, ref('base.group_user'))]"/>
    <field name="domain_force">[(1, '=', 1)]</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_record_rules(tmp_path)

    assert any(f.rule_id == "odoo-record-rule-universal-domain" for f in findings)


def test_xml_entities_are_not_expanded_into_record_rule_findings(tmp_path: Path) -> None:
    """XML entities must not synthesize broad record-rule domains."""
    security = tmp_path / "module" / "security"
    security.mkdir(parents=True)
    (security / "rules.xml").write_text(
        """<!DOCTYPE odoo [
<!ENTITY sensitive_model "sale.model_sale_order">
<!ENTITY broad_domain "[(1, '=', 1)]">
]>
<odoo>
  <record id="entity_portal_sale" model="ir.rule">
    <field name="model_id" ref="&sensitive_model;"/>
    <field name="groups" eval="[(4, ref('base.group_portal'))]"/>
    <field name="domain_force">&broad_domain;</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_record_rules(tmp_path) == []


def test_flags_context_dependent_domain(tmp_path: Path) -> None:
    """Record-rule domains should not depend on caller-controlled context."""
    security = tmp_path / "module" / "security"
    security.mkdir(parents=True)
    (security / "rules.xml").write_text(
        """<odoo>
  <record id="context_company" model="ir.rule">
    <field name="model_id" ref="sale.model_sale_order"/>
    <field name="domain_force">[('company_id', 'in', context.get('allowed_company_ids', []))]</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_record_rules(tmp_path)

    assert any(f.rule_id == "odoo-record-rule-context-dependent-domain" for f in findings)


def test_flags_rule_with_all_permissions_disabled(tmp_path: Path) -> None:
    """Rules with every perm flag false are usually ineffective metadata."""
    security = tmp_path / "module" / "security"
    security.mkdir(parents=True)
    (security / "rules.xml").write_text(
        """<odoo>
  <record id="disabled_rule" model="ir.rule">
    <field name="model_id" ref="sale.model_sale_order"/>
    <field name="domain_force">[('partner_id', '=', user.partner_id.id)]</field>
    <field name="perm_read" eval="False"/>
    <field name="perm_write" eval="False"/>
    <field name="perm_create" eval="False"/>
    <field name="perm_unlink" eval="False"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_record_rules(tmp_path)

    assert any(f.rule_id == "odoo-record-rule-empty-permissions" for f in findings)


def test_owner_scoped_portal_read_rule_is_ignored(tmp_path: Path) -> None:
    """Owner-scoped portal read rules should avoid broad-rule noise."""
    security = tmp_path / "module" / "security"
    security.mkdir(parents=True)
    (security / "rules.xml").write_text(
        """<odoo>
  <record id="portal_sale_owner" model="ir.rule">
    <field name="model_id" ref="sale.model_sale_order"/>
    <field name="groups" eval="[(4, ref('base.group_portal'))]"/>
    <field name="domain_force">[('partner_id', '=', user.partner_id.id)]</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_record_rules(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Record-rule fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "rules.xml").write_text(
        """<odoo>
  <record id="portal_sale_state" model="ir.rule">
    <field name="model_id" ref="sale.model_sale_order"/>
    <field name="groups" eval="[(4, ref('base.group_portal'))]"/>
    <field name="domain_force">[('state', '=', 'sale')]</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_record_rules(tmp_path) == []
