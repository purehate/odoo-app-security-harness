"""Tests for Odoo access-control analysis."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.access_control import AccessControlAnalyzer, analyze_access_control


def test_xml_entities_are_not_expanded_into_access_control_findings(tmp_path: Path) -> None:
    """XML entities must not synthesize record-rule access findings."""
    module = tmp_path / "test_module"
    _write_manifest(module)
    security = module / "security"
    security.mkdir()
    (security / "rules.xml").write_text(
        """<!DOCTYPE odoo [
<!ENTITY universal_domain "[(1, '=', 1)]">
]>
<odoo>
  <record id="entity_rule" model="ir.rule">
    <field name="name">Entity rule</field>
    <field name="model_id" ref="base.model_res_partner"/>
    <field name="domain_force">&universal_domain;</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = analyze_access_control(tmp_path)

    assert not any(f.rule_id == "odoo-acl-universal-pass" for f in findings)


def _write_manifest(module: Path) -> None:
    module.mkdir(parents=True, exist_ok=True)
    (module / "__manifest__.py").write_text("{'name': 'Test'}", encoding="utf-8")


def test_model_external_ids_normalize_to_dotted_names(tmp_path: Path) -> None:
    """ACL coverage should understand model_res_users as res.users."""
    analyzer = AccessControlAnalyzer(tmp_path)

    assert analyzer._normalize_model_id("model_res_users") == "res.users"
    assert analyzer._normalize_model_id("base.model_res_partner") == "res.partner"
    assert analyzer._normalize_model_id("account.move") == "account.move"
    assert analyzer._normalize_model_id("base.model_ir_config_parameter") == "ir.config_parameter"


def test_sensitive_model_acl_coverage_uses_normalized_ids(tmp_path: Path) -> None:
    """A model_res_users ACL should satisfy res.users sensitive-model coverage."""
    module = tmp_path / "test_module"
    _write_manifest(module)
    security = module / "security"
    security.mkdir()
    (security / "ir.model.access.csv").write_text(
        "id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink\n"
        "access_users,res.users,model_res_users,base.group_system,1,1,1,1\n",
        encoding="utf-8",
    )

    findings = analyze_access_control(tmp_path)

    assert not any(f.rule_id == "odoo-acl-missing-sensitive" and f.model == "res.users" for f in findings)


def test_public_group_write_acl_is_high_severity(tmp_path: Path) -> None:
    """Public or portal write ACLs should be reported."""
    module = tmp_path / "test_module"
    _write_manifest(module)
    security = module / "security"
    security.mkdir()
    (security / "ir.model.access.csv").write_text(
        "id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink\n"
        "access_public,test.public,model_test_model,base.group_public,1,1,0,0\n",
        encoding="utf-8",
    )

    findings = analyze_access_control(tmp_path)

    assert any(f.rule_id == "odoo-acl-public-write" and f.severity == "high" for f in findings)


def test_public_read_and_global_read_on_sensitive_models_are_reported(tmp_path: Path) -> None:
    """Sensitive model reads should not be granted to public groups or all users casually."""
    module = tmp_path / "test_module"
    _write_manifest(module)
    security = module / "security"
    security.mkdir()
    (security / "ir.model.access.csv").write_text(
        "id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink\n"
        "access_public_partner,public partner,base.model_res_partner,base.group_public,1,0,0,0\n"
        "access_global_invoice,global invoice,account.model_account_move,,1,0,0,0\n",
        encoding="utf-8",
    )

    findings = analyze_access_control(tmp_path)
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-acl-public-read-sensitive" in rule_ids
    assert "odoo-acl-global-read-sensitive" in rule_ids


def test_sensitive_model_unlink_outside_admin_group_is_reported(tmp_path: Path) -> None:
    """Delete rights on sensitive models should be administratively scoped."""
    module = tmp_path / "test_module"
    _write_manifest(module)
    security = module / "security"
    security.mkdir()
    (security / "ir.model.access.csv").write_text(
        "id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink\n"
        "access_portal_sale,portal sale,sale.model_sale_order,base.group_portal,1,0,0,1\n",
        encoding="utf-8",
    )

    findings = analyze_access_control(tmp_path)

    assert any(f.rule_id == "odoo-acl-sensitive-unlink" for f in findings)


def test_sensitive_model_write_outside_admin_group_is_reported(tmp_path: Path) -> None:
    """Write/create rights on sensitive models need explicit review when non-admin scoped."""
    module = tmp_path / "test_module"
    _write_manifest(module)
    security = module / "security"
    security.mkdir()
    (security / "ir.model.access.csv").write_text(
        "id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink\n"
        "access_user_invoice,user invoice,account.model_account_move,base.group_user,1,True,yes,0\n",
        encoding="utf-8",
    )

    findings = analyze_access_control(tmp_path)

    assert any(f.rule_id == "odoo-acl-sensitive-write" and f.severity == "high" for f in findings)


def test_security_metadata_model_acl_outside_admin_group_is_reported(tmp_path: Path) -> None:
    """ACLs on security metadata should be scoped to administrator groups."""
    module = tmp_path / "test_module"
    _write_manifest(module)
    security = module / "security"
    security.mkdir()
    (security / "ir.model.access.csv").write_text(
        "id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink\n"
        "access_rules_user,rules,base.model_ir_rule,base.group_user,1,1,0,0\n",
        encoding="utf-8",
    )

    findings = analyze_access_control(tmp_path)

    assert any(f.rule_id == "odoo-acl-security-model-non-admin" for f in findings)


def test_config_parameter_acl_external_id_is_reported(tmp_path: Path) -> None:
    """ir.config_parameter ACLs should not evade checks through model external IDs."""
    module = tmp_path / "test_module"
    _write_manifest(module)
    security = module / "security"
    security.mkdir()
    (security / "ir.model.access.csv").write_text(
        "id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink\n"
        "access_params_user,params,base.model_ir_config_parameter,base.group_user,1,1,1,0\n",
        encoding="utf-8",
    )

    findings = analyze_access_control(tmp_path)

    assert any(
        f.rule_id == "odoo-acl-security-model-non-admin" and f.model == "base.model_ir_config_parameter"
        for f in findings
    )


def test_payment_provider_acl_outside_admin_group_is_reported(tmp_path: Path) -> None:
    """Payment provider access should be scoped like security configuration."""
    module = tmp_path / "test_module"
    _write_manifest(module)
    security = module / "security"
    security.mkdir()
    (security / "ir.model.access.csv").write_text(
        "id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink\n"
        "access_provider_user,provider,payment.model_payment_provider,base.group_user,1,1,0,0\n",
        encoding="utf-8",
    )

    findings = analyze_access_control(tmp_path)

    assert any(
        f.rule_id == "odoo-acl-security-model-non-admin" and f.model == "payment.model_payment_provider"
        for f in findings
    )


def test_payment_transaction_sensitive_write_acl_is_reported(tmp_path: Path) -> None:
    """Payment transaction mutation ACLs need the same review as business records."""
    module = tmp_path / "test_module"
    _write_manifest(module)
    security = module / "security"
    security.mkdir()
    (security / "ir.model.access.csv").write_text(
        "id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink\n"
        "access_transaction_user,transaction,payment.model_payment_transaction,base.group_user,1,1,1,0\n",
        encoding="utf-8",
    )

    findings = analyze_access_control(tmp_path)

    assert any(
        f.rule_id == "odoo-acl-sensitive-write" and f.model == "payment.model_payment_transaction" for f in findings
    )


def test_record_rule_universal_pass_and_no_groups(tmp_path: Path) -> None:
    """Global universal-pass record rules should be visible to reviewers."""
    module = tmp_path / "test_module"
    _write_manifest(module)
    security = module / "security"
    security.mkdir()
    (security / "rules.xml").write_text(
        """<odoo>
  <record id="test_rule_all" model="ir.rule">
    <field name="name">All records</field>
    <field name="model_id" ref="model_res_partner"/>
    <field name="domain_force">[(1, '=', 1)]</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = analyze_access_control(tmp_path)
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-acl-universal-pass" in rule_ids
    assert "odoo-acl-rule-no-groups" in rule_ids


def test_public_broad_security_record_rule_is_reported(tmp_path: Path) -> None:
    """Public/portal rules on security metadata should get sensitive-rule treatment."""
    module = tmp_path / "test_module"
    _write_manifest(module)
    security = module / "security"
    security.mkdir()
    (security / "rules.xml").write_text(
        """<odoo>
  <record id="portal_params_all" model="ir.rule">
    <field name="name">Portal all params</field>
    <field name="model_id" ref="base.model_ir_config_parameter"/>
    <field name="groups_id" eval="[(4, ref('base.group_portal'))]"/>
    <field name="domain_force">[]</field>
    <field name="perm_write">1</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = analyze_access_control(tmp_path)
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-acl-public-rule-broad-sensitive" in rule_ids
    assert "odoo-acl-public-rule-sensitive-mutation" in rule_ids


def test_public_broad_sensitive_record_rule_and_unlink_are_reported(tmp_path: Path) -> None:
    """Public/portal broad domains on sensitive models should be critical review leads."""
    module = tmp_path / "test_module"
    _write_manifest(module)
    security = module / "security"
    security.mkdir()
    (security / "rules.xml").write_text(
        """<odoo>
  <record id="portal_sale_all" model="ir.rule">
    <field name="name">Portal all sales</field>
    <field name="model_id" ref="sale.model_sale_order"/>
    <field name="groups_id" eval="[(4, ref('base.group_portal'))]"/>
    <field name="domain_force">[]</field>
    <field name="perm_unlink">1</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = analyze_access_control(tmp_path)
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-acl-public-rule-broad-sensitive" in rule_ids
    assert "odoo-acl-rule-sensitive-unlink" in rule_ids
    assert "odoo-acl-public-rule-sensitive-mutation" in rule_ids


def test_public_portal_sensitive_write_rule_is_reported_with_owner_domain(tmp_path: Path) -> None:
    """Owner-scoped public/portal mutation rules still need explicit write-field review."""
    module = tmp_path / "test_module"
    _write_manifest(module)
    security = module / "security"
    security.mkdir()
    (security / "rules.xml").write_text(
        """<odoo>
  <record id="portal_invoice_write" model="ir.rule">
    <field name="name">Portal invoice write</field>
    <field name="model_id" ref="account.model_account_move"/>
    <field name="groups_id" eval="[(4, ref('base.group_portal'))]"/>
    <field name="domain_force">[('partner_id', '=', user.partner_id.id)]</field>
    <field name="perm_write" eval="true"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = analyze_access_control(tmp_path)

    assert any(f.rule_id == "odoo-acl-public-rule-sensitive-mutation" for f in findings)
