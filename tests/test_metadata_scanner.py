"""Tests for security-sensitive metadata scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.metadata_scanner import MetadataScanner, scan_metadata


def test_xml_entities_are_not_expanded_into_metadata_findings(tmp_path: Path) -> None:
    """XML entities must not synthesize public write ACL findings."""
    xml = tmp_path / "security.xml"
    xml.write_text(
        """<!DOCTYPE odoo [
<!ENTITY public_group "base.group_public">
]>
<odoo>
  <record id="access_entity" model="ir.model.access">
    <field name="model_id" ref="sale.model_sale_order"/>
    <field name="group_id" ref="&public_group;"/>
    <field name="perm_write">1</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert MetadataScanner(xml).scan_xml_file() == []


def test_xml_public_write_acl_is_reported(tmp_path: Path) -> None:
    """XML ir.model.access records can grant public mutation permissions."""
    xml = tmp_path / "security.xml"
    xml.write_text(
        """<odoo>
  <record id="access_public_order" model="ir.model.access">
    <field name="model_id" ref="sale.model_sale_order"/>
    <field name="group_id" ref="base.group_public"/>
    <field name="perm_read">1</field>
    <field name="perm_write">1</field>
    <field name="perm_create">0</field>
    <field name="perm_unlink">0</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MetadataScanner(xml).scan_xml_file()

    assert any(f.rule_id == "odoo-metadata-public-write-acl" for f in findings)


def test_xml_sensitive_public_read_acl_is_reported(tmp_path: Path) -> None:
    """Public/portal reads on sensitive models should be visible."""
    xml = tmp_path / "security.xml"
    xml.write_text(
        """<odoo>
  <record id="access_portal_users" model="ir.model.access">
    <field name="model_id" ref="base.model_res_users"/>
    <field name="group_id" ref="base.group_portal"/>
    <field name="perm_read">1</field>
    <field name="perm_write">0</field>
    <field name="perm_create">0</field>
    <field name="perm_unlink">0</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MetadataScanner(xml).scan_xml_file()

    assert any(f.rule_id == "odoo-metadata-sensitive-public-read-acl" for f in findings)


def test_security_model_external_ids_are_sensitive_public_read(tmp_path: Path) -> None:
    """Security model refs should normalize before public-read ACL checks."""
    xml = tmp_path / "security.xml"
    xml.write_text(
        """<odoo>
  <record id="access_public_params" model="ir.model.access">
    <field name="model_id" ref="base.model_ir_config_parameter"/>
    <field name="group_id" ref="base.group_public"/>
    <field name="perm_read">1</field>
    <field name="perm_write">0</field>
    <field name="perm_create">0</field>
    <field name="perm_unlink">0</field>
  </record>
  <record id="access_portal_payment_provider" model="ir.model.access">
    <field name="model_id" ref="payment.model_payment_provider"/>
    <field name="group_id" ref="base.group_portal"/>
    <field name="perm_read">1</field>
    <field name="perm_write">0</field>
    <field name="perm_create">0</field>
    <field name="perm_unlink">0</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MetadataScanner(xml).scan_xml_file()
    record_ids = {
        finding.record_id for finding in findings if finding.rule_id == "odoo-metadata-sensitive-public-read-acl"
    }

    assert {"access_public_params", "access_portal_payment_provider"} <= record_ids


def test_group_that_implies_admin_is_reported(tmp_path: Path) -> None:
    """Group inheritance can silently grant administrator privileges."""
    xml = tmp_path / "groups.xml"
    xml.write_text(
        """<odoo>
  <record id="group_partner_manager" model="res.groups">
    <field name="name">Partner Manager</field>
    <field name="implied_ids" eval="[(4, ref('base.group_system'))]"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MetadataScanner(xml).scan_xml_file()

    assert any(f.rule_id == "odoo-metadata-group-implies-admin" for f in findings)


def test_group_that_implies_internal_user_is_reported(tmp_path: Path) -> None:
    """Group inheritance can silently promote users to internal access."""
    xml = tmp_path / "groups.xml"
    xml.write_text(
        """<odoo>
  <record id="group_portal_plus" model="res.groups">
    <field name="name">Portal Plus</field>
    <field name="implied_ids" eval="[(4, ref('base.group_user'))]"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MetadataScanner(xml).scan_xml_file()

    assert any(f.rule_id == "odoo-metadata-group-implies-internal-user" for f in findings)


def test_group_inheritance_csv_is_reported(tmp_path: Path) -> None:
    """CSV res.groups rows should surface risky implied group inheritance."""
    csv_file = tmp_path / "res.groups.csv"
    csv_file.write_text(
        """id,name,implied_ids/id
group_partner_manager,Partner Manager,base.group_system
group_portal_plus,Portal Plus,base.group_user
""",
        encoding="utf-8",
    )

    findings = MetadataScanner(csv_file).scan_csv_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-metadata-group-implies-admin" in rule_ids
    assert "odoo-metadata-group-implies-internal-user" in rule_ids


def test_user_group_assignment_metadata_is_reported(tmp_path: Path) -> None:
    """XML user records can seed privilege-bearing groups."""
    xml = tmp_path / "users.xml"
    xml.write_text(
        """<odoo>
  <record id="demo_admin" model="res.users">
    <field name="login">demo-admin</field>
    <field name="groups_id" eval="[(4, ref('base.group_system'))]"/>
  </record>
  <record id="demo_internal" model="res.users">
    <field name="login">demo-user</field>
    <field name="groups_id" eval="[(4, ref('base.group_user'))]"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MetadataScanner(xml).scan_xml_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-metadata-user-admin-group-assignment" in rule_ids
    assert "odoo-metadata-user-internal-group-assignment" in rule_ids


def test_user_group_assignment_csv_is_reported(tmp_path: Path) -> None:
    """CSV user imports should not silently promote users."""
    csv_file = tmp_path / "res.users.csv"
    csv_file.write_text(
        """id,login,groups_id/id
demo_admin,demo-admin,base.group_erp_manager
demo_internal,demo-user,base.group_user
""",
        encoding="utf-8",
    )

    findings = MetadataScanner(csv_file).scan_csv_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-metadata-user-admin-group-assignment" in rule_ids
    assert "odoo-metadata-user-internal-group-assignment" in rule_ids


def test_sensitive_model_field_metadata_is_reported(tmp_path: Path) -> None:
    """ir.model.fields records can weaken field-level security metadata."""
    xml = tmp_path / "fields.xml"
    xml.write_text(
        """<odoo>
  <record id="field_api_key" model="ir.model.fields">
    <field name="model_id" ref="base.model_res_users"/>
    <field name="name">api_key</field>
    <field name="groups" eval="[(4, ref('base.group_portal'))]"/>
    <field name="readonly">0</field>
    <field name="compute">safe_eval(record.expression)</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MetadataScanner(xml).scan_xml_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-metadata-sensitive-field-public-groups" in rule_ids
    assert "odoo-metadata-sensitive-field-readonly-disabled" in rule_ids
    assert "odoo-metadata-field-dynamic-compute" in rule_ids


def test_sensitive_model_field_without_groups_is_reported(tmp_path: Path) -> None:
    """Sensitive field metadata without groups needs review."""
    xml = tmp_path / "fields.xml"
    xml.write_text(
        """<odoo>
  <record id="field_access_token" model="ir.model.fields">
    <field name="model_id" ref="sale.model_sale_order"/>
    <field name="name">access_token</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MetadataScanner(xml).scan_xml_file()

    assert any(f.rule_id == "odoo-metadata-sensitive-field-no-groups" for f in findings)


def test_integration_credential_field_metadata_is_reported(tmp_path: Path) -> None:
    """Integration credential field metadata should be treated as sensitive."""
    xml = tmp_path / "fields.xml"
    xml.write_text(
        """<odoo>
  <record id="field_access_key" model="ir.model.fields">
    <field name="model_id" ref="base.model_res_partner"/>
    <field name="name">access_key</field>
  </record>
  <record id="field_license_key" model="ir.model.fields">
    <field name="model_id" ref="base.model_res_partner"/>
    <field name="name">license_key</field>
    <field name="groups" eval="[(4, ref('base.group_public'))]"/>
  </record>
  <record id="field_reset_password_url" model="ir.model.fields">
    <field name="model_id" ref="base.model_res_partner"/>
    <field name="name">reset_password_url</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = MetadataScanner(xml).scan_xml_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-metadata-sensitive-field-no-groups" in rule_ids
    assert "odoo-metadata-sensitive-field-public-groups" in rule_ids
    assert any(
        finding.rule_id == "odoo-metadata-sensitive-field-no-groups" and finding.record_id == "field_reset_password_url"
        for finding in findings
    )


def test_sensitive_model_field_csv_is_reported(tmp_path: Path) -> None:
    """CSV ir.model.fields rows should use the same sensitive field checks as XML."""
    csv_file = tmp_path / "ir.model.fields.csv"
    csv_file.write_text(
        """id,model_id/id,name,groups/id,readonly,compute
field_api_key,base.model_res_users,api_key,base.group_portal,0,safe_eval(record.expression)
field_access_token,sale.model_sale_order,access_token,,1,
""",
        encoding="utf-8",
    )

    findings = MetadataScanner(csv_file).scan_csv_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-metadata-sensitive-field-public-groups" in rule_ids
    assert "odoo-metadata-sensitive-field-readonly-disabled" in rule_ids
    assert "odoo-metadata-field-dynamic-compute" in rule_ids
    assert "odoo-metadata-sensitive-field-no-groups" in rule_ids


def test_nonstandard_acl_csv_is_scanned(tmp_path: Path) -> None:
    """ACL-like CSV files outside ir.model.access.csv should still be inspected."""
    csv_file = tmp_path / "access_extra.csv"
    csv_file.write_text(
        """id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink
access_public_partner,public partner,base.model_res_partner,base.group_public,1,0,0,0
access_portal_sale,portal sale,sale.model_sale_order,base.group_portal,1,1,0,0
""",
        encoding="utf-8",
    )

    findings = MetadataScanner(csv_file).scan_csv_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-metadata-sensitive-public-read-acl" in rule_ids
    assert "odoo-metadata-public-write-acl" in rule_ids


def test_repository_scan_finds_metadata_files(tmp_path: Path) -> None:
    """Repository scanner should include XML and CSV metadata files."""
    module = tmp_path / "module" / "data"
    module.mkdir(parents=True)
    (module / "groups.xml").write_text(
        """<odoo><record id="group_adminish" model="res.groups">
<field name="implied_ids" eval="[(4, ref('base.group_erp_manager'))]"/>
</record></odoo>""",
        encoding="utf-8",
    )

    findings = scan_metadata(tmp_path)

    assert any(f.rule_id == "odoo-metadata-group-implies-admin" for f in findings)
