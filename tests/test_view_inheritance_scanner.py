"""Tests for risky Odoo inherited view modification scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.view_inheritance_scanner import scan_view_inheritance


def test_flags_removing_groups_from_inherited_button(tmp_path: Path) -> None:
    """Inherited views should not silently remove groups from sensitive controls."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "inherit.xml").write_text(
        """<odoo>
  <record id="view_sale_form_inherit" model="ir.ui.view">
    <field name="inherit_id" ref="sale.view_order_form"/>
    <field name="arch" type="xml">
      <xpath expr="//button[@name='action_confirm']" position="attributes">
        <attribute name="groups"/>
      </xpath>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_inheritance(tmp_path)

    assert any(f.rule_id == "odoo-view-inherit-removes-groups" for f in findings)


def test_flags_replacing_object_button_and_broad_xpath(tmp_path: Path) -> None:
    """Replacing object buttons can drop attrs/groups from the original view."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "button.xml").write_text(
        """<odoo>
  <record id="view_button_inherit" model="ir.ui.view">
    <field name="inherit_id" ref="sale.view_order_form"/>
    <field name="arch" type="xml">
      <xpath expr="//button[@type='object']" position="replace">
        <button name="action_approve" type="object"/>
      </xpath>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_inheritance(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-view-inherit-replaces-object-button" in rule_ids
    assert "odoo-view-inherit-broad-security-xpath" in rule_ids


def test_flags_replacing_sensitive_field(tmp_path: Path) -> None:
    """Sensitive field replacements should preserve groups and invisibility."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "field.xml").write_text(
        """<odoo>
  <record id="view_user_inherit" model="ir.ui.view">
    <field name="inherit_id" ref="base.view_users_form"/>
    <field name="arch" type="xml">
      <xpath expr="//field[@name='groups_id']" position="replace">
        <field name="groups_id"/>
      </xpath>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_inheritance(tmp_path)

    assert any(f.rule_id == "odoo-view-inherit-replaces-sensitive-field" for f in findings)


def test_flags_revealing_sensitive_field(tmp_path: Path) -> None:
    """Inherited view attributes can reveal fields meant to stay hidden."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "visible.xml").write_text(
        """<odoo>
  <record id="view_token_inherit" model="ir.ui.view">
    <field name="inherit_id" ref="auth_signup.reset_password_email"/>
    <field name="arch" type="xml">
      <xpath expr="//field[@name='signup_token']" position="attributes">
        <attribute name="invisible">0</attribute>
      </xpath>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_inheritance(tmp_path)

    assert any(f.rule_id == "odoo-view-inherit-reveals-sensitive-field" for f in findings)


def test_flags_making_sensitive_field_editable(tmp_path: Path) -> None:
    """Inherited view attributes can make privilege-bearing fields editable."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "editable.xml").write_text(
        """<odoo>
  <record id="view_user_editable_inherit" model="ir.ui.view">
    <field name="inherit_id" ref="base.view_users_form"/>
    <field name="arch" type="xml">
      <xpath expr="//field[@name='groups_id']" position="attributes">
        <attribute name="readonly">0</attribute>
      </xpath>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_inheritance(tmp_path)

    assert any(f.rule_id == "odoo-view-inherit-makes-sensitive-field-editable" for f in findings)


def test_flags_direct_attribute_group_removal(tmp_path: Path) -> None:
    """Direct inherited field attribute patches can remove groups too."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "direct.xml").write_text(
        """<odoo>
  <record id="view_user_direct_inherit" model="ir.ui.view">
    <field name="inherit_id" ref="base.view_users_form"/>
    <field name="arch" type="xml">
      <field name="groups_id" position="attributes">
        <attribute name="groups"/>
      </field>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_inheritance(tmp_path)

    assert any(f.rule_id == "odoo-view-inherit-removes-groups" for f in findings)


def test_flags_direct_sensitive_field_made_editable(tmp_path: Path) -> None:
    """Direct inherited field attribute patches can remove readonly from secrets."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "direct_editable.xml").write_text(
        """<odoo>
  <record id="view_user_direct_editable_inherit" model="ir.ui.view">
    <field name="inherit_id" ref="base.view_users_form"/>
    <field name="arch" type="xml">
      <field name="api_key" position="attributes">
        <attribute name="readonly">False</attribute>
      </field>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_inheritance(tmp_path)

    assert any(f.rule_id == "odoo-view-inherit-makes-sensitive-field-editable" for f in findings)


def test_flags_public_groups_on_sensitive_inherited_target(tmp_path: Path) -> None:
    """Inherited views should not expose sensitive fields to portal/public groups."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "public_groups.xml").write_text(
        """<odoo>
  <record id="view_user_public_inherit" model="ir.ui.view">
    <field name="inherit_id" ref="base.view_users_form"/>
    <field name="arch" type="xml">
      <xpath expr="//field[@name='groups_id']" position="attributes">
        <attribute name="groups">base.group_portal</attribute>
      </xpath>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_inheritance(tmp_path)

    assert any(f.rule_id == "odoo-view-inherit-public-groups-sensitive-target" for f in findings)


def test_flags_inserted_object_button_without_groups(tmp_path: Path) -> None:
    """Inherited views can add new object buttons without replacing existing controls."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "insert_button.xml").write_text(
        """<odoo>
  <record id="view_sale_insert_button" model="ir.ui.view">
    <field name="inherit_id" ref="sale.view_order_form"/>
    <field name="arch" type="xml">
      <xpath expr="//header" position="inside">
        <button name="action_force_approve" type="object"/>
      </xpath>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_inheritance(tmp_path)

    assert any(f.rule_id == "odoo-view-inherit-adds-object-button-no-groups" for f in findings)


def test_flags_inserted_public_object_button(tmp_path: Path) -> None:
    """Public object buttons inserted by inherited views are critical review leads."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "insert_public_button.xml").write_text(
        """<odoo>
  <record id="view_sale_insert_public_button" model="ir.ui.view">
    <field name="inherit_id" ref="sale.view_order_form"/>
    <field name="arch" type="xml">
      <xpath expr="//header" position="inside">
        <button name="action_public_cancel" type="object" groups="base.group_public"/>
      </xpath>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_inheritance(tmp_path)

    assert any(f.rule_id == "odoo-view-inherit-adds-public-object-button" for f in findings)


def test_flags_inserted_sensitive_field_without_groups(tmp_path: Path) -> None:
    """Inherited views can insert sensitive fields without touching existing targets."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "insert_sensitive_field.xml").write_text(
        """<odoo>
  <record id="view_user_insert_token" model="ir.ui.view">
    <field name="inherit_id" ref="base.view_users_form"/>
    <field name="arch" type="xml">
      <xpath expr="//group" position="inside">
        <field name="api_key"/>
      </xpath>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_inheritance(tmp_path)

    assert any(f.rule_id == "odoo-view-inherit-adds-sensitive-field-no-groups" for f in findings)


def test_flags_inserted_broad_sensitive_field_without_groups(tmp_path: Path) -> None:
    """Inherited views should catch key-shaped fields beyond token/password names."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "insert_license_key.xml").write_text(
        """<odoo>
  <record id="view_user_insert_license_key" model="ir.ui.view">
    <field name="inherit_id" ref="base.view_users_form"/>
    <field name="arch" type="xml">
      <xpath expr="//group" position="inside">
        <field name="license_key"/>
      </xpath>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_inheritance(tmp_path)

    assert any(f.rule_id == "odoo-view-inherit-adds-sensitive-field-no-groups" for f in findings)


def test_grouped_inserted_controls_are_not_reported_as_ungrouped(tmp_path: Path) -> None:
    """Admin-grouped inserted controls should avoid the ungrouped insertion findings."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "insert_grouped.xml").write_text(
        """<odoo>
  <record id="view_user_insert_grouped" model="ir.ui.view">
    <field name="inherit_id" ref="base.view_users_form"/>
    <field name="arch" type="xml">
      <xpath expr="//group" position="inside">
        <field name="api_key" groups="base.group_system"/>
        <button name="action_rotate_key" type="object" groups="base.group_system"/>
      </xpath>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_inheritance(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-view-inherit-adds-object-button-no-groups" not in rule_ids
    assert "odoo-view-inherit-adds-sensitive-field-no-groups" not in rule_ids


def test_xml_entities_are_not_expanded_into_view_inheritance_findings(tmp_path: Path) -> None:
    """XML entities must not synthesize inherited-view security changes."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "entity.xml").write_text(
        """<!DOCTYPE odoo [
<!ENTITY sensitive_xpath "//field[@name='groups_id']">
]>
<odoo>
  <record id="view_user_entity_inherit" model="ir.ui.view">
    <field name="inherit_id" ref="base.view_users_form"/>
    <field name="arch" type="xml">
      <xpath expr="&sensitive_xpath;" position="attributes">
        <attribute name="groups">base.group_portal</attribute>
      </xpath>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_view_inheritance(tmp_path) == []


def test_non_inherited_view_is_ignored(tmp_path: Path) -> None:
    """Base views are covered by other UI scanners and should not trigger this pass."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "base.xml").write_text(
        """<odoo>
  <record id="view_base" model="ir.ui.view">
    <field name="arch" type="xml">
      <form><field name="name"/></form>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_view_inheritance(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """View inheritance fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "inherit.xml").write_text(
        """<odoo>
  <record id="view_sale_form_inherit" model="ir.ui.view">
    <field name="inherit_id" ref="sale.view_order_form"/>
    <field name="arch" type="xml">
      <xpath expr="//button[@name='action_confirm']" position="attributes">
        <attribute name="groups"/>
      </xpath>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_view_inheritance(tmp_path) == []
