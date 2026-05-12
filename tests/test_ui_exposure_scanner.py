"""Tests for XML UI exposure scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.ui_exposure_scanner import UIExposureScanner, scan_ui_exposure


def test_object_button_without_groups_is_reported(tmp_path: Path) -> None:
    """Object-method buttons without groups are important manual-review leads."""
    xml = tmp_path / "views.xml"
    xml.write_text(
        """<odoo>
  <record id="view_order_form" model="ir.ui.view">
    <field name="arch" type="xml">
      <form>
        <button name="action_approve" type="object" string="Approve"/>
      </form>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = UIExposureScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-ui-object-button-no-groups" for f in findings)


def test_public_object_button_is_high_severity(tmp_path: Path) -> None:
    """Public object buttons should be escalated over ordinary ungrouped buttons."""
    xml = tmp_path / "views.xml"
    xml.write_text(
        """<odoo>
  <record id="portal_form" model="ir.ui.view">
    <field name="arch" type="xml">
      <form>
        <button name="action_cancel" type="object" groups="base.group_public"/>
      </form>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = UIExposureScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-ui-public-object-button" and f.severity == "high" for f in findings)


def test_portal_object_button_is_high_severity(tmp_path: Path) -> None:
    """Portal object buttons are externally reachable and need server-side checks."""
    xml = tmp_path / "views.xml"
    xml.write_text(
        """<odoo>
  <record id="portal_form" model="ir.ui.view">
    <field name="arch" type="xml">
      <form>
        <button name="action_cancel" type="object" groups="base.group_portal"/>
      </form>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = UIExposureScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-ui-public-object-button" and f.severity == "high" for f in findings)


def test_sensitive_action_and_menu_without_groups_are_reported(tmp_path: Path) -> None:
    """Sensitive actions and menus without groups should be flagged together."""
    xml = tmp_path / "menus.xml"
    xml.write_text(
        """<odoo>
  <record id="action_users" model="ir.actions.act_window">
    <field name="name">Users</field>
    <field name="res_model">res.users</field>
  </record>
  <menuitem id="menu_users" name="Users" action="action_users"/>
</odoo>""",
        encoding="utf-8",
    )

    findings = UIExposureScanner(xml).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-ui-sensitive-action-no-groups" in rule_ids
    assert "odoo-ui-sensitive-menu-no-groups" in rule_ids


def test_portal_sensitive_action_and_menu_are_high_severity(tmp_path: Path) -> None:
    """Portal/public groups on sensitive UI actions are external exposure, not a safe restriction."""
    xml = tmp_path / "menus.xml"
    xml.write_text(
        """<odoo>
  <record id="action_users" model="ir.actions.act_window">
    <field name="name">Users</field>
    <field name="res_model">res.users</field>
    <field name="groups_id" eval="[(4, ref('base.group_portal'))]"/>
  </record>
  <menuitem id="menu_users" name="Users" action="action_users" groups="base.group_portal"/>
</odoo>""",
        encoding="utf-8",
    )

    findings = UIExposureScanner(xml).scan_file()
    severities = {finding.rule_id: finding.severity for finding in findings}

    assert severities["odoo-ui-sensitive-action-external-groups"] == "high"
    assert severities["odoo-ui-sensitive-menu-external-groups"] == "high"


def test_public_sensitive_action_button_is_high_severity(tmp_path: Path) -> None:
    """Buttons opening sensitive actions for external groups should be escalated."""
    xml = tmp_path / "views.xml"
    xml.write_text(
        """<odoo>
  <record id="action_users" model="ir.actions.act_window">
    <field name="name">Users</field>
    <field name="res_model">res.users</field>
  </record>
  <record id="view_form" model="ir.ui.view">
    <field name="arch" type="xml">
      <form>
        <button name="%(action_users)d" type="action" groups="base.group_public"/>
      </form>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = UIExposureScanner(xml).scan_file()

    assert any(
        f.rule_id == "odoo-ui-sensitive-action-button-external-groups" and f.severity == "high" for f in findings
    )


def test_portal_sensitive_server_action_is_high_severity(tmp_path: Path) -> None:
    """Externally grouped server actions on sensitive models should be explicit high-risk leads."""
    xml = tmp_path / "server_actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_disable_users" model="ir.actions.server">
    <field name="name">Disable Users</field>
    <field name="model_id" ref="base.model_res_users"/>
    <field name="groups_id" eval="[(4, ref('base.group_portal'))]"/>
    <field name="state">code</field>
    <field name="code">records.write({'active': False})</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = UIExposureScanner(xml).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-ui-sensitive-server-action-external-groups" in rule_ids
    assert "odoo-ui-sensitive-action-external-groups" in rule_ids


def test_sensitive_action_without_groups_in_csv_is_reported(tmp_path: Path) -> None:
    """CSV action declarations should be scanned alongside XML records."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir_actions_act_window.csv").write_text(
        "id,name,res_model\n" "action_users,Users,res.users\n",
        encoding="utf-8",
    )

    findings = scan_ui_exposure(tmp_path)

    assert any(
        finding.rule_id == "odoo-ui-sensitive-action-no-groups" and finding.target == "action_users"
        for finding in findings
    )


def test_sensitive_server_action_without_groups_in_csv_is_reported(tmp_path: Path) -> None:
    """CSV relation columns should normalize model external IDs."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir_actions_server.csv").write_text(
        "id,name,model_id/id,state\n" "action_disable_users,Disable Users,base.model_res_users,code\n",
        encoding="utf-8",
    )

    findings = scan_ui_exposure(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-ui-sensitive-server-action-no-groups" in rule_ids
    assert "odoo-ui-sensitive-action-no-groups" in rule_ids


def test_sensitive_server_action_with_colon_csv_refs_is_reported(tmp_path: Path) -> None:
    """Colon-style CSV relation columns should normalize model external IDs."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir_actions_server.csv").write_text(
        "id,name,model_id:id,state\n" "action_disable_users,Disable Users,base.model_res_users,code\n",
        encoding="utf-8",
    )

    findings = scan_ui_exposure(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-ui-sensitive-server-action-no-groups" in rule_ids
    assert "odoo-ui-sensitive-action-no-groups" in rule_ids


def test_sensitive_csv_action_with_groups_is_ignored(tmp_path: Path) -> None:
    """Grouped CSV actions should not produce broad-exposure findings."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.actions.act_window.csv").write_text(
        "id,name,res_model,groups_id/id\n" "action_users,Users,res.users,base.group_system\n",
        encoding="utf-8",
    )

    assert scan_ui_exposure(tmp_path) == []


def test_csv_menu_exposing_csv_sensitive_action_is_reported(tmp_path: Path) -> None:
    """Repository scans should correlate menu CSV rows with action CSV rows."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.actions.act_window.csv").write_text(
        "id,name,res_model\n" "action_users,Users,res.users\n",
        encoding="utf-8",
    )
    (data / "ir.ui.menu.csv").write_text(
        "id,name,action\n" 'menu_users,Users,"ir.actions.act_window,action_users"\n',
        encoding="utf-8",
    )

    findings = scan_ui_exposure(tmp_path)

    assert any(
        finding.rule_id == "odoo-ui-sensitive-menu-no-groups" and finding.target == "menu_users" for finding in findings
    )


def test_csv_menu_exposing_portal_csv_sensitive_action_is_reported(tmp_path: Path) -> None:
    """CSV menu/action correlation should treat portal groups as external exposure."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.actions.act_window.csv").write_text(
        "id,name,res_model,groups_id/id\n" "action_users,Users,res.users,base.group_portal\n",
        encoding="utf-8",
    )
    (data / "ir.ui.menu.csv").write_text(
        "id,name,action,groups_id/id\n" 'menu_users,Users,"ir.actions.act_window,action_users",base.group_portal\n',
        encoding="utf-8",
    )

    findings = scan_ui_exposure(tmp_path)

    assert any(
        finding.rule_id == "odoo-ui-sensitive-menu-external-groups"
        and finding.severity == "high"
        and finding.target == "menu_users"
        for finding in findings
    )


def test_xml_menu_exposing_cross_file_csv_action_is_reported(tmp_path: Path) -> None:
    """XML menus should be correlated with CSV action declarations in another file."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.actions.act_window.csv").write_text(
        "id,name,res_model\n" "action_params,Parameters,ir.config_parameter\n",
        encoding="utf-8",
    )
    (data / "menus.xml").write_text(
        """<odoo>
  <menuitem id="menu_params" name="Parameters" action="%(action_params)d"/>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_ui_exposure(tmp_path)

    assert any(
        finding.rule_id == "odoo-ui-sensitive-menu-no-groups" and finding.target == "menu_params"
        for finding in findings
    )


def test_csv_menu_for_grouped_csv_action_is_ignored(tmp_path: Path) -> None:
    """A grouped action should keep an ungrouped menu from becoming a broad menu finding."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.actions.act_window.csv").write_text(
        "id,name,res_model,groups_id/id\n" "action_users,Users,res.users,base.group_system\n",
        encoding="utf-8",
    )
    (data / "ir.ui.menu.csv").write_text(
        "id,name,action\n" 'menu_users,Users,"ir.actions.act_window,action_users"\n',
        encoding="utf-8",
    )

    assert not any(f.rule_id == "odoo-ui-sensitive-menu-no-groups" for f in scan_ui_exposure(tmp_path))


def test_xml_entities_are_not_expanded_into_ui_exposure_findings(tmp_path: Path) -> None:
    """XML entities must not synthesize sensitive UI action targets."""
    xml = tmp_path / "menus.xml"
    xml.write_text(
        """<!DOCTYPE odoo [
<!ENTITY sensitive_model "res.users">
]>
<odoo>
  <record id="action_entity" model="ir.actions.act_window">
    <field name="name">Users</field>
    <field name="res_model">&sensitive_model;</field>
  </record>
  <menuitem id="menu_entity" name="Users" action="action_entity"/>
</odoo>""",
        encoding="utf-8",
    )

    assert UIExposureScanner(xml).scan_file() == []


def test_action_button_without_groups_is_reported(tmp_path: Path) -> None:
    """Ungrouped action buttons should be visible as low-risk review leads."""
    xml = tmp_path / "views.xml"
    xml.write_text(
        """<odoo>
  <record id="view_form" model="ir.ui.view">
    <field name="arch" type="xml">
      <form>
        <button name="%(action_users)d" type="action"/>
      </form>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = UIExposureScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-ui-action-button-no-groups" for f in findings)


def test_sensitive_action_button_without_groups_is_reported(tmp_path: Path) -> None:
    """Buttons opening sensitive actions should be escalated over generic action buttons."""
    xml = tmp_path / "views.xml"
    xml.write_text(
        """<odoo>
  <record id="action_users" model="ir.actions.act_window">
    <field name="name">Users</field>
    <field name="res_model">res.users</field>
  </record>
  <record id="view_form" model="ir.ui.view">
    <field name="arch" type="xml">
      <form>
        <button name="%(test_module.action_users)d" type="action"/>
      </form>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = UIExposureScanner(xml).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-ui-sensitive-action-button-no-groups" in rule_ids
    assert "odoo-ui-action-button-no-groups" in rule_ids


def test_sensitive_server_action_without_groups_is_reported(tmp_path: Path) -> None:
    """Server actions bound to sensitive models should not be broadly executable."""
    xml = tmp_path / "server_actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_disable_users" model="ir.actions.server">
    <field name="name">Disable Users</field>
    <field name="model_id" ref="base.model_res_users"/>
    <field name="state">code</field>
    <field name="code">records.write({'active': False})</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = UIExposureScanner(xml).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-ui-sensitive-server-action-no-groups" in rule_ids
    assert "odoo-ui-sensitive-action-no-groups" in rule_ids


def test_sensitive_server_action_button_without_groups_is_reported(tmp_path: Path) -> None:
    """Action buttons invoking sensitive server actions should be escalated."""
    xml = tmp_path / "views.xml"
    xml.write_text(
        """<odoo>
  <record id="action_disable_users" model="ir.actions.server">
    <field name="name">Disable Users</field>
    <field name="binding_model_id" ref="base.model_res_users"/>
    <field name="state">code</field>
  </record>
  <record id="view_form" model="ir.ui.view">
    <field name="arch" type="xml">
      <form>
        <button name="%(action_disable_users)d" type="action"/>
      </form>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = UIExposureScanner(xml).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-ui-sensitive-server-action-no-groups" in rule_ids
    assert "odoo-ui-sensitive-action-button-no-groups" in rule_ids
    assert "odoo-ui-action-button-no-groups" in rule_ids


def test_sensitive_model_external_ids_are_normalized(tmp_path: Path) -> None:
    """Model external IDs with underscores should normalize to real Odoo model names."""
    xml = tmp_path / "config_actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_config_params" model="ir.actions.server">
    <field name="name">Config Params</field>
    <field name="model_id" ref="base.model_ir_config_parameter"/>
    <field name="state">code</field>
    <field name="code">records.write({'value': 'x'})</field>
  </record>
  <record id="action_payment_provider" model="ir.actions.act_window">
    <field name="name">Payment Providers</field>
    <field name="res_model">payment.provider</field>
  </record>
  <menuitem id="menu_payment_provider" name="Payment Providers" action="action_payment_provider"/>
</odoo>""",
        encoding="utf-8",
    )

    findings = UIExposureScanner(xml).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-ui-sensitive-server-action-no-groups" in rule_ids
    assert "odoo-ui-sensitive-action-no-groups" in rule_ids
    assert "odoo-ui-sensitive-menu-no-groups" in rule_ids


def test_repository_scan_finds_ui_exposure(tmp_path: Path) -> None:
    """Repository scanner should include XML view files."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "views.xml").write_text(
        """<odoo><record id="view_form" model="ir.ui.view"><field name="arch" type="xml">
<form><button name="run_sudo" type="object"/></form>
</field></record></odoo>""",
        encoding="utf-8",
    )

    findings = scan_ui_exposure(tmp_path)

    assert any(f.rule_id == "odoo-ui-object-button-no-groups" for f in findings)
