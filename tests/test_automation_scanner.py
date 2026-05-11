"""Tests for Odoo automated action scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.automation_scanner import AutomationScanner, scan_automations


def test_broad_sensitive_automation_is_reported(tmp_path: Path) -> None:
    """Automations on sensitive models should have a narrowing domain."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_sale" model="base.automation">
    <field name="model_id" ref="sale.model_sale_order"/>
    <field name="trigger">on_create_or_write</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-broad-sensitive-trigger" for f in findings)


def test_xml_entities_are_not_expanded_into_automation_findings(tmp_path: Path) -> None:
    """XML entities must not synthesize broad sensitive automation findings."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<!DOCTYPE odoo [
<!ENTITY sensitive_model "sale.model_sale_order">
]>
<odoo>
  <record id="auto_entity" model="base.automation">
    <field name="model_id" ref="&sensitive_model;"/>
    <field name="trigger">on_create_or_write</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert AutomationScanner(xml).scan_file() == []


def test_dynamic_eval_in_automation_is_reported(tmp_path: Path) -> None:
    """Automated actions should not evaluate record-controlled expressions."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_eval" model="base.automation">
    <field name="code">safe_eval(record.expression)</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-dynamic-eval" for f in findings)


def test_sudo_mutation_in_automation_is_reported(tmp_path: Path) -> None:
    """sudo writes in automated actions bypass normal record boundaries."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_sudo" model="base.automation">
    <field name="code">record.sudo().write({'active': False})</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-sudo-mutation" for f in findings)


def test_sudo_alias_mutation_in_automation_is_reported(tmp_path: Path) -> None:
    """sudo aliases in automated action code should be recognized."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_sudo_alias" model="base.automation">
    <field name="code"><![CDATA[
records, partner = record.sudo(), record.partner_id
records.write({'active': False})
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-sudo-mutation" for f in findings)


def test_with_user_superuser_mutation_in_automation_is_reported(tmp_path: Path) -> None:
    """Superuser with_user writes in automated actions bypass normal boundaries."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_with_user" model="base.automation">
    <field name="code"><![CDATA[
record.with_user(SUPERUSER_ID).write({'active': False})
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-sudo-mutation" for f in findings)


def test_constant_backed_with_user_mutation_in_automation_is_reported(tmp_path: Path) -> None:
    """Automation code should resolve simple constants used for superuser aliases."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_with_user_constant" model="base.automation">
    <field name="code"><![CDATA[
ROOT_UID = 1
records = record.with_user(ROOT_UID)
records.write({'active': False})
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-sudo-mutation" for f in findings)


def test_recursive_constant_backed_with_user_mutation_in_automation_is_reported(tmp_path: Path) -> None:
    """Automation code should resolve chained constants used for superuser aliases."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_with_user_recursive_constant" model="base.automation">
    <field name="code"><![CDATA[
ROOT_UID = 1
ADMIN_UID = ROOT_UID
records = record.with_user(ADMIN_UID)
records.write({'active': False})
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-sudo-mutation" for f in findings)


def test_class_constant_backed_with_user_mutation_in_automation_is_reported(tmp_path: Path) -> None:
    """Class-scoped constants in automation helper code should resolve."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_with_user_class_constant" model="base.automation">
    <field name="code"><![CDATA[
class Helper:
    ROOT_UID = 1
    ADMIN_UID = ROOT_UID

    def run(self):
        records = record.with_user(ADMIN_UID)
        records.write({'active': False})
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-sudo-mutation" for f in findings)


def test_aliased_with_user_one_mutation_in_automation_is_reported(tmp_path: Path) -> None:
    """Aliased with_user(1) automated action recordsets should be recognized."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_with_user_alias" model="base.automation">
    <field name="code"><![CDATA[
records, partner = record.with_user(1), record.partner_id
records.write({'active': False})
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-sudo-mutation" for f in findings)


def test_env_ref_admin_mutation_in_automation_is_reported(tmp_path: Path) -> None:
    """with_user(base.user_admin) automated action recordsets should be elevated."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_with_user_admin" model="base.automation">
    <field name="code"><![CDATA[
records = record.with_user(env.ref('base.user_admin'))
records.write({'active': False})
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-sudo-mutation" for f in findings)


def test_regex_fallback_with_user_one_mutation_in_automation_is_reported(tmp_path: Path) -> None:
    """Malformed automation code should still catch obvious with_user mutations."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_with_user_fallback" model="base.automation">
    <field name="code">if broken: record.with_user(1).write({'active': False})</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-sudo-mutation" for f in findings)


def test_regex_fallback_with_user_root_mutation_in_automation_is_reported(
    tmp_path: Path,
) -> None:
    """Malformed automation code should catch base.user_root with_user mutations."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_with_user_root_fallback" model="base.automation">
    <field name="code">if broken: record.with_user(env.ref('base.user_root')).write({'active': False})</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-sudo-mutation" for f in findings)


def test_regex_fallback_keyword_with_user_mutation_in_automation_is_reported(tmp_path: Path) -> None:
    """Malformed automation code should catch keyword with_user mutations."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_with_user_keyword_fallback" model="base.automation">
    <field name="code">if broken: record.with_user(user=SUPERUSER_ID).write({'active': False})</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-sudo-mutation" for f in findings)


def test_starred_rest_sudo_alias_mutation_in_automation_is_reported(tmp_path: Path) -> None:
    """sudo aliases inside starred-rest collections should be recognized."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_sudo_rest_alias" model="base.automation">
    <field name="code"><![CDATA[
label, *items = 'x', record.partner_id, record.sudo()
records = items[1]
records.write({'active': False})
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-sudo-mutation" for f in findings)


def test_named_expression_sudo_alias_mutation_in_automation_is_reported(tmp_path: Path) -> None:
    """Walrus-bound sudo aliases in automated action code should be recognized."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_sudo_walrus_alias" model="base.automation">
    <field name="code"><![CDATA[
if records := record.sudo():
    records.write({'active': False})
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-sudo-mutation" for f in findings)


def test_mixed_tuple_sudo_alias_does_not_overtaint_automation(tmp_path: Path) -> None:
    """Mixed tuple assignments should not taint non-sudo automation neighbors."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_sudo_mixed_alias" model="base.automation">
    <field name="code"><![CDATA[
records, partner = record.sudo(), record.partner_id
partner.write({'comment': 'x'})
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert not any(f.rule_id == "odoo-automation-sudo-mutation" for f in findings)


def test_sensitive_model_mutation_in_automation_is_reported(tmp_path: Path) -> None:
    """Automated action code should not silently mutate security-sensitive models."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_identity" model="base.automation">
    <field name="code"><![CDATA[
env['res.users'].write({'active': False})
env['ir.config_parameter'].set_param('auth.signup.allow_uninvited', 'False')
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-sensitive-model-mutation" for f in findings)


def test_constant_backed_sensitive_model_mutation_in_automation_is_reported(tmp_path: Path) -> None:
    """Sensitive model detection should resolve env[...] constants in action code."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_identity_constant" model="base.automation">
    <field name="code"><![CDATA[
USERS_MODEL = 'res.users'
CONFIG_MODEL = 'ir.config_parameter'
env[USERS_MODEL].write({'active': False})
env[CONFIG_MODEL].set_param('auth.signup.allow_uninvited', 'False')
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert sum(f.rule_id == "odoo-automation-sensitive-model-mutation" for f in findings) == 1


def test_recursive_constant_backed_sensitive_model_mutation_in_automation_is_reported(
    tmp_path: Path,
) -> None:
    """Sensitive model detection should resolve chained env[...] constants."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_identity_recursive_constant" model="base.automation">
    <field name="code"><![CDATA[
USERS_MODEL = 'res.users'
TARGET_MODEL = USERS_MODEL
env[TARGET_MODEL].write({'active': False})
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-sensitive-model-mutation" for f in findings)


def test_class_constant_backed_sensitive_model_mutation_in_automation_is_reported(tmp_path: Path) -> None:
    """Class-scoped env model aliases in automation helper code should resolve."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_identity_class_constant" model="base.automation">
    <field name="code"><![CDATA[
class Helper:
    USERS_MODEL = 'res.users'
    TARGET_MODEL = USERS_MODEL
    PARAMS_MODEL = 'ir.config_parameter'
    CONFIG_MODEL = PARAMS_MODEL

    def run(self):
        env[TARGET_MODEL].write({'active': False})
        env[CONFIG_MODEL].set_param('auth.signup.allow_uninvited', 'False')
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-sensitive-model-mutation" for f in findings)


def test_http_without_timeout_in_automation_is_reported(tmp_path: Path) -> None:
    """Automated action HTTP calls can exhaust workers if unbounded."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_http" model="base.automation">
    <field name="code">requests.post(record.callback_url)</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-http-no-timeout" for f in findings)


def test_mixed_tuple_http_alias_does_not_overtaint_automation(tmp_path: Path) -> None:
    """Mixed tuple assignments should not taint non-client automation neighbors."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_http_mixed_alias" model="base.automation">
    <field name="code"><![CDATA[
import requests as rq
client, callback = rq.Session(), record.callback
callback.post(record.callback_url)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert not any(f.rule_id == "odoo-automation-http-no-timeout" for f in findings)


def test_starred_rest_http_client_alias_without_timeout_is_reported(tmp_path: Path) -> None:
    """HTTP clients inside starred-rest collections should be recognized."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_http_rest_alias" model="base.automation">
    <field name="code"><![CDATA[
import requests as rq
label, *items = 'x', record.callback, rq.Session()
client = items[1]
client.post(record.callback_url)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-http-no-timeout" for f in findings)


def test_imported_http_without_timeout_in_automation_is_reported(tmp_path: Path) -> None:
    """Imported HTTP helpers in automated action code should be recognized."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_http_alias" model="base.automation">
    <field name="code"><![CDATA[
from requests import post as http_post
http_post(record.callback_url)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-http-no-timeout" for f in findings)


def test_urllib_urlopen_without_timeout_in_automation_is_reported(tmp_path: Path) -> None:
    """urllib.request.urlopen in automated actions should require a timeout."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_http_urllib" model="base.automation">
    <field name="code"><![CDATA[
from urllib.request import urlopen
import urllib.request as urlreq
urlopen(record.callback_url)
urlreq.urlopen(record.status_url, timeout=10)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert len([f for f in findings if f.rule_id == "odoo-automation-http-no-timeout"]) == 1


def test_regex_fallback_urllib_urlopen_without_timeout_in_automation_is_reported(tmp_path: Path) -> None:
    """Malformed automation code should still catch urllib URL fetches."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_http_urllib_fallback" model="base.automation">
    <field name="code">if broken: urllib.request.urlopen(record.callback_url)</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-automation-http-no-timeout" for f in findings)


def test_http_client_with_timeout_in_automation_is_ignored(tmp_path: Path) -> None:
    """HTTP client aliases with visible timeout should not trigger timeout findings."""
    xml = tmp_path / "automation.xml"
    xml.write_text(
        """<odoo>
  <record id="auto_http_safe" model="base.automation">
    <field name="code"><![CDATA[
import requests as rq
client = rq.Session()
client.post(record.callback_url, timeout=10)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = AutomationScanner(xml).scan_file()

    assert not any(f.rule_id == "odoo-automation-http-no-timeout" for f in findings)


def test_repository_scan_finds_automations(tmp_path: Path) -> None:
    """Repository scan should include XML automated action data files."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "automation.xml").write_text(
        """<odoo><record id="auto_partner" model="base.automation">
<field name="model_id" ref="base.model_res_partner"/>
<field name="trigger">on_write</field>
</record></odoo>""",
        encoding="utf-8",
    )

    findings = scan_automations(tmp_path)

    assert any(f.rule_id == "odoo-automation-broad-sensitive-trigger" for f in findings)
