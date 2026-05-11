"""Tests for executable/risky Odoo XML data scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.xml_data_scanner import XmlDataScanner, scan_xml_data


def test_xml_entities_are_not_expanded_into_xml_data_findings(tmp_path: Path) -> None:
    """XML entities must not synthesize executable XML data findings."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<!DOCTYPE odoo [
<!ENTITY action_state "code">
]>
<odoo>
  <record id="action_entity" model="ir.actions.server">
    <field name="state">&action_state;</field>
    <field name="code">safe_eval(record.expression)</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert XmlDataScanner(xml).scan_file() == []


def test_server_action_code_reachable_by_users(tmp_path: Path) -> None:
    """Broadly reachable state=code server actions should be review leads."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_mass_update" model="ir.actions.server">
    <field name="state">code</field>
    <field name="groups_id" eval="[(4, ref('base.group_user'))]"/>
    <field name="code">records.sudo().write({'state': 'done'})</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-server-action-code-user-reachable" for f in findings)


def test_server_action_dynamic_eval(tmp_path: Path) -> None:
    """Server action code that evals expressions is high risk."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_eval" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code">safe_eval(record.expression)</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-server-action-dynamic-eval" for f in findings)


def test_server_action_sudo_mutation_and_http_without_timeout(tmp_path: Path) -> None:
    """Executable server actions should surface sudo mutations and unbounded HTTP."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_sudo_http" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code">
record.sudo().write({'state': 'done'})
requests.post(record.callback_url)
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-xml-server-action-sudo-mutation" in rule_ids
    assert "odoo-xml-server-action-http-no-timeout" in rule_ids


def test_server_action_urllib_httpx_and_aiohttp_without_timeout(tmp_path: Path) -> None:
    """Executable server actions should catch urllib/httpx/aiohttp calls without timeouts."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_url_fetch" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code"><![CDATA[
from urllib.request import urlopen
urlopen(record.callback_url)
httpx.post(record.audit_url, timeout=10)
aiohttp.request("GET", record.status_url)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert len([f for f in findings if f.rule_id == "odoo-xml-server-action-http-no-timeout"]) == 1


def test_server_action_aliased_urllib_urlopen_without_timeout(tmp_path: Path) -> None:
    """Executable server actions should catch aliased urllib urlopen calls."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_url_fetch" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code"><![CDATA[
import urllib.request as urlreq
urlreq.urlopen(record.callback_url)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-server-action-http-no-timeout" for f in findings)


def test_server_action_timeout_none_is_reported(tmp_path: Path) -> None:
    """XML server actions should treat timeout=None as no effective HTTP timeout."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_timeout_none" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code">requests.post(record.callback_url, timeout=None)</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-server-action-http-no-timeout" for f in findings)


def test_server_action_static_kwargs_timeout_is_not_reported(tmp_path: Path) -> None:
    """XML server actions should resolve static **kwargs timeout values."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_static_timeout" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code"><![CDATA[
HTTP_OPTIONS = {'timeout': 10}
requests.post(record.callback_url, **HTTP_OPTIONS)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert not any(f.rule_id == "odoo-xml-server-action-http-no-timeout" for f in findings)


def test_server_action_dict_union_static_kwargs_timeout_is_not_reported(tmp_path: Path) -> None:
    """XML server actions should resolve dict-union static **kwargs timeout values."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_static_timeout" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code"><![CDATA[
BASE_OPTIONS = {'timeout': 10}
HTTP_OPTIONS = BASE_OPTIONS | {'headers': {}}
requests.post(record.callback_url, **HTTP_OPTIONS)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert not any(f.rule_id == "odoo-xml-server-action-http-no-timeout" for f in findings)


def test_server_action_tls_verification_disabled(tmp_path: Path) -> None:
    """Executable server actions should surface disabled HTTP TLS verification."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_http_tls" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code"><![CDATA[
TLS_VERIFY = False
requests.post(record.callback_url, timeout=10, verify=TLS_VERIFY)
httpx.post(record.audit_url, timeout=10, verify=True)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()
    tls_findings = [f for f in findings if f.rule_id == "odoo-xml-server-action-tls-verify-disabled"]

    assert len(tls_findings) == 1


def test_server_action_static_kwargs_tls_verify_disabled(tmp_path: Path) -> None:
    """XML server actions should flag verify=False from static **kwargs."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_http_tls_kwargs" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code"><![CDATA[
HTTP_OPTIONS = {'timeout': 10, 'verify': False}
requests.post(record.callback_url, **HTTP_OPTIONS)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-server-action-tls-verify-disabled" for f in findings)


def test_server_action_dict_union_static_kwargs_tls_verify_disabled(tmp_path: Path) -> None:
    """XML server actions should flag verify=False from dict-union static **kwargs."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_http_tls_kwargs" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code"><![CDATA[
BASE_OPTIONS = {'timeout': 10}
HTTP_OPTIONS = BASE_OPTIONS | {'verify': False}
requests.post(record.callback_url, **HTTP_OPTIONS)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-server-action-tls-verify-disabled" for f in findings)


def test_server_action_cleartext_http_url(tmp_path: Path) -> None:
    """XML server action inline Python should flag literal cleartext HTTP URLs."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_http_cleartext" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code"><![CDATA[
CALLBACK_URL = 'http://hooks.example.test/server-action'
HTTP_OPTIONS = {'url': 'http://partner.example.test/action', 'timeout': 10}
requests.post(CALLBACK_URL, timeout=10)
requests.request('POST', **HTTP_OPTIONS)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert sum(f.rule_id == "odoo-xml-server-action-cleartext-http-url" for f in findings) == 1


def test_server_action_dict_union_static_kwargs_cleartext_http_url(tmp_path: Path) -> None:
    """XML server actions should flag cleartext URLs from dict-union static **kwargs."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_http_cleartext" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code"><![CDATA[
BASE_OPTIONS = {'url': 'http://partner.example.test/action'}
HTTP_OPTIONS = BASE_OPTIONS | {'timeout': 10}
requests.request('POST', **HTTP_OPTIONS)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-server-action-cleartext-http-url" for f in findings)


def test_server_action_keyword_with_user_mutation_is_reported(tmp_path: Path) -> None:
    """XML server actions should surface keyword with_user superuser mutations."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_with_user" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code">records.with_user(user=SUPERUSER_ID).write({'state': 'done'})</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-xml-server-action-sudo-mutation" in rule_ids


def test_server_action_aliased_import_with_user_mutation_is_reported(tmp_path: Path) -> None:
    """XML server actions should resolve imported SUPERUSER_ID aliases."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_with_user_alias_import" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code"><![CDATA[
from odoo import SUPERUSER_ID as ROOT_UID
records.with_user(ROOT_UID).write({'state': 'done'})
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-xml-server-action-sudo-mutation" in rule_ids


def test_server_action_constant_backed_with_user_mutation_is_reported(tmp_path: Path) -> None:
    """XML server action code should resolve simple superuser constants."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_with_user_constant" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code"><![CDATA[
ROOT_UID = 1
records.with_user(ROOT_UID).write({'state': 'done'})
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-xml-server-action-sudo-mutation" in rule_ids


def test_server_action_recursive_constant_backed_with_user_mutation_is_reported(tmp_path: Path) -> None:
    """XML server action code should resolve recursive superuser constants."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_with_user_recursive_constant" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code"><![CDATA[
ROOT_UID = 1
TARGET_UID = ROOT_UID
records.with_user(TARGET_UID).write({'state': 'done'})
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-xml-server-action-sudo-mutation" in rule_ids


def test_server_action_constant_backed_with_user_alias_mutation_is_reported(tmp_path: Path) -> None:
    """XML server action code should preserve elevated aliases."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_with_user_alias_constant" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code"><![CDATA[
ROOT_UID = 1
elevated = records.with_user(ROOT_UID)
elevated.write({'state': 'done'})
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-xml-server-action-sudo-mutation" in rule_ids


def test_server_action_sensitive_model_code_and_mutation(tmp_path: Path) -> None:
    """XML server actions against identity/config models should stand out."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_disable_users" model="ir.actions.server">
    <field name="state">code</field>
    <field name="model_id" ref="base.model_res_users"/>
    <field name="code">
env['ir.config_parameter'].set_param('auth_signup.invitation_scope', 'b2c')
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-xml-server-action-sensitive-model-code" in rule_ids
    assert "odoo-xml-server-action-sensitive-model-mutation" in rule_ids


def test_server_action_constant_backed_sensitive_model_mutation(tmp_path: Path) -> None:
    """XML server action code should resolve env[...] model constants."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_disable_users_constant" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code"><![CDATA[
CONFIG_MODEL = 'ir.config_parameter'
env[CONFIG_MODEL].set_param('auth_signup.invitation_scope', 'b2c')
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-xml-server-action-sensitive-model-mutation" in rule_ids


def test_server_action_recursive_constant_backed_sensitive_model_mutation(tmp_path: Path) -> None:
    """XML server action code should resolve recursive env[...] model constants."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_disable_users_recursive_constant" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code"><![CDATA[
CONFIG_MODEL = 'ir.config_parameter'
TARGET_MODEL = CONFIG_MODEL
env[TARGET_MODEL].set_param('auth_signup.invitation_scope', 'b2c')
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-xml-server-action-sensitive-model-mutation" in rule_ids


def test_server_action_non_sensitive_model_code_is_not_sensitive(tmp_path: Path) -> None:
    """Normal model-bound code actions should avoid the sensitive-model finding."""
    xml = tmp_path / "actions.xml"
    xml.write_text(
        """<odoo>
  <record id="action_partner_note" model="ir.actions.server">
    <field name="state">code</field>
    <field name="model_id" ref="base.model_res_partner"/>
    <field name="groups_id" eval="[(4, ref('base.group_system'))]"/>
    <field name="code">records.write({'comment': 'ok'})</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert not any(f.rule_id == "odoo-xml-server-action-sensitive-model-code" for f in findings)
    assert not any(f.rule_id == "odoo-xml-server-action-sensitive-model-mutation" for f in findings)


def test_root_cron_code_and_http_without_timeout(tmp_path: Path) -> None:
    """Root crons and outbound HTTP without timeout should be reported."""
    xml = tmp_path / "cron.xml"
    xml.write_text(
        """<odoo>
  <record id="cron_fetch" model="ir.cron">
    <field name="state">code</field>
    <field name="user_id" ref="base.user_root"/>
    <field name="code">requests.get(record.url)</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-xml-cron-admin-user" in rule_ids
    assert "odoo-xml-cron-root-code" in rule_ids
    assert "odoo-xml-cron-http-no-timeout" in rule_ids


def test_cron_csv_admin_doall_and_short_interval_are_reported(tmp_path: Path) -> None:
    """CSV ir.cron records should get the same direct field checks as XML."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir_cron.csv").write_text(
        "id,name,state,user_id/id,doall,interval_number,interval_type\n"
        "cron_root_fetch,Fetch Orders,code,base.user_root,1,5,minutes\n",
        encoding="utf-8",
    )

    findings = scan_xml_data(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-xml-cron-admin-user" in rule_ids
    assert "odoo-xml-cron-root-code" in rule_ids
    assert "odoo-xml-cron-doall-enabled" in rule_ids
    assert "odoo-xml-cron-short-interval" in rule_ids


def test_cron_urllib_without_timeout(tmp_path: Path) -> None:
    """Cron inline Python should catch urllib URL fetches without timeouts."""
    xml = tmp_path / "cron.xml"
    xml.write_text(
        """<odoo>
  <record id="cron_url_fetch" model="ir.cron">
    <field name="state">code</field>
    <field name="code">urllib.request.urlopen(record.url)</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-cron-http-no-timeout" for f in findings)


def test_cron_aliased_urllib_urlopen_without_timeout(tmp_path: Path) -> None:
    """Cron inline Python should catch aliased urllib URL fetches without timeouts."""
    xml = tmp_path / "cron.xml"
    xml.write_text(
        """<odoo>
  <record id="cron_url_fetch" model="ir.cron">
    <field name="state">code</field>
    <field name="code"><![CDATA[
import urllib.request as urlreq
urlreq.urlopen(record.url)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-cron-http-no-timeout" for f in findings)


def test_cron_aiohttp_without_timeout(tmp_path: Path) -> None:
    """Cron inline Python should catch aiohttp URL fetches without timeouts."""
    xml = tmp_path / "cron.xml"
    xml.write_text(
        """<odoo>
  <record id="cron_aiohttp_fetch" model="ir.cron">
    <field name="state">code</field>
    <field name="code">aiohttp.get(record.url)</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-cron-http-no-timeout" for f in findings)


def test_cron_head_without_timeout(tmp_path: Path) -> None:
    """Cron inline Python should catch HEAD URL fetches without timeouts."""
    xml = tmp_path / "cron.xml"
    xml.write_text(
        """<odoo>
  <record id="cron_head_fetch" model="ir.cron">
    <field name="state">code</field>
    <field name="code">httpx.head(record.url)</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-cron-http-no-timeout" for f in findings)


def test_cron_timeout_none_is_reported(tmp_path: Path) -> None:
    """XML cron inline Python should treat timeout=None as unbounded."""
    xml = tmp_path / "cron.xml"
    xml.write_text(
        """<odoo>
  <record id="cron_timeout_none" model="ir.cron">
    <field name="state">code</field>
    <field name="code">requests.get(record.url, timeout=None)</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-cron-http-no-timeout" for f in findings)


def test_cron_static_kwargs_timeout_is_not_reported(tmp_path: Path) -> None:
    """XML cron inline Python should resolve static **kwargs timeout values."""
    xml = tmp_path / "cron.xml"
    xml.write_text(
        """<odoo>
  <record id="cron_static_timeout" model="ir.cron">
    <field name="state">code</field>
    <field name="code"><![CDATA[
HTTP_OPTIONS = {'timeout': 10}
requests.get(record.url, **HTTP_OPTIONS)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert not any(f.rule_id == "odoo-xml-cron-http-no-timeout" for f in findings)


def test_cron_dict_union_static_kwargs_timeout_is_not_reported(tmp_path: Path) -> None:
    """XML cron inline Python should resolve dict-union static **kwargs timeout values."""
    xml = tmp_path / "cron.xml"
    xml.write_text(
        """<odoo>
  <record id="cron_static_timeout" model="ir.cron">
    <field name="state">code</field>
    <field name="code"><![CDATA[
BASE_OPTIONS = {'timeout': 10}
HTTP_OPTIONS = BASE_OPTIONS | {'headers': {}}
requests.get(record.url, **HTTP_OPTIONS)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert not any(f.rule_id == "odoo-xml-cron-http-no-timeout" for f in findings)


def test_cron_tls_verification_disabled(tmp_path: Path) -> None:
    """Cron inline Python should surface disabled HTTP TLS verification."""
    xml = tmp_path / "cron.xml"
    xml.write_text(
        """<odoo>
  <record id="cron_http_tls" model="ir.cron">
    <field name="state">code</field>
    <field name="code"><![CDATA[
TLS_VERIFY = False
requests.post(record.callback_url, timeout=10, verify=TLS_VERIFY)
requests.get(record.health_url, timeout=10, verify=True)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()
    tls_findings = [f for f in findings if f.rule_id == "odoo-xml-cron-tls-verify-disabled"]

    assert len(tls_findings) == 1


def test_cron_static_kwargs_tls_verify_disabled(tmp_path: Path) -> None:
    """XML cron inline Python should flag verify=False from static **kwargs."""
    xml = tmp_path / "cron.xml"
    xml.write_text(
        """<odoo>
  <record id="cron_http_tls_kwargs" model="ir.cron">
    <field name="state">code</field>
    <field name="code"><![CDATA[
HTTP_OPTIONS = {'timeout': 10, 'verify': False}
requests.get(record.url, **HTTP_OPTIONS)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-cron-tls-verify-disabled" for f in findings)


def test_cron_dict_union_static_kwargs_tls_verify_disabled(tmp_path: Path) -> None:
    """XML cron inline Python should flag verify=False from dict-union static **kwargs."""
    xml = tmp_path / "cron.xml"
    xml.write_text(
        """<odoo>
  <record id="cron_http_tls_kwargs" model="ir.cron">
    <field name="state">code</field>
    <field name="code"><![CDATA[
BASE_OPTIONS = {'timeout': 10}
HTTP_OPTIONS = BASE_OPTIONS | {'verify': False}
requests.get(record.url, **HTTP_OPTIONS)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-cron-tls-verify-disabled" for f in findings)


def test_cron_cleartext_http_url(tmp_path: Path) -> None:
    """XML cron inline Python should flag literal cleartext HTTP URLs."""
    xml = tmp_path / "cron.xml"
    xml.write_text(
        """<odoo>
  <record id="cron_http_cleartext" model="ir.cron">
    <field name="state">code</field>
    <field name="code"><![CDATA[
FEED_URL = 'http://feeds.example.test/orders'
HTTP_OPTIONS = {'url': 'http://partner.example.test/cron', 'timeout': 10}
requests.get(FEED_URL, timeout=10)
requests.request('POST', **HTTP_OPTIONS)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert sum(f.rule_id == "odoo-xml-cron-cleartext-http-url" for f in findings) == 1


def test_cron_dict_union_static_kwargs_cleartext_http_url(tmp_path: Path) -> None:
    """XML cron inline Python should flag cleartext URLs from dict-union static **kwargs."""
    xml = tmp_path / "cron.xml"
    xml.write_text(
        """<odoo>
  <record id="cron_http_cleartext" model="ir.cron">
    <field name="state">code</field>
    <field name="code"><![CDATA[
BASE_OPTIONS = {'url': 'http://partner.example.test/cron'}
HTTP_OPTIONS = BASE_OPTIONS | {'timeout': 10}
requests.request('POST', **HTTP_OPTIONS)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-cron-cleartext-http-url" for f in findings)


def test_admin_method_cron_without_state_code_is_reported(tmp_path: Path) -> None:
    """Admin/root cron posture matters even when the cron calls a model method."""
    xml = tmp_path / "cron.xml"
    xml.write_text(
        """<odoo>
  <record id="cron_sync" model="ir.cron">
    <field name="name">Fetch partner feed</field>
    <field name="user_id" ref="base.user_admin"/>
    <field name="model_id" ref="base.model_res_partner"/>
    <field name="function">fetch_external_records</field>
    <field name="interval_number">1</field>
    <field name="interval_type">minutes</field>
    <field name="doall">True</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-xml-cron-admin-user" in rule_ids
    assert "odoo-xml-cron-doall-enabled" in rule_ids
    assert "odoo-xml-cron-short-interval" in rule_ids
    assert "odoo-xml-cron-external-sync-review" in rule_ids


def test_long_batched_cron_is_not_flagged_for_frequency_or_sync_review(tmp_path: Path) -> None:
    """Normal low-frequency guarded jobs should avoid noisy cron posture leads."""
    xml = tmp_path / "cron.xml"
    xml.write_text(
        """<odoo>
  <record id="cron_sync" model="ir.cron">
    <field name="name">Sync partner batch with timeout</field>
    <field name="model_id" ref="base.model_res_partner"/>
    <field name="function">sync_partner_batch_with_timeout</field>
    <field name="interval_number">1</field>
    <field name="interval_type">days</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-xml-cron-short-interval" not in rule_ids
    assert "odoo-xml-cron-external-sync-review" not in rule_ids


def test_public_mail_channel(tmp_path: Path) -> None:
    """Public discuss/mail channels should be visible in review output."""
    xml = tmp_path / "mail.xml"
    xml.write_text(
        """<odoo>
  <record id="channel_public" model="mail.channel">
    <field name="allow_public_users">True</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-public-mail-channel" for f in findings)


def test_public_mail_channel_csv(tmp_path: Path) -> None:
    """CSV mail/discuss channel declarations can also allow public users."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "mail_channel.csv").write_text(
        "id,name,allow_public_users\nchannel_public,Public Channel,True\n",
        encoding="utf-8",
    )

    findings = scan_xml_data(tmp_path)

    assert any(f.rule_id == "odoo-xml-public-mail-channel" for f in findings)


def test_user_admin_group_assignment(tmp_path: Path) -> None:
    """XML data should not silently grant administrator groups to users."""
    xml = tmp_path / "users.xml"
    xml.write_text(
        """<odoo>
  <record id="demo_promoted_user" model="res.users">
    <field name="login">demo-admin</field>
    <field name="groups_id" eval="[(4, ref('base.group_system'))]"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-user-admin-group-assignment" for f in findings)


def test_user_admin_group_assignment_csv(tmp_path: Path) -> None:
    """CSV res.users group assignments should not hide administrator grants."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "res_users.csv").write_text(
        "id,login,groups_id/id\ndemo_promoted_user,demo-admin,base.group_system\n",
        encoding="utf-8",
    )

    findings = scan_xml_data(tmp_path)

    assert any(f.rule_id == "odoo-xml-user-admin-group-assignment" for f in findings)


def test_user_admin_group_assignment_csv_colon_groups(tmp_path: Path) -> None:
    """CSV res.users group assignments exported with colon headers should be scanned."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "res_users.csv").write_text(
        "id,login,groups_id:id\ndemo_promoted_user,demo-admin,base.group_system\n",
        encoding="utf-8",
    )

    findings = scan_xml_data(tmp_path)

    assert any(f.rule_id == "odoo-xml-user-admin-group-assignment" for f in findings)


def test_group_record_implies_internal_privilege(tmp_path: Path) -> None:
    """Group records can make public or signup groups imply internal access."""
    xml = tmp_path / "groups.xml"
    xml.write_text(
        """<odoo>
  <record id="group_signup" model="res.groups">
    <field name="implied_ids" eval="[(4, ref('base.group_user'))]"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(
        f.rule_id == "odoo-xml-group-implies-privilege" and f.severity == "high" and f.record_id == "group_signup"
        for f in findings
    )


def test_group_record_implies_admin_privilege_is_critical(tmp_path: Path) -> None:
    """Group implication toward administrator groups should be critical."""
    xml = tmp_path / "groups.xml"
    xml.write_text(
        """<odoo>
  <record id="group_support" model="res.groups">
    <field name="implied_ids" eval="[(4, ref('base.group_system'))]"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-group-implies-privilege" and f.severity == "critical" for f in findings)


def test_group_record_implies_admin_privilege_csv(tmp_path: Path) -> None:
    """CSV res.groups implied_ids should surface privilege inheritance."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "res_groups.csv").write_text(
        "id,name,implied_ids/id\ngroup_support,Support,base.group_system\n",
        encoding="utf-8",
    )

    findings = scan_xml_data(tmp_path)

    assert any(f.rule_id == "odoo-xml-group-implies-privilege" and f.severity == "critical" for f in findings)


def test_function_user_group_assignment(tmp_path: Path) -> None:
    """Install/update functions can silently grant user groups."""
    xml = tmp_path / "functions.xml"
    xml.write_text(
        """<odoo>
  <function model="res.users" name="write" eval="([ref('base.user_demo')], {'groups_id': [(4, ref('base.group_system'))]})"/>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-xml-function-security-model-mutation" in rule_ids
    assert "odoo-xml-function-user-group-assignment" in rule_ids


def test_function_group_implies_internal_privilege(tmp_path: Path) -> None:
    """Function-based group writes can make public/signup groups imply internal access."""
    xml = tmp_path / "functions.xml"
    xml.write_text(
        """<odoo>
  <function model="res.groups" name="write" eval="([ref('my_module.group_signup')], {'implied_ids': [(4, ref('base.group_user'))]})"/>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-xml-function-security-model-mutation" in rule_ids
    assert "odoo-xml-function-group-implies-privilege" in rule_ids


def test_function_security_model_unlink(tmp_path: Path) -> None:
    """Function-based deletes of rules/ACLs should be surfaced."""
    xml = tmp_path / "functions.xml"
    xml.write_text(
        """<odoo>
  <function model="ir.rule" name="unlink" eval="([ref('base.res_partner_rule_private_employee')])"/>
</odoo>""",
        encoding="utf-8",
    )

    findings = XmlDataScanner(xml).scan_file()

    assert any(f.rule_id == "odoo-xml-function-security-model-mutation" for f in findings)


def test_repository_scan_finds_xml_data(tmp_path: Path) -> None:
    """Repository scanner should include XML data files."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "actions.xml").write_text(
        """<odoo>
  <record id="action_eval" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code">eval(record.expression)</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_xml_data(tmp_path)

    assert any(f.rule_id == "odoo-xml-server-action-dynamic-eval" for f in findings)
