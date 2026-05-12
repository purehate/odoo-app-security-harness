"""Tests for heuristic secret/config scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.secrets_scanner import SecretScanner, scan_secrets


def test_hardcoded_python_secret_is_redacted(tmp_path: Path) -> None:
    """Secret-like assignments should be reported without exposing full values."""
    path = tmp_path / "settings.py"
    path.write_text("api_key = 'sk_live_1234567890abcdef'\n", encoding="utf-8")

    findings = SecretScanner(path).scan_file()

    assert any(f.rule_id == "odoo-secret-hardcoded-value" for f in findings)
    assert findings[0].redacted == "sk_l...cdef"
    assert "1234567890abcdef" not in findings[0].message


def test_placeholder_secret_is_ignored(tmp_path: Path) -> None:
    """Obvious placeholders should not create noise."""
    path = tmp_path / "settings.py"
    path.write_text("api_key = 'example_token'\npassword = 'changeme'\n", encoding="utf-8")

    assert SecretScanner(path).scan_file() == []


def test_quoted_key_secret_is_reported(tmp_path: Path) -> None:
    """JSON/YAML/Python dict-style quoted keys should be scanned too."""
    path = tmp_path / "settings.json"
    path.write_text('{"api_key": "sk_live_abcdef1234567890"}\n', encoding="utf-8")

    findings = SecretScanner(path).scan_file()

    assert any(f.rule_id == "odoo-secret-hardcoded-value" for f in findings)


def test_common_integration_key_assignments_are_reported(tmp_path: Path) -> None:
    """Access/license key shaped assignments should be treated as secrets."""
    path = tmp_path / "settings.py"
    path.write_text(
        """
access_key = 'ak_live_abcdef1234567890'
license_key = 'lic_live_abcdef1234567890'
reset_password_url = 'https://odoo.example/reset?token=abcdef1234567890'
webhook_secret = 'whsec_abcdef1234567890'
""",
        encoding="utf-8",
    )

    findings = SecretScanner(path).scan_file()
    kinds = {finding.secret_kind for finding in findings if finding.rule_id == "odoo-secret-hardcoded-value"}

    assert {"access_key", "license_key", "reset_password_url", "webhook_secret"} <= kinds


def test_set_param_secret_in_python_is_reported(tmp_path: Path) -> None:
    """Modules should not ship production ir.config_parameter values through code."""
    path = tmp_path / "settings.py"
    path.write_text(
        """
def configure(env):
    env['ir.config_parameter'].sudo().set_param('payment.secret_key', 'live_secret_abcdef123456')
""",
        encoding="utf-8",
    )

    findings = SecretScanner(path).scan_file()

    assert any(f.rule_id == "odoo-secret-config-parameter-set-param" for f in findings)


def test_private_key_block_is_reported(tmp_path: Path) -> None:
    """PEM private key blocks should be critical rotation leads."""
    path = tmp_path / "id_rsa.pem"
    path.write_text(
        """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC
-----END PRIVATE KEY-----
""",
        encoding="utf-8",
    )

    findings = SecretScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-secret-private-key-block" and f.severity == "critical" and f.redacted == "<private-key>"
        for f in findings
    )


def test_set_param_integration_key_in_python_is_reported(tmp_path: Path) -> None:
    """set_param with key-shaped integration secrets should be reported."""
    path = tmp_path / "settings.py"
    path.write_text(
        """
def configure(env):
    env['ir.config_parameter'].sudo().set_param('connector.access_key', 'ak_live_abcdef1234567890')
    env['ir.config_parameter'].sudo().set_param('connector.license_key', 'lic_live_abcdef1234567890')
    env['ir.config_parameter'].sudo().set_param('connector.reset_password_url', 'https://odoo.example/reset?token=abcdef1234567890')
""",
        encoding="utf-8",
    )

    findings = SecretScanner(path).scan_file()
    keys = {finding.secret_kind for finding in findings if finding.rule_id == "odoo-secret-config-parameter-set-param"}

    assert {"connector.access_key", "connector.license_key", "connector.reset_password_url"} <= keys


def test_set_param_placeholder_is_ignored(tmp_path: Path) -> None:
    """set_param examples should not create noise."""
    path = tmp_path / "settings.py"
    path.write_text(
        "env['ir.config_parameter'].set_param('payment.secret_key', 'example_secret')\n",
        encoding="utf-8",
    )

    assert SecretScanner(path).scan_file() == []


def test_ir_config_parameter_secret_in_xml(tmp_path: Path) -> None:
    """Sensitive ir.config_parameter values in module data should be reported."""
    path = tmp_path / "data.xml"
    path.write_text(
        """<odoo>
  <record id="database_secret" model="ir.config_parameter">
    <field name="key">database.secret</field>
    <field name="value">super-secret-value-123456</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = SecretScanner(path).scan_file()

    assert any(f.rule_id == "odoo-secret-config-parameter" for f in findings)


def test_ir_config_parameter_integration_key_in_xml(tmp_path: Path) -> None:
    """XML data should report key-shaped integration secrets."""
    path = tmp_path / "data.xml"
    path.write_text(
        """<odoo>
  <record id="connector_access_key" model="ir.config_parameter">
    <field name="key">connector.access_key</field>
    <field name="value">ak_live_abcdef1234567890</field>
  </record>
  <record id="connector_reset_url" model="ir.config_parameter">
    <field name="key">connector.reset_password_url</field>
    <field name="value">https://odoo.example/reset?token=abcdef1234567890</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = SecretScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-secret-config-parameter" and f.secret_kind == "connector." + "access_key" for f in findings
    )
    assert any(
        f.rule_id == "odoo-secret-config-parameter" and f.secret_kind == "connector." + "reset_password_url"
        for f in findings
    )


def test_res_users_password_in_xml(tmp_path: Path) -> None:
    """Committed user passwords in data files should be critical."""
    path = tmp_path / "users.xml"
    path.write_text(
        """<odoo>
  <record id="user_backdoor" model="res.users">
    <field name="login">backdoor@example.com</field>
    <field name="password">CorrectHorseBatteryStaple</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = SecretScanner(path).scan_file()

    assert any(f.rule_id == "odoo-secret-user-password-data" and f.severity == "critical" for f in findings)


def test_weak_res_users_password_in_xml(tmp_path: Path) -> None:
    """Weak default user passwords should be reported even when placeholder-like."""
    path = tmp_path / "users.xml"
    path.write_text(
        """<odoo>
  <record id="user_demo" model="res.users">
    <field name="login">demo@example.com</field>
    <field name="password">demo</field>
  </record>
  <record id="user_admin" model="res.users">
    <field name="login">admin@example.com</field>
    <field name="new_password" eval="'admin'"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = SecretScanner(path).scan_file()
    weak_passwords = [f for f in findings if f.rule_id == "odoo-secret-weak-user-password-data"]

    assert len(weak_passwords) == 2
    assert all(f.severity == "critical" for f in weak_passwords)


def test_res_users_password_in_csv(tmp_path: Path) -> None:
    """Committed user passwords in CSV data should be critical."""
    path = tmp_path / "res.users.csv"
    path.write_text(
        "id,login,password\nuser_backdoor,backdoor@example.com,CorrectHorseBatteryStaple\n",
        encoding="utf-8",
    )

    findings = SecretScanner(path).scan_file()

    assert any(f.rule_id == "odoo-secret-user-password-data" and f.severity == "critical" for f in findings)


def test_weak_res_users_password_in_csv(tmp_path: Path) -> None:
    """Weak CSV user passwords should be reported even when placeholder-like."""
    path = tmp_path / "users.csv"
    path.write_text(
        "id,login,new_password\nuser_demo,demo@example.com,demo\nuser_admin,admin@example.com,admin\n",
        encoding="utf-8",
    )

    findings = SecretScanner(path).scan_file()
    weak_passwords = [f for f in findings if f.rule_id == "odoo-secret-weak-user-password-data"]

    assert len(weak_passwords) == 2
    assert all(f.severity == "critical" for f in weak_passwords)


def test_ir_config_parameter_secret_in_csv(tmp_path: Path) -> None:
    """Sensitive ir.config_parameter CSV rows should be reported."""
    path = tmp_path / "ir.config_parameter.csv"
    path.write_text(
        "id,key,value\npayment_secret,payment.secret_key,live_secret_abcdef123456\n",
        encoding="utf-8",
    )

    findings = SecretScanner(path).scan_file()

    assert any(f.rule_id == "odoo-secret-config-parameter" and f.severity == "high" for f in findings)


def test_ir_config_parameter_secret_in_csv_colon_headers(tmp_path: Path) -> None:
    """CSV config parameter headers with colon suffixes should still expose secrets."""
    path = tmp_path / "ir.config_parameter.csv"
    path.write_text(
        "id,key:id,value:raw\npayment_secret,payment.secret_key,live_secret_abcdef123456\n",
        encoding="utf-8",
    )

    findings = SecretScanner(path).scan_file()

    assert any(f.rule_id == "odoo-secret-config-parameter" and f.severity == "high" for f in findings)


def test_ir_config_parameter_integration_key_in_csv(tmp_path: Path) -> None:
    """CSV data should report key-shaped integration secrets."""
    path = tmp_path / "ir.config_parameter.csv"
    path.write_text(
        "id,key,value\n"
        "connector_license,connector.license_key,lic_live_abcdef1234567890\n"
        "connector_reset,connector.reset_password_url,https://odoo.example/reset?token=abcdef1234567890\n",
        encoding="utf-8",
    )

    findings = SecretScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-secret-config-parameter" and f.secret_kind == "connector." + "license_key" for f in findings
    )
    assert any(
        f.rule_id == "odoo-secret-config-parameter" and f.secret_kind == "connector." + "reset_password_url"
        for f in findings
    )


def test_res_users_password_matching_login_is_reported(tmp_path: Path) -> None:
    """Account passwords equal to the login or email local part are weak defaults."""
    path = tmp_path / "users.xml"
    path.write_text(
        """<odoo>
  <record id="user_sales" model="res.users">
    <field name="login">sales@example.com</field>
    <field name="password">sales</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = SecretScanner(path).scan_file()

    assert any(f.rule_id == "odoo-secret-weak-user-password-data" for f in findings)


def test_xml_entities_are_not_expanded_into_secret_findings(tmp_path: Path) -> None:
    """Secret XML parsing should reject entities instead of expanding them into findings."""
    path = tmp_path / "data.xml"
    path.write_text(
        """<!DOCTYPE odoo [
<!ENTITY secret_value "super-secret-value-123456">
]>
<odoo>
  <record id="database_secret" model="ir.config_parameter">
    <field name="key">database.secret</field>
    <field name="value">&secret_value;</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = SecretScanner(path).scan_file()

    assert not findings


def test_weak_admin_passwd_in_config(tmp_path: Path) -> None:
    """admin_passwd=admin should be reported."""
    path = tmp_path / "odoo.conf"
    path.write_text("[options]\nadmin_passwd = admin\n", encoding="utf-8")

    findings = SecretScanner(path).scan_file()

    assert any(f.rule_id == "odoo-secret-weak-admin-passwd" for f in findings)


def test_integration_key_in_config_file_is_reported(tmp_path: Path) -> None:
    """Config files should report key-shaped integration secrets."""
    path = tmp_path / "odoo.conf"
    path.write_text(
        "[options]\n"
        "connector_access_key = ak_live_abcdef1234567890\n"
        "connector_reset_password_url = https://odoo.example/reset?token=abcdef1234567890\n",
        encoding="utf-8",
    )

    findings = SecretScanner(path).scan_file()

    assert any(
        f.rule_id == "odoo-secret-config-file-value" and f.secret_kind == "connector_" + "access_key" for f in findings
    )
    assert any(
        f.rule_id == "odoo-secret-config-file-value" and f.secret_kind == "connector_" + "reset_password_url"
        for f in findings
    )


def test_toml_secret_assignment_is_reported(tmp_path: Path) -> None:
    """TOML config files should be scanned for quoted secret assignments."""
    path = tmp_path / "settings.toml"
    path.write_text('api_key = "sk_live_abcdef1234567890"\n', encoding="utf-8")

    findings = scan_secrets(tmp_path)

    assert any(f.rule_id == "odoo-secret-hardcoded-value" and f.file == str(path) for f in findings)


def test_properties_secret_assignment_is_reported(tmp_path: Path) -> None:
    """Properties-style config files should be scanned for unquoted secrets."""
    path = tmp_path / "integration.properties"
    path.write_text("connector.secret_key = live_secret_abcdef1234567890\n", encoding="utf-8")

    findings = scan_secrets(tmp_path)

    assert any(f.rule_id == "odoo-secret-config-file-value" and f.file == str(path) for f in findings)


def test_yaml_unquoted_secret_assignment_is_reported(tmp_path: Path) -> None:
    """YAML config often stores unquoted deployment secrets."""
    path = tmp_path / "docker-compose.yml"
    path.write_text(
        """services:
  odoo:
    environment:
      api_key: sk_live_abcdef1234567890
      password: ${ODOO_PASSWORD}
""",
        encoding="utf-8",
    )

    findings = scan_secrets(tmp_path)

    assert any(
        f.rule_id == "odoo-secret-hardcoded-value" and f.file == str(path) and f.secret_kind == "api_key"
        for f in findings
    )
    assert not any(f.secret_kind == "password" for f in findings)


def test_shell_unquoted_secret_assignment_is_reported(tmp_path: Path) -> None:
    """Deployment scripts often export unquoted secrets before invoking Odoo."""
    path = tmp_path / "entrypoint.sh"
    path.write_text(
        """#!/usr/bin/env bash
export ODOO_API_KEY=sk_live_abcdef1234567890
ODOO_PASSWORD=${ODOO_PASSWORD}
""",
        encoding="utf-8",
    )

    findings = scan_secrets(tmp_path)

    assert any(
        f.rule_id == "odoo-secret-hardcoded-value" and f.file == str(path) and f.secret_kind == "odoo_api_key"
        for f in findings
    )
    assert not any(f.secret_kind == "odoo_password" for f in findings)


def test_dockerfile_env_secret_assignment_is_reported(tmp_path: Path) -> None:
    """Docker ARG/ENV layers should not bake Odoo integration secrets."""
    path = tmp_path / "Dockerfile"
    path.write_text(
        """FROM odoo:18
ARG ODOO_API_KEY=sk_live_abcdef1234567890
ENV ODOO_PASSWORD=${ODOO_PASSWORD}
""",
        encoding="utf-8",
    )

    findings = scan_secrets(tmp_path)

    assert any(
        f.rule_id == "odoo-secret-hardcoded-value" and f.file == str(path) and f.secret_kind == "odoo_api_key"
        for f in findings
    )
    assert not any(f.secret_kind == "odoo_password" for f in findings)


def test_repository_secret_scan_skips_virtualenv(tmp_path: Path) -> None:
    """Vendored/generated directories should not be scanned."""
    app = tmp_path / "app.py"
    app.write_text("token = 'tok_1234567890abcdef'\n", encoding="utf-8")
    venv_file = tmp_path / ".venv" / "lib" / "settings.py"
    venv_file.parent.mkdir(parents=True)
    venv_file.write_text("token = 'tok_ffffffffffffffff'\n", encoding="utf-8")

    findings = scan_secrets(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == str(app)


def test_repository_secret_scan_includes_key_material_files(tmp_path: Path) -> None:
    """Repository scanning should include standalone PEM/key material files."""
    key_file = tmp_path / "deploy.key"
    key_file.write_text(
        """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=
-----END OPENSSH PRIVATE KEY-----
""",
        encoding="utf-8",
    )

    findings = scan_secrets(tmp_path)

    assert any(f.rule_id == "odoo-secret-private-key-block" and f.file == str(key_file) for f in findings)
