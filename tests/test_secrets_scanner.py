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
