"""Tests for Odoo res.config.settings scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.settings_scanner import scan_settings


def test_flags_sensitive_config_parameter_without_admin_groups(tmp_path: Path) -> None:
    """Secret settings fields should be visibly admin-only."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import fields, models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    api_secret = fields.Char(config_parameter='payment.provider.api_secret')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sensitive-config-field-no-admin-groups" for f in findings)


def test_flags_common_integration_key_config_parameters(tmp_path: Path) -> None:
    """Key-shaped integration parameters should be treated as sensitive settings."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import fields, models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    access_key = fields.Char(config_parameter='connector.access_key')
    license_key = fields.Char(config_parameter='connector.license_key')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)
    fields = {
        finding.field
        for finding in findings
        if finding.rule_id == "odoo-settings-sensitive-config-field-no-admin-groups"
    }

    assert {"access_key", "license_key"} <= fields


def test_flags_direct_transient_model_base_and_direct_field_constructor(tmp_path: Path) -> None:
    """Direct TransientModel bases and field constructors should still be scanned."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo.fields import Char
from odoo.models import TransientModel

class ResConfigSettings(TransientModel):
    api_secret = Char(config_parameter='payment.provider.api_secret')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sensitive-config-field-no-admin-groups" for f in findings)


def test_flags_aliased_direct_transient_model_base(tmp_path: Path) -> None:
    """Aliased TransientModel bases should still identify settings classes."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo.fields import Char
from odoo.models import TransientModel as SettingsModel

class ResConfigSettings(SettingsModel):
    api_secret = Char(config_parameter='payment.provider.api_secret')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sensitive-config-field-no-admin-groups" for f in findings)


def test_flags_annotated_sensitive_config_parameter(tmp_path: Path) -> None:
    """Annotated settings field declarations should be scanned."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import fields, models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    api_secret: fields.Char = fields.Char(config_parameter='payment.provider.api_secret')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sensitive-config-field-no-admin-groups" for f in findings)


def test_flags_public_config_parameter_groups(tmp_path: Path) -> None:
    """Public/portal groups should never control config_parameter fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import fields, models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    callback_url = fields.Char(config_parameter='integration.callback_url', groups='base.group_portal')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-config-field-public-groups" for f in findings)


def test_flags_constant_backed_config_parameter_and_groups(tmp_path: Path) -> None:
    """Constant-backed config_parameter and groups metadata should be scanned."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import fields, models

SETTINGS_MODEL = 'res.config.settings'
SECRET_KEY = 'payment.provider.api_secret'
PORTAL_GROUP = 'base.group_portal'

class ResConfigSettings(models.TransientModel):
    _inherit = SETTINGS_MODEL

    api_secret = fields.Char(config_parameter=SECRET_KEY, groups=PORTAL_GROUP)
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-settings-sensitive-config-field-no-admin-groups" in rule_ids
    assert "odoo-settings-config-field-public-groups" in rule_ids


def test_flags_static_unpack_config_parameter_and_groups(tmp_path: Path) -> None:
    """Static **field options should not hide settings metadata."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import fields, models

SECRET_KEY = 'payment.provider.api_secret'
PORTAL_GROUP = 'base.group_portal'
FIELD_OPTIONS = {'config_parameter': SECRET_KEY, 'groups': PORTAL_GROUP}

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    api_secret = fields.Char(**FIELD_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-settings-sensitive-config-field-no-admin-groups" in rule_ids
    assert "odoo-settings-config-field-public-groups" in rule_ids


def test_flags_nested_static_unpack_config_parameter_and_groups(tmp_path: Path) -> None:
    """Nested static **field options should not hide settings metadata."""
    models = tmp_path / "models"
    models.mkdir()
    (models / "settings.py").write_text(
        """
from odoo import fields, models

SECRET_KEY = 'payment.provider.api_secret'
PORTAL_GROUP = 'base.group_portal'
BASE_OPTIONS = {'config_parameter': SECRET_KEY}
FIELD_OPTIONS = {**BASE_OPTIONS, 'groups': PORTAL_GROUP}

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    api_secret = fields.Char(**FIELD_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-settings-sensitive-config-field-no-admin-groups" in rule_ids
    assert "odoo-settings-config-field-public-groups" in rule_ids


def test_flags_class_constant_backed_config_parameter_and_groups(tmp_path: Path) -> None:
    """Class-level config_parameter and groups metadata should be scanned."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import fields, models

class ResConfigSettings(models.TransientModel):
    SETTINGS_MODEL = 'res.config.settings'
    SECRET_KEY = 'payment.provider.api_secret'
    PORTAL_GROUP = 'base.group_portal'
    FIELD_OPTIONS = {'config_parameter': SECRET_KEY, 'groups': PORTAL_GROUP}

    _inherit = SETTINGS_MODEL

    api_secret = fields.Char(**FIELD_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-settings-sensitive-config-field-no-admin-groups" in rule_ids
    assert "odoo-settings-config-field-public-groups" in rule_ids


def test_flags_constant_alias_settings_fields_and_config_model(tmp_path: Path) -> None:
    """Aliased settings metadata and ir.config_parameter model names should resolve."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import SUPERUSER_ID, fields, models

BASE_MODEL = 'res.config.settings'
SETTINGS_MODEL = BASE_MODEL
SECRET_BASE = 'payment.provider.api_secret'
SECRET_KEY = SECRET_BASE
PORTAL_BASE = 'base.group_portal'
PORTAL_GROUP = PORTAL_BASE
SIGNUP_BASE = 'auth_signup.allow_uninvited'
SIGNUP_KEY = SIGNUP_BASE
UNSAFE_BASE = True
UNSAFE_DEFAULT = UNSAFE_BASE
CONFIG_BASE = 'ir.config_parameter'
CONFIG_MODEL = CONFIG_BASE
ROOT = SUPERUSER_ID

class ResConfigSettings(models.TransientModel):
    _inherit = SETTINGS_MODEL

    api_secret = fields.Char(config_parameter=SECRET_KEY, groups=PORTAL_GROUP)
    allow_uninvited_signup = fields.Boolean(config_parameter=SIGNUP_KEY, default=UNSAFE_DEFAULT)

    def set_values(self):
        Config = self.env[CONFIG_MODEL].with_user(ROOT)
        Config.set_param(SIGNUP_KEY, 'True')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-settings-sensitive-config-field-no-admin-groups" in rule_ids
    assert "odoo-settings-config-field-public-groups" in rule_ids
    assert "odoo-settings-security-toggle-no-admin-groups" in rule_ids
    assert "odoo-settings-security-toggle-unsafe-default" in rule_ids
    assert any(
        f.rule_id == "odoo-settings-sudo-set-param" and f.field == "auth_signup.allow_uninvited" for f in findings
    )


def test_flags_admin_implied_group_and_module_toggle(tmp_path: Path) -> None:
    """Settings toggles can grant groups or install modules."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import fields, models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    allow_admin = fields.Boolean(implied_group='base.group_system')
    module_sensitive_connector = fields.Boolean()
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-settings-implies-admin-group" in rule_ids
    assert "odoo-settings-module-toggle-no-admin-groups" in rule_ids


def test_flags_constant_backed_implied_group_and_security_toggle_default(tmp_path: Path) -> None:
    """Constant-backed implied_group and default values should still be reviewed."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import fields, models

ADMIN_GROUP = 'base.group_system'
SIGNUP_KEY = 'auth_signup.allow_uninvited'
UNSAFE_DEFAULT = True

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    allow_admin = fields.Boolean(implied_group=ADMIN_GROUP)
    allow_uninvited_signup = fields.Boolean(config_parameter=SIGNUP_KEY, default=UNSAFE_DEFAULT)
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-settings-implies-admin-group" in rule_ids
    assert "odoo-settings-security-toggle-no-admin-groups" in rule_ids
    assert "odoo-settings-security-toggle-unsafe-default" in rule_ids


def test_flags_security_toggle_without_admin_groups(tmp_path: Path) -> None:
    """Signup/database security toggles should be visibly admin-only."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import fields, models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    allow_uninvited_signup = fields.Boolean(config_parameter='auth.signup.allow_uninvited')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-security-toggle-no-admin-groups" for f in findings)


def test_flags_oauth_signup_and_base_url_security_toggles(tmp_path: Path) -> None:
    """OAuth signup and base URL freeze settings should be admin-only too."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import fields, models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    oauth_signup = fields.Boolean(config_parameter='auth_oauth.allow_signup')
    freeze_base_url = fields.Boolean(config_parameter='web.base.url.freeze')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert len([f for f in findings if f.rule_id == "odoo-settings-security-toggle-no-admin-groups"]) == 2


def test_flags_security_toggle_unsafe_defaults(tmp_path: Path) -> None:
    """Settings fields should not default security toggles to unsafe values."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import fields, models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    allow_uninvited_signup = fields.Boolean(config_parameter='auth_signup.allow_uninvited', default=True)
    freeze_base_url = fields.Boolean(config_parameter='web.base.url.freeze', default=False)
    invitation_scope = fields.Selection(config_parameter='auth_signup.invitation_scope', default='b2c')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert len([f for f in findings if f.rule_id == "odoo-settings-security-toggle-unsafe-default"]) == 3


def test_flags_sudo_set_param_in_settings_method(tmp_path: Path) -> None:
    """Custom settings methods writing config with sudo should be surfaced."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    def set_values(self):
        self.env['ir.config_parameter'].sudo().set_param('auth.signup.allow_uninvited', 'True')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sudo-set-param" for f in findings)


def test_flags_tuple_unpacked_sudo_set_param_in_settings_method(tmp_path: Path) -> None:
    """Tuple-unpacked sudo config parameter aliases should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    def set_values(self):
        Config, Users = self.env['ir.config_parameter'].sudo(), self.env['res.users']
        Config.set_param('auth_oauth.allow_signup', 'True')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sudo-set-param" for f in findings)


def test_flags_with_user_superuser_set_param_in_settings_method(tmp_path: Path) -> None:
    """with_user(SUPERUSER_ID) config writes should be treated as elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    def set_values(self):
        self.env['ir.config_parameter'].with_user(SUPERUSER_ID).set_param('auth.signup.allow_uninvited', 'True')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sudo-set-param" for f in findings)


def test_flags_import_aliased_superuser_set_param_in_settings_method(tmp_path: Path) -> None:
    """Imported SUPERUSER_ID aliases in settings methods should be elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import SUPERUSER_ID as ROOT_UID, models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    def set_values(self):
        self.env['ir.config_parameter'].with_user(ROOT_UID).set_param('auth.signup.allow_uninvited', 'True')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sudo-set-param" for f in findings)


def test_flags_keyword_with_user_superuser_set_param_in_settings_method(tmp_path: Path) -> None:
    """Keyword with_user(user=SUPERUSER_ID) config writes are elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    def set_values(self):
        self.env['ir.config_parameter'].with_user(user=SUPERUSER_ID).set_param('auth.signup.allow_uninvited', 'True')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sudo-set-param" for f in findings)


def test_flags_aliased_with_user_one_set_param_in_settings_method(tmp_path: Path) -> None:
    """with_user(1) config aliases should preserve elevated posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    def set_values(self):
        Config = self.env['ir.config_parameter'].with_user(1)
        Config.set_param('auth_oauth.allow_signup', 'True')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sudo-set-param" for f in findings)


def test_flags_constant_backed_with_user_root_set_param_in_settings_method(tmp_path: Path) -> None:
    """Constant-backed superuser IDs and set_param keys should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import models

ROOT_UID = 1
SIGNUP_KEY = 'auth_oauth.allow_signup'

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    def set_values(self):
        Config = self.env['ir.config_parameter'].with_user(ROOT_UID)
        Config.set_param(SIGNUP_KEY, 'True')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sudo-set-param" and f.field == "auth_oauth.allow_signup" for f in findings)


def test_flags_class_constant_backed_with_user_root_set_param_in_settings_method(tmp_path: Path) -> None:
    """Class-level superuser IDs and set_param keys should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import models

class ResConfigSettings(models.TransientModel):
    ROOT_UID = 1
    SIGNUP_KEY = 'auth_oauth.allow_signup'

    _inherit = 'res.config.settings'

    def set_values(self):
        Config = self.env['ir.config_parameter'].with_user(ROOT_UID)
        Config.set_param(SIGNUP_KEY, 'True')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sudo-set-param" and f.field == "auth_oauth.allow_signup" for f in findings)


def test_flags_env_ref_root_set_param_in_settings_method(tmp_path: Path) -> None:
    """with_user(base.user_root) config aliases should preserve elevated posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    def set_values(self):
        Config = self.env['ir.config_parameter'].with_user(self.env.ref('base.user_root'))
        Config.set_param('auth_oauth.allow_signup', 'True')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sudo-set-param" for f in findings)


def test_flags_starred_rest_sudo_set_param_in_settings_method(tmp_path: Path) -> None:
    """Starred-rest sudo config parameter aliases should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    def set_values(self):
        marker, *items, tail = 'x', self.env['ir.config_parameter'].sudo(), self.env['res.users'], 'end'
        Config = items[0]
        Config.set_param('auth_oauth.allow_signup', 'True')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sudo-set-param" for f in findings)


def test_flags_named_expression_sudo_set_param_in_settings_method(tmp_path: Path) -> None:
    """Walrus-bound sudo config parameter aliases should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    def set_values(self):
        if Config := self.env['ir.config_parameter'].sudo():
            Config.set_param('auth_oauth.allow_signup', 'True')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sudo-set-param" for f in findings)


def test_flags_starred_sudo_set_param_in_settings_method(tmp_path: Path) -> None:
    """Starred sudo config parameter aliases should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    def set_values(self):
        *Config, Users = self.env['ir.config_parameter'].sudo(), self.env['res.users']
        Config.set_param('auth_oauth.allow_signup', 'True')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sudo-set-param" for f in findings)


def test_flags_copied_sudo_set_param_in_settings_method(tmp_path: Path) -> None:
    """Copied sudo config parameter aliases should preserve sudo posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    def set_values(self):
        Config = self.env['ir.config_parameter'].sudo()
        Alias = Config
        Alias.set_param('auth_oauth.allow_signup', 'True')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sudo-set-param" for f in findings)


def test_flags_aliased_sudo_set_param_in_settings_method(tmp_path: Path) -> None:
    """Aliased sudo config parameter models should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    def set_values(self):
        Config = self.env['ir.config_parameter'].sudo()
        Config.set_param('auth.signup.allow_uninvited', 'True')
""",
        encoding="utf-8",
    )

    findings = scan_settings(tmp_path)

    assert any(f.rule_id == "odoo-settings-sudo-set-param" for f in findings)


def test_admin_grouped_sensitive_setting_is_ignored(tmp_path: Path) -> None:
    """Admin-only secret settings should avoid noise."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import fields, models

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    api_secret = fields.Char(config_parameter='payment.provider.api_secret', groups='base.group_system')
""",
        encoding="utf-8",
    )

    assert scan_settings(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_settings.py").write_text(
        """
class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'
    api_secret = fields.Char(config_parameter='payment.provider.api_secret')
""",
        encoding="utf-8",
    )

    assert scan_settings(tmp_path) == []
