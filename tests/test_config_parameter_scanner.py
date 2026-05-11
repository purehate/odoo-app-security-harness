"""Tests for runtime ir.config_parameter scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.config_parameter_scanner import scan_config_parameters


def test_flags_public_sensitive_config_read(tmp_path: Path) -> None:
    """Public routes should not read sensitive system parameters."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request

class Config(http.Controller):
    @http.route('/public/config', auth='public')
    def config(self):
        return request.env['ir.config_parameter'].sudo().get_param('payment.provider.secret')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-public-sensitive-read" in rule_ids
    assert "odoo-config-param-sudo-sensitive-read" in rule_ids


def test_flags_public_integration_key_config_read(tmp_path: Path) -> None:
    """Key-shaped integration parameters should be treated as sensitive reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request

class Config(http.Controller):
    @http.route('/public/config', auth='public')
    def config(self):
        return {
            'access': request.env['ir.config_parameter'].sudo().get_param('connector.access_key'),
            'license': request.env['ir.config_parameter'].sudo().get_param('connector.license_key'),
        }
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    public_keys = {finding.key for finding in findings if finding.rule_id == "odoo-config-param-public-sensitive-read"}
    sudo_keys = {finding.key for finding in findings if finding.rule_id == "odoo-config-param-sudo-sensitive-read"}

    assert {"connector.access_key", "connector.license_key"} <= public_keys
    assert {"connector.access_key", "connector.license_key"} <= sudo_keys


def test_imported_route_decorator_public_sensitive_config_read(tmp_path: Path) -> None:
    """Imported route decorators should still expose public config reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request, route

class Config(http.Controller):
    @route('/public/config', auth='public')
    def config(self):
        return request.env['ir.config_parameter'].sudo().get_param('payment.provider.secret')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-public-sensitive-read" in rule_ids
    assert "odoo-config-param-sudo-sensitive-read" in rule_ids


def test_aliased_imported_route_decorator_public_sensitive_config_read(tmp_path: Path) -> None:
    """Aliased imported route decorators should still expose public config reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request, route as odoo_route

class Config(http.Controller):
    @odoo_route('/public/config', auth='public')
    def config(self):
        return request.env['ir.config_parameter'].sudo().get_param('payment.provider.secret')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-public-sensitive-read" in rule_ids
    assert "odoo-config-param-sudo-sensitive-read" in rule_ids


def test_aliased_http_module_public_sensitive_config_read(tmp_path: Path) -> None:
    """Aliased Odoo http module imports should still expose public config reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http as odoo_http
from odoo.http import request

class Config(odoo_http.Controller):
    @odoo_http.route('/public/config', auth='public')
    def config(self):
        return request.env['ir.config_parameter'].sudo().get_param('payment.provider.secret')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-public-sensitive-read" in rule_ids
    assert "odoo-config-param-sudo-sensitive-read" in rule_ids


def test_imported_odoo_http_module_public_sensitive_config_read(tmp_path: Path) -> None:
    """Direct odoo.http imports should still expose public config reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
import odoo.http as odoo_http

class Config(odoo_http.Controller):
    @odoo_http.route('/public/config', auth='public')
    def config(self):
        return odoo_http.request.env['ir.config_parameter'].sudo().get_param('payment.provider.secret')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-public-sensitive-read" in rule_ids
    assert "odoo-config-param-sudo-sensitive-read" in rule_ids


def test_imported_odoo_module_public_sensitive_config_read(tmp_path: Path) -> None:
    """Direct odoo imports should still expose public config reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
import odoo as od

class Config(od.http.Controller):
    @od.http.route('/public/config', auth='public')
    def config(self):
        return od.http.request.env['ir.config_parameter'].sudo().get_param('payment.provider.secret')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-public-sensitive-read" in rule_ids
    assert "odoo-config-param-sudo-sensitive-read" in rule_ids


def test_non_odoo_route_decorator_public_config_read_is_ignored(tmp_path: Path) -> None:
    """Local route-like decorators should not create Odoo route context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo.http import request

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class Config:
    @router.route('/public/config', auth='public')
    def config(self):
        return request.env['ir.config_parameter'].sudo().get_param('payment.provider.secret')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert not any(f.rule_id == "odoo-config-param-public-sensitive-read" for f in findings)
    assert any(f.rule_id == "odoo-config-param-sudo-sensitive-read" for f in findings)


def test_constant_backed_public_sensitive_config_read(tmp_path: Path) -> None:
    """Constant-backed public auth should still expose sensitive config reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request

CONFIG_ROUTES = ['/public/config', '/public/config/alt']
CONFIG_AUTH = 'public'

class Config(http.Controller):
    @http.route(CONFIG_ROUTES, auth=CONFIG_AUTH)
    def config(self):
        return request.env['ir.config_parameter'].sudo().get_param('payment.provider.secret')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(
        f.rule_id == "odoo-config-param-public-sensitive-read"
        and f.severity == "critical"
        and f.key == "payment.provider.secret"
        for f in findings
    )
    assert any(f.rule_id == "odoo-config-param-sudo-sensitive-read" for f in findings)


def test_class_constant_backed_public_sensitive_config_read(tmp_path: Path) -> None:
    """Class-scoped public auth should still expose sensitive config reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request

class Config(http.Controller):
    AUTH_BASE = 'public'
    CONFIG_AUTH = AUTH_BASE

    @http.route('/public/config', auth=CONFIG_AUTH)
    def config(self):
        return request.env['ir.config_parameter'].sudo().get_param('payment.provider.secret')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(
        f.rule_id == "odoo-config-param-public-sensitive-read"
        and f.severity == "critical"
        and f.key == "payment.provider.secret"
        for f in findings
    )
    assert any(f.rule_id == "odoo-config-param-sudo-sensitive-read" for f in findings)


def test_static_unpack_route_options_public_sensitive_config_read(tmp_path: Path) -> None:
    """Static route option dictionaries should preserve public config read posture."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request

CONFIG_OPTIONS = {'auth': 'public'}

class Config(http.Controller):
    @http.route('/public/config', **CONFIG_OPTIONS)
    def config(self):
        return request.env['ir.config_parameter'].sudo().get_param('payment.provider.secret')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(
        f.rule_id == "odoo-config-param-public-sensitive-read"
        and f.severity == "critical"
        and f.key == "payment.provider.secret"
        for f in findings
    )
    assert any(f.rule_id == "odoo-config-param-sudo-sensitive-read" for f in findings)


def test_nested_static_unpack_route_options_public_sensitive_config_read(tmp_path: Path) -> None:
    """Nested static route option dictionaries should preserve public config posture."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request

BASE_OPTIONS = {'auth': 'public'}
CONFIG_OPTIONS = {**BASE_OPTIONS}

class Config(http.Controller):
    @http.route('/public/config', **CONFIG_OPTIONS)
    def config(self):
        return request.env['ir.config_parameter'].sudo().get_param('payment.provider.secret')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(
        f.rule_id == "odoo-config-param-public-sensitive-read"
        and f.severity == "critical"
        and f.key == "payment.provider.secret"
        for f in findings
    )
    assert any(f.rule_id == "odoo-config-param-sudo-sensitive-read" for f in findings)


def test_class_constant_static_unpack_route_options_public_sensitive_config_read(tmp_path: Path) -> None:
    """Class-scoped route option dictionaries should preserve public config read posture."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request

class Config(http.Controller):
    CONFIG_OPTIONS = {'auth': 'public'}

    @http.route('/public/config', **CONFIG_OPTIONS)
    def config(self):
        return request.env['ir.config_parameter'].sudo().get_param('payment.provider.secret')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(
        f.rule_id == "odoo-config-param-public-sensitive-read"
        and f.severity == "critical"
        and f.key == "payment.provider.secret"
        for f in findings
    )
    assert any(f.rule_id == "odoo-config-param-sudo-sensitive-read" for f in findings)


def test_keyword_constant_backed_none_hardcoded_sensitive_config_write_is_critical(tmp_path: Path) -> None:
    """Constant-backed auth='none' should preserve critical hardcoded secret writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request

BOOTSTRAP_ROUTE = '/public/config/bootstrap'
BOOTSTRAP_AUTH = 'none'

class Config(http.Controller):
    @http.route(route=BOOTSTRAP_ROUTE, auth=BOOTSTRAP_AUTH, csrf=False)
    def bootstrap(self):
        return request.env['ir.config_parameter'].sudo().set_param('jwt.signing_key', 'dev-secret-token')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(
        f.rule_id == "odoo-config-param-hardcoded-sensitive-write"
        and f.severity == "critical"
        and f.key == "jwt.signing_key"
        for f in findings
    )


def test_recursive_static_unpack_route_options_hardcoded_sensitive_config_write_is_critical(tmp_path: Path) -> None:
    """Recursive route option aliases should preserve auth='none' critical posture."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request

AUTH_BASE = 'none'
CONFIG_AUTH = AUTH_BASE
CONFIG_OPTIONS = {'auth': CONFIG_AUTH}
OPTIONS_ALIAS = CONFIG_OPTIONS

class Config(http.Controller):
    @http.route('/public/config/bootstrap', **OPTIONS_ALIAS)
    def bootstrap(self):
        return request.env['ir.config_parameter'].sudo().set_param('jwt.signing_key', 'dev-secret-token')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(
        f.rule_id == "odoo-config-param-hardcoded-sensitive-write"
        and f.severity == "critical"
        and f.key == "jwt.signing_key"
        for f in findings
    )


def test_flags_tainted_config_key_read(tmp_path: Path) -> None:
    """Request-selected config keys can disclose arbitrary parameters."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo.http import request

def config(**kwargs):
    key = kwargs.get('key')
    return request.env['ir.config_parameter'].sudo().get_param(key)
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(f.rule_id == "odoo-config-param-tainted-key-read" for f in findings)


def test_flags_sensitive_config_default(tmp_path: Path) -> None:
    """Sensitive get_param defaults should not become deployable fallback secrets."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
def signing_key(self):
    return self.env['ir.config_parameter'].sudo().get_param('jwt.signing_key', 'dev-secret-token')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(f.rule_id == "odoo-config-param-sensitive-default" for f in findings)


def test_flags_tainted_config_writes_and_sudo(tmp_path: Path) -> None:
    """Request-controlled config writes should be high-signal findings."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request

class Config(http.Controller):
    @http.route('/public/config', auth='public', csrf=False)
    def write_config(self, **kwargs):
        return request.env['ir.config_parameter'].sudo().set_param(kwargs.get('key'), kwargs.get('value'))
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-tainted-key-write" in rule_ids
    assert "odoo-config-param-tainted-value-write" in rule_ids
    assert "odoo-config-param-sudo-write" in rule_ids


def test_flags_request_alias_tainted_config_write(tmp_path: Path) -> None:
    """Aliased Odoo request imports should still seed config-parameter taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Config(http.Controller):
    @http.route('/public/config', auth='public', csrf=False)
    def write_config(self):
        payload = req.get_http_params()
        return req.env['ir.config_parameter'].sudo().set_param('web.base.url', payload.get('url'))
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-tainted-value-write" in rule_ids
    assert "odoo-config-param-tainted-base-url-write" in rule_ids
    assert "odoo-config-param-sudo-write" in rule_ids


def test_flags_route_path_config_key_and_value_write(tmp_path: Path) -> None:
    """Path-selected config keys and values are request-controlled."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request

class Config(http.Controller):
    @http.route('/public/config/<string:config_key>/<string:config_value>', auth='public', csrf=False)
    def write_config_path(self, config_key, config_value):
        return request.env['ir.config_parameter'].sudo().set_param(config_key, config_value)
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-tainted-key-write" in rule_ids
    assert "odoo-config-param-tainted-value-write" in rule_ids
    assert "odoo-config-param-sudo-write" in rule_ids


def test_flags_config_key_argument_write(tmp_path: Path) -> None:
    """Config-like function arguments should still seed tainted key writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo.http import request

def write_config(key):
    return request.env['ir.config_parameter'].sudo().set_param(key, 'enabled')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(f.rule_id == "odoo-config-param-tainted-key-write" for f in findings)


def test_reassigned_config_key_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a request config key alias for static data should clear taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo.http import request

def write_config(**kwargs):
    key = kwargs.get('key')
    key = 'web.base.url'
    return request.env['ir.config_parameter'].sudo().set_param(key, 'https://example.com')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert not any(f.rule_id == "odoo-config-param-tainted-key-write" for f in findings)


def test_reassigned_config_value_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a request config value alias for static data should clear taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo.http import request

def write_config(**kwargs):
    value = kwargs.get('value')
    value = 'https://example.com'
    return request.env['ir.config_parameter'].sudo().set_param('web.base.url', value)
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert not any(f.rule_id == "odoo-config-param-tainted-value-write" for f in findings)


def test_flags_sudo_config_parameter_alias(tmp_path: Path) -> None:
    """A sudo() config model alias should keep sudo read/write posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
def set_values(self):
    Config = self.env['ir.config_parameter'].sudo()
    Config.get_param('payment.provider.secret')
    Config.set_param('web.base.url', 'https://example.com')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-sudo-sensitive-read" in rule_ids
    assert "odoo-config-param-sudo-write" in rule_ids


def test_flags_with_user_superuser_config_parameter_read_write(tmp_path: Path) -> None:
    """with_user(SUPERUSER_ID) config access should be treated as elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import SUPERUSER_ID

def set_values(self):
    Config = self.env['ir.config_parameter'].with_user(SUPERUSER_ID)
    Config.get_param('payment.provider.secret')
    Config.set_param('web.base.url', 'https://example.com')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-sudo-sensitive-read" in rule_ids
    assert "odoo-config-param-sudo-write" in rule_ids


def test_flags_import_aliased_superuser_config_parameter_read_write(tmp_path: Path) -> None:
    """Imported SUPERUSER_ID aliases should keep config access elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import SUPERUSER_ID as ROOT_UID

def set_values(self):
    Config = self.env['ir.config_parameter'].with_user(ROOT_UID)
    Config.get_param('payment.provider.secret')
    Config.set_param('web.base.url', 'https://example.com')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-sudo-sensitive-read" in rule_ids
    assert "odoo-config-param-sudo-write" in rule_ids


def test_flags_constant_alias_config_model_superuser_key_and_default(tmp_path: Path) -> None:
    """Aliased config model names, superuser IDs, keys, and defaults should resolve."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import SUPERUSER_ID

CONFIG_MODEL = 'ir.config_parameter'
MODEL = CONFIG_MODEL
ROOT_USER = SUPERUSER_ID
SECRET_KEY = 'jwt.signing_key'
KEY = SECRET_KEY
DEV_DEFAULT = 'dev-secret-token'
FALLBACK = DEV_DEFAULT

def set_values(self):
    Config = self.env[MODEL].with_user(ROOT_USER)
    Config.get_param(KEY, FALLBACK)
    Config.set_param(KEY, FALLBACK)
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-sudo-sensitive-read" in rule_ids
    assert "odoo-config-param-sensitive-default" in rule_ids
    assert "odoo-config-param-sudo-write" in rule_ids
    assert "odoo-config-param-hardcoded-sensitive-write" in rule_ids
    assert any(f.key == "jwt.signing_key" for f in findings)


def test_flags_keyword_with_user_superuser_config_parameter_read_write(tmp_path: Path) -> None:
    """Keyword with_user(user=SUPERUSER_ID) should keep elevated posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import SUPERUSER_ID

def set_values(self):
    Config = self.env['ir.config_parameter'].with_user(user=SUPERUSER_ID)
    Config.get_param('payment.provider.secret')
    Config.set_param('web.base.url', 'https://example.com')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-sudo-sensitive-read" in rule_ids
    assert "odoo-config-param-sudo-write" in rule_ids


def test_flags_copied_with_user_one_config_parameter_alias(tmp_path: Path) -> None:
    """Copied with_user(1) config aliases should keep elevated posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
def set_values(self):
    Config = self.env['ir.config_parameter'].with_user(1)
    Alias = Config
    Alias.get_param('payment.provider.secret')
    Alias.set_param('web.base.url', 'https://example.com')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-sudo-sensitive-read" in rule_ids
    assert "odoo-config-param-sudo-write" in rule_ids


def test_flags_env_ref_admin_config_parameter_alias(tmp_path: Path) -> None:
    """with_user(env.ref('base.user_admin')) config aliases are elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
def set_values(self):
    Config = self.env['ir.config_parameter'].with_user(self.env.ref('base.user_admin'))
    Config.get_param('payment.provider.secret')
    Config.set_param('web.base.url', 'https://example.com')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-sudo-sensitive-read" in rule_ids
    assert "odoo-config-param-sudo-write" in rule_ids


def test_flags_copied_sudo_config_parameter_alias(tmp_path: Path) -> None:
    """Copied sudo config aliases should keep sudo read/write posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
def set_values(self):
    Config = self.env['ir.config_parameter'].sudo()
    Alias = Config
    Alias.get_param('payment.provider.secret')
    Alias.set_param('web.base.url', 'https://example.com')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-sudo-sensitive-read" in rule_ids
    assert "odoo-config-param-sudo-write" in rule_ids


def test_flags_unpacked_sudo_config_parameter_alias_and_request_value(tmp_path: Path) -> None:
    """Unpacked config aliases and request values should stay visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request

class Config(http.Controller):
    @http.route('/public/config/unpacked', auth='public', csrf=False)
    def write_config(self, **kwargs):
        Config, value = (request.env['ir.config_parameter'].sudo(), kwargs.get('value'))
        return Config.set_param('web.base.url', value)
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-sudo-write" in rule_ids
    assert "odoo-config-param-tainted-value-write" in rule_ids


def test_flags_starred_sudo_config_parameter_alias_and_request_value(tmp_path: Path) -> None:
    """Starred unpacking should keep config aliases and request values visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request

class Config(http.Controller):
    @http.route('/public/config/starred', auth='public', csrf=False)
    def write_config(self, **kwargs):
        _, *items = ('fixed', request.env['ir.config_parameter'].sudo(), kwargs.get('value'))
        Config = items[0]
        value = items[1]
        return Config.set_param('web.base.url', value)
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-sudo-write" in rule_ids
    assert "odoo-config-param-tainted-value-write" in rule_ids


def test_reassigned_config_parameter_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned config aliases should not keep config-parameter state."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
def set_values(self):
    Config = self.env['ir.config_parameter'].sudo()
    Config = self.env['res.partner']
    Config.set_param('payment.provider.secret', 'not-a-config-write')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert not any(f.rule_id == "odoo-config-param-sudo-write" for f in findings)


def test_flags_comprehension_derived_config_key_write(tmp_path: Path) -> None:
    """Comprehension-derived request keys should remain tainted for set_param."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo.http import request

def write_config(**kwargs):
    Config = request.env['ir.config_parameter'].sudo()
    keys = [value for value in kwargs.get('keys')]
    return Config.set_param(keys[0], 'enabled')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(f.rule_id == "odoo-config-param-tainted-key-write" for f in findings)


def test_flags_loop_derived_config_value_write(tmp_path: Path) -> None:
    """Loop variables from request-derived config values should stay tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo.http import request

def write_config(**kwargs):
    Config = request.env['ir.config_parameter'].sudo()
    for value in kwargs.get('values'):
        return Config.set_param('web.base.url', value)
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(f.rule_id == "odoo-config-param-tainted-value-write" for f in findings)


def test_safe_loop_reassignment_clears_config_value_taint(tmp_path: Path) -> None:
    """Safe loop targets should clear stale config value taint before writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo.http import request

def write_config(**kwargs):
    Config = request.env['ir.config_parameter'].sudo()
    value = kwargs.get('value')
    for value in ['https://example.com']:
        return Config.set_param('web.base.url', value)
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert not any(f.rule_id == "odoo-config-param-tainted-value-write" for f in findings)


def test_comprehension_filter_derived_config_key_write(tmp_path: Path) -> None:
    """Tainted comprehension filters should keep config key aliases tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo.http import request

def write_config(**kwargs):
    Config = request.env['ir.config_parameter'].sudo()
    keys = [key for key in ['web.base.url'] if kwargs.get('key')]
    return Config.set_param(keys[0], 'enabled')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(f.rule_id == "odoo-config-param-tainted-key-write" for f in findings)


def test_named_expression_derived_config_value_write(tmp_path: Path) -> None:
    """Walrus-assigned request config values should remain tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo.http import request

def write_config(**kwargs):
    Config = request.env['ir.config_parameter'].sudo()
    if value := kwargs.get('value'):
        return Config.set_param('web.base.url', value)
    return False
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(f.rule_id == "odoo-config-param-tainted-value-write" for f in findings)


def test_boolop_derived_config_value_write(tmp_path: Path) -> None:
    """Boolean fallback config values should not clear request taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo.http import request

def write_config(**kwargs):
    Config = request.env['ir.config_parameter'].sudo()
    value = kwargs.get('value') or 'https://example.com'
    return Config.set_param('web.base.url', value)
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(f.rule_id == "odoo-config-param-tainted-value-write" for f in findings)


def test_flags_wrapped_keyword_config_value_write(tmp_path: Path) -> None:
    """Request-derived keyword values inside wrappers should stay tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request

class Config(http.Controller):
    @http.route('/public/config/wrapped', auth='public', csrf=False)
    def write_config(self, **kwargs):
        value = dict(raw=kwargs.get('value'))
        return request.env['ir.config_parameter'].sudo().set_param('web.base.url', value)
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(f.rule_id == "odoo-config-param-tainted-value-write" for f in findings)


def test_flags_tainted_security_toggle_value_write(tmp_path: Path) -> None:
    """Request-controlled values for known security toggles should get a specific finding."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request

class Config(http.Controller):
    @http.route('/public/config/list-db', auth='public', csrf=False)
    def write_list_db(self, **kwargs):
        return request.env['ir.config_parameter'].sudo().set_param('list_db', kwargs.get('enabled'))
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(
        f.rule_id == "odoo-config-param-tainted-security-toggle-write" and f.severity == "critical" for f in findings
    )


def test_flags_tainted_base_url_write(tmp_path: Path) -> None:
    """Request-controlled web.base.url writes can poison generated external links."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request

class Config(http.Controller):
    @http.route('/public/config/base-url', auth='public', csrf=False)
    def write_base_url(self, **kwargs):
        return request.env['ir.config_parameter'].sudo().set_param('web.base.url', kwargs.get('url'))
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(f.rule_id == "odoo-config-param-tainted-base-url-write" and f.severity == "critical" for f in findings)


def test_flags_security_toggle_enabled(tmp_path: Path) -> None:
    """Literal writes that enable dangerous config toggles should be explicit review leads."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
def set_values(self):
    self.env['ir.config_parameter'].sudo().set_param('auth.signup.allow_uninvited', True)
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(f.rule_id == "odoo-config-param-security-toggle-enabled" for f in findings)


def test_flags_base_url_freeze_disabled(tmp_path: Path) -> None:
    """Literal writes that unfreeze web.base.url should be explicit review leads."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
def set_values(self):
    self.env['ir.config_parameter'].sudo().set_param('web.base.url.freeze', False)
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(f.rule_id == "odoo-config-param-security-toggle-enabled" for f in findings)


def test_flags_insecure_base_url_literal_write(tmp_path: Path) -> None:
    """Literal web.base.url writes should use the public HTTPS origin."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
def set_values(self):
    self.env['ir.config_parameter'].sudo().set_param('web.base.url', 'http://localhost:8069')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(f.rule_id == "odoo-config-param-insecure-base-url-write" for f in findings)


def test_flags_hardcoded_sensitive_config_write(tmp_path: Path) -> None:
    """Literal writes to sensitive config keys commit deployable secrets."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
def set_values(self):
    Config = self.env['ir.config_parameter'].sudo()
    Config.set_param('payment.provider.api_key', 'sk_live_hardcoded_123456')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(
        f.rule_id == "odoo-config-param-hardcoded-sensitive-write"
        and f.severity == "high"
        and f.key == "payment.provider.api_key"
        for f in findings
    )


def test_public_hardcoded_sensitive_config_write_is_critical(tmp_path: Path) -> None:
    """Public routes setting literal sensitive config values deserve critical posture."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "config.py").write_text(
        """
from odoo import http
from odoo.http import request

class Config(http.Controller):
    @http.route('/public/config/bootstrap', auth='public', csrf=False)
    def bootstrap(self):
        return request.env['ir.config_parameter'].sudo().set_param('jwt.signing_key', 'dev-secret-token')
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)

    assert any(
        f.rule_id == "odoo-config-param-hardcoded-sensitive-write"
        and f.severity == "critical"
        and f.key == "jwt.signing_key"
        for f in findings
    )


def test_class_constant_config_key_default_and_model_are_resolved(tmp_path: Path) -> None:
    """Class-scoped constants should label config reads and defaults."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import models

class Settings(models.TransientModel):
    _inherit = 'res.config.settings'
    CONFIG_MODEL = 'ir.config_parameter'
    SECRET_KEY = 'payment.provider.api_key'
    FALLBACK = 'sk_live_hardcoded_123456'

    def get_values(self):
        Config = self.env[CONFIG_MODEL].sudo()
        return Config.get_param(SECRET_KEY, FALLBACK)
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-sudo-sensitive-read" in rule_ids
    assert "odoo-config-param-sensitive-default" in rule_ids
    assert any(f.key == "payment.provider.api_key" for f in findings)


def test_class_constant_config_write_key_and_value_are_resolved(tmp_path: Path) -> None:
    """Class-scoped constants should label sensitive config writes."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class Settings(models.TransientModel):
    _inherit = 'res.config.settings'
    ROOT = SUPERUSER_ID
    CONFIG_MODEL = 'ir.config_parameter'
    SECRET_KEY = 'jwt.signing_key'
    SECRET_VALUE = 'dev-secret-token'

    def set_values(self):
        Config = self.env[CONFIG_MODEL].with_user(ROOT)
        Config.set_param(SECRET_KEY, SECRET_VALUE)
""",
        encoding="utf-8",
    )

    findings = scan_config_parameters(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-config-param-sudo-write" in rule_ids
    assert "odoo-config-param-hardcoded-sensitive-write" in rule_ids
    assert any(f.key == "jwt.signing_key" for f in findings)


def test_safe_internal_config_read_is_ignored(tmp_path: Path) -> None:
    """Non-sensitive internal config reads should not create noise."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
def value(self):
    return self.env['ir.config_parameter'].get_param('web.base.url')
""",
        encoding="utf-8",
    )

    assert scan_config_parameters(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Python fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_config.py").write_text(
        "def test_config(**kwargs):\n    env['ir.config_parameter'].set_param(kwargs.get('key'), kwargs.get('value'))\n",
        encoding="utf-8",
    )

    assert scan_config_parameters(tmp_path) == []
