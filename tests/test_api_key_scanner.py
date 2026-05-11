"""Tests for Odoo API-key scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.api_key_scanner import scan_api_keys


def test_public_route_api_key_create_and_return_is_reported(tmp_path: Path) -> None:
    """Public controllers must not mint or return API keys."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/apikey', auth='public', csrf=False)
    def create_key(self, **kwargs):
        api_key = request.env['res.users.apikeys'].sudo().create({
            'name': kwargs.get('name'),
            'user_id': kwargs.get('user_id'),
        })
        return {'api_key': api_key}
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-public-route-mutation" in rule_ids
    assert "odoo-api-key-sudo-mutation" in rule_ids
    assert "odoo-api-key-request-derived-mutation" in rule_ids
    assert "odoo-api-key-returned-from-route" in rule_ids


def test_imported_route_decorator_api_key_create_is_reported(tmp_path: Path) -> None:
    """Imported route decorators should still expose public API-key mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request, route

class Controller(http.Controller):
    @route('/public/apikey', auth='public', csrf=False)
    def create_key(self, **kwargs):
        return request.env['res.users.apikeys'].sudo().create({
            'name': kwargs.get('name'),
            'user_id': kwargs.get('user_id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-public-route-mutation" in rule_ids
    assert "odoo-api-key-sudo-mutation" in rule_ids
    assert "odoo-api-key-request-derived-mutation" in rule_ids


def test_aliased_imported_route_decorator_api_key_create_is_reported(tmp_path: Path) -> None:
    """Aliased imported route decorators should still expose public API-key mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request, route as odoo_route

class Controller(http.Controller):
    @odoo_route('/public/apikey', auth='public', csrf=False)
    def create_key(self, **kwargs):
        return request.env['res.users.apikeys'].sudo().create({
            'name': kwargs.get('name'),
            'user_id': kwargs.get('user_id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-public-route-mutation" in rule_ids
    assert "odoo-api-key-sudo-mutation" in rule_ids
    assert "odoo-api-key-request-derived-mutation" in rule_ids


def test_aliased_http_module_api_key_create_is_reported(tmp_path: Path) -> None:
    """Aliased Odoo http modules should still expose public API-key mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http as odoo_http
from odoo.http import request

class Controller(odoo_http.Controller):
    @odoo_http.route('/public/apikey', auth='public', csrf=False)
    def create_key(self, **kwargs):
        return request.env['res.users.apikeys'].sudo().create({
            'name': kwargs.get('name'),
            'user_id': kwargs.get('user_id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-public-route-mutation" in rule_ids
    assert "odoo-api-key-sudo-mutation" in rule_ids
    assert "odoo-api-key-request-derived-mutation" in rule_ids


def test_non_odoo_route_decorator_api_key_create_is_not_public_route(tmp_path: Path) -> None:
    """Arbitrary .route decorators should not make API-key mutations look public."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo.http import request

class Bus:
    def route(self, path, **kwargs):
        return lambda func: func

bus = Bus()

class Controller:
    @bus.route('/public/apikey', auth='public', csrf=False)
    def create_key(self, **kwargs):
        return request.env['res.users.apikeys'].sudo().create({
            'name': kwargs.get('name'),
            'user_id': kwargs.get('user_id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert not any(f.rule_id == "odoo-api-key-public-route-mutation" for f in findings)


def test_constant_backed_public_route_api_key_create_is_reported(tmp_path: Path) -> None:
    """Constant-backed public route metadata should not hide API-key mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

API_KEY_ROUTES = ['/public/apikey']
API_KEY_AUTH = 'public'
API_KEY_CSRF = False

class Controller(http.Controller):
    @http.route(API_KEY_ROUTES, auth=API_KEY_AUTH, csrf=API_KEY_CSRF)
    def create_key(self, **kwargs):
        return request.env['res.users.apikeys'].sudo().create({
            'name': kwargs.get('name'),
            'user_id': kwargs.get('user_id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-public-route-mutation" in rule_ids
    assert "odoo-api-key-sudo-mutation" in rule_ids
    assert "odoo-api-key-request-derived-mutation" in rule_ids
    assert any(
        f.rule_id == "odoo-api-key-request-derived-mutation"
        and f.severity == "critical"
        and f.route == "/public/apikey"
        for f in findings
    )


def test_keyword_constant_backed_none_route_api_key_secret_config_is_critical(tmp_path: Path) -> None:
    """Keyword route constants with auth='none' should keep API key config writes critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

API_KEY_ROUTE = '/public/provider/key'
API_KEY_AUTH = 'none'

class Controller(http.Controller):
    @http.route(route=API_KEY_ROUTE, auth=API_KEY_AUTH)
    def set_provider_key(self, **kwargs):
        return request.env['ir.config_parameter'].sudo().set_param(
            'payment.provider.api_key',
            kwargs.get('api_key'),
        )
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(
        f.rule_id == "odoo-api-key-config-parameter-request-secret"
        and f.severity == "critical"
        and f.route == "/public/provider/key"
        for f in findings
    )


def test_static_unpack_route_options_api_key_create_is_reported(tmp_path: Path) -> None:
    """Static ** route options should not hide public API-key mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

API_KEY_OPTIONS = {
    'routes': ['/public/apikey', '/public/apikey/v2'],
    'auth': 'public',
}

class Controller(http.Controller):
    @http.route(**API_KEY_OPTIONS)
    def create_key(self, **kwargs):
        return request.env['res.users.apikeys'].sudo().create({
            'name': kwargs.get('name'),
            'user_id': kwargs.get('user_id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-public-route-mutation" in rule_ids
    assert "odoo-api-key-sudo-mutation" in rule_ids
    assert "odoo-api-key-request-derived-mutation" in rule_ids
    assert any(f.route == "/public/apikey,/public/apikey/v2" for f in findings)


def test_nested_static_unpack_route_options_api_key_create_is_reported(tmp_path: Path) -> None:
    """Nested static ** route options should not hide public API-key mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

BASE_OPTIONS = {'auth': 'public'}
API_KEY_OPTIONS = {
    **BASE_OPTIONS,
    'routes': ['/public/apikey', '/public/apikey/v2'],
}

class Controller(http.Controller):
    @http.route(**API_KEY_OPTIONS)
    def create_key(self, **kwargs):
        return request.env['res.users.apikeys'].sudo().create({
            'name': kwargs.get('name'),
            'user_id': kwargs.get('user_id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-public-route-mutation" in rule_ids
    assert "odoo-api-key-sudo-mutation" in rule_ids
    assert "odoo-api-key-request-derived-mutation" in rule_ids
    assert any(f.route == "/public/apikey,/public/apikey/v2" for f in findings)


def test_recursive_static_unpack_route_options_api_key_secret_config_is_critical(tmp_path: Path) -> None:
    """Recursive constant aliases inside ** route options should preserve public severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

ROUTE_BASE = '/public/provider/key'
ROUTES = [ROUTE_BASE]
AUTH_BASE = 'none'
AUTH = AUTH_BASE
API_KEY_OPTIONS = {
    'routes': ROUTES,
    'auth': AUTH,
}
OPTIONS_ALIAS = API_KEY_OPTIONS

class Controller(http.Controller):
    @http.route(**OPTIONS_ALIAS)
    def set_provider_key(self, **kwargs):
        return request.env['ir.config_parameter'].sudo().set_param(
            'payment.provider.api_key',
            kwargs.get('api_key'),
        )
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(
        f.rule_id == "odoo-api-key-config-parameter-request-secret"
        and f.severity == "critical"
        and f.route == "/public/provider/key"
        for f in findings
    )


def test_flags_route_path_user_id_api_key_create(tmp_path: Path) -> None:
    """Path-selected users must stay tainted when API keys are created."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/users/<int:user_id>/apikey', auth='public', csrf=False)
    def create_key_for_user(self, user_id):
        return request.env['res.users.apikeys'].sudo().create({
            'name': 'path-selected',
            'user_id': user_id,
        })
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-public-route-mutation" in rule_ids
    assert "odoo-api-key-sudo-mutation" in rule_ids
    assert "odoo-api-key-request-derived-mutation" in rule_ids


def test_tainted_api_key_lookup_is_reported(tmp_path: Path) -> None:
    """Raw request-derived key searches should be review-visible."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "apikey.py").write_text(
        """
class ApiKeyVerifier:
    def verify(self, token):
        keys = self.env['res.users.apikeys'].sudo()
        return keys.search([('key', '=', token)], limit=1)
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(f.rule_id == "odoo-api-key-tainted-lookup" for f in findings)


def test_tainted_api_key_search_read_lookup_is_reported(tmp_path: Path) -> None:
    """search_read() can expose API-key record metadata from request-selected keys."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/apikey/lookup', auth='public')
    def lookup(self, **kwargs):
        return request.env['res.users.apikeys'].sudo().search_read(
            [('key', '=', kwargs.get('api_key'))],
            ['name', 'user_id'],
            limit=1,
        )
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(
        f.rule_id == "odoo-api-key-tainted-lookup" and f.sink.endswith(".search_read") for f in findings
    )


def test_tainted_api_key_browse_lookup_is_reported(tmp_path: Path) -> None:
    """Route IDs should not directly select API-key rows."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/my/apikey/<int:key_id>', auth='user')
    def show(self, key_id):
        return request.env['res.users.apikeys'].sudo().browse(key_id).read(['name'])
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(f.rule_id == "odoo-api-key-tainted-lookup" and f.sink.endswith(".browse") for f in findings)


def test_flags_sudo_api_key_model_alias_mutation(tmp_path: Path) -> None:
    """A sudo() API-key model alias should keep its sudo posture at mutation sites."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "apikey.py").write_text(
        """
class ApiKeyWizard:
    def create_key(self, values):
        keys = self.env['res.users.apikeys'].sudo()
        return keys.create(values)
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-sudo-mutation" in rule_ids


def test_flags_with_user_superuser_api_key_mutation(tmp_path: Path) -> None:
    """API-key mutations through with_user(SUPERUSER_ID) should be elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "apikey.py").write_text(
        """
from odoo import SUPERUSER_ID

class ApiKeyWizard:
    def create_key(self, values):
        return self.env['res.users.apikeys'].with_user(SUPERUSER_ID).create(values)
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-sudo-mutation" in rule_ids


def test_flags_constant_alias_api_key_model_superuser_route_and_config_key(tmp_path: Path) -> None:
    """Aliased API-key model names, route metadata, superuser IDs, and config keys should resolve."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

BASE_ROUTE = '/public/apikey/aliased'
API_ROUTE = BASE_ROUTE
PUBLIC_AUTH = 'public'
API_AUTH = PUBLIC_AUTH
API_MODEL_BASE = 'res.users.apikeys'
API_MODEL = API_MODEL_BASE
CONFIG_MODEL_BASE = 'ir.config_parameter'
CONFIG_MODEL = CONFIG_MODEL_BASE
ROOT = SUPERUSER_ID
SECRET_KEY_BASE = 'payment.provider.api_key'
SECRET_KEY = SECRET_KEY_BASE

class Controller(http.Controller):
    @http.route(API_ROUTE, auth=API_AUTH, csrf=False)
    def create_key(self, **kwargs):
        keys = request.env[API_MODEL].with_user(ROOT)
        config = request.env[CONFIG_MODEL].sudo()
        config.set_param(SECRET_KEY, kwargs.get('api_key'))
        return keys.create({'name': kwargs.get('name')})
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-public-route-mutation" in rule_ids
    assert "odoo-api-key-sudo-mutation" in rule_ids
    assert "odoo-api-key-request-derived-mutation" in rule_ids
    assert "odoo-api-key-config-parameter-request-secret" in rule_ids
    assert any(
        f.rule_id == "odoo-api-key-config-parameter-request-secret"
        and f.severity == "critical"
        and f.route == "/public/apikey/aliased"
        for f in findings
    )


def test_flags_class_constant_alias_api_key_model_superuser_route_and_config_key(tmp_path: Path) -> None:
    """Class-scoped API-key route, model, superuser, and config aliases should resolve."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    API_ROUTE = '/public/apikey/class-aliased'
    API_AUTH = 'public'
    API_MODEL = 'res.users.apikeys'
    CONFIG_MODEL = 'ir.config_parameter'
    ROOT = 1
    SECRET_KEY = 'payment.provider.api_key'

    @http.route(API_ROUTE, auth=API_AUTH, csrf=False)
    def create_key(self, **kwargs):
        keys = request.env[API_MODEL].with_user(ROOT)
        config = request.env[CONFIG_MODEL].sudo()
        config.set_param(SECRET_KEY, kwargs.get('api_key'))
        return keys.create({'name': kwargs.get('name')})
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-public-route-mutation" in rule_ids
    assert "odoo-api-key-sudo-mutation" in rule_ids
    assert "odoo-api-key-request-derived-mutation" in rule_ids
    assert "odoo-api-key-config-parameter-request-secret" in rule_ids
    assert any(
        f.rule_id == "odoo-api-key-config-parameter-request-secret"
        and f.severity == "critical"
        and f.route == "/public/apikey/class-aliased"
        for f in findings
    )


def test_flags_class_constant_static_unpack_route_options_api_key_create(tmp_path: Path) -> None:
    """Class-scoped static ** route options should not hide public API-key mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    API_KEY_OPTIONS = {
        'routes': ['/public/apikey/class-options', '/public/apikey/class-options/v2'],
        'auth': 'public',
    }
    MODEL = 'res.users.apikeys'

    @http.route(**API_KEY_OPTIONS)
    def create_key(self, **kwargs):
        return request.env[MODEL].sudo().create({
            'name': kwargs.get('name'),
            'user_id': kwargs.get('user_id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-public-route-mutation" in rule_ids
    assert "odoo-api-key-sudo-mutation" in rule_ids
    assert "odoo-api-key-request-derived-mutation" in rule_ids
    assert any(f.route == "/public/apikey/class-options,/public/apikey/class-options/v2" for f in findings)


def test_flags_local_constant_alias_api_key_model_superuser_and_config_key(tmp_path: Path) -> None:
    """Function-scoped API-key model, superuser, and config key aliases should resolve."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/apikey/local-aliased', auth='public', csrf=False)
    def create_key(self, **kwargs):
        api_model = 'res.users.apikeys'
        config_model = 'ir.config_parameter'
        root_uid = 1
        secret_key = 'payment.provider.api_key'
        keys = request.env[api_model].with_user(root_uid)
        config = request.env[config_model].sudo()
        config.set_param(secret_key, kwargs.get('api_key'))
        return keys.create({'name': kwargs.get('name')})
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-public-route-mutation" in rule_ids
    assert "odoo-api-key-sudo-mutation" in rule_ids
    assert "odoo-api-key-request-derived-mutation" in rule_ids
    assert "odoo-api-key-config-parameter-request-secret" in rule_ids
    assert any(
        f.rule_id == "odoo-api-key-config-parameter-request-secret"
        and f.severity == "critical"
        and f.route == "/public/apikey/local-aliased"
        for f in findings
    )


def test_flags_keyword_with_user_superuser_api_key_mutation(tmp_path: Path) -> None:
    """Keyword with_user(user=SUPERUSER_ID) API-key mutations are elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "apikey.py").write_text(
        """
from odoo import SUPERUSER_ID

class ApiKeyWizard:
    def create_key(self, values):
        return self.env['res.users.apikeys'].with_user(user=SUPERUSER_ID).create(values)
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-sudo-mutation" in rule_ids


def test_flags_aliased_with_user_one_api_key_mutation(tmp_path: Path) -> None:
    """A with_user(1) API-key model alias should keep its elevated posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "apikey.py").write_text(
        """
class ApiKeyWizard:
    def create_key(self, values):
        keys = self.env['res.users.apikeys'].with_user(1)
        return keys.create(values)
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-sudo-mutation" in rule_ids


def test_flags_env_ref_root_api_key_mutation(tmp_path: Path) -> None:
    """API-key mutations through with_user(base.user_root) should be elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "apikey.py").write_text(
        """
class ApiKeyWizard:
    def create_key(self, values):
        return self.env['res.users.apikeys'].with_user(self.env.ref('base.user_root')).create(values)
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-sudo-mutation" in rule_ids


def test_unpacked_api_key_model_and_request_values_are_reported(tmp_path: Path) -> None:
    """Tuple-unpacked API-key model aliases and request values should stay visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/apikey/unpacked', auth='public', csrf=False)
    def create_key(self, **kwargs):
        Keys, name = (request.env['res.users.apikeys'].sudo(), kwargs.get('name'))
        return Keys.create({'name': name})
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-public-route-mutation" in rule_ids
    assert "odoo-api-key-sudo-mutation" in rule_ids
    assert "odoo-api-key-request-derived-mutation" in rule_ids


def test_starred_unpacked_api_key_model_and_request_values_are_reported(tmp_path: Path) -> None:
    """Starred unpacking should keep API-key model aliases and request values visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/apikey/starred', auth='public', csrf=False)
    def create_key(self, **kwargs):
        _, *items = ('fixed', request.env['res.users.apikeys'].sudo(), kwargs.get('name'))
        Keys = items[0]
        name = items[1]
        return Keys.create({'name': name})
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-public-route-mutation" in rule_ids
    assert "odoo-api-key-sudo-mutation" in rule_ids
    assert "odoo-api-key-request-derived-mutation" in rule_ids


def test_flags_walrus_api_key_model_alias_mutation(tmp_path: Path) -> None:
    """Walrus-bound API-key model aliases should keep elevated mutation posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "apikey.py").write_text(
        """
class ApiKeyWizard:
    def create_key(self, values):
        if Keys := self.env['res.users.apikeys'].sudo():
            return Keys.create(values)
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-api-key-sudo-mutation" in rule_ids


def test_reassigned_api_key_model_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned API-key aliases should not keep credential-model state."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "apikey.py").write_text(
        """
class ApiKeyWizard:
    def create_partner(self, values):
        Keys = self.env['res.users.apikeys'].sudo()
        Keys = self.env['res.partner']
        return Keys.create(values)
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert not any(f.rule_id == "odoo-api-key-sudo-mutation" for f in findings)


def test_walrus_reassigned_api_key_model_alias_is_not_stale(tmp_path: Path) -> None:
    """Walrus-reassigned API-key aliases should clear credential-model state."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "apikey.py").write_text(
        """
class ApiKeyWizard:
    def create_partner(self, values):
        Keys = self.env['res.users.apikeys'].sudo()
        if Keys := self.env['res.partner']:
            return Keys.create(values)
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert not any(f.rule_id == "odoo-api-key-sudo-mutation" for f in findings)


def test_comprehension_derived_api_key_lookup_is_reported(tmp_path: Path) -> None:
    """Comprehension-derived request tokens should remain tainted for raw key lookup."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "apikey.py").write_text(
        """
class ApiKeyVerifier:
    def verify(self, **kwargs):
        keys = self.env['res.users.apikeys'].sudo()
        tokens = [value for value in kwargs.get('tokens')]
        return keys.search([('key', 'in', tokens)])
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(f.rule_id == "odoo-api-key-tainted-lookup" for f in findings)


def test_loop_derived_api_key_lookup_is_reported(tmp_path: Path) -> None:
    """Loop-derived request tokens should remain tainted for raw key lookup."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "apikey.py").write_text(
        """
class ApiKeyVerifier:
    def verify(self, **kwargs):
        keys = self.env['res.users.apikeys'].sudo()
        for token in kwargs.get('tokens'):
            selected = token
        return keys.search([('key', '=', selected)], limit=1)
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(f.rule_id == "odoo-api-key-tainted-lookup" for f in findings)


def test_safe_loop_reassignment_clears_api_key_lookup_taint(tmp_path: Path) -> None:
    """A safe loop target should clear a stale request-token alias before lookup."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "apikey.py").write_text(
        """
class ApiKeyVerifier:
    def verify(self, **kwargs):
        keys = self.env['res.users.apikeys'].sudo()
        token = kwargs.get('token')
        for token in ['internal-placeholder']:
            return keys.search([('name', '=', token)], limit=1)
        return keys
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert not any(f.rule_id == "odoo-api-key-tainted-lookup" for f in findings)


def test_comprehension_filter_derived_api_key_lookup_is_reported(tmp_path: Path) -> None:
    """Request-token filters in comprehensions should taint key lookups."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "apikey.py").write_text(
        """
class ApiKeyVerifier:
    def verify(self, **kwargs):
        keys = self.env['res.users.apikeys'].sudo()
        token = kwargs.get('token')
        domains = [('name', '=', 'fallback') for marker in ['x'] if token]
        return keys.search(domains, limit=1)
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(f.rule_id == "odoo-api-key-tainted-lookup" for f in findings)


def test_named_expression_derived_api_key_lookup_is_reported(tmp_path: Path) -> None:
    """Walrus-bound API key lookup values should remain tainted after the condition."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "apikey.py").write_text(
        """
class ApiKeyVerifier:
    def verify(self, **kwargs):
        keys = self.env['res.users.apikeys'].sudo()
        if token := kwargs.get('token'):
            return keys.search([('name', '=', token)], limit=1)
        return keys
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(f.rule_id == "odoo-api-key-tainted-lookup" for f in findings)


def test_boolop_derived_api_key_lookup_is_reported(tmp_path: Path) -> None:
    """Boolean fallback API-key lookup values should not clear request taint."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "apikey.py").write_text(
        """
class ApiKeyVerifier:
    def verify(self, **kwargs):
        keys = self.env['res.users.apikeys'].sudo()
        token = kwargs.get('token') or 'internal-placeholder'
        return keys.search([('key', '=', token)], limit=1)
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(f.rule_id == "odoo-api-key-tainted-lookup" for f in findings)


def test_reassigned_token_alias_is_not_stale_for_lookup(tmp_path: Path) -> None:
    """Reusing a request token alias for a safe lookup should clear taint."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "apikey.py").write_text(
        """
class ApiKeyVerifier:
    def verify(self, **kwargs):
        keys = self.env['res.users.apikeys'].sudo()
        token = kwargs.get('token')
        token = 'internal-placeholder'
        return keys.search([('name', '=', token)], limit=1)
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert not any(f.rule_id == "odoo-api-key-tainted-lookup" for f in findings)


def test_assigned_api_key_response_return_is_reported(tmp_path: Path) -> None:
    """Returning an assigned response object should not hide key material exposure."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/apikey/show', auth='user')
    def show_key(self, key):
        response = {'api_key': key}
        return response
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(f.rule_id == "odoo-api-key-returned-from-route" for f in findings)


def test_starred_api_key_response_return_is_reported(tmp_path: Path) -> None:
    """Starred-unpacked response aliases should not hide API-key material exposure."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/apikey/show', auth='user')
    def show_key(self, key):
        _, *responses = ('fixed', {'api_key': key})
        return responses[0]
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(f.rule_id == "odoo-api-key-returned-from-route" for f in findings)


def test_walrus_api_key_response_return_is_reported(tmp_path: Path) -> None:
    """Walrus-bound response aliases should not hide API-key material exposure."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/apikey/show', auth='user')
    def show_key(self, key):
        if response := {'api_key': key}:
            return response
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(f.rule_id == "odoo-api-key-returned-from-route" for f in findings)


def test_reassigned_api_key_response_is_not_stale(tmp_path: Path) -> None:
    """Reassigned response aliases should not keep stale API-key exposure state."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/apikey/show', auth='user')
    def show_key(self, key):
        response = {'api_key': key}
        response = {'ok': True}
        return response
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert not any(f.rule_id == "odoo-api-key-returned-from-route" for f in findings)


def test_api_key_xml_record_is_reported(tmp_path: Path) -> None:
    """Seeded API-key records are credential material."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "apikey.xml").write_text(
        """
<odoo>
  <record id="seeded_api_key" model="res.users.apikeys">
    <field name="name">integration</field>
    <field name="user_id" ref="base.user_admin"/>
  </record>
</odoo>
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(f.rule_id == "odoo-api-key-xml-record" and f.record_id == "seeded_api_key" for f in findings)


def test_api_key_csv_record_is_reported(tmp_path: Path) -> None:
    """API-key records can also be seeded through Odoo CSV data files."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "res.users.apikeys.csv").write_text(
        "id,name,user_id,key\nseeded_api_key,Seeded Key,base.user_admin,sk_live_1234567890abcdef\n",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(f.rule_id == "odoo-api-key-csv-record" and f.record_id == "seeded_api_key" for f in findings)


def test_api_key_underscore_csv_record_is_reported(tmp_path: Path) -> None:
    """Underscore-style CSV model filenames should also be recognized."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "res_users_apikeys.csv").write_text(
        "id,name,user_id\nseeded_api_key,Seeded Key,base.user_admin\n",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(f.rule_id == "odoo-api-key-csv-record" and f.record_id == "seeded_api_key" for f in findings)


def test_request_api_key_stored_in_config_parameter_is_reported(tmp_path: Path) -> None:
    """Request-updated integration credentials should not silently land in config parameters."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/provider/key', auth='public', csrf=False)
    def set_provider_key(self, **kwargs):
        request.env['ir.config_parameter'].sudo().set_param(
            'payment.provider.api_key',
            kwargs.get('api_key'),
        )
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(
        f.rule_id == "odoo-api-key-config-parameter-request-secret" and f.severity == "critical" for f in findings
    )


def test_aliased_request_api_key_stored_in_config_parameter_is_reported(tmp_path: Path) -> None:
    """Aliased Odoo request imports should still seed API-key secret taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/public/provider/key', auth='public', csrf=False)
    def set_provider_key(self):
        payload = req.get_http_params()
        req.env['ir.config_parameter'].sudo().set_param(
            'payment.provider.api_key',
            payload.get('api_key'),
        )
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(
        f.rule_id == "odoo-api-key-config-parameter-request-secret" and f.severity == "critical" for f in findings
    )


def test_request_access_key_stored_in_config_parameter_is_reported(tmp_path: Path) -> None:
    """Access-key shaped config parameters should be treated like API-key sinks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/provider/access-key', auth='public', csrf=False)
    def set_provider_key(self, **kwargs):
        request.env['ir.config_parameter'].sudo().set_param(
            'connector.access_key',
            kwargs.get('access_key'),
        )
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(
        f.rule_id == "odoo-api-key-config-parameter-request-secret" and f.severity == "critical" for f in findings
    )


def test_direct_route_license_key_arg_stored_in_config_parameter_is_reported(tmp_path: Path) -> None:
    """Route args named like integration keys should seed taint for config writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/provider/license-key', auth='public', csrf=False)
    def set_provider_key(self, license_key):
        request.env['ir.config_parameter'].sudo().set_param(
            'connector.license_key',
            license_key,
        )
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(
        f.rule_id == "odoo-api-key-config-parameter-request-secret" and f.severity == "critical" for f in findings
    )


def test_walrus_config_parameter_api_key_store_is_reported(tmp_path: Path) -> None:
    """Walrus-bound config-parameter aliases should still report request-stored API keys."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/provider/key', auth='public', csrf=False)
    def set_provider_key(self, **kwargs):
        if config := request.env['ir.config_parameter'].sudo():
            config.set_param('payment.provider.api_key', kwargs.get('api_key'))
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(
        f.rule_id == "odoo-api-key-config-parameter-request-secret" and f.severity == "critical" for f in findings
    )


def test_static_config_parameter_api_key_is_not_request_secret(tmp_path: Path) -> None:
    """Static seeded config values are handled by secret scanning, not this request-flow rule."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
class Settings:
    def set_provider_key(self):
        self.env['ir.config_parameter'].sudo().set_param(
            key='payment.provider.api_key',
            value='managed-by-deployment',
        )
""",
        encoding="utf-8",
    )

    assert not any(f.rule_id == "odoo-api-key-config-parameter-request-secret" for f in scan_api_keys(tmp_path))


def test_access_key_response_return_is_reported(tmp_path: Path) -> None:
    """Route responses containing access keys should be treated like API-key exposure."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "apikey.py").write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/apikey/show-access-key', auth='user')
    def show_key(self):
        key = self.env['ir.config_parameter'].sudo().get_param('connector.access_key')
        return {'access_key': key}
""",
        encoding="utf-8",
    )

    findings = scan_api_keys(tmp_path)

    assert any(f.rule_id == "odoo-api-key-returned-from-route" and f.severity == "high" for f in findings)


def test_xml_entities_are_not_expanded_into_api_key_findings(tmp_path: Path) -> None:
    """XML entities must not synthesize credential-record findings."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "apikey.xml").write_text(
        """<!DOCTYPE odoo [
<!ENTITY api_key_model "res.users.apikeys">
]>
<odoo>
  <record id="entity_api_key" model="&api_key_model;">
    <field name="name">integration</field>
  </record>
</odoo>
""",
        encoding="utf-8",
    )

    assert scan_api_keys(tmp_path) == []


def test_safe_internal_description_create_is_not_public_route(tmp_path: Path) -> None:
    """Internal owner-scoped description creation should not trigger public route findings."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "apikey.py").write_text(
        """
class ApiKeyWizard:
    def create_description(self):
        return self.env['res.users.apikeys.description'].create({
            'name': 'Personal token',
            'user_id': self.env.uid,
        })
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_api_keys(tmp_path)}

    assert "odoo-api-key-public-route-mutation" not in rule_ids
    assert "odoo-api-key-request-derived-mutation" not in rule_ids
