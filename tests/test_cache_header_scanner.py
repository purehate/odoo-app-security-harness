"""Tests for Odoo controller cache-control scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.cache_header_scanner import scan_cache_headers


def test_public_sensitive_render_is_reported(tmp_path: Path) -> None:
    """Public rendered token pages need explicit no-store/private caching review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public')
    def reset_password(self, **kwargs):
        return request.render('auth_signup.reset_password', {'signup_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-render" for f in findings)


def test_public_sensitive_make_response_without_no_store_is_reported(tmp_path: Path) -> None:
    """Public token responses should not rely on default cache behavior."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/token', auth='public')
    def token(self, **kwargs):
        return request.make_response({'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_public_broad_sensitive_make_response_without_no_store_is_reported(tmp_path: Path) -> None:
    """Public key-shaped responses should not rely on default cache behavior."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "key.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/key', auth='public')
    def key(self, **kwargs):
        return request.make_response({'license_key': kwargs.get('key')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_public_sensitive_make_json_response_without_no_store_is_reported(tmp_path: Path) -> None:
    """Public JSON token responses should not rely on default cache behavior."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/token', auth='public', type='json')
    def token(self, **kwargs):
        return request.make_json_response({'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_public_sensitive_response_from_unpacked_request_value_is_reported(tmp_path: Path) -> None:
    """Unpacked request data on sensitive public routes should require no-store review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/token', auth='public', type='json')
    def token(self, **kwargs):
        label, value = 'payload', kwargs.get('code')
        return request.make_json_response({'value': value})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_public_sensitive_response_from_starred_unpacked_request_value_is_reported(tmp_path: Path) -> None:
    """Starred request-value unpacking should remain cache-sensitive."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/token', auth='public', type='json')
    def token(self, **kwargs):
        _, *values = ('payload', kwargs.get('code'))
        value = values[0]
        return request.make_json_response({'value': value})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_public_sensitive_response_from_comprehension_alias_is_reported(tmp_path: Path) -> None:
    """Comprehension aliases over request data should stay cache-sensitive."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public')
    def reset_password(self):
        payload = request.get_http_params()
        values = [item for item in payload.get('codes', [])]
        return request.make_response({'value': values[0]})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_request_alias_sensitive_make_response_is_reported(tmp_path: Path) -> None:
    """Aliased request response helpers should not hide cache-sensitive payloads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public')
    def reset_password(self):
        payload = req.get_http_params()
        return req.make_response({'value': payload.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_public_sensitive_response_from_comprehension_filter_is_reported(tmp_path: Path) -> None:
    """Request data in comprehension filters should still make public token routes cache-sensitive."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public')
    def reset_password(self):
        values = ['ok' for item in ['fixed'] if request.params.get('token')]
        return request.make_response({'value': values[0]})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_public_sensitive_response_from_named_expression_is_reported(tmp_path: Path) -> None:
    """Walrus-assigned request values should stay cache-sensitive."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public')
    def reset_password(self, **kwargs):
        if token := kwargs.get('token'):
            return request.make_response({'value': token})
        return request.make_response({'value': 'none'})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_request_alias_sensitive_render_is_reported(tmp_path: Path) -> None:
    """Aliased request render calls still need cache-control review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public')
    def reset_password(self):
        return req.render('auth_signup.reset_password', {'signup_token': req.params.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-render" for f in findings)


def test_public_sensitive_response_from_boolop_is_reported(tmp_path: Path) -> None:
    """Boolean fallback expressions should stay cache-sensitive."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

class Token(http.Controller):
    @http.route('/reset/token', auth='public')
    def reset_password(self, **kwargs):
        token = kwargs.get('token') or 'none'
        return request.make_response({'value': token})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_public_sensitive_response_from_loop_alias_is_reported(tmp_path: Path) -> None:
    """Loop variables over request data should remain cache-sensitive."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public')
    def reset_password(self):
        for value in request.params.get('tokens'):
            return request.make_response({'value': value})
        return request.make_response({'value': 'none'})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_public_sensitive_response_from_route_path_arg_is_reported(tmp_path: Path) -> None:
    """Path parameters on sensitive public routes should require no-store review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password/<string:reset_code>', auth='public')
    def reset_password(self, reset_code):
        return request.make_response({'value': reset_code})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_public_sensitive_response_from_token_argument_is_reported(tmp_path: Path) -> None:
    """Token-like arguments should still seed cache-sensitive public responses."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public')
    def reset_password(self, token):
        return request.make_response({'value': token})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_reassigned_filename_alias_is_not_stale_for_sensitive_response(tmp_path: Path) -> None:
    """Reusing a request filename alias for safe static data should clear taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

    class Controller(http.Controller):
        @http.route('/web/reset_password', auth='public')
        def reset_password(self, **kwargs):
        filename = kwargs.get('filename')
        filename = 'ok'
        return request.make_response({'value': filename})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert not any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_imported_make_json_response_without_no_store_is_reported(tmp_path: Path) -> None:
    """Imported make_json_response should be treated like request.make_json_response."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import make_json_response

class Controller(http.Controller):
    @http.route('/public/token', auth='public', type='json')
    def token(self, **kwargs):
        return make_json_response({'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_imported_route_decorator_sensitive_response_is_reported(tmp_path: Path) -> None:
    """Directly imported route decorators should still provide public route context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request, route

class Controller(http.Controller):
    @route('/public/token', auth='public')
    def token(self, **kwargs):
        return request.make_response({'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_aliased_imported_route_decorator_sensitive_response_is_reported(tmp_path: Path) -> None:
    """Aliased imported route decorators should still provide public route context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request, route as odoo_route

class Controller(http.Controller):
    @odoo_route('/public/token', auth='public')
    def token(self, **kwargs):
        return request.make_response({'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_aliased_http_module_sensitive_response_is_reported(tmp_path: Path) -> None:
    """Aliased Odoo http module imports should still provide public route context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http as odoo_http
from odoo.http import request

class Controller(odoo_http.Controller):
    @odoo_http.route('/public/token', auth='public')
    def token(self, **kwargs):
        return request.make_response({'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_imported_odoo_http_module_sensitive_response_is_reported(tmp_path: Path) -> None:
    """import odoo.http as aliases should preserve route and request response sinks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
import odoo.http as odoo_http

class Controller(odoo_http.Controller):
    @odoo_http.route('/public/token', auth='public')
    def token(self, **kwargs):
        payload = odoo_http.request.get_http_params()
        return odoo_http.request.make_response({'access_token': payload.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_imported_odoo_module_sensitive_response_is_reported(tmp_path: Path) -> None:
    """import odoo as aliases should preserve od.http route and request sinks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
import odoo as od

class Controller(od.http.Controller):
    @od.http.route('/public/token', auth='public')
    def token(self, **kwargs):
        return od.http.request.make_response({'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_non_odoo_route_decorator_sensitive_response_is_ignored(tmp_path: Path) -> None:
    """Local route-like decorators should not create Odoo route context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo.http import request

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class Controller:
    @router.route('/public/token', auth='public')
    def token(self, **kwargs):
        return request.make_response({'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert not any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_constant_backed_public_sensitive_response_is_reported(tmp_path: Path) -> None:
    """Constant-backed route metadata should still expose public token responses."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

TOKEN_ROUTES = ['/public/token', '/public/token/alt']
TOKEN_AUTH = 'public'

class Controller(http.Controller):
    @http.route(TOKEN_ROUTES, auth=TOKEN_AUTH)
    def token(self, **kwargs):
        return request.make_response({'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(
        f.rule_id == "odoo-cache-public-sensitive-response"
        and f.severity == "high"
        and f.route == "/public/token,/public/token/alt"
        for f in findings
    )


def test_recursive_constant_backed_public_sensitive_response_is_reported(tmp_path: Path) -> None:
    """Recursive route constants should still expose public token responses."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

TOKEN_BASE = '/public/token'
TOKEN_ROUTE = TOKEN_BASE
TOKEN_ROUTES = [TOKEN_ROUTE]
AUTH_BASE = 'public'
TOKEN_AUTH = AUTH_BASE

class Controller(http.Controller):
    @http.route(TOKEN_ROUTES, auth=TOKEN_AUTH)
    def token(self, **kwargs):
        return request.make_response({'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(
        f.rule_id == "odoo-cache-public-sensitive-response"
        and f.severity == "high"
        and f.route == "/public/token"
        for f in findings
    )


def test_class_constant_backed_public_sensitive_response_is_reported(tmp_path: Path) -> None:
    """Class-scoped route constants should still expose public token responses."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    TOKEN_BASE = '/public/token'
    TOKEN_ROUTE = TOKEN_BASE
    TOKEN_ROUTES = [TOKEN_ROUTE]
    AUTH_BASE = 'public'
    TOKEN_AUTH = AUTH_BASE

    @http.route(TOKEN_ROUTES, auth=TOKEN_AUTH)
    def token(self, **kwargs):
        return request.make_response({'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(
        f.rule_id == "odoo-cache-public-sensitive-response"
        and f.severity == "high"
        and f.route == "/public/token"
        for f in findings
    )


def test_static_unpack_route_options_sensitive_response_is_reported(tmp_path: Path) -> None:
    """Static ** route options should not hide public cache-sensitive responses."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

TOKEN_OPTIONS = {
    'routes': ['/public/token', '/public/token/alt'],
    'auth': 'public',
}

class Controller(http.Controller):
    @http.route(**TOKEN_OPTIONS)
    def token(self, **kwargs):
        return request.make_response({'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(
        f.rule_id == "odoo-cache-public-sensitive-response"
        and f.severity == "high"
        and f.route == "/public/token,/public/token/alt"
        for f in findings
    )


def test_nested_static_unpack_route_options_sensitive_response_is_reported(tmp_path: Path) -> None:
    """Nested static ** route options should not hide public cache-sensitive responses."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

BASE_OPTIONS = {'auth': 'public'}
TOKEN_OPTIONS = {
    **BASE_OPTIONS,
    'routes': ['/public/token', '/public/token/alt'],
}

class Controller(http.Controller):
    @http.route(**TOKEN_OPTIONS)
    def token(self, **kwargs):
        return request.make_response({'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(
        f.rule_id == "odoo-cache-public-sensitive-response"
        and f.severity == "high"
        and f.route == "/public/token,/public/token/alt"
        for f in findings
    )


def test_dict_union_static_unpack_route_options_sensitive_response_is_reported(tmp_path: Path) -> None:
    """Dict-union ** route options should not hide public cache-sensitive responses."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

BASE_OPTIONS = {'auth': 'public'}
TOKEN_OPTIONS = BASE_OPTIONS | {
    'routes': ['/public/token', '/public/token/alt'],
}

class Controller(http.Controller):
    @http.route(**TOKEN_OPTIONS)
    def token(self, **kwargs):
        return request.make_response({'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(
        f.rule_id == "odoo-cache-public-sensitive-response"
        and f.severity == "high"
        and f.route == "/public/token,/public/token/alt"
        for f in findings
    )


def test_updated_static_unpack_route_options_sensitive_response_is_reported(tmp_path: Path) -> None:
    """Updated ** route options should not hide public cache-sensitive responses."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

TOKEN_OPTIONS = {
    'routes': ['/public/token'],
    'auth': 'user',
}
TOKEN_OPTIONS.update({
    'auth': 'none',
    'type': 'json',
})

class Controller(http.Controller):
    @http.route(**TOKEN_OPTIONS)
    def token(self, **kwargs):
        return request.make_response({'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(
        f.rule_id == "odoo-cache-public-sensitive-response"
        and f.severity == "high"
        and f.route == "/public/token"
        for f in findings
    )


def test_class_constant_static_unpack_route_options_sensitive_response_is_reported(tmp_path: Path) -> None:
    """Class-scoped static ** route options should not hide public cache-sensitive responses."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    TOKEN_OPTIONS = {
        'routes': ['/public/token', '/public/token/alt'],
        'auth': 'public',
    }

    @http.route(**TOKEN_OPTIONS)
    def token(self, **kwargs):
        return request.make_response({'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(
        f.rule_id == "odoo-cache-public-sensitive-response"
        and f.severity == "high"
        and f.route == "/public/token,/public/token/alt"
        for f in findings
    )


def test_recursive_static_unpack_route_options_file_download_is_reported(tmp_path: Path) -> None:
    """Recursive constants inside ** route options should feed sensitive-route cache evidence."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.addons.web.controllers.main import send_file

ROUTE_BASE = '/public/download'
DOWNLOAD_ROUTES = [ROUTE_BASE]
AUTH_BASE = 'public'
DOWNLOAD_AUTH = AUTH_BASE
DOWNLOAD_OPTIONS = {
    'routes': DOWNLOAD_ROUTES,
    'auth': DOWNLOAD_AUTH,
}
OPTIONS_ALIAS = DOWNLOAD_OPTIONS

class Controller(http.Controller):
    @http.route(**OPTIONS_ALIAS)
    def download(self, **kwargs):
        return send_file('/tmp/invoice.pdf')
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(
        f.rule_id == "odoo-cache-public-file-download" and f.route == "/public/download" for f in findings
    )


def test_keyword_constant_backed_public_sensitive_file_download_is_reported(tmp_path: Path) -> None:
    """Keyword route constants should feed sensitive-route cache evidence."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.addons.web.controllers.main import send_file

DOWNLOAD_ROUTE = '/public/download'
DOWNLOAD_AUTH = 'public'

class Controller(http.Controller):
    @http.route(route=DOWNLOAD_ROUTE, auth=DOWNLOAD_AUTH)
    def download(self, **kwargs):
        return send_file('/tmp/invoice.pdf')
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(
        f.rule_id == "odoo-cache-public-file-download" and f.route == "/public/download" for f in findings
    )


def test_assigned_public_sensitive_response_is_reported_on_neutral_route(tmp_path: Path) -> None:
    """Assigned response aliases should keep sensitive body state even on neutral public paths."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "callback.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/oauth/callback', auth='public')
    def callback(self, **kwargs):
        response = request.make_response({'access_token': kwargs.get('token')})
        return response
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-response" for f in findings)


def test_reassigned_sensitive_response_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigning a sensitive response alias should clear assigned-body sensitivity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "callback.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/oauth/callback', auth='public')
    def callback(self, **kwargs):
        response = request.make_response({'access_token': kwargs.get('token')})
        response = request.make_response('ok')
        return response
""",
        encoding="utf-8",
    )

    assert scan_cache_headers(tmp_path) == []


def test_public_sensitive_cacheable_header_is_reported(tmp_path: Path) -> None:
    """Sensitive public routes should not set public/max-age cache headers."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invoice.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/my/invoice/<int:invoice_id>', auth='public')
    def invoice(self, invoice_id, access_token=None):
        response = request.make_response('invoice')
        response.headers['Cache-Control'] = 'public, max-age=3600'
        return response
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-cacheable-sensitive-route" for f in findings)


def test_constant_backed_public_sensitive_cacheable_header_is_reported(tmp_path: Path) -> None:
    """Constant-backed Cache-Control values should still expose cacheable sensitive routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invoice.py").write_text(
        """
from odoo import http
from odoo.http import request

CACHE_HEADER = 'Cache-Control'
CACHE_POLICY = 'public, max-age=3600'

class Controller(http.Controller):
    @http.route('/my/invoice/<int:invoice_id>', auth='public')
    def invoice(self, invoice_id, access_token=None):
        response = request.make_response('invoice')
        response.headers[CACHE_HEADER] = CACHE_POLICY
        return response
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-cacheable-sensitive-route" for f in findings)


def test_local_alias_public_sensitive_cacheable_header_is_reported(tmp_path: Path) -> None:
    """Route-local Cache-Control aliases should still expose cacheable sensitive routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invoice.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/my/invoice/<int:invoice_id>', auth='public')
    def invoice(self, invoice_id, access_token=None):
        response = request.make_response('invoice')
        policy = 'public, max-age=3600'
        response.headers['Cache-Control'] = policy
        return response
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-cacheable-sensitive-route" for f in findings)


def test_walrus_public_sensitive_cacheable_header_is_reported(tmp_path: Path) -> None:
    """Walrus-bound Cache-Control aliases should still expose cacheable sensitive routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invoice.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/my/invoice/<int:invoice_id>', auth='public')
    def invoice(self, invoice_id, access_token=None):
        response = request.make_response('invoice')
        if policy := 'public, max-age=3600':
            response.headers['Cache-Control'] = policy
        return response
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-cacheable-sensitive-route" for f in findings)


def test_annotated_public_sensitive_cacheable_header_is_reported(tmp_path: Path) -> None:
    """Annotated Cache-Control assignments should still expose cacheable sensitive routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invoice.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/my/invoice/<int:invoice_id>', auth='public')
    def invoice(self, invoice_id, access_token=None):
        response = request.make_response('invoice')
        response.headers['Cache-Control']: str = 'public, max-age=3600'
        return response
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-cacheable-sensitive-route" for f in findings)


def test_header_set_public_sensitive_cacheable_header_is_reported(tmp_path: Path) -> None:
    """Werkzeug-style header setters should still expose cacheable sensitive routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invoice.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/my/invoice/<int:invoice_id>', auth='public')
    def invoice(self, invoice_id, access_token=None):
        response = request.make_response('invoice')
        response.headers.set('Cache-Control', 'public, max-age=3600')
        return response
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-cacheable-sensitive-route" for f in findings)


def test_aliased_header_update_public_sensitive_cacheable_header_is_reported(tmp_path: Path) -> None:
    """Aliased header update maps should still expose cacheable sensitive routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invoice.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/my/invoice/<int:invoice_id>', auth='public')
    def invoice(self, invoice_id, access_token=None):
        response = request.make_response('invoice')
        headers = {'Cache-Control': 'public, max-age=3600'}
        response.headers.update(headers)
        return response
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-cacheable-sensitive-route" for f in findings)


def test_public_sensitive_send_file_without_cache_disable_is_reported(tmp_path: Path) -> None:
    """Public downloads should disable file response caching unless deliberately public."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.addons.web.controllers.main import send_file

class Controller(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        return send_file('/tmp/invoice.pdf')
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-file-download" for f in findings)


def test_constant_backed_send_file_cache_disable_is_ignored(tmp_path: Path) -> None:
    """Constant-backed cache_timeout=0 should suppress public file cache findings."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.addons.web.controllers.main import send_file

NO_CACHE_TIMEOUT = 0

class Controller(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        return send_file('/tmp/invoice.pdf', cache_timeout=NO_CACHE_TIMEOUT)
""",
        encoding="utf-8",
    )

    assert scan_cache_headers(tmp_path) == []


def test_public_sensitive_cookie_response_without_no_store_is_reported(tmp_path: Path) -> None:
    """Public auth flows that set token cookies should also be no-store/private."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "callback.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/oauth/callback', auth='public')
    def callback(self, **kwargs):
        response = request.make_response('ok')
        response.set_cookie('session_token', kwargs.get('token'), secure=True, httponly=True, samesite='Lax')
        return response
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-cookie-response" for f in findings)


def test_constant_backed_sensitive_cookie_response_without_no_store_is_reported(tmp_path: Path) -> None:
    """Constant-backed sensitive cookie names should still require no-store review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "callback.py").write_text(
        """
from odoo import http
from odoo.http import request

COOKIE_NAME = 'session_token'

class Controller(http.Controller):
    @http.route('/oauth/callback', auth='public')
    def callback(self, **kwargs):
        response = request.make_response('ok')
        response.set_cookie(COOKIE_NAME, kwargs.get('token'), secure=True, httponly=True)
        return response
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-cookie-response" for f in findings)


def test_public_sensitive_cookie_response_with_no_store_is_ignored(tmp_path: Path) -> None:
    """Explicit no-store/private headers should suppress cookie response cache findings."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "callback.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/oauth/callback', auth='public')
    def callback(self, **kwargs):
        response = request.make_response('ok')
        response.set_cookie(key='session_token', value=kwargs.get('token'), secure=True, httponly=True, samesite='Lax')
        response.headers['Cache-Control'] = 'no-store, private'
        return response
""",
        encoding="utf-8",
    )

    assert scan_cache_headers(tmp_path) == []


def test_annotated_no_store_sensitive_cookie_response_is_ignored(tmp_path: Path) -> None:
    """Annotated no-store headers should suppress cookie response cache findings."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "callback.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/oauth/callback', auth='public')
    def callback(self, **kwargs):
        response = request.make_response('ok')
        response.set_cookie(key='session_token', value=kwargs.get('token'), secure=True, httponly=True, samesite='Lax')
        response.headers['Cache-Control']: str = 'no-store, private'
        return response
""",
        encoding="utf-8",
    )

    assert scan_cache_headers(tmp_path) == []


def test_walrus_no_store_sensitive_cookie_response_is_ignored(tmp_path: Path) -> None:
    """Walrus-bound no-store headers should suppress cookie response cache findings."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "callback.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/oauth/callback', auth='public')
    def callback(self, **kwargs):
        response = request.make_response('ok')
        response.set_cookie(key='session_token', value=kwargs.get('token'), secure=True, httponly=True, samesite='Lax')
        if policy := 'no-store, private':
            response.headers['Cache-Control'] = policy
        return response
""",
        encoding="utf-8",
    )

    assert scan_cache_headers(tmp_path) == []


def test_no_store_sensitive_response_is_ignored(tmp_path: Path) -> None:
    """Explicit no-store/private headers should suppress missing-cache findings."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/token', auth='public')
    def token(self, **kwargs):
        return request.make_response(
            {'access_token': kwargs.get('token')},
            headers=[('Cache-Control', 'no-store, private')],
        )
""",
        encoding="utf-8",
    )

    assert scan_cache_headers(tmp_path) == []


def test_constant_backed_no_store_sensitive_response_is_ignored(tmp_path: Path) -> None:
    """Constant-backed no-store headers should suppress missing-cache findings."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

NO_STORE_HEADERS = [('Cache-Control', 'no-store, private')]

class Controller(http.Controller):
    @http.route('/public/token', auth='public')
    def token(self, **kwargs):
        return request.make_response(
            {'access_token': kwargs.get('token')},
            headers=NO_STORE_HEADERS,
        )
""",
        encoding="utf-8",
    )

    assert scan_cache_headers(tmp_path) == []


def test_no_store_header_update_sensitive_response_is_ignored(tmp_path: Path) -> None:
    """Header update helpers should mark returned response objects as no-store protected."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/token', auth='public')
    def token(self, **kwargs):
        response = request.make_response({'access_token': kwargs.get('token')})
        response.headers.update({'Cache-Control': 'no-store, private'})
        return response
""",
        encoding="utf-8",
    )

    assert scan_cache_headers(tmp_path) == []


def test_aliased_no_store_header_update_sensitive_response_is_ignored(tmp_path: Path) -> None:
    """Aliased header update maps should mark returned response objects as no-store protected."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/token', auth='public')
    def token(self, **kwargs):
        response = request.make_response({'access_token': kwargs.get('token')})
        headers = {'Cache-Control': 'no-store, private'}
        response.headers.update(headers)
        return response
""",
        encoding="utf-8",
    )

    assert scan_cache_headers(tmp_path) == []


def test_no_store_header_setdefault_sensitive_response_is_ignored(tmp_path: Path) -> None:
    """Header setdefault helpers should mark returned response objects as no-store protected."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/token', auth='public')
    def token(self, **kwargs):
        response = request.make_response({'access_token': kwargs.get('token')})
        response.headers.setdefault('Cache-Control', 'no-store, private')
        return response
""",
        encoding="utf-8",
    )

    assert scan_cache_headers(tmp_path) == []


def test_reassigned_response_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned response aliases should not keep missing-cache state."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/token', auth='public')
    def token(self):
        response = request.make_response('token')
        response = object()
        return response
""",
        encoding="utf-8",
    )

    assert scan_cache_headers(tmp_path) == []


def test_unpacked_no_store_response_is_ignored(tmp_path: Path) -> None:
    """Tuple-unpacked response aliases should preserve no-store tracking."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/token', auth='public')
    def token(self, **kwargs):
        response, label = (
            request.make_response(
                {'access_token': kwargs.get('token')},
                headers=[('Cache-Control', 'no-store')],
            ),
            'token',
        )
        return response
""",
        encoding="utf-8",
    )

    assert scan_cache_headers(tmp_path) == []


def test_starred_unpacked_no_store_response_is_ignored(tmp_path: Path) -> None:
    """Starred response aliases should preserve no-store tracking."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/token', auth='public')
    def token(self, **kwargs):
        _, *items = (
            'token',
            request.make_response(
                {'access_token': kwargs.get('token')},
                headers=[('Cache-Control', 'no-store')],
            ),
        )
        response = items[0]
        return response
""",
        encoding="utf-8",
    )

    assert scan_cache_headers(tmp_path) == []


def test_starred_unpacked_sensitive_cookie_response_is_reported(tmp_path: Path) -> None:
    """Starred response aliases should preserve sensitive-cookie response tracking."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/token', auth='public')
    def token(self, **kwargs):
        _, *items = ('token', request.make_response('ok'))
        response = items[0]
        response.set_cookie('session_token', kwargs.get('token'), secure=True, httponly=True)
        return response
""",
        encoding="utf-8",
    )

    findings = scan_cache_headers(tmp_path)

    assert any(f.rule_id == "odoo-cache-public-sensitive-cookie-response" for f in findings)


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Python fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_cache.py").write_text(
        """
def test_token(request, kwargs):
    return request.make_response({'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    assert scan_cache_headers(tmp_path) == []
