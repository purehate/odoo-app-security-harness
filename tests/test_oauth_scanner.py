"""Tests for Odoo OAuth/OIDC flow scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.oauth_scanner import scan_oauth_flows


def test_public_oauth_callback_risks_are_reported(tmp_path: Path) -> None:
    """Public OAuth callbacks need explicit provider, token, and identity validation."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request
import jwt
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        token = kwargs.get('id_token')
        claims = jwt.decode(token, options={'verify_signature': False})
        requests.get(kwargs.get('userinfo_url'), verify=False)
        request.env['res.users'].sudo().write({'oauth_uid': kwargs.get('sub')})
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('access_token'))
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-public-callback-route" in rule_ids
    assert "odoo-oauth-jwt-verification-disabled" in rule_ids
    assert "odoo-oauth-http-no-timeout" in rule_ids
    assert "odoo-oauth-http-verify-disabled" in rule_ids
    assert "odoo-oauth-tainted-validation-url" in rule_ids
    assert "odoo-oauth-tainted-identity-write" in rule_ids
    assert "odoo-oauth-session-authenticate" in rule_ids


def test_constant_backed_oauth_verification_disablement_is_reported(tmp_path: Path) -> None:
    """Constants should not hide disabled OAuth TLS or JWT verification."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import jwt
import requests

TLS_VERIFY = False
VERIFY_SIGNATURE = False
JWT_OPTIONS = {'verify_signature': VERIFY_SIGNATURE}

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        token = kwargs.get('id_token')
        claims = jwt.decode(token, options=JWT_OPTIONS)
        response = requests.get(kwargs.get('userinfo_url'), timeout=10, verify=TLS_VERIFY)
        return claims, response
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-jwt-verification-disabled" in rule_ids
    assert "odoo-oauth-http-verify-disabled" in rule_ids


def test_oauth_http_timeout_none_is_reported(tmp_path: Path) -> None:
    """timeout=None should not satisfy OAuth provider HTTP timeout requirements."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        return requests.get(kwargs.get('userinfo_url'), timeout=None)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-http-no-timeout" for f in findings)


def test_oauth_http_timeout_none_constant_is_reported(tmp_path: Path) -> None:
    """OAuth timeout constants should not hide unbounded provider HTTP calls."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests

OAUTH_TIMEOUT = None

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        return requests.get(kwargs.get('userinfo_url'), timeout=OAUTH_TIMEOUT)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-http-no-timeout" for f in findings)


def test_oauth_http_static_kwargs_timeout_is_not_reported(tmp_path: Path) -> None:
    """Static **kwargs dictionaries should satisfy OAuth provider HTTP timeout checks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests

HTTP_OPTIONS = {'timeout': 10}

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        return requests.get(kwargs.get('userinfo_url'), **HTTP_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert not any(f.rule_id == "odoo-oauth-http-no-timeout" for f in findings)


def test_oauth_http_nested_static_kwargs_timeout_is_not_reported(tmp_path: Path) -> None:
    """Nested static **kwargs dictionaries should satisfy OAuth provider HTTP timeout checks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests

BASE_OPTIONS = {'timeout': 10}
HTTP_OPTIONS = {**BASE_OPTIONS}

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        return requests.get(kwargs.get('userinfo_url'), **HTTP_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert not any(f.rule_id == "odoo-oauth-http-no-timeout" for f in findings)


def test_oauth_http_verify_false_static_kwargs_is_reported(tmp_path: Path) -> None:
    """Static **kwargs dictionaries should not hide disabled OAuth HTTP TLS verification."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests

HTTP_OPTIONS = {'timeout': 10, 'verify': False}

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        return requests.get(kwargs.get('userinfo_url'), **HTTP_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-http-verify-disabled" for f in findings)


def test_oauth_cleartext_http_url_is_reported(tmp_path: Path) -> None:
    """OAuth token and userinfo validation must not target literal cleartext URLs."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests

USERINFO_URL = 'http://provider.example.test/oauth/userinfo'
TOKEN_OPTIONS = {'url': 'http://provider.example.test/oauth/token', 'timeout': 10}

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        profile = requests.get(USERINFO_URL, timeout=10)
        token = requests.request('POST', **TOKEN_OPTIONS)
        return profile, token
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert sum(f.rule_id == "odoo-oauth-cleartext-http-url" for f in findings) == 2


def test_urllib_oauth_validation_url_is_reported(tmp_path: Path) -> None:
    """urllib URL fetches in OAuth callbacks should receive timeout and SSRF review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from urllib.request import urlopen

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        return urlopen(kwargs.get('userinfo_url'))
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-http-no-timeout" in rule_ids
    assert "odoo-oauth-tainted-validation-url" in rule_ids


def test_aliased_requests_oauth_validation_url_is_reported(tmp_path: Path) -> None:
    """Aliased requests imports in OAuth callbacks should still be HTTP sinks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests as rq

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        return rq.get(kwargs.get('userinfo_url'))
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-http-no-timeout" in rule_ids
    assert "odoo-oauth-tainted-validation-url" in rule_ids


def test_from_requests_alias_oauth_validation_url_is_reported(tmp_path: Path) -> None:
    """Aliased requests function imports should still be OAuth validation HTTP sinks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from requests import get as http_get

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        return http_get(kwargs.get('userinfo_url'))
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-http-no-timeout" in rule_ids
    assert "odoo-oauth-tainted-validation-url" in rule_ids


def test_aiohttp_oauth_validation_url_is_reported(tmp_path: Path) -> None:
    """aiohttp validation calls in OAuth callbacks should receive timeout and SSRF review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import aiohttp

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    async def callback(self, **kwargs):
        return await aiohttp.request('GET', kwargs.get('userinfo_url'))
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-http-no-timeout" in rule_ids
    assert "odoo-oauth-tainted-validation-url" in rule_ids


def test_head_oauth_validation_url_is_reported(tmp_path: Path) -> None:
    """HEAD validation calls in OAuth callbacks should receive timeout and SSRF review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import httpx

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        return httpx.head(kwargs.get('userinfo_url'))
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-http-no-timeout" in rule_ids
    assert "odoo-oauth-tainted-validation-url" in rule_ids


def test_local_constant_oauth_verification_disablement_is_reported(tmp_path: Path) -> None:
    """Function-local constants should not hide disabled OAuth TLS or JWT verification."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import jwt
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        token = kwargs.get('id_token')
        tls_verify = False
        jwt_options = {'verify_signature': False}
        claims = jwt.decode(token, options=jwt_options)
        response = requests.get(kwargs.get('userinfo_url'), timeout=10, verify=tls_verify)
        return claims, response
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-jwt-verification-disabled" in rule_ids
    assert "odoo-oauth-http-verify-disabled" in rule_ids


def test_request_alias_oauth_session_authenticate_is_reported(tmp_path: Path) -> None:
    """Aliased Odoo request imports should not hide OAuth session creation."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        return req.session.authenticate(req.db, kwargs.get('login'), kwargs.get('access_token'))
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-session-authenticate" for f in findings)


def test_refresh_token_oauth_session_authenticate_is_reported(tmp_path: Path) -> None:
    """Refresh-token backed OAuth session creation should remain review-visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('refresh_token'))
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-session-authenticate" for f in findings)


def test_imported_route_decorator_oauth_callback_risks_are_reported(tmp_path: Path) -> None:
    """Imported route decorators should still expose OAuth callback risks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import route
import jwt

class Controller(http.Controller):
    @route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        token = kwargs.get('id_token')
        claims = jwt.decode(token, audience='client')
        return jwt.decode(token, options={'verify_signature': False})
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-public-callback-route" in rule_ids
    assert "odoo-oauth-jwt-verification-disabled" in rule_ids
    assert "odoo-oauth-request-token-decode" in rule_ids


def test_aliased_imported_route_decorator_oauth_callback_risks_are_reported(tmp_path: Path) -> None:
    """Aliased imported route decorators should still expose OAuth callback risks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import route as odoo_route
import jwt

class Controller(http.Controller):
    @odoo_route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        token = kwargs.get('id_token')
        claims = jwt.decode(token, audience='client')
        return jwt.decode(token, options={'verify_signature': False})
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-public-callback-route" in rule_ids
    assert "odoo-oauth-jwt-verification-disabled" in rule_ids
    assert "odoo-oauth-request-token-decode" in rule_ids


def test_aliased_http_module_oauth_callback_risks_are_reported(tmp_path: Path) -> None:
    """Aliased Odoo http module imports should still expose OAuth callback risks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http as odoo_http
import jwt

class Controller(odoo_http.Controller):
    @odoo_http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        token = kwargs.get('id_token')
        return jwt.decode(token, options={'verify_signature': False})
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-public-callback-route" in rule_ids
    assert "odoo-oauth-jwt-verification-disabled" in rule_ids


def test_imported_odoo_http_module_oauth_callback_risks_are_reported(tmp_path: Path) -> None:
    """Direct odoo.http imports should expose OAuth callback risks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
import odoo.http as odoo_http
import jwt

class Controller(odoo_http.Controller):
    @odoo_http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        token = odoo_http.request.get_http_params().get('id_token')
        jwt.decode(token, audience='client')
        return odoo_http.request.session.authenticate(odoo_http.request.db, kwargs.get('login'), kwargs.get('access_token'))
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-public-callback-route" in rule_ids
    assert "odoo-oauth-request-token-decode" in rule_ids
    assert "odoo-oauth-session-authenticate" in rule_ids


def test_imported_odoo_module_oauth_callback_risks_are_reported(tmp_path: Path) -> None:
    """Direct odoo imports should expose OAuth callback risks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
import odoo as od
import jwt

class Controller(od.http.Controller):
    @od.http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        token = od.http.request.get_http_params().get('id_token')
        jwt.decode(token, audience='client')
        return od.http.request.session.authenticate(od.http.request.db, kwargs.get('login'), kwargs.get('access_token'))
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-public-callback-route" in rule_ids
    assert "odoo-oauth-request-token-decode" in rule_ids
    assert "odoo-oauth-session-authenticate" in rule_ids


def test_non_odoo_route_decorator_oauth_callback_is_ignored(tmp_path: Path) -> None:
    """Local route-like decorators should not create Odoo route context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class Controller:
    @router.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        return kwargs.get('id_token')
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert not any(f.rule_id == "odoo-oauth-public-callback-route" for f in findings)


def test_constant_backed_public_oauth_callback_risks_are_reported(tmp_path: Path) -> None:
    """Constant-backed public callback routes should still expose OAuth risks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

CALLBACK_ROUTES = ['/auth/oauth/callback']
CALLBACK_AUTH = 'public'
CALLBACK_CSRF = False

class Controller(http.Controller):
    @http.route(CALLBACK_ROUTES, auth=CALLBACK_AUTH, csrf=CALLBACK_CSRF)
    def callback(self, **kwargs):
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('access_token'))
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-public-callback-route" in rule_ids
    assert "odoo-oauth-missing-state-nonce-validation" in rule_ids
    assert "odoo-oauth-session-authenticate" in rule_ids
    assert any(f.rule_id == "odoo-oauth-public-callback-route" and f.route == "/auth/oauth/callback" for f in findings)


def test_recursive_constant_backed_public_oauth_callback_risks_are_reported(tmp_path: Path) -> None:
    """Recursive route constants should still expose OAuth callback posture."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

CALLBACK_BASE = '/auth/oauth/callback'
CALLBACK_ROUTE = CALLBACK_BASE
CALLBACK_ROUTES = [CALLBACK_ROUTE]
AUTH_BASE = 'public'
CALLBACK_AUTH = AUTH_BASE

class Controller(http.Controller):
    @http.route(CALLBACK_ROUTES, auth=CALLBACK_AUTH, csrf=False)
    def callback(self, **kwargs):
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('access_token'))
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-public-callback-route" in rule_ids
    assert "odoo-oauth-session-authenticate" in rule_ids
    assert any(f.rule_id == "odoo-oauth-public-callback-route" and f.route == "/auth/oauth/callback" for f in findings)


def test_static_unpack_route_options_oauth_callback_risks_are_reported(tmp_path: Path) -> None:
    """Static ** route option dictionaries should not hide public OAuth callbacks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

CALLBACK_OPTIONS = {
    'routes': ['/auth/oauth/callback', '/auth/oidc/callback'],
    'auth': 'public',
}

class Controller(http.Controller):
    @http.route(**CALLBACK_OPTIONS)
    def callback(self, **kwargs):
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('access_token'))
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-public-callback-route" in rule_ids
    assert "odoo-oauth-session-authenticate" in rule_ids
    assert any(f.route == "/auth/oauth/callback,/auth/oidc/callback" for f in findings)


def test_nested_static_unpack_route_options_oauth_callback_risks_are_reported(tmp_path: Path) -> None:
    """Nested static ** route options should not hide public OAuth callbacks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

BASE_OPTIONS = {'auth': 'public'}
CALLBACK_OPTIONS = {
    **BASE_OPTIONS,
    'routes': ['/auth/oauth/callback', '/auth/oidc/callback'],
}

class Controller(http.Controller):
    @http.route(**CALLBACK_OPTIONS)
    def callback(self, **kwargs):
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('access_token'))
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-public-callback-route" in rule_ids
    assert "odoo-oauth-session-authenticate" in rule_ids
    assert any(f.route == "/auth/oauth/callback,/auth/oidc/callback" for f in findings)


def test_class_constant_backed_public_oauth_callback_risks_are_reported(tmp_path: Path) -> None:
    """Class-scoped public callback constants should still expose OAuth risks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request
import jwt
import requests

class Controller(http.Controller):
    CALLBACK_ROUTES = ['/auth/oauth/class-callback']
    CALLBACK_AUTH = 'public'
    TLS_VERIFY = False
    JWT_OPTIONS = {'verify_signature': False}

    @http.route(CALLBACK_ROUTES, auth=CALLBACK_AUTH, csrf=False)
    def callback(self, **kwargs):
        token = kwargs.get('id_token')
        claims = jwt.decode(token, options=JWT_OPTIONS)
        response = requests.get(kwargs.get('userinfo_url'), timeout=10, verify=TLS_VERIFY)
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('access_token'))
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-public-callback-route" in rule_ids
    assert "odoo-oauth-jwt-verification-disabled" in rule_ids
    assert "odoo-oauth-http-verify-disabled" in rule_ids
    assert "odoo-oauth-session-authenticate" in rule_ids
    assert any(f.rule_id == "odoo-oauth-public-callback-route" and f.route == "/auth/oauth/class-callback" for f in findings)


def test_class_constant_static_unpack_route_options_identity_write_is_critical(tmp_path: Path) -> None:
    """Class-scoped ** route options should preserve auth='none' severity for identity writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    CALLBACK_OPTIONS = {
        'routes': ['/auth/oauth/class-options'],
        'auth': 'none',
    }
    USER_MODEL = 'res.users'

    @http.route(**CALLBACK_OPTIONS)
    def callback(self, **kwargs):
        return request.env[USER_MODEL].sudo().write({'oauth_uid': kwargs.get('sub')})
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(
        f.rule_id == "odoo-oauth-tainted-identity-write"
        and f.severity == "critical"
        and f.route == "/auth/oauth/class-options"
        for f in findings
    )


def test_local_constant_user_model_oauth_identity_write_is_reported(tmp_path: Path) -> None:
    """Function-local user model aliases should not hide OAuth identity writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/auth/oauth/local-model', auth='public', csrf=False)
    def callback(self, **kwargs):
        user_model = 'res.users'
        users = request.env[user_model].sudo()
        return users.write({'oauth_uid': kwargs.get('sub')})
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(
        f.rule_id == "odoo-oauth-tainted-identity-write"
        and f.severity == "critical"
        and f.route == "/auth/oauth/local-model"
        for f in findings
    )


def test_recursive_static_unpack_route_options_identity_write_is_critical(tmp_path: Path) -> None:
    """Recursive constant aliases inside ** route options should preserve public severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

ROUTE_BASE = '/auth/oauth/callback'
CALLBACK_ROUTES = [ROUTE_BASE]
AUTH_BASE = 'none'
CALLBACK_AUTH = AUTH_BASE
CALLBACK_OPTIONS = {
    'routes': CALLBACK_ROUTES,
    'auth': CALLBACK_AUTH,
}
OPTIONS_ALIAS = CALLBACK_OPTIONS

class Controller(http.Controller):
    @http.route(**OPTIONS_ALIAS)
    def callback(self, **kwargs):
        return request.env['res.users'].sudo().write({'oauth_uid': kwargs.get('sub')})
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(
        f.rule_id == "odoo-oauth-tainted-identity-write"
        and f.severity == "critical"
        and f.route == "/auth/oauth/callback"
        for f in findings
    )


def test_keyword_constant_backed_none_oauth_identity_write_is_critical(tmp_path: Path) -> None:
    """Keyword route constants with auth='none' should keep identity writes critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

CALLBACK_ROUTE = '/auth/oauth/callback'
CALLBACK_AUTH = 'none'

class Controller(http.Controller):
    @http.route(route=CALLBACK_ROUTE, auth=CALLBACK_AUTH)
    def callback(self, **kwargs):
        return request.env['res.users'].sudo().write({'oauth_uid': kwargs.get('sub')})
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(
        f.rule_id == "odoo-oauth-tainted-identity-write"
        and f.severity == "critical"
        and f.route == "/auth/oauth/callback"
        for f in findings
    )


def test_unpacked_oauth_values_are_reported(tmp_path: Path) -> None:
    """Unpacked request values should stay tainted in OAuth callbacks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request
import jwt
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        token, endpoint = kwargs.get('id_token'), kwargs.get('userinfo_url')
        claims = jwt.decode(token, audience='client')
        requests.get(endpoint, timeout=10)
        return claims
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-request-token-decode" in rule_ids
    assert "odoo-oauth-tainted-validation-url" in rule_ids


def test_starred_unpacked_oauth_values_are_reported(tmp_path: Path) -> None:
    """Starred-unpacked request values should stay tainted in OAuth callbacks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import jwt
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        _, *values = ('fixed', kwargs.get('id_token'), kwargs.get('userinfo_url'))
        token = values[0]
        endpoint = values[1]
        claims = jwt.decode(token, audience='client')
        requests.get(endpoint, timeout=10)
        return claims
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-request-token-decode" in rule_ids
    assert "odoo-oauth-tainted-validation-url" in rule_ids


def test_oauth_token_argument_decode_is_reported(tmp_path: Path) -> None:
    """OAuth route token arguments should still seed request taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import jwt

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, token):
        return jwt.decode(token, audience='client')
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-request-token-decode" in rule_ids


def test_public_oauth_callback_missing_state_nonce_is_reported(tmp_path: Path) -> None:
    """OAuth callbacks that never bind state/nonce should stand out from generic route risk."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, code):
        return {'code': code}
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-public-callback-route" in rule_ids
    assert "odoo-oauth-missing-state-nonce-validation" in rule_ids


def test_public_oauth_callback_state_read_without_validation_is_reported(tmp_path: Path) -> None:
    """Reading a state parameter is not enough; callbacks must visibly validate it."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, state, code):
        return {'state': state, 'code': code}
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-missing-state-nonce-validation" for f in findings)


def test_public_oauth_callback_with_state_reference_is_not_missing_state(tmp_path: Path) -> None:
    """Callbacks that explicitly compare state should not get the missing-state finding."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, state, code):
        if state != request.session.get('oauth_state'):
            return request.not_found()
        return {'code': code}
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert not any(f.rule_id == "odoo-oauth-missing-state-nonce-validation" for f in findings)


def test_public_oauth_callback_with_state_validator_is_not_missing_state(tmp_path: Path) -> None:
    """Callbacks that pass state into a visible validator should not get the missing-state finding."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, state, code):
        self._validate_oauth_state(state)
        return {'code': code}
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert not any(f.rule_id == "odoo-oauth-missing-state-nonce-validation" for f in findings)


def test_reassigned_oauth_token_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a token alias for static data should clear request taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import jwt

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        token = kwargs.get('id_token')
        token = 'trusted-service-token'
        return jwt.decode(token, audience='client')
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert not any(f.rule_id == "odoo-oauth-request-token-decode" for f in findings)


def test_aliased_user_model_identity_write_is_reported(tmp_path: Path) -> None:
    """Aliased res.users writes should not hide OAuth identity mutation."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        Users = request.env['res.users'].sudo()
        oauth_uid = kwargs.get('sub')
        return Users.write({'oauth_uid': oauth_uid, 'login': kwargs.get('email')})
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-identity-write" for f in findings)


def test_walrus_user_model_identity_write_is_reported(tmp_path: Path) -> None:
    """Assignment-expression res.users aliases should not hide OAuth identity mutation."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        oauth_uid = kwargs.get('sub')
        if Users := request.env['res.users'].sudo():
            return Users.write({'oauth_uid': oauth_uid, 'login': kwargs.get('email')})
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-identity-write" for f in findings)


def test_aliased_oauth_identity_payload_is_reported(tmp_path: Path) -> None:
    """Aliased identity payload dictionaries should not hide OAuth user mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        Users = request.env['res.users'].with_user(1)
        vals = {'oauth_uid': kwargs.get('sub'), 'login': kwargs.get('email')}
        return Users.write(vals)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-identity-write" for f in findings)


def test_incremental_oauth_identity_payload_is_reported(tmp_path: Path) -> None:
    """Identity payload dictionaries populated in steps should not hide user mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        Users = request.env['res.users'].with_user(1)
        vals = {}
        vals['oauth_uid'] = kwargs.get('sub')
        vals['login'] = kwargs.get('email')
        return Users.write(vals)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-identity-write" for f in findings)


def test_updated_oauth_identity_payload_is_reported(tmp_path: Path) -> None:
    """dict.update calls should not hide OAuth identity payload writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

OAUTH_UID = 'oauth_uid'

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        Users = request.env['res.users'].with_user(1)
        vals = {}
        vals.update({OAUTH_UID: kwargs.get('sub'), 'login': kwargs.get('email')})
        return Users.write(vals)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-identity-write" for f in findings)


def test_walrus_oauth_identity_payload_is_reported(tmp_path: Path) -> None:
    """Assignment-expression identity payloads should not hide OAuth user mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        Users = request.env['res.users'].with_user(1)
        if vals := {'oauth_uid': kwargs.get('sub'), 'login': kwargs.get('email')}:
            return Users.write(vals)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-identity-write" for f in findings)


def test_reassigned_oauth_identity_payload_is_not_stale(tmp_path: Path) -> None:
    """Reusing an identity payload alias for unrelated data should clear payload state."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        Users = request.env['res.users'].sudo()
        vals = {'oauth_uid': kwargs.get('sub'), 'login': kwargs.get('email')}
        vals = {'name': 'Internal Service User'}
        return Users.write(vals)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert not any(f.rule_id == "odoo-oauth-tainted-identity-write" for f in findings)


def test_starred_user_model_identity_write_is_reported(tmp_path: Path) -> None:
    """Starred-unpacked res.users aliases should not hide OAuth identity mutation."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        _, *items = ('fixed', request.env['res.users'].sudo(), kwargs.get('sub'))
        Users = items[0]
        oauth_uid = items[1]
        return Users.write({'oauth_uid': oauth_uid})
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-identity-write" for f in findings)


def test_reassigned_user_model_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned res.users aliases should not keep identity-write state."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        Users = request.env['res.users'].sudo()
        Users = request.env['res.partner']
        return Users.write({'oauth_uid': kwargs.get('sub'), 'login': kwargs.get('email')})
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert not any(f.rule_id == "odoo-oauth-tainted-identity-write" for f in findings)


def test_comprehension_derived_oauth_url_is_reported(tmp_path: Path) -> None:
    """Comprehension aliases over request data should taint validation URLs."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self):
        payload = request.get_http_params()
        endpoints = [url for url in payload.get('userinfo_urls', [])]
        return requests.get(endpoints[0], timeout=10)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-validation-url" for f in findings)


def test_request_alias_oauth_url_is_reported(tmp_path: Path) -> None:
    """Aliased Odoo request imports should still taint OAuth validation URLs."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request as req
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self):
        payload = req.get_http_params()
        return requests.get(payload.get('userinfo_url'), timeout=10)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-validation-url" for f in findings)


def test_comprehension_filter_derived_oauth_url_is_reported(tmp_path: Path) -> None:
    """Request-derived comprehension filters should taint OAuth validation URLs."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        requested = kwargs.get('userinfo_url')
        endpoints = ['https://idp.example.com/oauth/userinfo' for marker in ['x'] if requested]
        return requests.get(endpoints[0], timeout=10)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-validation-url" for f in findings)


def test_named_expression_derived_oauth_url_is_reported(tmp_path: Path) -> None:
    """Walrus-bound OAuth validation URLs should remain tainted after the condition."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        if endpoint := kwargs.get('userinfo_url'):
            return requests.get(endpoint, timeout=10)
        return None
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-validation-url" for f in findings)


def test_boolop_derived_oauth_url_is_reported(tmp_path: Path) -> None:
    """Boolean fallback OAuth validation URLs should not clear request taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        endpoint = kwargs.get('userinfo_url') or 'https://idp.example.com/oauth/userinfo'
        return requests.get(endpoint, timeout=10)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-validation-url" for f in findings)


def test_comprehension_filter_derived_oauth_token_decode_is_reported(tmp_path: Path) -> None:
    """Request-derived comprehension filters should taint decoded OAuth tokens."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import jwt

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        requested = kwargs.get('id_token')
        id_token = ['trusted-service-token' for marker in ['x'] if requested][0]
        return jwt.decode(id_token, audience='client')
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-request-token-decode" for f in findings)


def test_comprehension_filter_derived_oauth_identity_write_is_reported(tmp_path: Path) -> None:
    """Request-derived comprehension filters should taint OAuth identity writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, **kwargs):
        requested = kwargs.get('sub')
        oauth_uid = ['provider-user' for marker in ['x'] if requested][0]
        return request.env['res.users'].sudo().write({'oauth_uid': oauth_uid})
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-identity-write" for f in findings)


def test_route_path_oauth_validation_url_is_reported(tmp_path: Path) -> None:
    """OAuth callback path parameters should not control validation URLs."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback/<path:userinfo_endpoint>', auth='public', csrf=False)
    def callback(self, userinfo_endpoint):
        return requests.get(userinfo_endpoint, timeout=10)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-validation-url" for f in findings)


def test_safe_internal_provider_call_is_ignored(tmp_path: Path) -> None:
    """Fixed provider endpoints with timeouts should not create OAuth HTTP findings."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "oauth.py").write_text(
        """
import requests

class OAuthProvider:
    def fetch_userinfo(self):
        return requests.get('https://idp.example.com/oauth/userinfo', timeout=10)
""",
        encoding="utf-8",
    )

    assert scan_oauth_flows(tmp_path) == []


def test_helper_oauth_endpoint_arguments_are_tainted(tmp_path: Path) -> None:
    """OAuth helper methods should not trust caller-supplied provider endpoints."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "oauth.py").write_text(
        """
import requests

class OAuthProvider:
    def fetch_userinfo(self, userinfo_url):
        return requests.get(userinfo_url)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-oauth-http-no-timeout" in rule_ids
    assert "odoo-oauth-tainted-validation-url" in rule_ids


def test_authorization_code_exchange_without_pkce_is_reported(tmp_path: Path) -> None:
    """Authorization-code token exchanges should show PKCE or equivalent binding."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, code):
        return requests.post(
            'https://idp.example.com/oauth/token',
            timeout=10,
            data={'grant_type': 'authorization_code', 'code': code},
        )
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-token-exchange-missing-pkce" for f in findings)


def test_local_authorization_code_exchange_without_pkce_is_reported(tmp_path: Path) -> None:
    """Function-local token payload constants should keep PKCE review leads visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, code):
        token_endpoint = 'https://idp.example.com/oauth/token'
        payload = {'grant_type': 'authorization_code', 'code': code}
        return requests.post(token_endpoint, timeout=10, data=payload)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-token-exchange-missing-pkce" for f in findings)


def test_authorization_code_exchange_with_pkce_is_ignored(tmp_path: Path) -> None:
    """A visible code_verifier should suppress the PKCE review lead."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
from odoo.http import request
import requests

TOKEN_DATA = {'grant_type': 'authorization_code'}

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, code):
        payload = dict(TOKEN_DATA, code=code, code_verifier=request.session.get('pkce_verifier'))
        return requests.post('https://idp.example.com/oauth/token', timeout=10, data=payload)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert not any(f.rule_id == "odoo-oauth-token-exchange-missing-pkce" for f in findings)


def test_authorization_code_exchange_with_tainted_redirect_uri_is_reported(tmp_path: Path) -> None:
    """Token exchanges should not forward callback-controlled redirect_uri values."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, code, redirect_uri):
        return requests.post(
            'https://idp.example.com/oauth/token',
            timeout=10,
            data={'grant_type': 'authorization_code', 'code': code, 'redirect_uri': redirect_uri},
        )
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-redirect-uri" for f in findings)


def test_local_token_payload_tainted_redirect_uri_is_reported(tmp_path: Path) -> None:
    """Aliased token payload dictionaries should keep redirect_uri taint visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, code, **kwargs):
        payload = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': kwargs.get('redirect_uri'),
        }
        return requests.post('https://idp.example.com/oauth/token', timeout=10, data=payload)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-redirect-uri" for f in findings)


def test_static_token_payload_redirect_uri_is_ignored(tmp_path: Path) -> None:
    """Provider-owned redirect_uri values should not create tainted redirect findings."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, code):
        payload = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'https://odoo.example.com/auth/oauth/callback',
            'code_verifier': 'server-side-verifier',
        }
        return requests.post('https://idp.example.com/oauth/token', timeout=10, data=payload)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert not any(f.rule_id == "odoo-oauth-tainted-redirect-uri" for f in findings)


def test_incremental_token_payload_tainted_redirect_uri_is_reported(tmp_path: Path) -> None:
    """Incrementally built token payloads should not hide tainted redirect_uri values."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, code, **kwargs):
        payload = {'grant_type': 'authorization_code', 'code': code}
        payload['redirect_uri'] = kwargs.get('redirect_uri')
        return requests.post('https://idp.example.com/oauth/token', timeout=10, data=payload)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-redirect-uri" for f in findings)


def test_updated_token_payload_tainted_redirect_uri_is_reported(tmp_path: Path) -> None:
    """dict.update token payload construction should keep redirect_uri taint visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "oauth.py").write_text(
        """
from odoo import http
import requests

class Controller(http.Controller):
    @http.route('/auth/oauth/callback', auth='public', csrf=False)
    def callback(self, code, **kwargs):
        payload = {'grant_type': 'authorization_code', 'code': code}
        payload.update({'redirect_uri': kwargs.get('redirect_uri')})
        return requests.post('https://idp.example.com/oauth/token', timeout=10, data=payload)
""",
        encoding="utf-8",
    )

    findings = scan_oauth_flows(tmp_path)

    assert any(f.rule_id == "odoo-oauth-tainted-redirect-uri" for f in findings)


def test_scanner_skips_test_fixtures(tmp_path: Path) -> None:
    """Repository tests can contain intentionally insecure OAuth examples."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_oauth.py").write_text(
        """
import jwt

def test_decode():
    return jwt.decode(id_token, options={'verify_signature': False})
""",
        encoding="utf-8",
    )

    assert scan_oauth_flows(tmp_path) == []
