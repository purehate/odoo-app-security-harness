"""Tests for session/authentication controller scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.session_auth_scanner import scan_session_auth


def test_flags_public_authenticate_with_request_credentials(tmp_path: Path) -> None:
    """Public routes that authenticate request credentials need review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "auth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/login/token', auth='public', csrf=False)
    def login(self, **kwargs):
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('password'))
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-public-authenticate" for f in findings)


def test_imported_route_decorator_public_authenticate_is_reported(tmp_path: Path) -> None:
    """Imported route decorators should still expose public authentication routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "auth.py").write_text(
        """
from odoo import http
from odoo.http import request, route

class Controller(http.Controller):
    @route('/login/token', auth='public', csrf=False)
    def login(self, **kwargs):
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('password'))
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-public-authenticate" for f in findings)


def test_aliased_imported_route_decorator_public_authenticate_is_reported(tmp_path: Path) -> None:
    """Aliased imported route decorators should still expose public authentication routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "auth.py").write_text(
        """
from odoo import http
from odoo.http import request, route as odoo_route

class Controller(http.Controller):
    @odoo_route('/login/token', auth='public', csrf=False)
    def login(self, **kwargs):
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('password'))
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-public-authenticate" for f in findings)


def test_aliased_http_module_public_authenticate_is_reported(tmp_path: Path) -> None:
    """Aliased Odoo http modules should still expose public authentication routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "auth.py").write_text(
        """
from odoo import http as odoo_http
from odoo.http import request

class Controller(odoo_http.Controller):
    @odoo_http.route('/login/token', auth='public', csrf=False)
    def login(self, **kwargs):
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('password'))
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-public-authenticate" for f in findings)


def test_imported_odoo_http_module_public_authenticate_is_reported(tmp_path: Path) -> None:
    """Direct odoo.http imports should expose public authentication routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "auth.py").write_text(
        """
import odoo.http as odoo_http

class Controller(odoo_http.Controller):
    @odoo_http.route('/login/token', auth='public', csrf=False)
    def login(self, **kwargs):
        return odoo_http.request.session.authenticate(odoo_http.request.db, kwargs.get('login'), kwargs.get('password'))
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-public-authenticate" for f in findings)


def test_imported_odoo_module_public_authenticate_is_reported(tmp_path: Path) -> None:
    """Direct odoo module imports should expose public authentication routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "auth.py").write_text(
        """
import odoo as od

class Controller(od.http.Controller):
    @od.http.route('/login/token', auth='public', csrf=False)
    def login(self, **kwargs):
        return od.http.request.session.authenticate(od.http.request.db, kwargs.get('login'), kwargs.get('password'))
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-public-authenticate" for f in findings)


def test_non_odoo_route_decorator_public_authenticate_is_ignored(tmp_path: Path) -> None:
    """Arbitrary .route decorators should not make authenticate calls look public."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "auth.py").write_text(
        """
from odoo.http import request

class Bus:
    def route(self, path, **kwargs):
        return lambda func: func

bus = Bus()

class Controller:
    @bus.route('/login/token', auth='public', csrf=False)
    def login(self, **kwargs):
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('password'))
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert not any(f.rule_id == "odoo-session-public-authenticate" for f in findings)


def test_constant_backed_public_authenticate_is_reported(tmp_path: Path) -> None:
    """Constant-backed public auth should still expose authentication routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "auth.py").write_text(
        """
from odoo import http
from odoo.http import request

LOGIN_ROUTES = ['/login/token', '/login/token/alt']
LOGIN_AUTH = 'public'
LOGIN_CSRF = False

class Controller(http.Controller):
    @http.route(LOGIN_ROUTES, auth=LOGIN_AUTH, csrf=LOGIN_CSRF)
    def login(self, **kwargs):
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('password'))
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-public-authenticate" for f in findings)


def test_static_unpack_route_options_public_authenticate_is_reported(tmp_path: Path) -> None:
    """Static ** route options should not hide public authentication routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "auth.py").write_text(
        """
from odoo import http
from odoo.http import request

LOGIN_OPTIONS = {
    'auth': 'public',
    'csrf': False,
}

class Controller(http.Controller):
    @http.route('/login/token', **LOGIN_OPTIONS)
    def login(self, **kwargs):
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('password'))
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-public-authenticate" for f in findings)


def test_nested_static_unpack_route_options_public_authenticate_is_reported(tmp_path: Path) -> None:
    """Nested static ** route options should not hide public authentication routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "auth.py").write_text(
        """
from odoo import http
from odoo.http import request

BASE_OPTIONS = {'auth': 'public'}
LOGIN_OPTIONS = {
    **BASE_OPTIONS,
    'csrf': False,
}

class Controller(http.Controller):
    @http.route('/login/token', **LOGIN_OPTIONS)
    def login(self, **kwargs):
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('password'))
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-public-authenticate" for f in findings)


def test_class_constant_backed_public_authenticate_is_reported(tmp_path: Path) -> None:
    """Class-scoped public auth constants should still expose authentication routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "auth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    LOGIN_ROUTES = ['/login/token', '/login/token/alt']
    LOGIN_AUTH = 'public'
    LOGIN_CSRF = False

    @http.route(LOGIN_ROUTES, auth=LOGIN_AUTH, csrf=LOGIN_CSRF)
    def login(self, **kwargs):
        return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('password'))
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-public-authenticate" for f in findings)


def test_class_constant_static_unpack_route_options_logout_is_reported(tmp_path: Path) -> None:
    """Class-scoped static ** route options should preserve weak logout posture."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "logout.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    AUTH_BASE = 'public'
    AUTH = AUTH_BASE
    CSRF_DISABLED = False
    METHODS_BASE = ['GET']
    METHODS = METHODS_BASE
    LOGOUT_OPTIONS = {
        'auth': AUTH,
        'csrf': CSRF_DISABLED,
        'methods': METHODS,
    }
    OPTIONS_ALIAS = LOGOUT_OPTIONS

    @http.route('/bye', **OPTIONS_ALIAS)
    def bye(self):
        request.session.logout()
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-logout-weak-route" for f in findings)


def test_recursive_static_unpack_route_options_logout_is_reported(tmp_path: Path) -> None:
    """Recursive constant aliases inside ** route options should preserve weak logout posture."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "logout.py").write_text(
        """
from odoo import http
from odoo.http import request

AUTH_BASE = 'public'
AUTH = AUTH_BASE
CSRF_DISABLED = False
METHODS_BASE = ['GET']
METHODS = METHODS_BASE
LOGOUT_OPTIONS = {
    'auth': AUTH,
    'csrf': CSRF_DISABLED,
    'methods': METHODS,
}
OPTIONS_ALIAS = LOGOUT_OPTIONS

class Controller(http.Controller):
    @http.route('/bye', **OPTIONS_ALIAS)
    def bye(self):
        request.session.logout()
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-logout-weak-route" for f in findings)


def test_keyword_constant_backed_none_update_env_is_critical(tmp_path: Path) -> None:
    """Constant-backed auth='none' should preserve critical update_env findings."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "switch.py").write_text(
        """
from odoo import http
from odoo.http import request

SWITCH_ROUTE = '/public/switch'
SWITCH_AUTH = 'none'
SWITCH_CSRF = False

class Controller(http.Controller):
    @http.route(route=SWITCH_ROUTE, auth=SWITCH_AUTH, csrf=SWITCH_CSRF)
    def switch(self, **kwargs):
        request.update_env(user=int(kwargs.get('uid')))
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-update-env-tainted-user" and f.severity == "critical" for f in findings)


def test_constant_backed_get_logout_route_is_reported(tmp_path: Path) -> None:
    """Constant-backed methods/csrf route posture should expose weak logout routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "logout.py").write_text(
        """
from odoo import http
from odoo.http import request

LOGOUT_METHODS = ['GET']
LOGOUT_AUTH = 'user'
LOGOUT_CSRF = False

class Controller(http.Controller):
    @http.route('/bye', auth=LOGOUT_AUTH, methods=LOGOUT_METHODS, csrf=LOGOUT_CSRF)
    def bye(self):
        return request.session.logout()
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-logout-weak-route" for f in findings)


def test_flags_public_authenticate_with_unpacked_request_credentials(tmp_path: Path) -> None:
    """Unpacked request credentials should stay tainted for authenticate()."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "auth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/login/token', auth='public', csrf=False)
    def login(self, **kwargs):
        login, password = kwargs.get('login'), kwargs.get('password')
        return request.session.authenticate(request.db, login, password)
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-public-authenticate" for f in findings)


def test_flags_public_authenticate_with_starred_request_credentials(tmp_path: Path) -> None:
    """Starred-unpacked request credentials should stay tainted for authenticate()."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "auth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/login/token', auth='public', csrf=False)
    def login(self, **kwargs):
        _, *credentials = ('fixed', kwargs.get('login'), kwargs.get('password'))
        login = credentials[0]
        password = credentials[1]
        return request.session.authenticate(request.db, login, password)
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-public-authenticate" for f in findings)


def test_flags_public_user_lookup_with_request_login(tmp_path: Path) -> None:
    """Public pre-auth user lookups can create account enumeration side channels."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "auth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/login/check', auth='public', csrf=False)
    def login_check(self, **kwargs):
        user = request.env['res.users'].sudo().search([('login', '=', kwargs.get('login'))], limit=1)
        return {'exists': bool(user)}
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-public-user-lookup" for f in findings)


def test_flags_public_user_search_read_with_request_email(tmp_path: Path) -> None:
    """search_read() on res.users should not evade public pre-auth lookup review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "auth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/login/check', auth='none', csrf=False)
    def login_check(self, **kwargs):
        return request.env['res.users'].sudo().search_read([('email', '=', kwargs.get('email'))], ['id'], limit=1)
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-public-user-lookup" for f in findings)


def test_flags_public_user_read_group_with_request_email(tmp_path: Path) -> None:
    """read_group() on res.users can still become a pre-auth enumeration oracle."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "auth.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/login/check', auth='public', csrf=False)
    def login_check(self, **kwargs):
        return request.env['res.users'].sudo().read_group(
            [('email', '=', kwargs.get('email'))],
            ['id:count'],
            ['active'],
        )
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-public-user-lookup" for f in findings)


def test_authenticated_user_lookup_is_not_public_user_lookup(tmp_path: Path) -> None:
    """Authenticated user management searches should not get the public lookup finding."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/users/search', auth='user')
    def user_search(self, **kwargs):
        return request.env['res.users'].search([('login', '=', kwargs.get('login'))])
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert not any(f.rule_id == "odoo-session-public-user-lookup" for f in findings)


def test_flags_direct_session_uid_assignment(tmp_path: Path) -> None:
    """Direct session uid assignment can become account switching."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "impersonate.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/impersonate', auth='user')
    def impersonate(self, **kwargs):
        request.session.uid = kwargs.get('uid')
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-direct-uid-assignment" and f.severity == "high" for f in findings)


def test_request_alias_direct_session_uid_assignment(tmp_path: Path) -> None:
    """Aliased Odoo request imports should still expose session uid assignment."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "impersonate.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/impersonate', auth='user')
    def impersonate(self, **kwargs):
        req.session.uid = kwargs.get('uid')
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-direct-uid-assignment" and f.severity == "high" for f in findings)


def test_imported_odoo_http_module_direct_session_uid_assignment(tmp_path: Path) -> None:
    """Direct odoo.http request access should expose session uid assignment."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "impersonate.py").write_text(
        """
import odoo.http as odoo_http

class Controller(odoo_http.Controller):
    @odoo_http.route('/impersonate', auth='user')
    def impersonate(self, **kwargs):
        odoo_http.request.session.uid = kwargs.get('uid')
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-direct-uid-assignment" and f.severity == "high" for f in findings)


def test_imported_odoo_module_direct_session_uid_assignment(tmp_path: Path) -> None:
    """Direct odoo module request access should expose session uid assignment."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "impersonate.py").write_text(
        """
import odoo as od

class Controller(od.http.Controller):
    @od.http.route('/impersonate', auth='user')
    def impersonate(self, **kwargs):
        od.http.request.session.uid = kwargs.get('uid')
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-direct-uid-assignment" and f.severity == "high" for f in findings)


def test_flags_direct_session_uid_assignment_from_wrapped_request_value(tmp_path: Path) -> None:
    """Wrapped request values like int(kwargs.get(...)) should stay tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "impersonate.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/impersonate', auth='user')
    def impersonate(self, **kwargs):
        uid = int(kwargs.get('uid'))
        request.session.uid = uid
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-direct-uid-assignment" and f.severity == "high" for f in findings)


def test_flags_annotated_direct_session_uid_assignment(tmp_path: Path) -> None:
    """Annotated direct session uid assignment should not hide account switching."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "impersonate.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/impersonate', auth='user')
    def impersonate(self, **kwargs):
        request.session.uid: int = int(kwargs.get('uid'))
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-direct-uid-assignment" and f.severity == "high" for f in findings)


def test_reassigned_uid_alias_is_not_stale_for_update_env(tmp_path: Path) -> None:
    """Reusing a request-derived uid alias for a safe user should clear taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "switch.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/switch', auth='user')
    def switch(self, **kwargs):
        uid = int(kwargs.get('uid'))
        uid = request.env.user.id
        request.update_env(user=uid)
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert not any(f.rule_id == "odoo-session-update-env-tainted-user" for f in findings)


def test_flags_dict_style_session_uid_assignment(tmp_path: Path) -> None:
    """Dict-style request.session uid assignment should not hide account switching."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "impersonate.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/impersonate', auth='user')
    def impersonate(self, **kwargs):
        request.session['uid'] = kwargs.get('uid')
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-direct-uid-assignment" and f.severity == "high" for f in findings)


def test_flags_session_update_uid_assignment(tmp_path: Path) -> None:
    """request.session.update({...}) should be treated like direct uid assignment."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "impersonate.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/impersonate', auth='user')
    def impersonate(self, **kwargs):
        request.session.update({'uid': int(kwargs.get('uid'))})
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-direct-uid-assignment" and f.severity == "high" for f in findings)


def test_flags_aliased_session_update_uid_assignment(tmp_path: Path) -> None:
    """Aliased session update dictionaries should preserve uid assignment checks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "impersonate.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/impersonate', auth='user')
    def impersonate(self, **kwargs):
        values = {'uid': int(kwargs.get('uid'))}
        return request.session.update(values)
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-direct-uid-assignment" and f.severity == "high" for f in findings)


def test_flags_incremental_session_update_uid_assignment(tmp_path: Path) -> None:
    """Session update dictionaries populated in steps should be inspected."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "impersonate.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/impersonate', auth='user')
    def impersonate(self, **kwargs):
        values = {}
        values['uid'] = int(kwargs.get('uid'))
        return request.session.update(values)
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-direct-uid-assignment" and f.severity == "high" for f in findings)


def test_flags_updated_session_update_uid_assignment(tmp_path: Path) -> None:
    """dict.update calls should not hide session uid updates."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "impersonate.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/impersonate', auth='user')
    def impersonate(self, **kwargs):
        values = {}
        values.update({'uid': int(kwargs.get('uid'))})
        return request.session.update(values)
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-direct-uid-assignment" and f.severity == "high" for f in findings)


def test_flags_public_request_uid_assignment(tmp_path: Path) -> None:
    """Public routes must not assign request.uid directly."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "impersonate.py").write_text(
        """
from odoo import http, SUPERUSER_ID
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/root', auth='public', csrf=False)
    def root(self):
        request.uid = SUPERUSER_ID
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-direct-request-uid-assignment" and f.severity == "critical" for f in findings)


def test_flags_annotated_public_request_uid_assignment(tmp_path: Path) -> None:
    """Annotated request.uid assignments should keep public superuser severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "impersonate.py").write_text(
        """
from odoo import http, SUPERUSER_ID
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/root', auth='public', csrf=False)
    def root(self):
        request.uid: int = SUPERUSER_ID
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-direct-request-uid-assignment" and f.severity == "critical" for f in findings)


def test_flags_update_env_with_tainted_and_superuser_identity(tmp_path: Path) -> None:
    """request.update_env should not switch to request-selected or root users."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "switch.py").write_text(
        """
from odoo import http, SUPERUSER_ID
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/switch', auth='public', csrf=False)
    def switch(self, **kwargs):
        request.update_env(user=kwargs.get('uid'))
        request.update_env(user=SUPERUSER_ID)
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-session-update-env-tainted-user" in rule_ids
    assert "odoo-session-update-env-superuser" in rule_ids


def test_flags_aliased_superuser_import_session_auth_boundaries(tmp_path: Path) -> None:
    """Imported SUPERUSER_ID aliases should still count as root identity switching."""
    controllers = tmp_path / "module" / "controllers"
    models = tmp_path / "module" / "models"
    controllers.mkdir(parents=True)
    models.mkdir(parents=True)
    (controllers / "switch.py").write_text(
        """
from odoo import SUPERUSER_ID as ROOT_UID, api, http
from odoo.http import request

ROOT = ROOT_UID

class Controller(http.Controller):
    @http.route('/public/switch', auth='public', csrf=False)
    def switch(self):
        request.uid = ROOT_UID
        request.update_env(user=ROOT)
        root_env = api.Environment(request.cr, ROOT_UID, {})
        return root_env['res.users'].browse(ROOT)
""",
        encoding="utf-8",
    )
    (models / "ir_http.py").write_text(
        """
from odoo import SUPERUSER_ID as ROOT_UID, models
from odoo.http import request

class IrHttp(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _auth_method_public(cls):
        request.uid = ROOT_UID
        return True
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-session-direct-request-uid-assignment" in rule_ids
    assert "odoo-session-update-env-superuser" in rule_ids
    assert "odoo-session-environment-superuser" in rule_ids
    assert "odoo-session-ir-http-superuser-auth" in rule_ids


def test_flags_constant_alias_session_auth_boundaries(tmp_path: Path) -> None:
    """Aliased route metadata, session keys, superusers, token names, and cookie flags should resolve."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "switch.py").write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

BASE_AUTH = 'public'
AUTH = BASE_AUTH
BASE_CSRF = False
CSRF = BASE_CSRF
ROOT = SUPERUSER_ID
UID_KEY = 'uid'
COOKIE_BASE = 'session_token'
COOKIE_NAME = COOKIE_BASE
SECURE_FLAG = True
HTTPONLY_FLAG = True
SAMESITE_BASE = 'Lax'
SAMESITE = SAMESITE_BASE
TOKEN_KEY_BASE = 'csrf_token'
TOKEN_KEY = TOKEN_KEY_BASE

class Controller(http.Controller):
    @http.route('/public/switch', auth=AUTH, csrf=CSRF)
    def switch(self):
        request.update_env(user=ROOT)
        request.session.update({UID_KEY: ROOT})
        response = request.make_response({TOKEN_KEY: request.session.sid})
        response.set_cookie(
            key=COOKIE_NAME,
            value=request.session.sid,
            secure=SECURE_FLAG,
            httponly=HTTPONLY_FLAG,
            samesite=SAMESITE,
        )
        return response
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-session-update-env-superuser" in rule_ids
    assert "odoo-session-public-update-env" in rule_ids
    assert "odoo-session-direct-uid-assignment" in rule_ids
    assert "odoo-session-token-exposed" in rule_ids
    assert "odoo-session-sensitive-cookie-weak-flags" not in rule_ids


def test_flags_class_constant_alias_session_auth_boundaries(tmp_path: Path) -> None:
    """Class constants should resolve for route, session, token, root, and cookie checks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "switch.py").write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class Controller(http.Controller):
    BASE_AUTH = 'public'
    AUTH = BASE_AUTH
    BASE_CSRF = False
    CSRF = BASE_CSRF
    ROOT = SUPERUSER_ID
    UID_KEY = 'uid'
    COOKIE_BASE = 'session_token'
    COOKIE_NAME = COOKIE_BASE
    SECURE_FLAG = True
    HTTPONLY_FLAG = True
    SAMESITE_BASE = 'Lax'
    SAMESITE = SAMESITE_BASE
    TOKEN_KEY_BASE = 'csrf_token'
    TOKEN_KEY = TOKEN_KEY_BASE

    @http.route('/public/switch', auth=AUTH, csrf=CSRF)
    def switch(self):
        request.update_env(user=ROOT)
        request.session.update({UID_KEY: ROOT})
        response = request.make_response({TOKEN_KEY: request.session.sid})
        response.set_cookie(
            key=COOKIE_NAME,
            value=request.session.sid,
            secure=SECURE_FLAG,
            httponly=HTTPONLY_FLAG,
            samesite=SAMESITE,
        )
        return response
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-session-update-env-superuser" in rule_ids
    assert "odoo-session-public-update-env" in rule_ids
    assert "odoo-session-direct-uid-assignment" in rule_ids
    assert "odoo-session-token-exposed" in rule_ids
    assert "odoo-session-sensitive-cookie-weak-flags" not in rule_ids


def test_flags_get_json_data_update_env_user(tmp_path: Path) -> None:
    """Modern JSON routes should treat request.get_json_data() as tainted identity input."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "switch.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/switch', auth='public', type='json', csrf=False)
    def switch(self):
        payload = request.get_json_data()
        request.update_env(user=payload.get('uid'))
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-session-update-env-tainted-user" in rule_ids


def test_request_alias_get_json_data_update_env_user(tmp_path: Path) -> None:
    """Aliased Odoo request imports should still taint update_env identities."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "switch.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/public/switch', auth='public', type='json', csrf=False)
    def switch(self):
        payload = req.get_json_data()
        req.update_env(user=payload.get('uid'))
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-session-update-env-tainted-user" in rule_ids


def test_flags_loop_derived_update_env_user(tmp_path: Path) -> None:
    """Loop variables over request data should stay tainted for update_env."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "switch.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/switch', auth='public', csrf=False)
    def switch(self, **kwargs):
        for uid in kwargs.get('uids'):
            request.update_env(user=uid)
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-update-env-tainted-user" for f in findings)


def test_safe_loop_reassignment_clears_session_uid_taint(tmp_path: Path) -> None:
    """Loop target taint should clear when the name is rebound from safe data."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "switch.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/switch', auth='user')
    def switch(self, **kwargs):
        for uid in kwargs.get('uids'):
            pass
        for uid in [request.env.user.id]:
            request.update_env(user=uid)
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert not any(f.rule_id == "odoo-session-update-env-tainted-user" for f in findings)


def test_flags_comprehension_derived_update_env_user(tmp_path: Path) -> None:
    """Comprehension aliases over request data should stay tainted for update_env."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "switch.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/switch', auth='public', csrf=False)
    def switch(self):
        payload = request.get_http_params()
        uids = [uid for uid in payload.get('uids', [])]
        request.update_env(user=int(uids[0]))
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-session-update-env-tainted-user" in rule_ids


def test_flags_starred_unpacked_update_env_user(tmp_path: Path) -> None:
    """Starred-unpacked request user IDs should stay tainted for update_env."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "switch.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/switch', auth='public', csrf=False)
    def switch(self, **kwargs):
        _, *uids = ('fixed', kwargs.get('uid'))
        request.update_env(user=int(uids[0]))
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-update-env-tainted-user" for f in findings)


def test_comprehension_filter_derived_update_env_user(tmp_path: Path) -> None:
    """Tainted comprehension filters should keep update_env user aliases tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "switch.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/switch', auth='public', csrf=False)
    def switch(self, **kwargs):
        uids = [request.env.user.id for uid in [request.env.user.id] if kwargs.get('uid')]
        request.update_env(user=uids[0])
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-update-env-tainted-user" for f in findings)


def test_named_expression_derived_update_env_user(tmp_path: Path) -> None:
    """Walrus-bound user IDs should remain tainted for update_env."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "switch.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/switch', auth='public', csrf=False)
    def switch(self, **kwargs):
        if uid := kwargs.get('uid'):
            request.update_env(user=int(uid))
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-update-env-tainted-user" for f in findings)


def test_boolop_derived_update_env_user(tmp_path: Path) -> None:
    """Boolean fallback user IDs should not clear update_env taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "switch.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/switch', auth='public', csrf=False)
    def switch(self, **kwargs):
        uid = kwargs.get('uid') or request.env.user.id
        request.update_env(user=uid)
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-update-env-tainted-user" for f in findings)


def test_flags_manual_environment_with_superuser_or_tainted_user(tmp_path: Path) -> None:
    """Manual Environment construction should not pick privileged/request uids."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "env.py").write_text(
        """
from odoo import api, http, SUPERUSER_ID
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/env', auth='public', csrf=False)
    def env(self, **kwargs):
        root_env = api.Environment(request.cr, SUPERUSER_ID, {})
        user_env = api.Environment(request.cr, kwargs.get('uid'), {})
        return root_env['res.users'].browse(user_env.uid)
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-session-environment-superuser" in rule_ids
    assert "odoo-session-environment-tainted-user" in rule_ids


def test_flags_aliased_odoo_api_module_environment(tmp_path: Path) -> None:
    """Aliased Odoo API modules should not hide manual Environment construction."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "env.py").write_text(
        """
from odoo import api as odoo_api, http, SUPERUSER_ID
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/env', auth='public', csrf=False)
    def env(self, **kwargs):
        root_env = odoo_api.Environment(request.cr, SUPERUSER_ID, {})
        user_env = odoo_api.Environment(request.cr, kwargs.get('uid'), {})
        return root_env['res.users'].browse(user_env.uid)
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-session-environment-superuser" in rule_ids
    assert "odoo-session-environment-tainted-user" in rule_ids


def test_flags_imported_odoo_api_module_environment(tmp_path: Path) -> None:
    """Direct odoo.api module imports should not hide manual Environment construction."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "env.py").write_text(
        """
import odoo.api as odoo_api
from odoo import http, SUPERUSER_ID
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/env', auth='public', csrf=False)
    def env(self, **kwargs):
        root_env = odoo_api.Environment(request.cr, SUPERUSER_ID, {})
        user_env = odoo_api.Environment(request.cr, kwargs.get('uid'), {})
        return root_env['res.users'].browse(user_env.uid)
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-session-environment-superuser" in rule_ids
    assert "odoo-session-environment-tainted-user" in rule_ids


def test_flags_imported_odoo_module_api_environment(tmp_path: Path) -> None:
    """Direct odoo module imports should not hide manual Environment construction."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "env.py").write_text(
        """
import odoo as od
from odoo import http, SUPERUSER_ID
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/env', auth='public', csrf=False)
    def env(self, **kwargs):
        root_env = od.api.Environment(request.cr, SUPERUSER_ID, {})
        user_env = od.api.Environment(request.cr, kwargs.get('uid'), {})
        return root_env['res.users'].browse(user_env.uid)
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-session-environment-superuser" in rule_ids
    assert "odoo-session-environment-tainted-user" in rule_ids


def test_flags_aliased_imported_environment_constructor(tmp_path: Path) -> None:
    """Aliased direct Environment imports should remain visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "env.py").write_text(
        """
from odoo import http, SUPERUSER_ID
from odoo.api import Environment as OdooEnvironment
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/env', auth='public', csrf=False)
    def env(self, **kwargs):
        root_env = OdooEnvironment(request.cr, SUPERUSER_ID, {})
        user_env = OdooEnvironment(request.cr, kwargs.get('uid'), {})
        return root_env['res.users'].browse(user_env.uid)
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-session-environment-superuser" in rule_ids
    assert "odoo-session-environment-tainted-user" in rule_ids


def test_flags_uid_argument_environment_user(tmp_path: Path) -> None:
    """Uid-shaped function arguments should remain tainted identity input."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "env.py").write_text(
        """
from odoo import api, models

class Helper(models.Model):
    _name = 'x.helper'

    def build_env(self, uid):
        return api.Environment(self.env.cr, uid, {})
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-environment-tainted-user" for f in findings)


def test_flags_route_path_id_session_switching(tmp_path: Path) -> None:
    """Route path IDs should be tainted for session switching sinks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "impersonate.py").write_text(
        """
from odoo import api, http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/impersonate/<int:target_uid>', auth='public', csrf=False)
    def impersonate(self, target_uid):
        request.session.uid = target_uid
        request.update_env(user=target_uid)
        return api.Environment(request.cr, target_uid, {})['res.users'].browse(target_uid)
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-session-direct-uid-assignment" in rule_ids
    assert "odoo-session-update-env-tainted-user" in rule_ids
    assert "odoo-session-environment-tainted-user" in rule_ids


def test_flags_public_token_exposure(tmp_path: Path) -> None:
    """Public token-returning endpoints should be review leads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "token.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/token', auth='public')
    def token(self):
        return {'csrf_token': request.csrf_token(), 'sid': request.session.sid}
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-token-exposed" and f.severity == "high" for f in findings)


def test_flags_weak_logout_route(tmp_path: Path) -> None:
    """GET or csrf-disabled logout routes can enable cross-site logout."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "logout.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/bye', auth='public', methods=['GET'], csrf=False)
    def bye(self):
        request.session.logout()
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-logout-weak-route" for f in findings)


def test_flags_sensitive_cookie_without_hardened_flags(tmp_path: Path) -> None:
    """Session/token cookies need secure, HttpOnly, and SameSite posture."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "cookie.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/cookie', auth='public', csrf=False)
    def cookie(self):
        response = request.make_response('ok')
        response.set_cookie('session_token', request.session.sid)
        return response
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert any(f.rule_id == "odoo-session-sensitive-cookie-weak-flags" and f.severity == "high" for f in findings)


def test_safe_sensitive_cookie_flags_are_ignored(tmp_path: Path) -> None:
    """Properly hardened session/token cookies should avoid noise."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "cookie.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/cookie', auth='user', methods=['POST'])
    def cookie(self):
        response = request.make_response('ok')
        response.set_cookie(
            key='session_token',
            value=request.session.sid,
            secure=True,
            httponly=True,
            samesite='Lax',
        )
        return response
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)

    assert not any(f.rule_id == "odoo-session-sensitive-cookie-weak-flags" for f in findings)


def test_flags_ir_http_auth_override_and_superuser_assignment(tmp_path: Path) -> None:
    """Global ir.http auth hooks should be explicit review leads."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "ir_http.py").write_text(
        """
from odoo import models, SUPERUSER_ID
from odoo.http import request

class IrHttp(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _auth_method_public(cls):
        request.uid = SUPERUSER_ID
        return True
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-session-ir-http-auth-override" in rule_ids
    assert "odoo-session-ir-http-superuser-auth" in rule_ids
    assert "odoo-session-ir-http-bypass" in rule_ids


def test_class_constant_ir_http_auth_override_and_superuser_assignment(tmp_path: Path) -> None:
    """Class constants should resolve ir.http inheritance and superuser aliases."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "ir_http.py").write_text(
        """
from odoo import models, SUPERUSER_ID
from odoo.http import request

class IrHttp(models.AbstractModel):
    IR_HTTP_MODEL = 'ir.http'
    ROOT = SUPERUSER_ID
    _inherit = IR_HTTP_MODEL

    @classmethod
    def _auth_method_public(cls):
        request.uid = ROOT
        return True
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-session-ir-http-auth-override" in rule_ids
    assert "odoo-session-ir-http-superuser-auth" in rule_ids
    assert "odoo-session-ir-http-bypass" in rule_ids


def test_ir_http_override_calling_super_is_not_marked_as_bypass(tmp_path: Path) -> None:
    """Parent auth calls keep the bypass heuristic quiet."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "ir_http.py").write_text(
        """
from odoo import models

class IrHttp(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _auth_method_user(cls):
        return super()._auth_method_user()
""",
        encoding="utf-8",
    )

    findings = scan_session_auth(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-session-ir-http-auth-override" in rule_ids
    assert "odoo-session-ir-http-bypass" not in rule_ids


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Session fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_auth.py").write_text(
        """
def test_login(kwargs):
    return request.session.authenticate(request.db, kwargs.get('login'), kwargs.get('password'))
""",
        encoding="utf-8",
    )

    assert scan_session_auth(tmp_path) == []
