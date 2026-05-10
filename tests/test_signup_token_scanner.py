"""Tests for Odoo signup/reset token scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.signup_token_scanner import scan_signup_tokens


def test_public_reset_route_token_lifecycle_risks_are_reported(tmp_path: Path) -> None:
    """Public reset routes must not trust request-selected tokens or passwords."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        partner = request.env['res.partner'].sudo().search([('signup_token', '=', kwargs.get('token'))], limit=1)
        request.env['res.users'].sudo().write({
            'signup_token': kwargs.get('token'),
            'password': kwargs.get('password'),
        })
        return request.render('auth_signup.reset_password', {'signup_token': partner.signup_token})
""",
        encoding="utf-8",
    )

    findings = scan_signup_tokens(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-signup-public-token-route" in rule_ids
    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids
    assert "odoo-signup-tainted-identity-token-write" in rule_ids
    assert "odoo-signup-public-sudo-identity-flow" in rule_ids
    assert "odoo-signup-token-exposed" in rule_ids


def test_imported_route_decorator_public_reset_token_lifecycle_risks_are_reported(tmp_path: Path) -> None:
    """Imported route decorators must not hide public reset token risks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request, route

class Controller(http.Controller):
    @route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        partner = request.env['res.partner'].sudo().search([('signup_token', '=', kwargs.get('token'))], limit=1)
        request.env['res.users'].sudo().write({
            'signup_token': kwargs.get('token'),
            'password': kwargs.get('password'),
        })
        return request.render('auth_signup.reset_password', {'signup_token': partner.signup_token})
""",
        encoding="utf-8",
    )

    findings = scan_signup_tokens(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-signup-public-token-route" in rule_ids
    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids
    assert "odoo-signup-tainted-identity-token-write" in rule_ids
    assert "odoo-signup-public-sudo-identity-flow" in rule_ids
    assert "odoo-signup-token-exposed" in rule_ids


def test_aliased_imported_route_decorator_public_reset_token_lifecycle_risks_are_reported(tmp_path: Path) -> None:
    """Aliased imported route decorators must not hide public reset token risks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request, route as odoo_route

class Controller(http.Controller):
    @odoo_route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        partner = request.env['res.partner'].sudo().search([('signup_token', '=', kwargs.get('token'))], limit=1)
        request.env['res.users'].sudo().write({
            'signup_token': kwargs.get('token'),
            'password': kwargs.get('password'),
        })
        return request.render('auth_signup.reset_password', {'signup_token': partner.signup_token})
""",
        encoding="utf-8",
    )

    findings = scan_signup_tokens(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-signup-public-token-route" in rule_ids
    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids
    assert "odoo-signup-tainted-identity-token-write" in rule_ids
    assert "odoo-signup-public-sudo-identity-flow" in rule_ids
    assert "odoo-signup-token-exposed" in rule_ids


def test_constant_backed_public_reset_token_lifecycle_risks_are_reported(tmp_path: Path) -> None:
    """Constant-backed public reset route metadata must not hide token risks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

RESET_ROUTES = ['/web/reset_password']
RESET_AUTH = 'public'
RESET_CSRF = False

class Controller(http.Controller):
    @http.route(RESET_ROUTES, auth=RESET_AUTH, csrf=RESET_CSRF)
    def reset_password(self, **kwargs):
        partner = request.env['res.partner'].sudo().search([('signup_token', '=', kwargs.get('token'))], limit=1)
        return request.render('auth_signup.reset_password', {'signup_token': partner.signup_token})
""",
        encoding="utf-8",
    )

    findings = scan_signup_tokens(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-signup-public-token-route" in rule_ids
    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids
    assert "odoo-signup-public-sudo-identity-flow" in rule_ids
    assert "odoo-signup-token-exposed" in rule_ids
    assert any(
        f.rule_id == "odoo-signup-tainted-token-lookup"
        and f.severity == "critical"
        and f.route == "/web/reset_password"
        for f in findings
    )


def test_static_unpack_route_options_public_reset_token_lifecycle_risks_are_reported(tmp_path: Path) -> None:
    """Static ** route options must not hide public reset token risks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

RESET_OPTIONS = {
    'routes': ['/web/reset_password', '/web/signup/reset'],
    'auth': 'public',
}

class Controller(http.Controller):
    @http.route(**RESET_OPTIONS)
    def reset_password(self, **kwargs):
        partner = request.env['res.partner'].sudo().search([('signup_token', '=', kwargs.get('token'))], limit=1)
        return request.render('auth_signup.reset_password', {'signup_token': partner.signup_token})
""",
        encoding="utf-8",
    )

    findings = scan_signup_tokens(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-signup-public-token-route" in rule_ids
    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids
    assert "odoo-signup-public-sudo-identity-flow" in rule_ids
    assert "odoo-signup-token-exposed" in rule_ids
    assert any(f.route == "/web/reset_password,/web/signup/reset" for f in findings)


def test_recursive_static_unpack_route_options_reset_token_write_is_critical(tmp_path: Path) -> None:
    """Recursive constants inside ** route options should preserve public reset severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

ROUTE_BASE = '/web/reset_password'
RESET_ROUTES = [ROUTE_BASE]
AUTH_BASE = 'none'
RESET_AUTH = AUTH_BASE
RESET_OPTIONS = {
    'routes': RESET_ROUTES,
    'auth': RESET_AUTH,
}
OPTIONS_ALIAS = RESET_OPTIONS

class Controller(http.Controller):
    @http.route(**OPTIONS_ALIAS)
    def reset_password(self, **kwargs):
        Users = request.env['res.users'].sudo()
        return Users.write({'signup_token': kwargs.get('token'), 'password': kwargs.get('password')})
""",
        encoding="utf-8",
    )

    findings = scan_signup_tokens(tmp_path)

    assert any(
        f.rule_id == "odoo-signup-tainted-identity-token-write"
        and f.severity == "critical"
        and f.route == "/web/reset_password"
        for f in findings
    )


def test_constant_alias_reset_model_token_fields_and_superuser_are_reported(tmp_path: Path) -> None:
    """Aliased model names, token fields, route metadata, and superusers should resolve."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

BASE_ROUTE = '/web/reset_password'
RESET_ROUTE = BASE_ROUTE
RESET_ROUTES = [RESET_ROUTE]
PUBLIC_AUTH = 'public'
RESET_AUTH = PUBLIC_AUTH
PARTNER_BASE = 'res.partner'
PARTNER_MODEL = PARTNER_BASE
USER_BASE = 'res.users'
USER_MODEL = USER_BASE
TOKEN_BASE = 'signup_token'
TOKEN_FIELD = TOKEN_BASE
PASSWORD_BASE = 'password'
PASSWORD_FIELD = PASSWORD_BASE
ROOT = SUPERUSER_ID

class Controller(http.Controller):
    @http.route(RESET_ROUTES, auth=RESET_AUTH, csrf=False)
    def reset_password(self, **kwargs):
        Partners = request.env[PARTNER_MODEL].with_user(ROOT)
        Users = request.env[USER_MODEL].sudo()
        token = kwargs.get('token')
        Partners.search([(TOKEN_FIELD, '=', token)], limit=1)
        return Users.write({TOKEN_FIELD: token, PASSWORD_FIELD: kwargs.get('password')})
""",
        encoding="utf-8",
    )

    findings = scan_signup_tokens(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-signup-public-token-route" in rule_ids
    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids
    assert "odoo-signup-tainted-identity-token-write" in rule_ids
    assert "odoo-signup-public-sudo-identity-flow" in rule_ids
    assert any(
        f.rule_id == "odoo-signup-tainted-token-lookup"
        and f.severity == "critical"
        and f.route == "/web/reset_password"
        for f in findings
    )


def test_class_constant_alias_reset_model_token_fields_and_superuser_are_reported(tmp_path: Path) -> None:
    """Class-scoped model names, token fields, route metadata, and superusers should resolve."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class Controller(http.Controller):
    BASE_ROUTE = '/web/reset_password'
    RESET_ROUTE = BASE_ROUTE
    RESET_ROUTES = [RESET_ROUTE]
    PUBLIC_AUTH = 'public'
    RESET_AUTH = PUBLIC_AUTH
    PARTNER_BASE = 'res.partner'
    PARTNER_MODEL = PARTNER_BASE
    USER_BASE = 'res.users'
    USER_MODEL = USER_BASE
    TOKEN_BASE = 'signup_token'
    TOKEN_FIELD = TOKEN_BASE
    PASSWORD_BASE = 'password'
    PASSWORD_FIELD = PASSWORD_BASE
    ROOT = SUPERUSER_ID

    @http.route(RESET_ROUTES, auth=RESET_AUTH, csrf=False)
    def reset_password(self, **kwargs):
        Partners = request.env[PARTNER_MODEL].with_user(ROOT)
        Users = request.env[USER_MODEL].sudo()
        token = kwargs.get('token')
        Partners.search([(TOKEN_FIELD, '=', token)], limit=1)
        return Users.write({TOKEN_FIELD: token, PASSWORD_FIELD: kwargs.get('password')})
""",
        encoding="utf-8",
    )

    findings = scan_signup_tokens(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-signup-public-token-route" in rule_ids
    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids
    assert "odoo-signup-tainted-identity-token-write" in rule_ids
    assert "odoo-signup-public-sudo-identity-flow" in rule_ids
    assert any(
        f.rule_id == "odoo-signup-tainted-token-lookup"
        and f.severity == "critical"
        and f.route == "/web/reset_password"
        for f in findings
    )


def test_keyword_constant_backed_none_reset_token_write_is_critical(tmp_path: Path) -> None:
    """Keyword route constants with auth='none' should keep reset token writes critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

RESET_ROUTE = '/web/reset_password'
RESET_AUTH = 'none'

class Controller(http.Controller):
    @http.route(route=RESET_ROUTE, auth=RESET_AUTH)
    def reset_password(self, **kwargs):
        Users = request.env['res.users'].sudo()
        return Users.write({'signup_token': kwargs.get('token'), 'password': kwargs.get('password')})
""",
        encoding="utf-8",
    )

    findings = scan_signup_tokens(tmp_path)

    assert any(
        f.rule_id == "odoo-signup-tainted-identity-token-write"
        and f.severity == "critical"
        and f.route == "/web/reset_password"
        for f in findings
    )


def test_signup_token_lookup_with_expiry_constraint_avoids_expiry_finding(tmp_path: Path) -> None:
    """Token lookup rules should distinguish visible expiry constraints."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http, fields
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        return request.env['res.partner'].sudo().search([
            ('signup_token', '=', kwargs.get('token')),
            ('signup_expiration', '>', fields.Datetime.now()),
        ], limit=1)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" not in rule_ids


def test_signup_token_search_count_without_expiry_is_reported(tmp_path: Path) -> None:
    """search_count() token probes need the same expiry review as search()."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        count = request.env['res.users'].sudo().search_count([
            ('signup_token', '=', kwargs.get('token')),
        ])
        return {'valid': bool(count)}
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids
    assert "odoo-signup-public-sudo-identity-flow" in rule_ids


def test_signup_token_search_count_with_expiry_constraint_avoids_expiry_finding(tmp_path: Path) -> None:
    """Visible expiry constraints should suppress the search_count() expiry finding."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import fields, http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        count = request.env['res.users'].sudo().search_count([
            ('signup_token', '=', kwargs.get('token')),
            ('signup_expiration', '>', fields.Datetime.now()),
        ])
        return {'valid': bool(count)}
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" not in rule_ids


def test_flags_aliased_identity_model_token_lookup(tmp_path: Path) -> None:
    """Token lookups are risky even when the identity model is assigned first."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        Partners = request.env['res.partner'].sudo()
        return Partners.search([('signup_token', '=', kwargs.get('token'))], limit=1)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids


def test_flags_aliased_identity_model_sudo_in_public_reset_flow(tmp_path: Path) -> None:
    """Public reset flows should flag sudo even when the identity model is aliased first."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        Users = request.env['res.users']
        return Users.sudo().search([('login', '=', kwargs.get('login'))], limit=1)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-public-sudo-identity-flow" in rule_ids


def test_flags_superuser_identity_access_in_public_reset_flow(tmp_path: Path) -> None:
    """Public reset flows should treat with_user(SUPERUSER_ID) like sudo."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        return request.env['res.users'].with_user(SUPERUSER_ID).search([('login', '=', kwargs.get('login'))], limit=1)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-public-sudo-identity-flow" in rule_ids


def test_flags_keyword_superuser_identity_access_in_public_reset_flow(tmp_path: Path) -> None:
    """Public reset flows should treat keyword with_user(user=SUPERUSER_ID) as sudo."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        return request.env['res.users'].with_user(user=SUPERUSER_ID).search([('login', '=', kwargs.get('login'))], limit=1)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-public-sudo-identity-flow" in rule_ids


def test_flags_aliased_superuser_identity_access_in_public_reset_flow(tmp_path: Path) -> None:
    """Aliased with_user(1) identity models should remain privileged reset-flow signals."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        Users = request.env['res.users'].with_user(1)
        return Users.search([('login', '=', kwargs.get('login'))], limit=1)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-public-sudo-identity-flow" in rule_ids


def test_flags_env_ref_admin_identity_access_in_public_reset_flow(tmp_path: Path) -> None:
    """Public reset flows should treat with_user(base.user_admin) like sudo."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        Users = request.env['res.users'].with_user(request.env.ref('base.user_admin'))
        return Users.search([('login', '=', kwargs.get('login'))], limit=1)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-public-sudo-identity-flow" in rule_ids


def test_reassigned_superuser_identity_alias_is_not_stale(tmp_path: Path) -> None:
    """Privileged identity aliases should clear after rebinding to a normal model."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        Users = request.env['res.users'].with_user(1)
        Users = request.env['res.users']
        return Users.search([('login', '=', kwargs.get('login'))], limit=1)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-public-sudo-identity-flow" not in rule_ids


def test_flags_aliased_identity_model_token_write(tmp_path: Path) -> None:
    """Aliased identity models should not hide tainted token/password writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        Users = request.env['res.users'].sudo()
        token, password = kwargs.get('token'), kwargs.get('password')
        return Users.write({'signup_token': token, 'password': password})
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-identity-token-write" in rule_ids


def test_flags_starred_unpacked_identity_model_token_lookup(tmp_path: Path) -> None:
    """Starred rest aliases should not hide request-derived signup token lookups."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        _, *items = ('fixed', request.env['res.partner'].sudo(), kwargs.get('token'))
        Partners = items[0]
        token = items[1]
        return Partners.search([('signup_token', '=', token)], limit=1)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids


def test_flags_starred_unpacked_identity_model_token_write(tmp_path: Path) -> None:
    """Starred rest aliases should not hide token/password mutation dictionaries."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        _, *items = (
            'fixed',
            request.env['res.users'].sudo(),
            {'signup_token': kwargs.get('token'), 'password': kwargs.get('password')},
        )
        Users = items[0]
        values = items[1]
        return Users.write(values)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-identity-token-write" in rule_ids


def test_reassigned_identity_model_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned identity model aliases should not keep token-write state."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        Users = request.env['res.users'].sudo()
        Users = request.env['product.template']
        return Users.write({'signup_token': kwargs.get('token'), 'password': kwargs.get('password')})
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-identity-token-write" not in rule_ids


def test_flags_direct_identity_token_assignment(tmp_path: Path) -> None:
    """Direct assignments to identity token/password fields are account mutation sinks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        partner = request.env['res.partner'].sudo().search([('signup_token', '=', kwargs.get('token'))], limit=1)
        user = request.env['res.users'].sudo().browse(kwargs.get('user_id'))
        partner.signup_token = kwargs.get('token')
        user.password = kwargs.get('password')
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_signup_tokens(tmp_path)

    assert sum(1 for f in findings if f.rule_id == "odoo-signup-tainted-identity-token-write") >= 2
    assert any(
        f.rule_id == "odoo-signup-tainted-identity-token-write"
        and f.severity == "critical"
        and f.sink == "partner.signup_token"
        for f in findings
    )


def test_flags_route_path_user_id_identity_token_assignment(tmp_path: Path) -> None:
    """Path-selected IDs are request input for reset/signup identity mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/users/<int:user_id>/reset', auth='public', csrf=False)
    def reset_user(self, user_id):
        user = request.env['res.users'].sudo().browse(user_id)
        user.password = user_id
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_signup_tokens(tmp_path)

    assert any(
        f.rule_id == "odoo-signup-tainted-identity-token-write"
        and f.severity == "critical"
        and f.sink == "user.password"
        for f in findings
    )


def test_internal_direct_identity_token_assignment_is_high(tmp_path: Path) -> None:
    """Internal direct token assignments should still be visible without public-route severity."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "users.py").write_text(
        """
def apply_token(self, token):
    user = self.env['res.users'].browse(self.env.context.get('uid'))
    user.signup_token = token
""",
        encoding="utf-8",
    )

    findings = scan_signup_tokens(tmp_path)

    assert any(
        f.rule_id == "odoo-signup-tainted-identity-token-write"
        and f.severity == "high"
        and f.sink == "user.signup_token"
        for f in findings
    )


def test_flags_keyword_vals_identity_token_write(tmp_path: Path) -> None:
    """Odoo write/create helpers often pass mutation dictionaries through vals=."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        Users = request.env['res.users'].sudo()
        values = {'signup_token': kwargs.get('token')}
        return Users.write(vals=values)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-identity-token-write" in rule_ids


def test_flags_incremental_identity_token_write_values(tmp_path: Path) -> None:
    """Token/password dictionaries are often built incrementally before write()."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        Users = request.env['res.users'].sudo()
        values = {}
        values['password'] = kwargs.get('password')
        return Users.write(values)
""",
        encoding="utf-8",
    )

    findings = scan_signup_tokens(tmp_path)

    assert any(
        finding.rule_id == "odoo-signup-tainted-identity-token-write"
        and finding.severity == "critical"
        and finding.sink == "Users.write"
        for finding in findings
    )


def test_safe_incremental_identity_token_write_value_is_ignored(tmp_path: Path) -> None:
    """Static service-issued token writes should not be treated as request-derived."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self):
        Users = request.env['res.users'].sudo()
        values = {}
        values['signup_token'] = 'service-issued-token'
        return Users.write(values)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-identity-token-write" not in rule_ids


def test_flags_comprehension_derived_token_lookup(tmp_path: Path) -> None:
    """Comprehension aliases over request data should stay tainted for token lookup."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self):
        payload = request.get_http_params()
        tokens = [token for token in payload.get('tokens', [])]
        return request.env['res.partner'].sudo().search([('signup_token', '=', tokens[0])], limit=1)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids


def test_flags_comprehension_filter_derived_token_lookup(tmp_path: Path) -> None:
    """Request-derived comprehension filters should taint signup token domains."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        token = kwargs.get('token')
        selected = [fallback for fallback in ['fallback'] if token][0]
        return request.env['res.partner'].sudo().search([('signup_token', '=', selected)], limit=1)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids


def test_flags_named_expression_derived_token_lookup(tmp_path: Path) -> None:
    """Walrus-bound signup tokens should remain tainted after the condition."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        if token := kwargs.get('token'):
            return request.env['res.partner'].sudo().search([('signup_token', '=', token)], limit=1)
        return request.env['res.partner']
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids


def test_flags_walrus_identity_model_token_lookup(tmp_path: Path) -> None:
    """Walrus-bound identity model aliases should not hide token lookups."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        if Partners := request.env['res.partner'].sudo():
            return Partners.search([('signup_token', '=', kwargs.get('token'))], limit=1)
        return False
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids


def test_flags_walrus_elevated_identity_access_in_public_reset_flow(tmp_path: Path) -> None:
    """Walrus-bound sudo identity aliases should remain privileged reset signals."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        if Users := request.env['res.users'].with_user(1):
            return Users.search([('login', '=', kwargs.get('login'))], limit=1)
        return False
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-public-sudo-identity-flow" in rule_ids


def test_walrus_reassigned_identity_model_alias_is_not_stale(tmp_path: Path) -> None:
    """Walrus rebinding should clear stale identity model aliases."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        if Users := request.env['res.users'].sudo():
            Users = request.env['product.template']
            return Users.write({'signup_token': kwargs.get('token'), 'password': kwargs.get('password')})
        return False
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-identity-token-write" not in rule_ids


def test_flags_walrus_token_mutation_values(tmp_path: Path) -> None:
    """Walrus-bound token/password dictionaries should be tracked into writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        Users = request.env['res.users'].sudo()
        if values := {'signup_token': kwargs.get('token'), 'password': kwargs.get('password')}:
            return Users.write(values)
        return False
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-identity-token-write" in rule_ids


def test_flags_walrus_identity_record_token_assignment(tmp_path: Path) -> None:
    """Walrus-bound identity records should be tracked for direct token writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        if user := request.env['res.users'].sudo().browse(kwargs.get('user_id')):
            user.password = kwargs.get('password')
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_signup_tokens(tmp_path)

    assert any(
        finding.rule_id == "odoo-signup-tainted-identity-token-write"
        and finding.severity == "critical"
        and finding.sink == "user.password"
        for finding in findings
    )


def test_flags_boolop_derived_token_lookup(tmp_path: Path) -> None:
    """Boolean fallback signup token aliases should not clear request taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        token = kwargs.get('token') or 'fixed-token'
        return request.env['res.partner'].sudo().search([('signup_token', '=', token)], limit=1)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids


def test_flags_loop_derived_token_lookup(tmp_path: Path) -> None:
    """Loop variables over request payloads should remain tainted for token domains."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        Partners = request.env['res.partner'].sudo()
        for token in kwargs.get('tokens', []):
            return Partners.search([('signup_token', '=', token)], limit=1)
        return False
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids


def test_safe_loop_reassignment_clears_signup_token_taint(tmp_path: Path) -> None:
    """Safe loop variables should clear stale request-token aliases before lookup."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        token = kwargs.get('token')
        for token in ['service-issued-token']:
            return request.env['res.partner'].sudo().search([('name', '=', token)], limit=1)
        return False
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-token-lookup" not in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" not in rule_ids


def test_reassigned_token_name_is_not_permanently_tainted(tmp_path: Path) -> None:
    """Token-like local names should not stay tainted after safe reassignment."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self, **kwargs):
        token = kwargs.get('token')
        token = 'service-issued-token'
        return request.env['res.partner'].sudo().search([('signup_token', '=', token)], limit=1)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-token-lookup" not in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" not in rule_ids


def test_public_reset_helper_with_tainted_input_is_reported(tmp_path: Path) -> None:
    """Request-driven reset helpers need anti-enumeration and throttling review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/auth/reset/send', auth='public', csrf=False)
    def send_reset(self, **kwargs):
        return request.env['res.users'].sudo().action_reset_password(kwargs.get('login'))
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-public-token-route" in rule_ids
    assert "odoo-signup-tainted-reset-trigger" in rule_ids


def test_request_alias_signup_token_lookup_is_reported(tmp_path: Path) -> None:
    """Aliased request objects should not hide reset-token lookup taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self):
        payload = req.get_http_params()
        return req.env['res.partner'].sudo().search([('signup_token', '=', payload.get('token'))], limit=1)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-token-lookup" in rule_ids
    assert "odoo-signup-token-lookup-without-expiry" in rule_ids


def test_request_alias_signup_token_write_is_reported(tmp_path: Path) -> None:
    """Aliased request payloads remain tainted for identity token/password writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "reset.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/web/reset_password', auth='public', csrf=False)
    def reset_password(self):
        payload = req.params
        Users = req.env['res.users'].sudo()
        return Users.write({'signup_token': payload.get('token'), 'password': payload.get('password')})
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_signup_tokens(tmp_path)}

    assert "odoo-signup-tainted-identity-token-write" in rule_ids


def test_safe_portal_token_forwarding_is_ignored(tmp_path: Path) -> None:
    """Portal token checks without identity mutation are covered elsewhere."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='user')
    def portal_order(self, order_id, access_token=None):
        order = self._document_check_access('sale.order', order_id, access_token=access_token)
        return {'name': order.name}
""",
        encoding="utf-8",
    )

    assert scan_signup_tokens(tmp_path) == []


def test_scanner_skips_test_fixtures(tmp_path: Path) -> None:
    """Repository tests can include intentionally unsafe reset snippets."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_reset.py").write_text(
        """
def test_reset(request, kwargs):
    return request.env['res.partner'].sudo().search([('signup_token', '=', kwargs.get('token'))])
""",
        encoding="utf-8",
    )

    assert scan_signup_tokens(tmp_path) == []
