"""Tests for risky Odoo route decorator security scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.route_security_scanner import scan_route_security


def test_flags_auth_none_route(tmp_path: Path) -> None:
    """auth='none' routes should be rare and explicit."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http

class Health(http.Controller):
    @http.route('/health/update', auth='none')
    def update(self):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)

    assert any(f.rule_id == "odoo-route-auth-none" for f in findings)


def test_flags_wildcard_cors_and_public_all_methods(tmp_path: Path) -> None:
    """Public routes with wildcard CORS and no methods restriction deserve review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "cors.py").write_text(
        """
from odoo import http

class Api(http.Controller):
    @http.route('/public/profile', auth='public', cors='*')
    def profile(self):
        return '{}'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-route-cors-wildcard" in rule_ids
    assert "odoo-route-public-all-methods" in rule_ids


def test_flags_constant_backed_public_route_options(tmp_path: Path) -> None:
    """Route decorator options are often hoisted to module constants."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "cors.py").write_text(
        """
from odoo import http

ROUTES = ['/public/profile']
AUTH = 'public'
CORS = '*'

class Api(http.Controller):
    @http.route(ROUTES, auth=AUTH, cors=CORS)
    def profile(self):
        return '{}'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-route-cors-wildcard" in rule_ids
    assert "odoo-route-public-all-methods" in rule_ids


def test_flags_class_constant_public_route_options(tmp_path: Path) -> None:
    """Class-body route option constants should be resolved for method decorators."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "cors.py").write_text(
        """
from odoo import http

class Api(http.Controller):
    ROUTE = '/public/profile'
    AUTH = 'public'
    CORS = '*'

    @http.route(ROUTE, auth=AUTH, cors=CORS)
    def profile(self):
        return '{}'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-route-cors-wildcard" in rule_ids
    assert "odoo-route-public-all-methods" in rule_ids
    assert any(f.route == "/public/profile" for f in findings)


def test_flags_constant_alias_public_route_options(tmp_path: Path) -> None:
    """Alias chains inside route option lists should not hide risky public routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "cors.py").write_text(
        """
from odoo import http

PUBLIC_ROUTE_BASE = '/public/profile'
PUBLIC_ROUTE = PUBLIC_ROUTE_BASE
ROUTES = [PUBLIC_ROUTE]
AUTH_BASE = 'public'
AUTH = AUTH_BASE
CORS_BASE = '*'
CORS = CORS_BASE

class Api(http.Controller):
    @http.route(ROUTES, auth=AUTH, cors=CORS)
    def profile(self):
        return '{}'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-route-cors-wildcard" in rule_ids
    assert "odoo-route-public-all-methods" in rule_ids
    assert any(f.route == "/public/profile" for f in findings)


def test_flags_static_unpack_public_route_options(tmp_path: Path) -> None:
    """Static **route options should preserve generic route posture checks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "cors.py").write_text(
        """
from odoo import http

PROFILE_ROUTE = '/public/profile'
PROFILE_OPTIONS = {'route': [PROFILE_ROUTE], 'auth': 'public', 'cors': '*'}

class Api(http.Controller):
    @http.route(**PROFILE_OPTIONS)
    def profile(self):
        return '{}'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-route-cors-wildcard" in rule_ids
    assert "odoo-route-public-all-methods" in rule_ids
    assert any(
        f.rule_id == "odoo-route-cors-wildcard" and f.severity == "high" and f.route == "/public/profile"
        for f in findings
    )


def test_flags_imported_route_decorator_options(tmp_path: Path) -> None:
    """Controllers may import route directly instead of using http.route."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "cors.py").write_text(
        """
from odoo import http
from odoo.http import route

class Api(http.Controller):
    @route('/public/profile', auth='public', cors='*')
    def profile(self):
        return '{}'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-route-cors-wildcard" in rule_ids
    assert "odoo-route-public-all-methods" in rule_ids


def test_flags_aliased_imported_route_decorator_options(tmp_path: Path) -> None:
    """Aliased imported route decorators should not hide route posture."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "cors.py").write_text(
        """
from odoo import http
from odoo.http import route as odoo_route

class Api(http.Controller):
    @odoo_route('/public/profile', auth='public', cors='*')
    def profile(self):
        return '{}'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-route-cors-wildcard" in rule_ids
    assert "odoo-route-public-all-methods" in rule_ids


def test_flags_aliased_http_module_route_options(tmp_path: Path) -> None:
    """Aliased Odoo http modules should still expose route posture."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "cors.py").write_text(
        """
from odoo import http as odoo_http

class Api(odoo_http.Controller):
    @odoo_http.route('/public/profile', auth='public', cors='*')
    def profile(self):
        return '{}'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-route-cors-wildcard" in rule_ids
    assert "odoo-route-public-all-methods" in rule_ids


def test_ignores_non_odoo_route_attribute(tmp_path: Path) -> None:
    """Arbitrary .route decorators should not be treated as Odoo controllers."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
class Bus:
    def route(self, path, **kwargs):
        return lambda func: func

bus = Bus()

class Api:
    @bus.route('/public/profile', auth='public', cors='*')
    def profile(self):
        return '{}'
""",
        encoding="utf-8",
    )

    assert scan_route_security(tmp_path) == []


def test_flags_csrf_disabled_on_mutating_route(tmp_path: Path) -> None:
    """Unsafe methods and mutating route names should not disable CSRF casually."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "upload.py").write_text(
        """
from odoo import http

class Upload(http.Controller):
    @http.route('/public/upload', auth='public', methods=['POST'], csrf=False)
    def upload(self, **kwargs):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)

    assert any(f.rule_id == "odoo-route-unsafe-csrf-disabled" for f in findings)


def test_flags_constant_backed_csrf_and_methods(tmp_path: Path) -> None:
    """Static method and csrf constants should still expose mutating public routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "upload.py").write_text(
        """
from odoo import http

METHODS = ['POST']
CSRF = False
WEBSITE = True
SITEMAP = False

class Upload(http.Controller):
    @http.route('/public/upload', auth='public', methods=METHODS, csrf=CSRF, website=WEBSITE, sitemap=SITEMAP)
    def upload(self, **kwargs):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-route-unsafe-csrf-disabled" in rule_ids
    assert "odoo-route-public-sitemap-indexed" not in rule_ids


def test_flags_class_constant_csrf_and_methods(tmp_path: Path) -> None:
    """Class-body methods/csrf constants should preserve route posture checks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "upload.py").write_text(
        """
from odoo import http

class Upload(http.Controller):
    METHODS = ['POST']
    CSRF = False
    WEBSITE = True
    SITEMAP = False

    @http.route('/public/upload', auth='public', methods=METHODS, csrf=CSRF, website=WEBSITE, sitemap=SITEMAP)
    def upload(self, **kwargs):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-route-unsafe-csrf-disabled" in rule_ids
    assert "odoo-route-public-sitemap-indexed" not in rule_ids


def test_flags_constant_alias_csrf_and_methods(tmp_path: Path) -> None:
    """Alias chains in methods/csrf/website/sitemap should preserve route posture."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "upload.py").write_text(
        """
from odoo import http

POST_METHOD = 'POST'
METHODS_BASE = [POST_METHOD]
METHODS = METHODS_BASE
CSRF_BASE = False
CSRF = CSRF_BASE
WEBSITE_BASE = True
WEBSITE = WEBSITE_BASE
SITEMAP_BASE = False
SITEMAP = SITEMAP_BASE

class Upload(http.Controller):
    @http.route('/public/upload', auth='public', methods=METHODS, csrf=CSRF, website=WEBSITE, sitemap=SITEMAP)
    def upload(self, **kwargs):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-route-unsafe-csrf-disabled" in rule_ids
    assert "odoo-route-public-sitemap-indexed" not in rule_ids


def test_flags_static_unpack_csrf_and_methods(tmp_path: Path) -> None:
    """Static **options should preserve csrf and method posture checks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "upload.py").write_text(
        """
from odoo import http

UPLOAD_OPTIONS = {
    'route': '/public/upload',
    'auth': 'public',
    'methods': ['POST'],
    'csrf': False,
    'website': True,
    'sitemap': False,
}

class Upload(http.Controller):
    @http.route(**UPLOAD_OPTIONS)
    def upload(self, **kwargs):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-route-unsafe-csrf-disabled" in rule_ids
    assert "odoo-route-csrf-disabled-all-methods" not in rule_ids
    assert "odoo-route-public-sitemap-indexed" not in rule_ids


def test_flags_public_csrf_disabled_without_methods(tmp_path: Path) -> None:
    """csrf=False public routes should still restrict allowed HTTP methods."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "webhook.py").write_text(
        """
from odoo import http

class Webhook(http.Controller):
    @http.route('/public/webhook', auth='public', csrf=False)
    def webhook(self, **kwargs):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)

    assert any(f.rule_id == "odoo-route-csrf-disabled-all-methods" for f in findings)


def test_flags_public_website_sitemap_indexing(tmp_path: Path) -> None:
    """Public website routes should opt out of sitemap when not intended for discovery."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "website.py").write_text(
        """
from odoo import http

class Website(http.Controller):
    @http.route('/my/private-offer', auth='public', website=True)
    def offer(self):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)

    assert any(f.rule_id == "odoo-route-public-sitemap-indexed" for f in findings)


def test_flags_bearer_route_that_saves_session(tmp_path: Path) -> None:
    """Bearer-token API routes should not casually persist browser sessions."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bearer.py").write_text(
        """
from odoo import http

class Api(http.Controller):
    @http.route('/api/token-sync', auth='bearer', methods=['POST'], save_session=True)
    def token_sync(self):
        return '{}'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)

    assert any(f.rule_id == "odoo-route-bearer-save-session" for f in findings)


def test_flags_constant_backed_bearer_save_session(tmp_path: Path) -> None:
    """Bearer save_session posture should be checked through static constants."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bearer.py").write_text(
        """
from odoo import http

AUTH = 'bearer'
SAVE_SESSION = True

class Api(http.Controller):
    @http.route('/api/token-sync', auth=AUTH, methods=['POST'], save_session=SAVE_SESSION)
    def token_sync(self):
        return '{}'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)

    assert any(f.rule_id == "odoo-route-bearer-save-session" for f in findings)


def test_flags_constant_alias_bearer_save_session(tmp_path: Path) -> None:
    """Alias chains should not hide bearer routes that persist browser sessions."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bearer.py").write_text(
        """
from odoo import http

AUTH_BASE = 'bearer'
AUTH = AUTH_BASE
SAVE_BASE = True
SAVE_SESSION = SAVE_BASE
POST_METHOD = 'POST'
METHODS = [POST_METHOD]

class Api(http.Controller):
    @http.route('/api/token-sync', auth=AUTH, methods=METHODS, save_session=SAVE_SESSION)
    def token_sync(self):
        return '{}'
""",
        encoding="utf-8",
    )

    findings = scan_route_security(tmp_path)

    assert any(f.rule_id == "odoo-route-bearer-save-session" for f in findings)


def test_safe_user_route_is_ignored(tmp_path: Path) -> None:
    """Authenticated routes with explicit safe methods should avoid decorator noise."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "safe.py").write_text(
        """
from odoo import http

class Safe(http.Controller):
    @http.route('/my/profile', auth='user', methods=['GET'], website=True, sitemap=False)
    def profile(self):
        return 'ok'
""",
        encoding="utf-8",
    )

    assert scan_route_security(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Route fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_route.py").write_text(
        """
from odoo import http

class Api(http.Controller):
    @http.route('/public/profile', auth='public', cors='*')
    def profile(self):
        return '{}'
""",
        encoding="utf-8",
    )

    assert scan_route_security(tmp_path) == []
