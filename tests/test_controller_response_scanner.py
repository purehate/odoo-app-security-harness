"""Tests for Odoo controller response scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.controller_response_scanner import scan_controller_responses


def test_flags_public_open_redirect(tmp_path: Path) -> None:
    """Public routes should not redirect to request-controlled URLs."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/go', auth='public')
    def go(self, **kwargs):
        return request.redirect(kwargs.get('next'))
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)


def test_imported_route_decorator_public_open_redirect(tmp_path: Path) -> None:
    """Imported route decorators should not hide public response sinks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request, route

class Controller(http.Controller):
    @route('/go', auth='public')
    def go(self, **kwargs):
        return request.redirect(kwargs.get('next'))
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)


def test_aliased_imported_route_decorator_public_open_redirect(tmp_path: Path) -> None:
    """Aliased imported route decorators should preserve public response severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request, route as odoo_route

class Controller(http.Controller):
    @odoo_route('/go', auth='public')
    def go(self, **kwargs):
        return request.redirect(kwargs.get('next'))
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)


def test_aliased_http_module_route_public_open_redirect(tmp_path: Path) -> None:
    """Aliased odoo.http module route decorators should remain recognized."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http as odoo_http
from odoo.http import request

class Controller(odoo_http.Controller):
    @odoo_http.route('/go', auth='public')
    def go(self, **kwargs):
        return request.redirect(kwargs.get('next'))
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)


def test_non_odoo_route_decorator_open_redirect_is_not_public(tmp_path: Path) -> None:
    """Local route decorators should not make response sinks public routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class Controller(http.Controller):
    @router.route('/go', auth='public')
    def go(self, **kwargs):
        return request.redirect(kwargs.get('next'))
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert not any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)
    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "medium" for f in findings)


def test_constant_backed_public_open_redirect(tmp_path: Path) -> None:
    """Constant-backed public auth should preserve open redirect severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

AUTH = 'public'

class Controller(http.Controller):
    @http.route('/go', auth=AUTH)
    def go(self, **kwargs):
        return request.redirect(kwargs.get('next'))
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)


def test_static_unpack_public_open_redirect(tmp_path: Path) -> None:
    """Static **route options should preserve public response severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

ROUTE_OPTIONS = {'auth': 'public', 'type': 'http'}

class Controller(http.Controller):
    @http.route('/go', **ROUTE_OPTIONS)
    def go(self, **kwargs):
        return request.redirect(kwargs.get('next'))
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)


def test_constant_alias_public_open_redirect(tmp_path: Path) -> None:
    """Recursive auth aliases should preserve public-route redirect severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

AUTH_BASE = 'public'
AUTH = AUTH_BASE

class Controller(http.Controller):
    @http.route('/go', auth=AUTH)
    def go(self, **kwargs):
        return request.redirect(kwargs.get('next'))
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)


def test_class_constant_alias_public_open_redirect(tmp_path: Path) -> None:
    """Class-scoped auth aliases should preserve public-route redirect severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    AUTH_BASE = 'public'
    AUTH = AUTH_BASE

    @http.route('/go', auth=AUTH)
    def go(self, **kwargs):
        return request.redirect(kwargs.get('next'))
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)


def test_class_constant_static_unpack_public_open_redirect(tmp_path: Path) -> None:
    """Class-scoped static **route options should preserve public response severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    ROUTE_OPTIONS = {'auth': 'public', 'type': 'http'}

    @http.route('/go', **ROUTE_OPTIONS)
    def go(self, **kwargs):
        return request.redirect(kwargs.get('next'))
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)


def test_flags_keyword_open_redirect(tmp_path: Path) -> None:
    """Redirect sinks often receive request-controlled targets as keyword args."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/go', auth='public')
    def go(self, **kwargs):
        target = kwargs.get('next')
        return request.redirect(location=target)
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)


def test_aliased_werkzeug_redirect_is_reported(tmp_path: Path) -> None:
    """Aliased Werkzeug redirect helpers should still scan tainted targets."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from werkzeug.utils import redirect as wz_redirect

class Controller(http.Controller):
    @http.route('/go', auth='public')
    def go(self, **kwargs):
        return wz_redirect(kwargs.get('next'))
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.sink == "werkzeug.utils.redirect" for f in findings)


def test_reassigned_redirect_target_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a redirect target for a safe local path should clear taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/go', auth='public')
    def go(self, **kwargs):
        target = kwargs.get('next')
        target = '/web'
        return request.redirect(target)
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert not any(f.rule_id == "odoo-controller-open-redirect" for f in findings)


def test_reassigned_redirect_name_is_not_permanently_tainted(tmp_path: Path) -> None:
    """Redirect-like local names should not stay tainted after safe reassignment."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/go', auth='public')
    def go(self, **kwargs):
        redirect = kwargs.get('next')
        redirect = '/web'
        return request.redirect(redirect)
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert not any(f.rule_id == "odoo-controller-open-redirect" for f in findings)


def test_flags_open_redirect_from_unpacking(tmp_path: Path) -> None:
    """Unpacked request values should remain tainted for redirect sinks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/go', auth='public')
    def go(self, **kwargs):
        label, target = 'next', kwargs.get('next')
        return request.redirect(target)
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)


def test_flags_open_redirect_from_starred_unpacking(tmp_path: Path) -> None:
    """Starred request values should remain tainted for redirect sinks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/go', auth='public')
    def go(self, **kwargs):
        *target, marker = kwargs.get('next'), 'x'
        return request.redirect(target)
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)


def test_flags_open_redirect_from_comprehension_alias(tmp_path: Path) -> None:
    """Comprehension aliases over request data should stay tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/go', auth='public')
    def go(self):
        payload = request.get_http_params()
        targets = [target for target in payload.get('next_urls', [])]
        return request.redirect(targets[0])
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)


def test_request_alias_public_open_redirect_is_reported(tmp_path: Path) -> None:
    """Aliased request redirects should not hide request-controlled targets."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/go', auth='public')
    def go(self):
        payload = req.get_http_params()
        return req.redirect(payload.get('next'))
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)


def test_flags_open_redirect_from_comprehension_filter(tmp_path: Path) -> None:
    """Request data in comprehension filters should taint the resulting redirect target."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/go', auth='public')
    def go(self):
        targets = ["/web" for value in ["ok"] if request.params.get('next')]
        return request.redirect(targets[0])
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)


def test_flags_open_redirect_from_named_expression(tmp_path: Path) -> None:
    """Walrus-bound redirect targets should remain tainted after the condition."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/go', auth='public')
    def go(self):
        if target := request.params.get('next'):
            return request.redirect(target)
        return request.redirect('/web')
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)


def test_flags_open_redirect_from_loop_alias(tmp_path: Path) -> None:
    """Loop variables over request data should remain tainted for redirect sinks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/go', auth='public')
    def go(self):
        for target in request.params.get('next_urls'):
            return request.redirect(target)
        return request.redirect('/web')
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-open-redirect" and f.severity == "high" for f in findings)


def test_flags_tainted_file_download(tmp_path: Path) -> None:
    """Controller file response paths should not come from request input."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.addons.web.controllers.main import send_file

class Controller(http.Controller):
    @http.route('/download', auth='user')
    def download(self, path=None):
        return send_file(path)
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-tainted-file-download" for f in findings)


def test_aliased_imported_send_file_tainted_file_download(tmp_path: Path) -> None:
    """Aliased imported send_file helpers should still scan tainted paths."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.addons.web.controllers.main import send_file as send_odoo_file

class Controller(http.Controller):
    @http.route('/download', auth='user')
    def download(self, **kwargs):
        return send_odoo_file(kwargs.get('path'))
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-tainted-file-download" and f.sink == "send_file" for f in findings)


def test_flags_keyword_tainted_file_download(tmp_path: Path) -> None:
    """File response helpers often receive paths through keyword arguments."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.addons.web.controllers.main import send_file

class Controller(http.Controller):
    @http.route('/download', auth='user')
    def download(self, **kwargs):
        return send_file(path=kwargs.get('path'))
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-tainted-file-download" for f in findings)


def test_flags_tainted_file_read_in_public_route(tmp_path: Path) -> None:
    """Controllers should not read request-controlled filesystem paths."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        with open(kwargs.get('path'), 'rb') as handle:
            return request.make_response(handle.read())
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(
        f.rule_id == "odoo-controller-tainted-file-read" and f.severity == "high" and f.sink == "open" for f in findings
    )


def test_flags_tainted_path_read_bytes_in_user_route(tmp_path: Path) -> None:
    """Path helpers should receive the same request-controlled read review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from pathlib import Path
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/download', auth='user')
    def download(self, path=None):
        return request.make_response(Path(path).read_bytes())
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(
        f.rule_id == "odoo-controller-tainted-file-read" and f.severity == "medium" and f.sink == "Path.read_bytes"
        for f in findings
    )


def test_flags_route_path_id_file_read(tmp_path: Path) -> None:
    """Route path IDs should be tainted when used to construct filesystem reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/file/<int:document_id>', auth='public')
    def download(self, document_id):
        with open(f'/srv/odoo/private/{document_id}.pdf', 'rb') as handle:
            return request.make_response(handle.read())
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(
        f.rule_id == "odoo-controller-tainted-file-read" and f.severity == "high" and f.sink == "open" for f in findings
    )


def test_aliased_imported_route_path_id_file_read(tmp_path: Path) -> None:
    """Aliased imported route decorators should taint route path parameters."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request, route as odoo_route

class Controller(http.Controller):
    @odoo_route('/public/file/<int:document_id>', auth='public')
    def download(self, document_id):
        with open(f'/srv/odoo/private/{document_id}.pdf', 'rb') as handle:
            return request.make_response(handle.read())
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(
        f.rule_id == "odoo-controller-tainted-file-read" and f.severity == "high" and f.sink == "open" for f in findings
    )


def test_static_file_read_is_ignored(tmp_path: Path) -> None:
    """Static template/help files should not look request-controlled."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/terms', auth='public')
    def terms(self):
        with open('/srv/odoo/static/terms.txt', 'rb') as handle:
            return request.make_response(handle.read())
""",
        encoding="utf-8",
    )

    assert scan_controller_responses(tmp_path) == []


def test_flags_tainted_headers_and_cookie_values(tmp_path: Path) -> None:
    """Response headers and cookie values should not be raw request input."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/export', auth='user')
    def export(self, **kwargs):
        response = request.make_response('ok', headers=[('Content-Disposition', kwargs.get('filename'))])
        response.set_cookie('download_name', kwargs.get('filename'))
        response.headers['X-Trace'] = kwargs.get('trace')
        return response
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-controller-response-header-injection" in rule_ids
    assert "odoo-controller-tainted-cookie-value" in rule_ids


def test_flags_keyword_tainted_cookie_value(tmp_path: Path) -> None:
    """Cookie value keyword arguments should receive the same taint checks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/export', auth='user')
    def export(self, **kwargs):
        response = request.make_response('ok')
        response.set_cookie('download_token', value=kwargs.get('token'))
        return response
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-tainted-cookie-value" for f in findings)


def test_flags_tainted_cookie_name(tmp_path: Path) -> None:
    """Cookie names should not be controlled by request input."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/preferences', auth='public')
    def preferences(self, **kwargs):
        response = request.make_response('ok')
        response.set_cookie(kwargs.get('cookie'), 'enabled')
        return response
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-tainted-cookie-name" for f in findings)


def test_flags_keyword_cookie_name_missing_security_flags(tmp_path: Path) -> None:
    """Keyword cookie names should still be checked for sensitive names."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/session-marker', auth='user')
    def marker(self):
        response = request.make_response('ok')
        response.set_cookie(key='session_marker', value='1')
        return response
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-cookie-missing-security-flags" for f in findings)


def test_flags_public_sensitive_token_dict_response(tmp_path: Path) -> None:
    """Public controller payloads should not return token-shaped credentials."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/public/signup-token', auth='public', type='json')
    def signup_token(self, partner_id):
        partner = request.env['res.partner'].sudo().browse(partner_id)
        return {'signup_token': partner.signup_token}
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(
        f.rule_id == "odoo-controller-sensitive-token-response" and f.severity == "high" and f.sink == "return"
        for f in findings
    )


def test_constant_backed_public_sensitive_token_dict_response(tmp_path: Path) -> None:
    """Constant-backed public auth should preserve token response severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http

AUTH = 'public'

class Controller(http.Controller):
    @http.route('/public/signup-token', auth=AUTH, type='json')
    def signup_token(self, partner_id):
        partner = request.env['res.partner'].sudo().browse(partner_id)
        return {'signup_token': partner.signup_token}
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(
        f.rule_id == "odoo-controller-sensitive-token-response" and f.severity == "high" and f.sink == "return"
        for f in findings
    )


def test_constant_alias_sensitive_token_dict_response(tmp_path: Path) -> None:
    """Constant-backed token-shaped response keys should still be reviewed."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http

AUTH_BASE = 'public'
AUTH = AUTH_BASE
TOKEN_KEY_BASE = 'signup_token'
TOKEN_KEY = TOKEN_KEY_BASE

class Controller(http.Controller):
    @http.route('/public/signup-token', auth=AUTH, type='json')
    def signup_token(self, partner_id):
        partner = request.env['res.partner'].sudo().browse(partner_id)
        return {TOKEN_KEY: partner.signup_token}
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(
        f.rule_id == "odoo-controller-sensitive-token-response" and f.severity == "high" and f.sink == "return"
        for f in findings
    )


def test_flags_sensitive_token_make_json_response(tmp_path: Path) -> None:
    """JSON response factories should receive the same token response review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/account/api-key', auth='user', type='json')
    def api_key(self):
        key = request.env.user.api_key
        return request.make_json_response({'api_key': key})
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(
        f.rule_id == "odoo-controller-sensitive-token-response"
        and f.severity == "medium"
        and f.sink == "request.make_json_response"
        for f in findings
    )


def test_flags_sensitive_token_keyword_make_json_response(tmp_path: Path) -> None:
    """Keyword response bodies should receive the same token response review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/account/api-key', auth='user', type='json')
    def api_key(self):
        key = request.env.user.api_key
        return request.make_json_response(data={'api_key': key})
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(
        f.rule_id == "odoo-controller-sensitive-token-response"
        and f.severity == "medium"
        and f.sink == "request.make_json_response"
        for f in findings
    )


def test_flags_public_tainted_html_make_response(tmp_path: Path) -> None:
    """Public controllers should not return request-derived HTML bodies."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/preview', auth='public')
    def preview(self, **kwargs):
        return request.make_response(kwargs.get('body'), headers=[('Content-Type', 'text/html; charset=utf-8')])
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(
        f.rule_id == "odoo-controller-tainted-html-response"
        and f.severity == "high"
        and f.sink == "request.make_response"
        for f in findings
    )


def test_flags_keyword_tainted_html_make_response(tmp_path: Path) -> None:
    """Response factory content_type keywords should trigger HTML taint checks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/preview', auth='user')
    def preview(self, body=None):
        return request.make_response(body, content_type='text/html')
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(
        f.rule_id == "odoo-controller-tainted-html-response"
        and f.severity == "medium"
        and f.sink == "request.make_response"
        for f in findings
    )


def test_static_html_make_response_ignored(tmp_path: Path) -> None:
    """Static reviewed HTML responses are not request-derived by themselves."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/health', auth='public')
    def health(self):
        return request.make_response('<strong>ok</strong>', mimetype='text/html')
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert not any(f.rule_id == "odoo-controller-tainted-html-response" for f in findings)


def test_walrus_response_factory_return_is_not_direct_html(tmp_path: Path) -> None:
    """Walrus-bound response objects should not be treated as raw direct returns."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/preview', auth='public')
    def preview(self, **kwargs):
        if response := request.make_response(kwargs.get('body')):
            return response
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert not any(f.rule_id == "odoo-controller-tainted-html-response" for f in findings)


def test_flags_public_direct_tainted_http_return(tmp_path: Path) -> None:
    """Direct string returns from HTTP routes are HTML responses in Odoo."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/preview', auth='public')
    def preview(self, **kwargs):
        return kwargs.get('body')
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(
        f.rule_id == "odoo-controller-tainted-html-response" and f.severity == "high" and f.sink == "return"
        for f in findings
    )


def test_direct_tainted_json_return_is_ignored_for_html(tmp_path: Path) -> None:
    """JSON routes can return request-derived values without becoming HTML responses."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/preview', auth='public', type='json')
    def preview(self, **kwargs):
        return kwargs.get('body')
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert not any(f.rule_id == "odoo-controller-tainted-html-response" for f in findings)


def test_safe_public_response_payload_is_ignored(tmp_path: Path) -> None:
    """Ordinary public JSON payloads should not be treated as credential leakage."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/public/status', auth='public', type='json')
    def status(self):
        return {'name': 'portal', 'status': 'ok'}
""",
        encoding="utf-8",
    )

    assert scan_controller_responses(tmp_path) == []


def test_flags_tainted_headers_and_cookie_values_from_unpacking(tmp_path: Path) -> None:
    """Unpacked request values should still taint headers and cookies."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/export', auth='user')
    def export(self, **kwargs):
        filename, token = kwargs.get('filename'), kwargs.get('token')
        response = request.make_response('ok')
        response.headers['Content-Disposition'] = filename
        response.set_cookie('download_token', token)
        return response
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-controller-response-header-injection" in rule_ids
    assert "odoo-controller-tainted-cookie-value" in rule_ids


def test_flags_tainted_headers_and_cookie_values_from_starred_unpacking(tmp_path: Path) -> None:
    """Starred request values should still taint headers and cookies."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/export', auth='user')
    def export(self, **kwargs):
        *filename, token = kwargs.get('filename'), kwargs.get('token')
        response = request.make_response('ok')
        response.headers['Content-Disposition'] = filename
        response.set_cookie('download_token', token)
        return response
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-controller-response-header-injection" in rule_ids
    assert "odoo-controller-tainted-cookie-value" in rule_ids


def test_flags_tainted_headers_and_cookie_values_from_starred_rest_unpacking(tmp_path: Path) -> None:
    """Starred-rest request values should still taint headers and cookies."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/export', auth='user')
    def export(self, **kwargs):
        label, *items = 'export', kwargs.get('filename'), kwargs.get('token')
        filename = items[0]
        token = items[1]
        response = request.make_response('ok')
        response.headers['Content-Disposition'] = filename
        response.set_cookie('download_token', token)
        return response
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-controller-response-header-injection" in rule_ids
    assert "odoo-controller-tainted-cookie-value" in rule_ids


def test_boolop_derived_header_value_is_reported(tmp_path: Path) -> None:
    """Boolean fallback header expressions should not clear request taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/export', auth='user')
    def export(self, **kwargs):
        filename = kwargs.get('filename') or 'report.csv'
        response = request.make_response('ok')
        response.headers['Content-Disposition'] = filename
        return response
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-response-header-injection" for f in findings)


def test_flags_route_path_header_value(tmp_path: Path) -> None:
    """Arbitrary route path parameters should be tainted in response headers."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/export/<string:download_name>', auth='public')
    def export(self, download_name):
        response = request.make_response('ok')
        response.headers['Content-Disposition'] = download_name
        return response
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-response-header-injection" for f in findings)


def test_flags_make_json_response_tainted_headers(tmp_path: Path) -> None:
    """JSON response helpers can set unsafe request-derived headers too."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/export', auth='user', type='json')
    def export(self, **kwargs):
        return request.make_json_response({'ok': True}, headers={'Content-Disposition': kwargs.get('filename')})
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-response-header-injection" for f in findings)


def test_request_alias_make_json_response_tainted_headers(tmp_path: Path) -> None:
    """Aliased request response factories should still scan tainted headers."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/response', auth='user', type='json')
    def response(self):
        return req.make_json_response({'ok': True}, headers={'Content-Disposition': req.params.get('filename')})
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-response-header-injection" for f in findings)


def test_flags_imported_make_json_response_tainted_headers(tmp_path: Path) -> None:
    """Imported JSON response helpers should use the same header checks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import make_json_response

class Controller(http.Controller):
    @http.route('/export', auth='user', type='json')
    def export(self, **kwargs):
        headers = {'X-Trace': kwargs.get('trace')}
        return make_json_response({'ok': True}, headers=headers)
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-response-header-injection" for f in findings)


def test_flags_header_mutation_helpers_and_sensitive_cookie_flags(tmp_path: Path) -> None:
    """Header helper methods and sensitive cookies need the same response review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/export', auth='user')
    def export(self, **kwargs):
        response = request.make_response('ok')
        response.headers.update({'Content-Disposition': content_disposition(kwargs.get('filename'))})
        response.headers.add('X-Trace', kwargs.get('trace'))
        response.set_cookie('session_token', kwargs.get('token'))
        return response
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-controller-response-header-injection" in rule_ids
    assert "odoo-controller-tainted-cookie-value" in rule_ids
    assert "odoo-controller-cookie-missing-security-flags" in rule_ids


def test_flags_tainted_x_accel_redirect_header(tmp_path: Path) -> None:
    """Internal file offload headers should not be request-controlled."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/offload', auth='public')
    def offload(self, **kwargs):
        response = request.make_response('')
        response.headers['X-Accel-Redirect'] = kwargs.get('path')
        return response
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(
        f.rule_id == "odoo-controller-tainted-file-offload-header" and f.severity == "high" and f.sink == "headers"
        for f in findings
    )


def test_flags_tainted_x_sendfile_header_update(tmp_path: Path) -> None:
    """Header update helpers should keep X-Sendfile path risk visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/offload', auth='user')
    def offload(self, **kwargs):
        response = request.make_response('')
        response.headers.update({'X-Sendfile': kwargs.get('path')})
        return response
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(
        f.rule_id == "odoo-controller-tainted-file-offload-header"
        and f.severity == "medium"
        and f.sink == "response.headers.update"
        for f in findings
    )


def test_flags_tainted_file_offload_header_from_response_factory(tmp_path: Path) -> None:
    """Response factory headers should include file offload path checks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/offload', auth='public')
    def offload(self, **kwargs):
        return request.make_response('', headers=[('X-Accel-Redirect', kwargs.get('path'))])
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-tainted-file-offload-header" for f in findings)


def test_flags_route_path_id_file_offload_header(tmp_path: Path) -> None:
    """Route path IDs should be tainted in internal offload headers."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/offload/<int:attachment_id>', auth='public')
    def offload(self, attachment_id):
        response = request.make_response('')
        response.headers['X-Accel-Redirect'] = f'/internal/attachments/{attachment_id}'
        return response
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(
        f.rule_id == "odoo-controller-tainted-file-offload-header" and f.severity == "high" and f.sink == "headers"
        for f in findings
    )


def test_flags_public_wildcard_cors_header_from_response_factory(tmp_path: Path) -> None:
    """Public controllers should not casually allow every CORS origin."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/api', auth='public')
    def export(self):
        return request.make_response('ok', headers=[('Access-Control-Allow-Origin', '*')])
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-cors-wildcard-origin" and f.severity == "high" for f in findings)


def test_flags_public_reflected_origin_cors_header(tmp_path: Path) -> None:
    """Public controllers should not reflect arbitrary request origins into CORS."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/api', auth='public')
    def export(self):
        origin = request.httprequest.headers.get('Origin')
        response = request.make_response('ok')
        response.headers['Access-Control-Allow-Origin'] = origin
        return response
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-cors-reflected-origin" and f.severity == "high" for f in findings)


def test_flags_user_reflected_origin_cors_header_from_response_factory(tmp_path: Path) -> None:
    """Response factory headers should receive reflected-origin CORS review too."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/api', auth='user')
    def export(self):
        return request.make_response('ok', headers={'Access-Control-Allow-Origin': request.params.get('origin')})
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(
        f.rule_id == "odoo-controller-cors-reflected-origin"
        and f.severity == "medium"
        and f.sink == "request.make_response"
        for f in findings
    )


def test_constant_alias_public_wildcard_cors_header_from_response_factory(tmp_path: Path) -> None:
    """Constant-backed header names and values should not hide wildcard CORS."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

AUTH_BASE = 'public'
AUTH = AUTH_BASE
HEADER_BASE = 'Access-Control-Allow-Origin'
HEADER_NAME = HEADER_BASE
WILDCARD_BASE = '*'
WILDCARD = WILDCARD_BASE
HEADERS = [(HEADER_NAME, WILDCARD)]

class Controller(http.Controller):
    @http.route('/public/api', auth=AUTH)
    def export(self):
        return request.make_response('ok', headers=HEADERS)
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-cors-wildcard-origin" and f.severity == "high" for f in findings)


def test_local_alias_public_wildcard_cors_header_from_response_factory(tmp_path: Path) -> None:
    """Route-local header aliases should not hide wildcard CORS."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/api', auth='public')
    def export(self):
        header_name = 'Access-Control-Allow-Origin'
        wildcard = '*'
        headers = [(header_name, wildcard)]
        return request.make_response('ok', headers=headers)
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-cors-wildcard-origin" and f.severity == "high" for f in findings)


def test_walrus_wildcard_cors_header_from_header_mutation(tmp_path: Path) -> None:
    """Walrus-bound wildcard header values should not hide CORS mutation risks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/api', auth='user')
    def export(self):
        response = request.make_response('ok')
        if wildcard := '*':
            response.headers['Access-Control-Allow-Origin'] = wildcard
        return response
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-cors-wildcard-origin" and f.severity == "medium" for f in findings)


def test_flags_wildcard_cors_header_from_header_mutation(tmp_path: Path) -> None:
    """Wildcard CORS can be introduced after response creation."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/api', auth='user')
    def export(self):
        response = request.make_response('ok')
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers.update({'Access-Control-Allow-Origin': '*'})
        return response
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(f.rule_id == "odoo-controller-cors-wildcard-origin" and f.severity == "medium" for f in findings)


def test_flags_weak_csp_header_from_response_factory(tmp_path: Path) -> None:
    """Controller CSP headers should not rely on unsafe script allowances."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/page', auth='public')
    def page(self):
        return request.make_response('ok', headers={'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-inline'"})
""",
        encoding="utf-8",
    )

    findings = scan_controller_responses(tmp_path)

    assert any(
        f.rule_id == "odoo-controller-weak-csp-header"
        and f.severity == "medium"
        and "'unsafe-inline'" in f.message
        for f in findings
    )


def test_strict_csp_header_is_ignored(tmp_path: Path) -> None:
    """Static CSP headers without unsafe allowances should avoid CSP noise."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/page', auth='public')
    def page(self):
        response = request.make_response('ok')
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
        return response
""",
        encoding="utf-8",
    )

    assert scan_controller_responses(tmp_path) == []


def test_sensitive_cookie_with_security_flags_is_ignored(tmp_path: Path) -> None:
    """Explicit HttpOnly/Secure/SameSite flags suppress the cookie posture warning."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/export', auth='user')
    def export(self):
        response = request.make_response('ok')
        response.set_cookie('session_token', 'fixed', httponly=True, secure=True, samesite='Lax')
        return response
""",
        encoding="utf-8",
    )

    assert scan_controller_responses(tmp_path) == []


def test_sensitive_cookie_with_constant_alias_security_flags_is_ignored(tmp_path: Path) -> None:
    """Constant-backed cookie hardening flags should suppress the posture warning."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "response.py").write_text(
        """
from odoo import http
from odoo.http import request

COOKIE_BASE = 'session_token'
COOKIE_NAME = COOKIE_BASE
HTTPONLY_BASE = True
HTTPONLY = HTTPONLY_BASE
SECURE_BASE = True
SECURE = SECURE_BASE
SAMESITE_BASE = 'Lax'
SAMESITE = SAMESITE_BASE

class Controller(http.Controller):
    @http.route('/export', auth='user')
    def export(self):
        response = request.make_response('ok')
        response.set_cookie(COOKIE_NAME, 'fixed', httponly=HTTPONLY, secure=SECURE, samesite=SAMESITE)
        return response
""",
        encoding="utf-8",
    )

    assert scan_controller_responses(tmp_path) == []


def test_safe_static_redirect_is_ignored(tmp_path: Path) -> None:
    """Static local redirects should not produce findings."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/go', auth='public')
    def go(self):
        return request.redirect('/web')
""",
        encoding="utf-8",
    )

    assert scan_controller_responses(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Controller fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_controller.py").write_text(
        """
def test_redirect(kwargs):
    return request.redirect(kwargs.get('next'))
""",
        encoding="utf-8",
    )

    assert scan_controller_responses(tmp_path) == []
