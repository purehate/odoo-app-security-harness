"""Tests for Odoo portal route scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.portal_scanner import scan_portal_routes


def test_flags_portal_sudo_route_id_read_and_token_exposure(tmp_path: Path) -> None:
    """Portal routes should not sudo-read URL-selected records then expose tokens."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id, access_token=None):
        order = request.env['sale.order'].sudo().browse(order_id)
        return request.render('sale.portal_order_page', {'order': order, 'access_token': order.access_token})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-sudo-route-id-read" in rule_ids
    assert "odoo-portal-token-exposed-without-check" in rule_ids


def test_flags_public_portal_route_and_missing_token_forwarding(tmp_path: Path) -> None:
    """Shared portal routes should pass access_token into _document_check_access."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/invoices/<int:invoice_id>', auth='public', website=True)
    def portal_invoice(self, invoice_id, access_token=None):
        invoice = self._document_check_access('account.move', invoice_id)
        return request.render('account.portal_invoice_page', {'invoice': invoice})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-public-route" in rule_ids
    assert "odoo-portal-document-check-missing-token" in rule_ids
    assert "odoo-portal-sudo-route-id-read" not in rule_ids


def test_flags_access_token_argument_without_access_helper(tmp_path: Path) -> None:
    """Portal token parameters should be visibly validated, not merely accepted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='public', website=True)
    def portal_order(self, order_id, access_token=None):
        return request.render('sale.portal_order_page', {'order_id': order_id})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-access-token-without-helper" in rule_ids
    assert "odoo-portal-public-route" in rule_ids


def test_flags_imported_route_decorator_access_token_without_helper(tmp_path: Path) -> None:
    """Imported route decorators should still mark portal controllers as routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request, route

class Portal(http.Controller):
    @route('/my/orders/<int:order_id>', auth='public', website=True)
    def portal_order(self, order_id, access_token=None):
        return request.render('sale.portal_order_page', {'order_id': order_id})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-access-token-without-helper" in rule_ids
    assert "odoo-portal-public-route" in rule_ids


def test_flags_aliased_imported_route_decorator_access_token_without_helper(tmp_path: Path) -> None:
    """Aliased imported route decorators should still mark portal controllers as routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request, route as portal_route

class Portal(http.Controller):
    @portal_route('/my/orders/<int:order_id>', auth='public', website=True)
    def portal_order(self, order_id, access_token=None):
        return request.render('sale.portal_order_page', {'order_id': order_id})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-access-token-without-helper" in rule_ids
    assert "odoo-portal-public-route" in rule_ids


def test_flags_static_unpack_public_portal_route_options(tmp_path: Path) -> None:
    """Static route option unpacking should preserve public portal context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

ROUTE_OPTIONS = {
    'route': ['/my/orders/<int:order_id>', '/my/orders/<int:order_id>/print'],
    'auth': 'public',
    'website': True,
}

class Portal(http.Controller):
    @http.route(**ROUTE_OPTIONS)
    def portal_order(self, order_id, access_token=None):
        return request.render('sale.portal_order_page', {'order_id': order_id})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-public-route" in rule_ids
    assert "odoo-portal-access-token-without-helper" in rule_ids
    assert any(f.route == "/my/orders/<int:order_id>,/my/orders/<int:order_id>/print" for f in findings)


def test_flags_constant_backed_public_portal_route(tmp_path: Path) -> None:
    """Route constants should not hide public portal exposure."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

PORTAL_ROUTES = ['/my/orders/<int:order_id>', '/my/orders/<int:order_id>/print']
AUTH = 'public'
WEBSITE = True

class Portal(http.Controller):
    @http.route(PORTAL_ROUTES, auth=AUTH, website=WEBSITE)
    def portal_order(self, order_id, access_token=None):
        return request.render('sale.portal_order_page', {'order_id': order_id})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-public-route" in rule_ids
    assert "odoo-portal-access-token-without-helper" in rule_ids
    assert any(f.route == "/my/orders/<int:order_id>,/my/orders/<int:order_id>/print" for f in findings)


def test_flags_recursive_constant_backed_public_portal_route(tmp_path: Path) -> None:
    """Recursive route constants should not hide public portal exposure."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

ORDER_ROUTE = '/my/orders/<int:order_id>'
PRINT_ROUTE = '/my/orders/<int:order_id>/print'
PORTAL_ROUTES = [ORDER_ROUTE, PRINT_ROUTE]
ROUTE_ALIAS = PORTAL_ROUTES
PUBLIC_AUTH = 'public'
AUTH_ALIAS = PUBLIC_AUTH
WEBSITE_ENABLED = True
WEBSITE_ALIAS = WEBSITE_ENABLED

class Portal(http.Controller):
    @http.route(ROUTE_ALIAS, auth=AUTH_ALIAS, website=WEBSITE_ALIAS)
    def portal_order(self, order_id, access_token=None):
        return request.render('sale.portal_order_page', {'order_id': order_id})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-public-route" in rule_ids
    assert "odoo-portal-access-token-without-helper" in rule_ids
    assert any(f.route == "/my/orders/<int:order_id>,/my/orders/<int:order_id>/print" for f in findings)


def test_flags_keyword_constant_backed_portal_sudo_route_id_read(tmp_path: Path) -> None:
    """route= constants should still mark portal routes for sudo URL-id reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

PORTAL_ROUTE = '/my/orders/<int:order_id>'
AUTH = 'user'
WEBSITE = True

class Portal(http.Controller):
    @http.route(route=PORTAL_ROUTE, auth=AUTH, website=WEBSITE)
    def portal_order(self, order_id):
        order = request.env['sale.order'].sudo().browse(order_id)
        return request.render('sale.portal_order_page', {'order': order})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(
        f.rule_id == "odoo-portal-sudo-route-id-read" and f.route == "/my/orders/<int:order_id>"
        for f in findings
    )


def test_class_constant_backed_public_portal_route(tmp_path: Path) -> None:
    """Class-scoped route constants should not hide public portal exposure."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    ORDER_ROUTE = '/my/orders/<int:order_id>'
    PRINT_ROUTE = '/my/orders/<int:order_id>/print'
    PORTAL_ROUTES = [ORDER_ROUTE, PRINT_ROUTE]
    AUTH_PUBLIC = 'public'
    AUTH_ALIAS = AUTH_PUBLIC
    WEBSITE_ENABLED = True

    @http.route(PORTAL_ROUTES, auth=AUTH_ALIAS, website=WEBSITE_ENABLED)
    def portal_order(self, order_id, access_token=None):
        return request.render('sale.portal_order_page', {'order_id': order_id})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-public-route" in rule_ids
    assert "odoo-portal-access-token-without-helper" in rule_ids
    assert any(f.route == "/my/orders/<int:order_id>,/my/orders/<int:order_id>/print" for f in findings)


def test_class_constant_static_unpack_public_portal_route_options(tmp_path: Path) -> None:
    """Class-scoped static route option unpacking should preserve public portal context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    PORTAL_AUTH = 'public'
    ROUTE_OPTIONS = {
        'route': ['/my/orders/<int:order_id>', '/my/orders/<int:order_id>/print'],
        'auth': PORTAL_AUTH,
        'website': True,
    }

    @http.route(**ROUTE_OPTIONS)
    def portal_order(self, order_id, access_token=None):
        return request.render('sale.portal_order_page', {'order_id': order_id})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-public-route" in rule_ids
    assert "odoo-portal-access-token-without-helper" in rule_ids
    assert any(f.route == "/my/orders/<int:order_id>,/my/orders/<int:order_id>/print" for f in findings)


def test_flags_access_token_read_from_kwargs_without_access_helper(tmp_path: Path) -> None:
    """Portal routes often pull access_token from kw/kwargs instead of declaring it."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='public', website=True)
    def portal_order(self, order_id, **kw):
        token = kw.get('access_token')
        order = request.env['sale.order'].sudo().browse(order_id)
        return request.render('sale.portal_order_page', {'order': order, 'token': token})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-access-token-without-helper" in rule_ids
    assert "odoo-portal-sudo-route-id-read" in rule_ids


def test_flags_access_token_read_from_request_params_without_access_helper(tmp_path: Path) -> None:
    """Portal routes may read shared-link tokens directly from request.params."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='public', website=True)
    def portal_order(self, order_id):
        token = request.params.get('access_token')
        return request.render('sale.portal_order_page', {'token': token})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-access-token-without-helper" in rule_ids


def test_request_alias_access_token_read_without_access_helper(tmp_path: Path) -> None:
    """Request aliases should still expose access_token reads from params."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='public', website=True)
    def portal_order(self, order_id):
        token = req.params.get('access_token')
        return req.render('sale.portal_order_page', {'token': token})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-access-token-without-helper" in rule_ids


def test_flags_subscript_access_token_without_access_helper(tmp_path: Path) -> None:
    """Portal routes may read shared-link tokens through mapping subscripts."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='public', website=True)
    def portal_order(self, order_id, **kwargs):
        token = kwargs['access_token']
        return request.render('sale.portal_order_page', {'token': token})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-access-token-without-helper" in rule_ids


def test_flags_aliased_sudo_route_id_read(tmp_path: Path) -> None:
    """Portal sudo reads should remain visible when the sudo recordset is aliased."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id):
        Orders = request.env['sale.order'].sudo()
        order = Orders.browse(order_id)
        return request.render('sale.portal_order_page', {'order': order})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(f.rule_id == "odoo-portal-sudo-route-id-read" for f in findings)


def test_flags_sudo_search_count_route_id_read(tmp_path: Path) -> None:
    """Portal count probes over URL-selected records can disclose private record existence."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>/invoice-count', auth='user', website=True)
    def portal_invoice_count(self, order_id):
        count = request.env['account.move'].sudo().search_count([('invoice_origin_id', '=', order_id)])
        return request.render('account.portal_invoice_count', {'count': count})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(f.rule_id == "odoo-portal-sudo-route-id-read" and f.sink.endswith("search_count") for f in findings)


def test_flags_with_user_superuser_route_id_read(tmp_path: Path) -> None:
    """Portal superuser reads should be treated like sudo route-selected reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id):
        order = request.env['sale.order'].with_user(SUPERUSER_ID).browse(order_id)
        return request.render('sale.portal_order_page', {'order': order})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(f.rule_id == "odoo-portal-sudo-route-id-read" for f in findings)


def test_flags_recursive_constant_superuser_route_id_read(tmp_path: Path) -> None:
    """Recursive superuser aliases should be treated like sudo route-selected reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

ROOT_UID = 1
ADMIN_UID = ROOT_UID

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id):
        order = request.env['sale.order'].with_user(ADMIN_UID).browse(order_id)
        return request.render('sale.portal_order_page', {'order': order})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(f.rule_id == "odoo-portal-sudo-route-id-read" for f in findings)


def test_flags_local_constant_superuser_route_id_read(tmp_path: Path) -> None:
    """Function-local superuser aliases should be treated like sudo route-selected reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id):
        root_user = SUPERUSER_ID
        order = request.env['sale.order'].with_user(root_user).browse(order_id)
        return request.render('sale.portal_order_page', {'order': order})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(f.rule_id == "odoo-portal-sudo-route-id-read" for f in findings)


def test_flags_class_constant_superuser_route_id_read(tmp_path: Path) -> None:
    """Class-scoped superuser aliases should be treated like sudo route-selected reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class Portal(http.Controller):
    ROOT_UID = SUPERUSER_ID
    ADMIN_UID = ROOT_UID

    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id):
        order = request.env['sale.order'].with_user(ADMIN_UID).browse(order_id)
        return request.render('sale.portal_order_page', {'order': order})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(f.rule_id == "odoo-portal-sudo-route-id-read" for f in findings)


def test_flags_aliased_with_user_one_route_id_read(tmp_path: Path) -> None:
    """Aliased with_user(1) recordsets should count as elevated portal reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id):
        Orders = request.env['sale.order'].with_user(1)
        order = Orders.browse(order_id)
        return request.render('sale.portal_order_page', {'order': order})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(f.rule_id == "odoo-portal-sudo-route-id-read" for f in findings)


def test_flags_env_ref_root_route_id_read(tmp_path: Path) -> None:
    """Aliases elevated with base.user_root should count as privileged portal reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id):
        Orders = request.env['sale.order'].with_user(request.env.ref('base.user_root'))
        order = Orders.browse(order_id)
        return request.render('sale.portal_order_page', {'order': order})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(f.rule_id == "odoo-portal-sudo-route-id-read" for f in findings)


def test_flags_tuple_unpacked_sudo_route_id_read(tmp_path: Path) -> None:
    """Tuple-unpacked sudo recordsets should still count as privileged portal reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id):
        Orders, line_id = (request.env['sale.order'].sudo(), order_id)
        order = Orders.browse(line_id)
        return request.render('sale.portal_order_page', {'order': order})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(f.rule_id == "odoo-portal-sudo-route-id-read" for f in findings)


def test_flags_named_expression_sudo_route_id_read(tmp_path: Path) -> None:
    """Walrus-bound sudo recordsets should still count as privileged portal reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id):
        if Orders := request.env['sale.order'].sudo():
            order = Orders.browse(order_id)
            return request.render('sale.portal_order_page', {'order': order})
        return request.not_found()
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(f.rule_id == "odoo-portal-sudo-route-id-read" for f in findings)


def test_flags_starred_tuple_sudo_route_id_read(tmp_path: Path) -> None:
    """Starred sudo aliases should still count as privileged portal reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id):
        *Orders, line_id = request.env['sale.order'].sudo(), order_id
        order = Orders.browse(line_id)
        return request.render('sale.portal_order_page', {'order': order})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(f.rule_id == "odoo-portal-sudo-route-id-read" for f in findings)


def test_flags_starred_rest_sudo_route_id_read(tmp_path: Path) -> None:
    """Starred rest aliases should preserve privileged portal reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id):
        marker, *items, tail = 'x', request.env['sale.order'].sudo(), order_id, 'end'
        Orders = items[0]
        line_id = items[1]
        order = Orders.browse(line_id)
        return request.render('sale.portal_order_page', {'order': order})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(f.rule_id == "odoo-portal-sudo-route-id-read" for f in findings)


def test_flags_request_param_id_sudo_read_without_access_helper(tmp_path: Path) -> None:
    """Route-selected IDs can also be pulled from request parameter mappings."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders', auth='public', website=True)
    def portal_order(self):
        order_id = request.params.get('order_id')
        order = request.env['sale.order'].sudo().browse(order_id)
        return request.render('sale.portal_order_page', {'order': order})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(f.rule_id == "odoo-portal-sudo-route-id-read" for f in findings)


def test_flags_recursive_constant_request_param_keys(tmp_path: Path) -> None:
    """Recursive request parameter key constants should still mark tokens and route IDs."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

TOKEN_KEY = 'access_token'
TOKEN_ALIAS = TOKEN_KEY
ORDER_KEY = 'order_id'
ORDER_ALIAS = ORDER_KEY

class Portal(http.Controller):
    @http.route('/my/orders', auth='public', website=True)
    def portal_order(self):
        token = request.params.get(TOKEN_ALIAS)
        order_id = request.params[ORDER_ALIAS]
        order = request.env['sale.order'].sudo().browse(order_id)
        return request.render('sale.portal_order_page', {'order': order, 'token': token})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-access-token-without-helper" in rule_ids
    assert "odoo-portal-sudo-route-id-read" in rule_ids


def test_flags_local_constant_request_param_keys(tmp_path: Path) -> None:
    """Function-local request parameter key constants should still mark tokens and route IDs."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders', auth='public', website=True)
    def portal_order(self):
        token_key = 'access_token'
        order_key = 'order_id'
        token = request.params.get(token_key)
        order_id = request.params[order_key]
        order = request.env['sale.order'].sudo().browse(order_id)
        return request.render('sale.portal_order_page', {'order': order, 'token': token})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-access-token-without-helper" in rule_ids
    assert "odoo-portal-sudo-route-id-read" in rule_ids


def test_flags_class_constant_request_param_keys(tmp_path: Path) -> None:
    """Class-scoped request parameter key constants should still mark tokens and route IDs."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    TOKEN_KEY = 'access_token'
    TOKEN_ALIAS = TOKEN_KEY
    ORDER_KEY = 'order_id'
    ORDER_ALIAS = ORDER_KEY

    @http.route('/my/orders', auth='public', website=True)
    def portal_order(self):
        token = request.params.get(TOKEN_ALIAS)
        order_id = request.params[ORDER_ALIAS]
        order = request.env['sale.order'].sudo().browse(order_id)
        return request.render('sale.portal_order_page', {'order': order, 'token': token})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-access-token-without-helper" in rule_ids
    assert "odoo-portal-sudo-route-id-read" in rule_ids


def test_request_alias_param_id_sudo_read_without_access_helper(tmp_path: Path) -> None:
    """Request aliases should still mark param-selected sudo reads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Portal(http.Controller):
    @http.route('/my/orders', auth='public', website=True)
    def portal_order(self):
        order_id = req.params.get('order_id')
        order = req.env['sale.order'].sudo().browse(order_id)
        return req.render('sale.portal_order_page', {'order': order})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(f.rule_id == "odoo-portal-sudo-route-id-read" for f in findings)


def test_flags_subscript_request_param_id_sudo_read_without_access_helper(tmp_path: Path) -> None:
    """Subscripted request parameter IDs should still count as route-selected records."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders', auth='public', website=True)
    def portal_order(self):
        order_id = request.params['order_id']
        order = request.env['sale.order'].sudo().browse(order_id)
        return request.render('sale.portal_order_page', {'order': order})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(f.rule_id == "odoo-portal-sudo-route-id-read" for f in findings)


def test_flags_manual_access_token_comparison_without_helper(tmp_path: Path) -> None:
    """Custom access_token comparisons should not replace portal access helpers silently."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='public', website=True)
    def portal_order(self, order_id, access_token=None):
        order = request.env['sale.order'].sudo().browse(order_id)
        if access_token != order.access_token:
            return request.not_found()
        return request.render('sale.portal_order_page', {'order': order})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(
        f.rule_id == "odoo-portal-manual-access-token-check"
        and f.severity == "high"
        and "access_token != order.access_token" in f.sink
        for f in findings
    )


def test_flags_kwargs_access_token_not_forwarded_to_document_check(tmp_path: Path) -> None:
    """A token read from kwargs still needs to be passed into _document_check_access."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/invoices/<int:invoice_id>', auth='public', website=True)
    def portal_invoice(self, invoice_id, **kwargs):
        token = kwargs.get('access_token')
        invoice = self._document_check_access('account.move', invoice_id)
        return request.render('account.portal_invoice_page', {'invoice': invoice, 'token': token})
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)

    assert any(f.rule_id == "odoo-portal-document-check-missing-token" for f in findings)


def test_safe_portal_route_with_document_check_and_token_is_ignored(tmp_path: Path) -> None:
    """Standard portal access helpers with token forwarding should suppress risky read findings."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id, access_token=None):
        order = self._document_check_access('sale.order', order_id, access_token=access_token)
        return request.render('sale.portal_order_page', {'order': order})
""",
        encoding="utf-8",
    )

    assert scan_portal_routes(tmp_path) == []


def test_document_check_with_extra_manual_token_compare_does_not_duplicate(tmp_path: Path) -> None:
    """Visible portal helpers should suppress the manual comparison review lead."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http
from odoo.http import request

class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='user', website=True)
    def portal_order(self, order_id, access_token=None):
        order = self._document_check_access('sale.order', order_id, access_token=access_token)
        if access_token == order.access_token:
            return request.render('sale.portal_order_page', {'order': order})
        return request.not_found()
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_portal_routes(tmp_path)}

    assert "odoo-portal-manual-access-token-check" not in rule_ids


def test_generic_public_website_route_is_ignored(tmp_path: Path) -> None:
    """Plain website controllers should not be treated as portal routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Website(http.Controller):
    @http.route('/shop/product/<int:product_id>', auth='public', website=True)
    def product(self, product_id):
        product = request.env['product.template'].sudo().browse(product_id)
        return request.render('website_sale.product', {'product': product})
""",
        encoding="utf-8",
    )

    assert scan_portal_routes(tmp_path) == []


def test_flags_portal_url_generation_without_access_helper(tmp_path: Path) -> None:
    """Portal URL creation in portal routes should be tied to an access decision."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "portal.py").write_text(
        """
from odoo import http

class Portal(http.Controller):
    @http.route('/my/share/<int:order_id>', auth='user', website=True)
    def share_order(self, order_id):
        order = request.env['sale.order'].browse(order_id)
        return {'url': order.get_portal_url()}
""",
        encoding="utf-8",
    )

    findings = scan_portal_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-portal-url-generated-without-check" in rule_ids


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Controller fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_portal.py").write_text(
        """
class Portal(http.Controller):
    @http.route('/my/orders/<int:order_id>', auth='public', website=True)
    def portal_order(self, order_id):
        return request.env['sale.order'].sudo().browse(order_id)
""",
        encoding="utf-8",
    )

    assert scan_portal_routes(tmp_path) == []
