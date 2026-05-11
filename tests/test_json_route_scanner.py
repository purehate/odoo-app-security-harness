"""Tests for Odoo JSON route scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.json_route_scanner import scan_json_routes


def test_flags_public_json_route_with_csrf_disabled(tmp_path: Path) -> None:
    """Public JSON endpoints should be explicit review leads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http

class Api(http.Controller):
    @http.route('/api/public', auth='public', type='json', csrf=False)
    def public(self, **kwargs):
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-auth" in rule_ids
    assert "odoo-json-route-csrf-disabled" in rule_ids


def test_flags_imported_route_decorator_public_json_route(tmp_path: Path) -> None:
    """Imported route decorators should still mark JSON endpoints as routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import route

class Api(http.Controller):
    @route('/api/public', auth='public', type='json', csrf=False)
    def public(self, **kwargs):
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-auth" in rule_ids
    assert "odoo-json-route-csrf-disabled" in rule_ids


def test_flags_aliased_imported_route_decorator_public_json_route(tmp_path: Path) -> None:
    """Aliased imported route decorators should still mark JSON endpoints as routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import route as odoo_route

class Api(http.Controller):
    @odoo_route('/api/public', auth='public', type='json', csrf=False)
    def public(self, **kwargs):
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-auth" in rule_ids
    assert "odoo-json-route-csrf-disabled" in rule_ids


def test_flags_aliased_http_module_public_json_route(tmp_path: Path) -> None:
    """Aliased Odoo http modules should still mark JSON endpoints as routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http as odoo_http

class Api(odoo_http.Controller):
    @odoo_http.route('/api/public', auth='public', type='json', csrf=False)
    def public(self, **kwargs):
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-auth" in rule_ids
    assert "odoo-json-route-csrf-disabled" in rule_ids


def test_ignores_non_odoo_route_attribute(tmp_path: Path) -> None:
    """Arbitrary .route decorators should not be treated as Odoo JSON routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
class Bus:
    def route(self, path, **kwargs):
        return lambda func: func

bus = Bus()

class Api:
    @bus.route('/api/public', auth='public', type='json', csrf=False)
    def public(self, **kwargs):
        return {'ok': True}
""",
        encoding="utf-8",
    )

    assert scan_json_routes(tmp_path) == []


def test_flags_public_jsonrpc_route_with_csrf_disabled(tmp_path: Path) -> None:
    """Odoo's documented jsonrpc route type should be treated as JSON."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http

class Api(http.Controller):
    @http.route('/api/public', auth='public', type='jsonrpc', csrf=False)
    def public(self, **kwargs):
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-auth" in rule_ids
    assert "odoo-json-route-csrf-disabled" in rule_ids


def test_flags_constant_backed_public_json_route_options(tmp_path: Path) -> None:
    """Route decorator constants should not hide public JSON exposure."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http

ROUTES = ['/api/public', '/api/public/v2']
AUTH = 'public'
ROUTE_TYPE = 'json'
CSRF = False

class Api(http.Controller):
    @http.route(ROUTES, auth=AUTH, type=ROUTE_TYPE, csrf=CSRF)
    def public(self, **kwargs):
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-auth" in rule_ids
    assert "odoo-json-route-csrf-disabled" in rule_ids
    assert any(f.route == "/api/public,/api/public/v2" for f in findings)


def test_flags_class_constant_public_json_route_options(tmp_path: Path) -> None:
    """Class-body route constants should not hide public JSON exposure."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http

class Api(http.Controller):
    ROUTES = ['/api/public', '/api/public/v2']
    AUTH = 'public'
    ROUTE_TYPE = 'json'
    CSRF = False

    @http.route(ROUTES, auth=AUTH, type=ROUTE_TYPE, csrf=CSRF)
    def public(self, **kwargs):
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-auth" in rule_ids
    assert "odoo-json-route-csrf-disabled" in rule_ids
    assert any(f.route == "/api/public,/api/public/v2" for f in findings)


def test_flags_keyword_constant_backed_public_json_route_options(tmp_path: Path) -> None:
    """route= keyword constants should be resolved for JSON route posture."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http

ROUTE = '/api/public'
AUTH = 'none'
ROUTE_TYPE = 'jsonrpc'

class Api(http.Controller):
    @http.route(route=ROUTE, auth=AUTH, type=ROUTE_TYPE)
    def public(self, **kwargs):
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)

    assert any(
        f.rule_id == "odoo-json-route-public-auth" and f.severity == "critical" and f.route == "/api/public"
        for f in findings
    )


def test_flags_constant_alias_public_json_route_options(tmp_path: Path) -> None:
    """Recursive aliases in route paths and options should not hide JSON exposure."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http

ROUTE_BASE = '/api/public'
ROUTE = ROUTE_BASE
ROUTES = [ROUTE]
AUTH_BASE = 'public'
AUTH = AUTH_BASE
TYPE_BASE = 'json'
ROUTE_TYPE = TYPE_BASE
CSRF_BASE = False
CSRF = CSRF_BASE

class Api(http.Controller):
    @http.route(ROUTES, auth=AUTH, type=ROUTE_TYPE, csrf=CSRF)
    def public(self, **kwargs):
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-auth" in rule_ids
    assert "odoo-json-route-csrf-disabled" in rule_ids
    assert any(f.route == "/api/public" for f in findings)


def test_flags_static_unpack_route_options_public_json_route(tmp_path: Path) -> None:
    """Static ** route option dictionaries should not hide public JSON exposure."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http

JSON_OPTIONS = {
    'routes': ['/api/public', '/api/public/v2'],
    'auth': 'none',
    'type': 'jsonrpc',
    'csrf': False,
}

class Api(http.Controller):
    @http.route(**JSON_OPTIONS)
    def public(self, **kwargs):
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-auth" in rule_ids
    assert "odoo-json-route-csrf-disabled" in rule_ids
    assert any(f.route == "/api/public,/api/public/v2" for f in findings)


def test_flags_nested_static_unpack_route_options_public_json_route(tmp_path: Path) -> None:
    """Nested static ** route option dictionaries should preserve JSON exposure."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http

BASE_OPTIONS = {
    'auth': 'none',
    'type': 'jsonrpc',
}
JSON_OPTIONS = {
    **BASE_OPTIONS,
    'routes': ['/api/public', '/api/public/v2'],
    'csrf': False,
}

class Api(http.Controller):
    @http.route(**JSON_OPTIONS)
    def public(self, **kwargs):
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-auth" in rule_ids
    assert "odoo-json-route-csrf-disabled" in rule_ids
    assert any(f.route == "/api/public,/api/public/v2" for f in findings)


def test_flags_class_constant_static_unpack_route_options_public_json_route(tmp_path: Path) -> None:
    """Class-body ** route option dictionaries should preserve JSON route posture."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http

class Api(http.Controller):
    JSON_OPTIONS = {
        'routes': ['/api/public', '/api/public/v2'],
        'auth': 'none',
        'type': 'jsonrpc',
        'csrf': False,
    }

    @http.route(**JSON_OPTIONS)
    def public(self, **kwargs):
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-auth" in rule_ids
    assert "odoo-json-route-csrf-disabled" in rule_ids
    assert any(f.route == "/api/public,/api/public/v2" for f in findings)


def test_flags_recursive_static_unpack_route_options_public_json_route(tmp_path: Path) -> None:
    """Recursive constant aliases inside ** route options should be resolved."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http

ROUTE_BASE = '/api/public'
ROUTES = [ROUTE_BASE]
AUTH_BASE = 'public'
AUTH = AUTH_BASE
JSON_TYPE = 'json'
CSRF_DISABLED = False
JSON_OPTIONS = {
    'routes': ROUTES,
    'auth': AUTH,
    'type': JSON_TYPE,
    'csrf': CSRF_DISABLED,
}
OPTIONS_ALIAS = JSON_OPTIONS

class Api(http.Controller):
    @http.route(**OPTIONS_ALIAS)
    def public(self, **kwargs):
        return {'ok': True}
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-auth" in rule_ids
    assert "odoo-json-route-csrf-disabled" in rule_ids
    assert any(f.route == "/api/public" for f in findings)


def test_flags_json_sudo_mutation_and_mass_assignment(tmp_path: Path) -> None:
    """JSON request payloads should not flow straight into sudo create/write."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order', auth='public', type='json')
    def order(self):
        payload = request.jsonrequest
        return request.env['sale.order'].sudo().create(payload)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-sudo-mutation" in rule_ids
    assert "odoo-json-route-mass-assignment" in rule_ids


def test_flags_aliased_json_sudo_mutation_and_mass_assignment(tmp_path: Path) -> None:
    """JSON routes should not hide sudo mutations behind local aliases."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order', auth='public', type='json')
    def order(self):
        payload = request.jsonrequest
        Orders = request.env['sale.order'].sudo()
        return Orders.create(payload)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-sudo-mutation" in rule_ids
    assert "odoo-json-route-mass-assignment" in rule_ids


def test_flags_json_with_user_superuser_mutation_and_mass_assignment(tmp_path: Path) -> None:
    """Superuser with_user JSON mutations should be treated like sudo mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order', auth='public', type='json')
    def order(self):
        payload = request.jsonrequest
        return request.env['sale.order'].with_user(SUPERUSER_ID).create(payload)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-sudo-mutation" in rule_ids
    assert "odoo-json-route-mass-assignment" in rule_ids


def test_flags_constant_alias_json_with_user_superuser_mutation(tmp_path: Path) -> None:
    """Recursive SUPERUSER_ID aliases should still mark JSON ORM mutations as elevated."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

ROOT_BASE = SUPERUSER_ID
ROOT_UID = ROOT_BASE

class Api(http.Controller):
    @http.route('/api/order', auth='public', type='json')
    def order(self):
        payload = request.jsonrequest
        Orders = request.env['sale.order'].with_user(ROOT_UID)
        return Orders.create(payload)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-sudo-mutation" in rule_ids
    assert "odoo-json-route-mass-assignment" in rule_ids


def test_flags_local_constant_json_with_user_superuser_mutation(tmp_path: Path) -> None:
    """Function-local superuser aliases should still mark JSON ORM mutations as elevated."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order', auth='public', type='json')
    def order(self):
        admin_uid = 1
        payload = request.jsonrequest
        Orders = request.env['sale.order'].with_user(admin_uid)
        return Orders.create(payload)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-sudo-mutation" in rule_ids
    assert "odoo-json-route-mass-assignment" in rule_ids


def test_flags_aliased_json_with_user_one_mutation_and_mass_assignment(tmp_path: Path) -> None:
    """Aliased with_user(1) JSON mutations should be treated like sudo mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order', auth='public', type='json')
    def order(self):
        payload = request.jsonrequest
        Orders = request.env['sale.order'].with_user(1)
        return Orders.create(payload)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-sudo-mutation" in rule_ids
    assert "odoo-json-route-mass-assignment" in rule_ids


def test_flags_json_env_ref_admin_mutation_and_mass_assignment(tmp_path: Path) -> None:
    """with_user(base.user_admin) JSON mutations should be treated like sudo."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order', auth='public', type='json')
    def order(self):
        payload = request.jsonrequest
        Orders = request.env['sale.order'].with_user(request.env.ref('base.user_admin'))
        return Orders.create(payload)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-sudo-mutation" in rule_ids
    assert "odoo-json-route-mass-assignment" in rule_ids


def test_flags_unpacked_json_sudo_mutation_and_mass_assignment(tmp_path: Path) -> None:
    """Tuple-unpacked sudo aliases and payloads should stay visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order', auth='public', type='json')
    def order(self):
        Orders, payload = (request.env['sale.order'].sudo(), request.jsonrequest)
        return Orders.create(payload)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-sudo-mutation" in rule_ids
    assert "odoo-json-route-mass-assignment" in rule_ids


def test_flags_starred_unpacked_json_sudo_mutation_and_mass_assignment(tmp_path: Path) -> None:
    """Starred-unpacked sudo aliases and payloads should stay visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order', auth='public', type='json')
    def order(self):
        _, *items = ('fixed', request.env['sale.order'].sudo(), request.jsonrequest)
        Orders = items[0]
        payload = items[1]
        return Orders.create(payload)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-sudo-mutation" in rule_ids
    assert "odoo-json-route-mass-assignment" in rule_ids


def test_flags_get_json_data_mass_assignment(tmp_path: Path) -> None:
    """Odoo request.get_json_data() payloads should be treated as request-derived."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order', auth='public', type='json')
    def order(self):
        payload = request.get_json_data()
        return request.env['sale.order'].create(payload)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-mass-assignment" in rule_ids


def test_flags_request_alias_json_mass_assignment(tmp_path: Path) -> None:
    """Aliased Odoo request imports should still seed JSON payload taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Api(http.Controller):
    @http.route('/api/order', auth='public', type='json')
    def order(self):
        payload = req.get_json_data()
        return req.env['sale.order'].sudo().create(payload)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-sudo-mutation" in rule_ids
    assert "odoo-json-route-mass-assignment" in rule_ids


def test_flags_payload_argument_mass_assignment(tmp_path: Path) -> None:
    """Payload-like function arguments should still seed JSON mass-assignment taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order', auth='user', type='json')
    def order(self, payload):
        return request.env['sale.order'].create(payload)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)

    assert any(f.rule_id == "odoo-json-route-mass-assignment" for f in findings)


def test_reassigned_payload_alias_is_not_stale_for_mass_assignment(tmp_path: Path) -> None:
    """Reusing a JSON payload alias for safe static data should clear taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order', auth='public', type='json')
    def order(self):
        payload = request.jsonrequest
        payload = {'name': 'fixed'}
        return request.env['sale.order'].create(payload)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)

    assert not any(f.rule_id == "odoo-json-route-mass-assignment" for f in findings)


def test_flags_keyword_wrapped_json_payload_mass_assignment(tmp_path: Path) -> None:
    """Tainted JSON payloads wrapped through keyword calls should still be tracked."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order', auth='public', type='json')
    def order(self):
        values = dict(payload=request.get_json_data())
        return request.env['sale.order'].create(values)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-mass-assignment" in rule_ids


def test_named_expression_json_payload_mass_assignment_is_reported(tmp_path: Path) -> None:
    """Walrus-assigned JSON payloads should remain tainted for ORM mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order', auth='public', type='json')
    def order(self):
        if payload := request.get_json_data():
            return request.env['sale.order'].create(payload)
        return False
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)

    assert any(f.rule_id == "odoo-json-route-mass-assignment" for f in findings)


def test_ifexp_json_payload_mass_assignment_is_reported(tmp_path: Path) -> None:
    """Ternary JSON payload expressions should remain tainted for ORM mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order', auth='public', type='json')
    def order(self):
        values = request.get_json_data() if request.jsonrequest.get('use_payload') else {'name': 'fixed'}
        return request.env['sale.order'].create(values)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)

    assert any(f.rule_id == "odoo-json-route-mass-assignment" for f in findings)


def test_flags_route_path_id_json_mass_assignment(tmp_path: Path) -> None:
    """Route path IDs used in JSON mutation values are request-controlled."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order/<int:order_id>/line/<int:product_id>', auth='public', type='json')
    def add_line(self, order_id, product_id):
        return request.env['sale.order.line'].sudo().create({
            'order_id': order_id,
            'product_id': product_id,
        })
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-sudo-mutation" in rule_ids
    assert "odoo-json-route-mass-assignment" in rule_ids


def test_flags_tainted_browse_json_mutation(tmp_path: Path) -> None:
    """Request-controlled record selection before static JSON writes is still IDOR-prone."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order/<int:order_id>/confirm', auth='user', type='json')
    def confirm(self, order_id):
        return request.env['sale.order'].browse(order_id).write({'state': 'sale'})
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)

    assert any(f.rule_id == "odoo-json-route-tainted-record-mutation" and f.severity == "high" for f in findings)


def test_flags_tainted_browse_public_json_read(tmp_path: Path) -> None:
    """Public JSON reads selected by request IDs should be treated as IDOR leads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order/<int:order_id>', auth='public', type='json')
    def order(self, order_id):
        return request.env['sale.order'].sudo().browse(order_id).read(['name', 'amount_total'])
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-sudo-read" in rule_ids
    assert "odoo-json-route-tainted-record-read" in rule_ids
    assert any(f.rule_id == "odoo-json-route-tainted-record-read" and f.severity == "critical" for f in findings)


def test_flags_public_json_sudo_read_and_tainted_domain(tmp_path: Path) -> None:
    """Public JSON search APIs should not accept arbitrary domains under sudo."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/search', auth='none', type='json')
    def search(self):
        domain = request.jsonrequest.get('domain')
        return request.env['res.partner'].sudo().search_read(domain)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-sudo-read" in rule_ids
    assert "odoo-json-route-tainted-domain" in rule_ids


def test_flags_public_json_sudo_search_count_and_tainted_domain(tmp_path: Path) -> None:
    """Public JSON count APIs can disclose record existence through arbitrary domains."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/count', auth='public', type='json')
    def count(self):
        domain = request.jsonrequest.get('domain')
        return request.env['res.partner'].sudo().search_count(domain)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-sudo-read" in rule_ids
    assert "odoo-json-route-tainted-domain" in rule_ids


def test_flags_search_count_chain_as_tainted_record_read(tmp_path: Path) -> None:
    """Request-selected search_count() chains should be visible as JSON read IDOR leads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order/<int:partner_id>/count', auth='user', type='json')
    def count(self, partner_id):
        return request.env['sale.order'].search([('partner_id', '=', partner_id)]).search_count([])
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)

    assert any(f.rule_id == "odoo-json-route-tainted-record-read" and f.severity == "high" for f in findings)


def test_flags_keyword_public_json_sudo_read_and_tainted_domain(tmp_path: Path) -> None:
    """Keyword JSON search domains should get the same domain review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/search', auth='none', type='json')
    def search(self):
        domain = request.jsonrequest.get('domain')
        return request.env['res.partner'].sudo().search_read(domain=domain)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-sudo-read" in rule_ids
    assert "odoo-json-route-tainted-domain" in rule_ids


def test_flags_route_path_id_json_tainted_domain(tmp_path: Path) -> None:
    """JSON search domains built from route path IDs should be review leads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/order/<int:order_id>/lines', auth='none', type='json')
    def order_lines(self, order_id):
        return request.env['sale.order.line'].sudo().search_read([('order_id', '=', order_id)])
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-sudo-read" in rule_ids
    assert "odoo-json-route-tainted-domain" in rule_ids


def test_flags_comprehension_derived_tainted_domain(tmp_path: Path) -> None:
    """Domains derived through comprehensions over JSON payloads remain request-controlled."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/search', auth='none', type='json')
    def search(self):
        fields = [item for item in request.jsonrequest.get('fields')]
        domain = [(fields[0], '=', request.jsonrequest.get('value'))]
        return request.env['res.partner'].sudo().search_read(domain)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-sudo-read" in rule_ids
    assert "odoo-json-route-tainted-domain" in rule_ids


def test_flags_comprehension_filter_derived_tainted_domain(tmp_path: Path) -> None:
    """Request-only comprehension filters should taint generated JSON route domains."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/search', auth='none', type='json')
    def search(self):
        domain = [('active', '=', True) for _ in range(1) if request.jsonrequest.get('include')]
        return request.env['res.partner'].sudo().search_read(domain)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-sudo-read" in rule_ids
    assert "odoo-json-route-tainted-domain" in rule_ids


def test_flags_loop_derived_tainted_domain(tmp_path: Path) -> None:
    """Loop variables over JSON request data should stay tainted for search domains."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/search', auth='none', type='json')
    def search(self):
        for item in request.jsonrequest.get('domain'):
            return request.env['res.partner'].sudo().search_read([item])
        return []
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-sudo-read" in rule_ids
    assert "odoo-json-route-tainted-domain" in rule_ids


def test_flags_aliased_public_json_sudo_read_and_tainted_domain(tmp_path: Path) -> None:
    """Public JSON route sudo reads should be visible through local aliases."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/search', auth='none', type='json')
    def search(self):
        domain = request.jsonrequest.get('domain')
        Partners = request.env['res.partner'].sudo()
        return Partners.search_read(domain)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-sudo-read" in rule_ids
    assert "odoo-json-route-tainted-domain" in rule_ids


def test_flags_aliased_public_json_with_user_one_read_and_tainted_domain(tmp_path: Path) -> None:
    """Public JSON route with_user(1) reads should be visible through local aliases."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/search', auth='none', type='json')
    def search(self):
        domain = request.jsonrequest.get('domain')
        Partners = request.env['res.partner'].with_user(1)
        return Partners.search_read(domain)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-sudo-read" in rule_ids
    assert "odoo-json-route-tainted-domain" in rule_ids


def test_flags_local_constant_public_json_with_user_read_and_tainted_domain(tmp_path: Path) -> None:
    """Public JSON route reads should resolve local with_user superuser constants."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/search', auth='none', type='json')
    def search(self):
        admin_xmlid = 'base.user_admin'
        domain = request.jsonrequest.get('domain')
        Partners = request.env['res.partner'].with_user(admin_xmlid)
        return Partners.search_read(domain)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-sudo-read" in rule_ids
    assert "odoo-json-route-tainted-domain" in rule_ids


def test_flags_starred_public_json_sudo_read_and_tainted_domain(tmp_path: Path) -> None:
    """Starred-unpacked sudo read aliases and domains should stay visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http
from odoo.http import request

class Api(http.Controller):
    @http.route('/api/search', auth='none', type='json')
    def search(self):
        _, *items = ('fixed', request.env['res.partner'].sudo(), request.jsonrequest.get('domain'))
        Partners = items[0]
        domain = items[1]
        return Partners.search_read(domain)
""",
        encoding="utf-8",
    )

    findings = scan_json_routes(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-json-route-public-sudo-read" in rule_ids
    assert "odoo-json-route-tainted-domain" in rule_ids


def test_safe_user_json_route_is_ignored(tmp_path: Path) -> None:
    """Authenticated JSON routes without request-driven ORM should not be noisy."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "api.py").write_text(
        """
from odoo import http

class Api(http.Controller):
    @http.route('/api/ping', auth='user', type='json')
    def ping(self):
        return {'ok': True}
""",
        encoding="utf-8",
    )

    assert scan_json_routes(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Controller fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_api.py").write_text(
        """
class Api(http.Controller):
    @http.route('/api/public', auth='public', type='json')
    def public(self):
        return {}
""",
        encoding="utf-8",
    )

    assert scan_json_routes(tmp_path) == []
