"""Tests for Odoo realtime bus/notification scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.realtime_scanner import scan_realtime


def test_flags_public_route_bus_send_with_sensitive_payload(tmp_path: Path) -> None:
    """Public routes sending bus notifications need channel/payload review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http
from odoo.http import request

class BusController(http.Controller):
    @http.route('/public/bus', auth='public')
    def bus(self, **kwargs):
        payload = {'email': kwargs.get('email'), 'access_token': kwargs.get('token')}
        request.env['bus.bus']._sendone('public_notifications', payload)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-public-route-bus-send" in rule_ids
    assert "odoo-realtime-broad-or-tainted-channel" in rule_ids
    assert "odoo-realtime-sensitive-payload" in rule_ids


def test_imported_route_decorator_public_bus_send_with_sensitive_payload(tmp_path: Path) -> None:
    """Imported route decorators should not hide public bus sends."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http
from odoo.http import request, route

class BusController(http.Controller):
    @route('/public/bus', auth='public')
    def bus(self, **kwargs):
        payload = {'email': kwargs.get('email'), 'access_token': kwargs.get('token')}
        request.env['bus.bus']._sendone('public_notifications', payload)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-public-route-bus-send" in rule_ids
    assert "odoo-realtime-broad-or-tainted-channel" in rule_ids
    assert "odoo-realtime-sensitive-payload" in rule_ids


def test_aliased_imported_route_decorator_public_bus_send_with_sensitive_payload(tmp_path: Path) -> None:
    """Aliased imported route decorators should not hide public bus sends."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http
from odoo.http import request, route as web_route

class BusController(http.Controller):
    @web_route('/public/bus', auth='public')
    def bus(self, **kwargs):
        payload = {'email': kwargs.get('email'), 'access_token': kwargs.get('token')}
        request.env['bus.bus']._sendone('public_notifications', payload)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-public-route-bus-send" in rule_ids
    assert "odoo-realtime-broad-or-tainted-channel" in rule_ids
    assert "odoo-realtime-sensitive-payload" in rule_ids


def test_aliased_http_module_route_public_bus_send_with_sensitive_payload(tmp_path: Path) -> None:
    """Aliased odoo.http module route decorators should remain recognized."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http as odoo_http
from odoo.http import request

class BusController(odoo_http.Controller):
    @odoo_http.route('/public/bus', auth='public')
    def bus(self, **kwargs):
        payload = {'email': kwargs.get('email'), 'access_token': kwargs.get('token')}
        request.env['bus.bus']._sendone('public_notifications', payload)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-public-route-bus-send" in rule_ids
    assert "odoo-realtime-broad-or-tainted-channel" in rule_ids
    assert "odoo-realtime-sensitive-payload" in rule_ids


def test_non_odoo_route_decorator_bus_send_is_not_public_route(tmp_path: Path) -> None:
    """Local route decorators should not make bus sends public routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http
from odoo.http import request

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class BusController(http.Controller):
    @router.route('/public/bus', auth='public')
    def bus(self, **kwargs):
        payload = {'email': kwargs.get('email'), 'access_token': kwargs.get('token')}
        request.env['bus.bus']._sendone('public_notifications', payload)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-public-route-bus-send" not in rule_ids
    assert "odoo-realtime-broad-or-tainted-channel" in rule_ids
    assert "odoo-realtime-sensitive-payload" in rule_ids


def test_constant_backed_public_bus_send_with_sensitive_payload(tmp_path: Path) -> None:
    """Constant-backed public route auth should still expose bus sends."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http
from odoo.http import request

BUS_ROUTES = ['/public/bus', '/public/bus/alt']
BUS_AUTH = 'public'

class BusController(http.Controller):
    @http.route(BUS_ROUTES, auth=BUS_AUTH)
    def bus(self, **kwargs):
        payload = {'email': kwargs.get('email'), 'access_token': kwargs.get('token')}
        request.env['bus.bus']._sendone('public_notifications', payload)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-public-route-bus-send" in rule_ids
    assert "odoo-realtime-broad-or-tainted-channel" in rule_ids
    assert "odoo-realtime-sensitive-payload" in rule_ids


def test_static_unpack_public_bus_send_with_sensitive_payload(tmp_path: Path) -> None:
    """Static **route options should not hide public bus sends."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http
from odoo.http import request

BUS_OPTIONS = {'route': '/public/bus', 'auth': 'public'}

class BusController(http.Controller):
    @http.route(**BUS_OPTIONS)
    def bus(self, **kwargs):
        payload = {'email': kwargs.get('email'), 'access_token': kwargs.get('token')}
        request.env['bus.bus']._sendone('public_notifications', payload)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-public-route-bus-send" in rule_ids
    assert "odoo-realtime-broad-or-tainted-channel" in rule_ids
    assert "odoo-realtime-sensitive-payload" in rule_ids


def test_class_constant_backed_public_bus_send_with_sensitive_payload(tmp_path: Path) -> None:
    """Class-scoped public route constants should still expose bus sends."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http
from odoo.http import request

class BusController(http.Controller):
    BUS_ROUTES = ['/public/bus', '/public/bus/alt']
    BUS_AUTH = 'public'

    @http.route(BUS_ROUTES, auth=BUS_AUTH)
    def bus(self, **kwargs):
        payload = {'email': kwargs.get('email'), 'access_token': kwargs.get('token')}
        request.env['bus.bus']._sendone('public_notifications', payload)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-public-route-bus-send" in rule_ids
    assert "odoo-realtime-broad-or-tainted-channel" in rule_ids
    assert "odoo-realtime-sensitive-payload" in rule_ids


def test_class_constant_static_unpack_public_bus_send_with_sensitive_payload(tmp_path: Path) -> None:
    """Class-scoped static **route options should not hide public bus sends."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http
from odoo.http import request

class BusController(http.Controller):
    BUS_OPTIONS = {'route': '/public/bus', 'auth': 'public'}

    @http.route(**BUS_OPTIONS)
    def bus(self, **kwargs):
        payload = {'email': kwargs.get('email'), 'access_token': kwargs.get('token')}
        request.env['bus.bus']._sendone('public_notifications', payload)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-public-route-bus-send" in rule_ids
    assert "odoo-realtime-broad-or-tainted-channel" in rule_ids
    assert "odoo-realtime-sensitive-payload" in rule_ids


def test_recursive_constant_backed_public_bus_send_with_sensitive_payload(tmp_path: Path) -> None:
    """Chained public route auth constants should still expose bus sends."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http
from odoo.http import request

PUBLIC_AUTH = 'public'
BUS_AUTH = PUBLIC_AUTH

class BusController(http.Controller):
    @http.route('/public/bus', auth=BUS_AUTH)
    def bus(self, **kwargs):
        payload = {'email': kwargs.get('email'), 'access_token': kwargs.get('token')}
        request.env['bus.bus']._sendone('public_notifications', payload)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-public-route-bus-send" in rule_ids
    assert "odoo-realtime-broad-or-tainted-channel" in rule_ids
    assert "odoo-realtime-sensitive-payload" in rule_ids


def test_keyword_constant_backed_none_channel_subscription_is_high(tmp_path: Path) -> None:
    """Constant-backed auth='none' should keep channel subscription severity high."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http

LISTEN_ROUTE = '/public/listen'
LISTEN_AUTH = 'none'

class BusController(http.Controller):
    @http.route(route=LISTEN_ROUTE, auth=LISTEN_AUTH)
    def listen(self, channels):
        channels.extend(['public_notifications'])
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(
        f.rule_id == "odoo-realtime-broad-or-tainted-channel-subscription" and f.severity == "high"
        for f in findings
    )


def test_request_alias_public_bus_send_with_sensitive_payload(tmp_path: Path) -> None:
    """Request aliases should still taint bus channels and payloads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class BusController(http.Controller):
    @http.route('/public/bus', auth='public')
    def bus(self):
        payload = req.get_http_params()
        req.env['bus.bus']._sendone(
            payload.get('channel'),
            {'email': payload.get('email')},
        )
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-public-route-bus-send" in rule_ids
    assert "odoo-realtime-broad-or-tainted-channel" in rule_ids
    assert "odoo-realtime-sensitive-payload" in rule_ids


def test_flags_sudo_bus_send(tmp_path: Path) -> None:
    """Bus sends through sudo can bypass recipient scoping."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
def notify(self):
    self.env['bus.bus'].sudo()._sendmany([('global', {'message': 'done'})])
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(f.rule_id == "odoo-realtime-bus-send-sudo" for f in findings)


def test_flags_sendone_notification_type_sensitive_payload(tmp_path: Path) -> None:
    """Modern sendone calls place the payload after a notification type argument."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
def notify(self):
    self.env['bus.bus']._sendone(
        ('res.partner', self.env.user.partner_id.id),
        'notification',
        {'access_token': self.access_token, 'email': self.email},
    )
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(f.rule_id == "odoo-realtime-sensitive-payload" for f in findings)


def test_flags_route_path_id_bus_channel_and_payload(tmp_path: Path) -> None:
    """Route path IDs in bus channels and payloads are request-controlled."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http
from odoo.http import request

class BusController(http.Controller):
    @http.route('/public/orders/<int:order_id>/partner/<int:partner_id>/bus', auth='public')
    def bus_order(self, order_id, partner_id):
        request.env['bus.bus']._sendone(
            ('sale.order', order_id),
            'notification',
            {'order_id': order_id, 'partner_id': partner_id},
        )
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-public-route-bus-send" in rule_ids
    assert "odoo-realtime-broad-or-tainted-channel" in rule_ids
    assert "odoo-realtime-sensitive-payload" in rule_ids


def test_flags_sendmany_channels_and_payloads(tmp_path: Path) -> None:
    """Batched bus sends should inspect each tuple channel and payload."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
def notify(self):
    self.env['bus.bus']._sendmany([
        ('public_notifications', 'notification', {'email': self.email}),
        (self.env.user.partner_id, {'status': 'ok'}),
    ])
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-broad-or-tainted-channel" in rule_ids
    assert "odoo-realtime-sensitive-payload" in rule_ids


def test_flags_payload_argument_notification_content(tmp_path: Path) -> None:
    """Payload-shaped method arguments should remain tainted notification input."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "message.py").write_text(
        """
def post(self, payload):
    self.message_post(body=payload)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(f.rule_id == "odoo-realtime-tainted-notification-content" for f in findings)


def test_reassigned_payload_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a request-derived payload alias for safe content should clear taint."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "message.py").write_text(
        """
def post(self, **kwargs):
    payload = kwargs.get('body')
    payload = 'Internal update'
    self.message_post(body=payload)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert not any(f.rule_id == "odoo-realtime-tainted-notification-content" for f in findings)


def test_flags_loop_derived_bus_payload(tmp_path: Path) -> None:
    """Loop targets over request payloads should remain tainted for bus sends."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http
from odoo.http import request

class BusController(http.Controller):
    @http.route('/bus', auth='user')
    def bus(self, **kwargs):
        for payload in kwargs.get('payloads'):
            request.env['bus.bus']._sendone(('res.partner', request.env.user.partner_id.id), payload)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(f.rule_id == "odoo-realtime-sensitive-payload" for f in findings)


def test_safe_loop_reassignment_clears_realtime_payload_taint(tmp_path: Path) -> None:
    """Loop target taint should clear when rebound from safe payloads."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "message.py").write_text(
        """
def post(self, **kwargs):
    for payload in kwargs.get('payloads'):
        pass
    for payload in ['Internal update']:
        self.message_post(body=payload)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert not any(f.rule_id == "odoo-realtime-tainted-notification-content" for f in findings)


def test_flags_comprehension_derived_bus_channel(tmp_path: Path) -> None:
    """Request-derived comprehensions should remain tainted for bus channels."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http
from odoo.http import request

class BusController(http.Controller):
    @http.route('/bus', auth='user')
    def bus(self, **kwargs):
        channels = [channel for channel in kwargs.get('channels')]
        request.env['bus.bus']._sendone(channels[0], {'status': 'ok'})
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(f.rule_id == "odoo-realtime-broad-or-tainted-channel" for f in findings)


def test_flags_comprehension_filter_derived_bus_channel(tmp_path: Path) -> None:
    """Request-only comprehension filters should taint generated bus channels."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http
from odoo.http import request

class BusController(http.Controller):
    @http.route('/bus', auth='user')
    def bus(self, **kwargs):
        channels = ['sale.order' for _ in range(1) if kwargs.get('channels')]
        request.env['bus.bus']._sendone(channels[0], {'status': 'ok'})
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(f.rule_id == "odoo-realtime-broad-or-tainted-channel" for f in findings)


def test_flags_named_expression_derived_bus_channel(tmp_path: Path) -> None:
    """Walrus-bound bus channels should remain tainted after the condition."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http
from odoo.http import request

class BusController(http.Controller):
    @http.route('/bus', auth='user')
    def bus(self, **kwargs):
        if channel := kwargs.get('channel'):
            request.env['bus.bus']._sendone(channel, {'status': 'ok'})
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(f.rule_id == "odoo-realtime-broad-or-tainted-channel" for f in findings)


def test_flags_starred_rest_derived_bus_channel_and_payload(tmp_path: Path) -> None:
    """Starred-rest bus channel and payload aliases should stay tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http
from odoo.http import request

class BusController(http.Controller):
    @http.route('/bus', auth='user')
    def bus(self, **kwargs):
        marker, *items, tail = 'x', kwargs.get('channel'), {'email': kwargs.get('email')}, 'end'
        channel = items[0]
        payload = items[1]
        request.env['bus.bus']._sendone(channel, payload)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-broad-or-tainted-channel" in rule_ids
    assert "odoo-realtime-sensitive-payload" in rule_ids


def test_flags_boolop_derived_bus_channel(tmp_path: Path) -> None:
    """Boolean fallback expressions should not hide request-controlled channels."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http
from odoo.http import request

class BusController(http.Controller):
    @http.route('/bus', auth='user')
    def bus(self, **kwargs):
        channel = kwargs.get('channel') or ('res.partner', request.env.user.partner_id.id)
        request.env['bus.bus']._sendone(channel, {'status': 'ok'})
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(f.rule_id == "odoo-realtime-broad-or-tainted-channel" for f in findings)


def test_flags_aliased_sudo_bus_send(tmp_path: Path) -> None:
    """Bus sudo posture should survive local aliases."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
def notify(self):
    Bus = self.env['bus.bus'].sudo()
    Bus._sendmany([('global', {'message': 'done'})])
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(f.rule_id == "odoo-realtime-bus-send-sudo" for f in findings)


def test_flags_with_user_superuser_bus_send(tmp_path: Path) -> None:
    """Bus sends through superuser with_user can bypass recipient scoping."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
from odoo import SUPERUSER_ID

def notify(self):
    self.env['bus.bus'].with_user(SUPERUSER_ID)._sendmany([('global', {'message': 'done'})])
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(f.rule_id == "odoo-realtime-bus-send-sudo" for f in findings)


def test_flags_aliased_with_user_one_bus_send(tmp_path: Path) -> None:
    """Bus superuser with_user posture should survive local aliases."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
def notify(self):
    Bus = self.env['bus.bus'].with_user(1)
    Bus._sendmany([('global', {'message': 'done'})])
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(f.rule_id == "odoo-realtime-bus-send-sudo" for f in findings)


def test_flags_recursive_constant_with_user_bus_send(tmp_path: Path) -> None:
    """Chained superuser ID constants should keep bus send sudo posture visible."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
ROOT_UID = 1
ADMIN_UID = ROOT_UID

def notify(self):
    Bus = self.env['bus.bus'].with_user(ADMIN_UID)
    Bus._sendmany([('global', {'message': 'done'})])
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(f.rule_id == "odoo-realtime-bus-send-sudo" for f in findings)


def test_flags_class_constant_with_user_bus_send(tmp_path: Path) -> None:
    """Class-scoped superuser constants should keep bus send sudo posture visible."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
class Sync:
    ROOT_UID = 1
    ADMIN_UID = ROOT_UID

    def notify(self):
        Bus = self.env['bus.bus'].with_user(ADMIN_UID)
        Bus._sendmany([('global', {'message': 'done'})])
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(f.rule_id == "odoo-realtime-bus-send-sudo" for f in findings)


def test_flags_env_ref_root_bus_send(tmp_path: Path) -> None:
    """Root XML-ID with_user calls should count as elevated bus sends."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
def notify(self):
    Bus = self.env['bus.bus'].with_user(self.env.ref('base.user_root'))
    Bus._sendmany([('global', {'message': 'done'})])
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(f.rule_id == "odoo-realtime-bus-send-sudo" for f in findings)


def test_flags_walrus_with_user_one_notification(tmp_path: Path) -> None:
    """Walrus-bound superuser notification aliases should remain visible."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "message.py").write_text(
        """
def post(self, **kwargs):
    if record := self.with_user(1):
        record.message_post(body=kwargs.get('body'))
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-notification-sudo" in rule_ids
    assert "odoo-realtime-tainted-notification-content" in rule_ids


def test_flags_starred_rest_aliased_sudo_bus_send(tmp_path: Path) -> None:
    """Bus sudo posture should survive starred-rest local aliases."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
def notify(self):
    marker, *items, tail = 'x', self.env['bus.bus'].sudo(), {'message': 'done'}, 'end'
    Bus = items[0]
    payload = items[1]
    Bus._sendmany([('global', payload)])
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(f.rule_id == "odoo-realtime-bus-send-sudo" for f in findings)


def test_flags_sudo_and_tainted_notifications(tmp_path: Path) -> None:
    """Follower notifications should not use sudo with raw request content."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "message.py").write_text(
        """
def post(self, **kwargs):
    self.sudo().message_post(body=kwargs.get('body'))
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-notification-sudo" in rule_ids
    assert "odoo-realtime-tainted-notification-content" in rule_ids


def test_request_alias_notification_content_is_tainted(tmp_path: Path) -> None:
    """Request aliases should taint notification body content."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "message.py").write_text(
        """
from odoo.http import request as req

def post(self):
    self.message_post(body=req.params.get('body'))
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(f.rule_id == "odoo-realtime-tainted-notification-content" for f in findings)


def test_flags_aliased_sudo_notification(tmp_path: Path) -> None:
    """Notification sudo posture should remain visible through aliases."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "message.py").write_text(
        """
def post(self, **kwargs):
    record = self.sudo()
    record.message_post(body=kwargs.get('body'))
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-notification-sudo" in rule_ids
    assert "odoo-realtime-tainted-notification-content" in rule_ids


def test_flags_poll_request_controlled_channel_subscription(tmp_path: Path) -> None:
    """Bus poll extensions should not subscribe clients to request-controlled channels."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
class BusController:
    def _poll(self, dbname, channels, last, options):
        channels.append(options.get('channel'))
        return super()._poll(dbname, channels, last, options)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(
        f.rule_id == "odoo-realtime-broad-or-tainted-channel-subscription" and f.severity == "high" for f in findings
    )


def test_flags_public_route_broad_channel_subscription(tmp_path: Path) -> None:
    """Public routes should not extend bus channel lists with broad channels."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
from odoo import http

class BusController(http.Controller):
    @http.route('/public/listen', auth='public')
    def listen(self, channels):
        channels.extend(['public_notifications'])
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)

    assert any(
        f.rule_id == "odoo-realtime-broad-or-tainted-channel-subscription" and f.severity == "high" for f in findings
    )


def test_flags_constant_backed_broad_channel_and_sensitive_payload(tmp_path: Path) -> None:
    """Constant-backed channel and payload shapes should still be inspected."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
PUBLIC_CHANNEL = 'public_notifications'
CHANNEL = PUBLIC_CHANNEL
SECRET_PAYLOAD = {'access_token': 'redacted', 'email': 'a@example.com'}
PAYLOAD = SECRET_PAYLOAD

def notify(self):
    self.env['bus.bus']._sendone(CHANNEL, PAYLOAD)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-broad-or-tainted-channel" in rule_ids
    assert "odoo-realtime-sensitive-payload" in rule_ids


def test_flags_class_constant_backed_broad_channel_and_sensitive_payload(tmp_path: Path) -> None:
    """Class-scoped channel and payload shapes should still be inspected."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
class Sync:
    PUBLIC_CHANNEL = 'public_notifications'
    CHANNEL = PUBLIC_CHANNEL
    SECRET_PAYLOAD = {'access_token': 'redacted', 'email': 'a@example.com'}
    PAYLOAD = SECRET_PAYLOAD

    def notify(self):
        self.env['bus.bus']._sendone(CHANNEL, PAYLOAD)
""",
        encoding="utf-8",
    )

    findings = scan_realtime(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-realtime-broad-or-tainted-channel" in rule_ids
    assert "odoo-realtime-sensitive-payload" in rule_ids


def test_safe_internal_bus_send_is_ignored(tmp_path: Path) -> None:
    """Scoped internal bus messages without sensitive data should not be noisy."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "safe.py").write_text(
        """
def notify(self):
    self.env['bus.bus']._sendone(('res.partner', self.env.user.partner_id.id), {'status': 'ok'})
""",
        encoding="utf-8",
    )

    assert scan_realtime(tmp_path) == []


def test_safe_static_partner_channel_subscription_is_ignored(tmp_path: Path) -> None:
    """Scoped static partner channels should not be treated as broad subscriptions."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "bus.py").write_text(
        """
class BusController:
    def _poll(self, dbname, channels, last, options):
        channels.append(('res.partner', self.env.user.partner_id.id))
        return super()._poll(dbname, channels, last, options)
""",
        encoding="utf-8",
    )

    assert scan_realtime(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Python fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_bus.py").write_text(
        "def test_bus(**kwargs):\n    env['bus.bus']._sendone('public', {'email': kwargs.get('email')})\n",
        encoding="utf-8",
    )

    assert scan_realtime(tmp_path) == []
