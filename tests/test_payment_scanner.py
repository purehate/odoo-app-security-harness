"""Tests for Odoo payment/webhook scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.payment_scanner import PaymentScanner, scan_payments


def test_public_payment_callback_without_signature_is_reported(tmp_path: Path) -> None:
    """Public csrf=False payment callbacks must validate provider signatures."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http

class PaymentController(http.Controller):
    @http.route('/payment/provider/webhook', auth='public', csrf=False)
    def webhook(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" for f in findings)


def test_imported_route_decorator_payment_callback_without_signature_is_reported(tmp_path: Path) -> None:
    """Imported route decorators should still expose public payment callbacks."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http
from odoo.http import route

class PaymentController(http.Controller):
    @route('/payment/provider/webhook', auth='public', csrf=False)
    def webhook(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" for f in findings)


def test_aliased_imported_route_decorator_payment_callback_without_signature_is_reported(tmp_path: Path) -> None:
    """Aliased imported route decorators should still expose public payment callbacks."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http
from odoo.http import route as odoo_route

class PaymentController(http.Controller):
    @odoo_route('/payment/provider/webhook', auth='public', csrf=False)
    def webhook(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" for f in findings)


def test_aliased_http_module_payment_callback_without_signature_is_reported(tmp_path: Path) -> None:
    """Aliased Odoo http modules should still expose public payment callbacks."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http as odoo_http

class PaymentController(odoo_http.Controller):
    @odoo_http.route('/payment/provider/webhook', auth='public', csrf=False)
    def webhook(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" for f in findings)


def test_imported_odoo_http_module_payment_callback_without_signature_is_reported(tmp_path: Path) -> None:
    """Direct odoo.http imports should still expose public payment callbacks."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
import odoo.http as odoo_http

class PaymentController(odoo_http.Controller):
    @odoo_http.route('/payment/provider/webhook', auth='public', csrf=False)
    def webhook(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" for f in findings)


def test_imported_odoo_module_payment_callback_without_signature_is_reported(tmp_path: Path) -> None:
    """Direct odoo imports should still expose public payment callbacks."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
import odoo as od

class PaymentController(od.http.Controller):
    @od.http.route('/payment/provider/webhook', auth='public', csrf=False)
    def webhook(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" for f in findings)


def test_non_odoo_route_decorator_payment_callback_is_ignored(tmp_path: Path) -> None:
    """Arbitrary .route decorators should not be treated as Odoo payment callbacks."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
class Bus:
    def route(self, path, **kwargs):
        return lambda func: func

bus = Bus()

class PaymentController:
    @bus.route('/payment/provider/webhook', auth='public', csrf=False)
    def webhook(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-payment-public-callback-no-signature" for f in findings)


def test_signed_payment_callback_is_not_reported(tmp_path: Path) -> None:
    """Visible signature validation should suppress the route-level callback finding."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http

class PaymentController(http.Controller):
    @http.route('/payment/provider/webhook', auth='public', csrf=False)
    def webhook(self, **post):
        self._verify_signature(post)
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-payment-public-callback-no-signature" for f in findings)


def test_signature_parameter_read_without_validation_is_reported(tmp_path: Path) -> None:
    """Reading a signature field is not the same as validating it."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http

class PaymentController(http.Controller):
    @http.route('/payment/provider/webhook', auth='public', csrf=False)
    def webhook(self, **post):
        provider_signature = post.get('signature')
        return {'signature': provider_signature}
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" for f in findings)


def test_ipn_callback_without_signature_is_reported(tmp_path: Path) -> None:
    """IPN endpoints are payment callbacks even when the route omits payment/webhook words."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http

class PaymentController(http.Controller):
    @http.route('/paypal/ipn', auth='public', csrf=False)
    def ipn(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" for f in findings)


def test_hmac_compare_digest_counts_as_signature_validation(tmp_path: Path) -> None:
    """Provider HMAC comparison should count as visible signature validation."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
import hmac
from odoo import http

class PaymentController(http.Controller):
    @http.route('/payment/provider/webhook', auth='public', csrf=False)
    def webhook(self, **post):
        if not hmac.compare_digest(post.get('signature'), self._expected_signature(post)):
            return 'invalid'
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-payment-public-callback-no-signature" for f in findings)


def test_stripe_construct_event_counts_as_signature_validation(tmp_path: Path) -> None:
    """Stripe construct_event verifies webhook signatures through provider SDKs."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
import stripe
from odoo import http
from odoo.http import request

class PaymentController(http.Controller):
    @http.route('/stripe/webhook', auth='public', csrf=False)
    def webhook(self, **post):
        payload = request.httprequest.get_data()
        sig_header = request.httprequest.headers.get('Stripe-Signature')
        stripe.Webhook.construct_event(payload, sig_header, self._webhook_secret())
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-payment-public-callback-no-signature" for f in findings)


def test_hmac_digest_without_compare_is_not_signature_validation(tmp_path: Path) -> None:
    """Computing a digest is not enough unless it is compared or verified."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
import hmac
from odoo import http

class PaymentController(http.Controller):
    @http.route('/payment/provider/webhook', auth='public', csrf=False)
    def webhook(self, **post):
        digest = hmac.new(b'secret', post.get('payload', '').encode(), 'sha256').hexdigest()
        return {'digest': digest}
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" for f in findings)


def test_weak_signature_compare_is_reported(tmp_path: Path) -> None:
    """Signature equality checks are visible validation, but should use constant-time comparison."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http
from odoo.http import request

class PaymentController(http.Controller):
    @http.route('/payment/provider/webhook', auth='public', csrf=False)
    def webhook(self, **post):
        tx = request.env['payment.transaction'].sudo().search([
            ('provider_code', '=', 'demo'),
            ('provider_reference', '=', post.get('reference')),
        ])
        if post.get('signature') != self._expected_signature(post):
            return 'invalid'
        tx._set_done()
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-payment-weak-signature-compare" in rule_ids
    assert "odoo-payment-public-callback-no-signature" not in rule_ids
    assert "odoo-payment-state-without-validation" not in rule_ids


def test_keyword_route_payment_callback_without_signature_is_reported(tmp_path: Path) -> None:
    """Payment callbacks declared with route= should not evade callback detection."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http

class PaymentController(http.Controller):
    @http.route(route='/payment/provider/webhook', auth='public', csrf=False)
    def webhook(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" for f in findings)


def test_constant_backed_payment_callback_without_signature_is_reported(tmp_path: Path) -> None:
    """Route constants should not hide public csrf-disabled payment callbacks."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http

PAYMENT_ROUTES = ['/payment/provider/webhook', '/payment/provider/notify']
AUTH = 'public'
CSRF = False

class PaymentController(http.Controller):
    @http.route(PAYMENT_ROUTES, auth=AUTH, csrf=CSRF)
    def webhook(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" and f.handler == "webhook" for f in findings)


def test_keyword_constant_backed_payment_callback_without_signature_is_reported(tmp_path: Path) -> None:
    """route= constants should not hide auth='none' payment callbacks."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http

PAYMENT_ROUTE = '/payment/provider/callback'
AUTH = 'none'
CSRF = False

class PaymentController(http.Controller):
    @http.route(route=PAYMENT_ROUTE, auth=AUTH, csrf=CSRF)
    def callback(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" and f.handler == "callback" for f in findings)


def test_static_unpack_payment_callback_without_signature_is_reported(tmp_path: Path) -> None:
    """Static route option dictionaries should not hide public csrf-disabled callbacks."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http

PAYMENT_OPTIONS = {
    'route': '/payment/provider/webhook',
    'auth': 'public',
    'csrf': False,
}

class PaymentController(http.Controller):
    @http.route(**PAYMENT_OPTIONS)
    def webhook(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" and f.handler == "webhook" for f in findings)


def test_recursive_static_unpack_payment_callback_without_signature_is_reported(tmp_path: Path) -> None:
    """Recursive route option aliases should not hide auth/csrf/path posture."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http

ROUTE_BASE = '/payment/provider/notify'
PAYMENT_ROUTE = ROUTE_BASE
AUTH_BASE = 'none'
AUTH = AUTH_BASE
CSRF_BASE = False
CSRF = CSRF_BASE
PAYMENT_OPTIONS = {
    'routes': [PAYMENT_ROUTE],
    'auth': AUTH,
    'csrf': CSRF,
}
OPTIONS_ALIAS = PAYMENT_OPTIONS

class PaymentController(http.Controller):
    @http.route(**OPTIONS_ALIAS)
    def notify(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" and f.handler == "notify" for f in findings)


def test_nested_static_unpack_payment_callback_without_signature_is_reported(tmp_path: Path) -> None:
    """Nested static ** route options should not hide auth/csrf/path posture."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http

PAYMENT_BASE_OPTIONS = {
    'routes': ['/payment/provider/notify'],
    'auth': 'none',
}
PAYMENT_OPTIONS = {
    **PAYMENT_BASE_OPTIONS,
    'csrf': False,
}

class PaymentController(http.Controller):
    @http.route(**PAYMENT_OPTIONS)
    def notify(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" and f.handler == "notify" for f in findings)


def test_dict_union_static_unpack_payment_callback_without_signature_is_reported(tmp_path: Path) -> None:
    """Dict-union ** route options should not hide auth/csrf/path posture."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http

PAYMENT_BASE_OPTIONS = {
    'routes': ['/payment/provider/notify'],
    'auth': 'none',
}
PAYMENT_OPTIONS = PAYMENT_BASE_OPTIONS | {
    'csrf': False,
}

class PaymentController(http.Controller):
    @http.route(**PAYMENT_OPTIONS)
    def notify(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" and f.handler == "notify" for f in findings)


def test_class_constant_backed_payment_callback_without_signature_is_reported(tmp_path: Path) -> None:
    """Class-scoped route constants should not hide public csrf-disabled payment callbacks."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http

class PaymentController(http.Controller):
    PAYMENT_ROUTE = '/payment/provider/webhook'
    AUTH_BASE = 'public'
    AUTH = AUTH_BASE
    CSRF = False

    @http.route(PAYMENT_ROUTE, auth=AUTH, csrf=CSRF)
    def webhook(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" and f.handler == "webhook" for f in findings)


def test_class_constant_static_unpack_payment_callback_without_signature_is_reported(tmp_path: Path) -> None:
    """Class-scoped route option dictionaries should not hide auth/csrf/path posture."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http

class PaymentController(http.Controller):
    PAYMENT_ROUTE = '/payment/provider/notify'
    AUTH = 'none'
    CSRF = False
    PAYMENT_OPTIONS = {
        'routes': [PAYMENT_ROUTE],
        'auth': AUTH,
        'csrf': CSRF,
    }

    @http.route(**PAYMENT_OPTIONS)
    def notify(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" and f.handler == "notify" for f in findings)


def test_constant_alias_payment_route_state_and_lookup_are_reported(tmp_path: Path) -> None:
    """Alias chains should not hide payment route metadata, state writes, or weak lookups."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

ROUTE_BASE = '/payment/provider/webhook'
PAYMENT_ROUTE = ROUTE_BASE
PAYMENT_ROUTES = [PAYMENT_ROUTE]
AUTH_BASE = 'public'
AUTH = AUTH_BASE
CSRF_BASE = False
CSRF = CSRF_BASE
TX_MODEL_BASE = 'payment.transaction'
TX_MODEL = TX_MODEL_BASE
STATE_KEY = 'state'
DONE_BASE = 'done'
DONE_STATE = DONE_BASE
ROOT_BASE = SUPERUSER_ID
ROOT = ROOT_BASE

class PaymentController(http.Controller):
    @http.route(PAYMENT_ROUTES, auth=AUTH, csrf=CSRF)
    def webhook(self, **post):
        tx = request.env[TX_MODEL].with_user(ROOT).search([('reference', '=', post.get('reference'))])
        vals = {STATE_KEY: DONE_STATE}
        tx.write(vals)
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-payment-public-callback-no-signature" in rule_ids
    assert "odoo-payment-state-without-validation" in rule_ids
    assert "odoo-payment-transaction-lookup-weak" in rule_ids


def test_class_constant_alias_payment_route_state_and_lookup_are_reported(tmp_path: Path) -> None:
    """Class-scoped aliases should expose route metadata, state writes, and weak lookups."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class PaymentController(http.Controller):
    ROUTE_BASE = '/payment/provider/webhook'
    PAYMENT_ROUTE = ROUTE_BASE
    AUTH = 'public'
    CSRF = False
    TX_MODEL = 'payment.transaction'
    STATE_KEY = 'state'
    DONE_STATE = 'done'
    ROOT = SUPERUSER_ID

    @http.route(PAYMENT_ROUTE, auth=AUTH, csrf=CSRF)
    def webhook(self, **post):
        tx = request.env[TX_MODEL].with_user(ROOT).search([('reference', '=', post.get('reference'))])
        vals = {STATE_KEY: DONE_STATE}
        tx.write(vals)
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-payment-public-callback-no-signature" in rule_ids
    assert "odoo-payment-state-without-validation" in rule_ids
    assert "odoo-payment-transaction-lookup-weak" in rule_ids


def test_payment_state_transition_without_validation_is_reported(tmp_path: Path) -> None:
    """Notification handlers should validate provider data before changing state."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _handle_notification_data(self, provider_code, notification_data):
        self._set_done()
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-state-without-validation" for f in findings)


def test_direct_payment_state_write_without_validation_is_reported(tmp_path: Path) -> None:
    """Direct writes to payment state should be treated like state transition helpers."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _process_notification_data(self, provider_code, notification_data):
        self.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-payment-state-without-validation" in rule_ids
    assert "odoo-payment-state-without-amount-currency-check" in rule_ids
    assert "odoo-payment-state-without-idempotency-check" in rule_ids


def test_local_constant_payment_state_write_without_validation_is_reported(tmp_path: Path) -> None:
    """Function-local state keys should still reveal payment state writes."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _process_notification_data(self, provider_code, notification_data):
        state_key = 'state'
        done_state = 'done'
        self.write({state_key: done_state})
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-payment-state-without-validation" in rule_ids
    assert "odoo-payment-state-without-amount-currency-check" in rule_ids
    assert "odoo-payment-state-without-idempotency-check" in rule_ids


def test_aliased_payment_state_write_without_validation_is_reported(tmp_path: Path) -> None:
    """Aliased payment state payloads should still count as state transitions."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _process_notification_data(self, provider_code, notification_data):
        vals = {'state': 'done'}
        self.write(vals)
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-payment-state-without-validation" in rule_ids
    assert "odoo-payment-state-without-amount-currency-check" in rule_ids
    assert "odoo-payment-state-without-idempotency-check" in rule_ids


def test_walrus_payment_state_write_without_validation_is_reported(tmp_path: Path) -> None:
    """Assignment-expression payment state payloads should still count as state transitions."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _process_notification_data(self, provider_code, notification_data):
        if vals := {'state': 'done'}:
            self.write(vals)
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-payment-state-without-validation" in rule_ids
    assert "odoo-payment-state-without-amount-currency-check" in rule_ids
    assert "odoo-payment-state-without-idempotency-check" in rule_ids


def test_reassigned_payment_state_payload_is_not_stale(tmp_path: Path) -> None:
    """Reusing a state payload alias for unrelated data should clear state tracking."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _process_notification_data(self, provider_code, notification_data):
        vals = {'state': 'done'}
        vals = {'provider_reference': notification_data['reference']}
        self.write(vals)
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-payment-state-without-validation" for f in findings)


def test_public_callback_state_write_without_reconciliation_is_reported(tmp_path: Path) -> None:
    """Payment callback routes that finalize transactions need the full review surface."""
    py = tmp_path / "controllers.py"
    py.write_text(
        """
from odoo import http
from odoo.http import request

class PaymentController(http.Controller):
    @http.route('/payment/provider/return', auth='public', csrf=False)
    def callback(self, **post):
        tx = request.env['payment.transaction'].sudo().search([('reference', '=', post.get('reference'))])
        tx.write({'state': post.get('state')})
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-payment-public-callback-no-signature" in rule_ids
    assert "odoo-payment-state-without-validation" in rule_ids
    assert "odoo-payment-state-without-amount-currency-check" in rule_ids
    assert "odoo-payment-state-without-idempotency-check" in rule_ids


def test_payment_state_transition_without_amount_currency_check_is_reported(tmp_path: Path) -> None:
    """Signed payment notifications still need amount and currency reconciliation."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _handle_notification_data(self, provider_code, notification_data):
        self._verify_signature(notification_data)
        self._set_done()
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-state-without-amount-currency-check" for f in findings)


def test_payment_state_transition_with_amount_currency_check_is_ignored(tmp_path: Path) -> None:
    """Visible amount/currency reconciliation should suppress the amount rule."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _handle_notification_data(self, provider_code, notification_data):
        self._verify_signature(notification_data)
        self._check_amount_currency(notification_data['amount'], notification_data['currency'])
        self._set_done()
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-payment-state-without-amount-currency-check" for f in findings)


def test_payment_state_transition_without_idempotency_check_is_reported(tmp_path: Path) -> None:
    """Webhook retries should not repeatedly finalize transactions without a guard."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _handle_notification_data(self, provider_code, notification_data):
        self._verify_signature(notification_data)
        self._check_amount_currency(notification_data['amount'], notification_data['currency'])
        self._set_done()
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-state-without-idempotency-check" for f in findings)


def test_provider_reference_lookup_is_not_idempotency_guard(tmp_path: Path) -> None:
    """Provider references alone do not prove duplicate webhook replay handling."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _handle_notification_data(self, provider_code, notification_data):
        self._verify_signature(notification_data)
        tx = self.search([('provider_reference', '=', notification_data['reference'])])
        tx._check_amount_currency(notification_data['amount'], notification_data['currency'])
        tx._set_done()
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-state-without-idempotency-check" for f in findings)


def test_payment_state_transition_with_idempotency_check_is_ignored(tmp_path: Path) -> None:
    """Visible state guards should suppress the idempotency finding."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _handle_notification_data(self, provider_code, notification_data):
        self._verify_signature(notification_data)
        self._check_amount_currency(notification_data['amount'], notification_data['currency'])
        if self.state == 'done':
            return
        self._set_done()
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-payment-state-without-idempotency-check" for f in findings)


def test_payment_transaction_lookup_without_provider_scope_is_reported(tmp_path: Path) -> None:
    """Transaction lookup should include provider/reference scoping."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        return self.env['payment.transaction'].sudo().search([('reference', '=', notification_data['reference'])])
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-transaction-lookup-weak" for f in findings)


def test_local_model_payment_transaction_lookup_without_provider_scope_is_reported(tmp_path: Path) -> None:
    """Function-local payment.transaction aliases should still expose weak lookups."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        tx_model = 'payment.transaction'
        return self.env[tx_model].sudo().search([('reference', '=', notification_data['reference'])])
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-transaction-lookup-weak" for f in findings)


def test_superuser_self_transaction_lookup_without_provider_scope_is_reported(tmp_path: Path) -> None:
    """Notification lookups through admin-root with_user should still be scoped."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import SUPERUSER_ID, models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        return self.with_user(user=SUPERUSER_ID).search([('reference', '=', notification_data['reference'])])
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-transaction-lookup-weak" for f in findings)


def test_import_aliased_superuser_self_transaction_lookup_without_provider_scope_is_reported(
    tmp_path: Path,
) -> None:
    """Imported SUPERUSER_ID aliases should keep self.with_user lookups weakly scoped."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import SUPERUSER_ID as ROOT_UID, models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        return self.with_user(user=ROOT_UID).search([('reference', '=', notification_data['reference'])])
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-transaction-lookup-weak" for f in findings)


def test_unrelated_provider_reference_does_not_hide_weak_lookup(tmp_path: Path) -> None:
    """Provider-reference text outside the search domain should not suppress weak lookup."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        provider_reference = notification_data.get('reference')
        return self.env['payment.transaction'].sudo().search([('reference', '=', provider_reference)])
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-transaction-lookup-weak" for f in findings)


def test_payment_transaction_browse_lookup_is_reported(tmp_path: Path) -> None:
    """Direct browse() lookup in notification handlers bypasses provider/reference scoping."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        return self.env['payment.transaction'].sudo().browse(notification_data['tx_id'])
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-transaction-lookup-weak" for f in findings)


def test_payment_transaction_search_read_without_provider_scope_is_reported(tmp_path: Path) -> None:
    """search_read() transaction lookups need the same provider/reference scoping as search()."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        return self.env['payment.transaction'].sudo().search_read([
            ('reference', '=', notification_data['reference']),
        ], ['id'])
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-transaction-lookup-weak" for f in findings)


def test_payment_transaction_search_count_without_provider_scope_is_reported(tmp_path: Path) -> None:
    """search_count() transaction lookups can still bind webhook decisions to the wrong tx."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        return self.env['payment.transaction'].sudo().search_count([
            ('reference', '=', notification_data['reference']),
        ])
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-transaction-lookup-weak" for f in findings)


def test_payment_transaction_read_group_without_provider_scope_is_reported(tmp_path: Path) -> None:
    """read_group() transaction probes also need provider/reference scoping."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        return self.env['payment.transaction'].sudo().read_group([
            ('reference', '=', notification_data['reference']),
        ], ['id:count'], ['state'])
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert any(f.rule_id == "odoo-payment-transaction-lookup-weak" for f in findings)


def test_provider_scoped_payment_transaction_search_read_is_ignored(tmp_path: Path) -> None:
    """Provider/reference scoped search_read() lookups should not be reported as weak."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        return self.env['payment.transaction'].sudo().search_read([
            ('provider_code', '=', provider_code),
            ('provider_reference', '=', notification_data['reference']),
        ], ['id'])
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-payment-transaction-lookup-weak" for f in findings)


def test_provider_scoped_payment_transaction_search_count_is_ignored(tmp_path: Path) -> None:
    """Provider/reference scoped search_count() lookups should not be reported as weak."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        return self.env['payment.transaction'].sudo().search_count([
            ('provider_code', '=', provider_code),
            ('provider_reference', '=', notification_data['reference']),
        ])
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-payment-transaction-lookup-weak" for f in findings)


def test_provider_scoped_payment_transaction_read_group_is_ignored(tmp_path: Path) -> None:
    """Provider/reference scoped read_group() lookups should not be reported as weak."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        return self.env['payment.transaction'].sudo().read_group([
            ('provider_code', '=', provider_code),
            ('provider_reference', '=', notification_data['reference']),
        ], ['id:count'], ['state'])
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-payment-transaction-lookup-weak" for f in findings)


def test_aliased_provider_scoped_transaction_lookup_is_ignored(tmp_path: Path) -> None:
    """Aliased domains with provider/reference scope should not be reported as weak."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        domain = [
            ('provider_code', '=', provider_code),
            ('provider_reference', '=', notification_data['reference']),
        ]
        return self.env['payment.transaction'].sudo().search(domain)
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-payment-transaction-lookup-weak" for f in findings)


def test_walrus_provider_scoped_transaction_lookup_is_ignored(tmp_path: Path) -> None:
    """Assignment-expression domains with provider/reference scope should not be reported as weak."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        if domain := [
            ('provider_code', '=', provider_code),
            ('provider_reference', '=', notification_data['reference']),
        ]:
            return self.env['payment.transaction'].sudo().search(domain)
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-payment-transaction-lookup-weak" for f in findings)


def test_constant_alias_provider_scoped_transaction_lookup_is_ignored(tmp_path: Path) -> None:
    """Constant-backed provider/reference domain fields should count as scoped."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import SUPERUSER_ID, models

PROVIDER_CODE = 'provider_code'
PROVIDER_REF_BASE = 'provider_reference'
PROVIDER_REF = PROVIDER_REF_BASE
ROOT_BASE = SUPERUSER_ID
ROOT = ROOT_BASE

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        domain = [
            (PROVIDER_CODE, '=', provider_code),
            (PROVIDER_REF, '=', notification_data['reference']),
        ]
        return self.with_user(user=ROOT).search(domain)
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-payment-transaction-lookup-weak" for f in findings)


def test_class_constant_provider_scoped_transaction_lookup_is_ignored(tmp_path: Path) -> None:
    """Class-scoped provider/reference domain fields should count as scoped."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import SUPERUSER_ID, models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'
    PROVIDER_CODE = 'provider_code'
    PROVIDER_REF = 'provider_reference'
    ROOT = SUPERUSER_ID

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        domain = [
            (PROVIDER_CODE, '=', provider_code),
            (PROVIDER_REF, '=', notification_data['reference']),
        ]
        return self.with_user(user=ROOT).search(domain)
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-payment-transaction-lookup-weak" for f in findings)


def test_local_constant_provider_scoped_transaction_lookup_is_ignored(tmp_path: Path) -> None:
    """Function-local provider/reference domain field aliases should count as scoped."""
    py = tmp_path / "models.py"
    py.write_text(
        """
from odoo import models

class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    def _get_tx_from_notification_data(self, provider_code, notification_data):
        provider_field = 'provider_code'
        reference_field = 'provider_reference'
        domain = [
            (provider_field, '=', provider_code),
            (reference_field, '=', notification_data['reference']),
        ]
        return self.env['payment.transaction'].sudo().search(domain)
""",
        encoding="utf-8",
    )

    findings = PaymentScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-payment-transaction-lookup-weak" for f in findings)


def test_repository_scan_finds_payment_handlers(tmp_path: Path) -> None:
    """Repository scanner should include addon Python files."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "payment.py").write_text(
        """
from odoo import http
class Controller(http.Controller):
    @http.route('/webhook/payment', auth='public', csrf=False)
    def notify(self, **post):
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_payments(tmp_path)

    assert any(f.rule_id == "odoo-payment-public-callback-no-signature" for f in findings)
