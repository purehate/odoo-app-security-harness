"""Tests for Odoo Python mail/chatter scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.mail_chatter_scanner import scan_mail_chatter


def test_flags_public_sudo_message_post_sensitive_and_tainted(tmp_path: Path) -> None:
    """Public chatter endpoints should not sudo-post request content or tokens."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/ticket/comment', auth='public')
    def comment(self, **kwargs):
        ticket = request.env['helpdesk.ticket'].sudo().browse(kwargs.get('id'))
        return ticket.sudo().message_post(
            body=f"Token {ticket.access_token}: {kwargs.get('body')}",
            partner_ids=kwargs.get('partner_ids'),
        )
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-chatter-public-route-send" in rule_ids
    assert "odoo-mail-chatter-sudo-post" in rule_ids
    assert "odoo-mail-sensitive-body" in rule_ids
    assert "odoo-mail-tainted-body" in rule_ids
    assert "odoo-mail-tainted-recipients" in rule_ids


def test_imported_route_decorator_public_sudo_message_post_is_reported(tmp_path: Path) -> None:
    """Imported route decorators should not hide public chatter endpoints."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request, route

class Controller(http.Controller):
    @route('/ticket/comment', auth='public')
    def comment(self, **kwargs):
        ticket = request.env['helpdesk.ticket'].sudo().browse(kwargs.get('id'))
        return ticket.sudo().message_post(
            body=f"Token {ticket.access_token}: {kwargs.get('body')}",
            partner_ids=kwargs.get('partner_ids'),
        )
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-chatter-public-route-send" in rule_ids
    assert "odoo-mail-chatter-sudo-post" in rule_ids
    assert "odoo-mail-sensitive-body" in rule_ids
    assert "odoo-mail-tainted-body" in rule_ids
    assert "odoo-mail-tainted-recipients" in rule_ids


def test_aliased_imported_route_decorator_public_sudo_message_post_is_reported(tmp_path: Path) -> None:
    """Aliased imported route decorators should not hide public chatter endpoints."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request, route as web_route

class Controller(http.Controller):
    @web_route('/ticket/comment', auth='public')
    def comment(self, **kwargs):
        ticket = request.env['helpdesk.ticket'].sudo().browse(kwargs.get('id'))
        return ticket.sudo().message_post(
            body=kwargs.get('body'),
            partner_ids=kwargs.get('partner_ids'),
        )
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-chatter-public-route-send" in rule_ids
    assert "odoo-mail-chatter-sudo-post" in rule_ids
    assert "odoo-mail-tainted-body" in rule_ids
    assert "odoo-mail-tainted-recipients" in rule_ids


def test_constant_backed_public_route_message_post_is_reported(tmp_path: Path) -> None:
    """Constant-backed public route auth should not hide chatter endpoints."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

COMMENT_ROUTE = '/ticket/comment'
COMMENT_AUTH = 'public'

class Controller(http.Controller):
    @http.route(COMMENT_ROUTE, auth=COMMENT_AUTH)
    def comment(self, **kwargs):
        ticket = request.env['helpdesk.ticket'].sudo().browse(kwargs.get('id'))
        return ticket.sudo().message_post(
            body=kwargs.get('body'),
            partner_ids=kwargs.get('partner_ids'),
        )
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-chatter-public-route-send" in rule_ids
    assert "odoo-mail-chatter-sudo-post" in rule_ids
    assert "odoo-mail-tainted-body" in rule_ids
    assert "odoo-mail-tainted-recipients" in rule_ids


def test_static_unpack_public_route_message_post_is_reported(tmp_path: Path) -> None:
    """Static **route options should not hide public chatter endpoints."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

COMMENT_AUTH = 'public'
ROUTE_OPTIONS = {'route': '/ticket/comment', 'auth': COMMENT_AUTH}

class Controller(http.Controller):
    @http.route(**ROUTE_OPTIONS)
    def comment(self, **kwargs):
        ticket = request.env['helpdesk.ticket'].sudo().browse(kwargs.get('id'))
        return ticket.sudo().message_post(
            body=kwargs.get('body'),
            partner_ids=kwargs.get('partner_ids'),
        )
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-chatter-public-route-send" in rule_ids
    assert "odoo-mail-chatter-sudo-post" in rule_ids
    assert "odoo-mail-tainted-body" in rule_ids
    assert "odoo-mail-tainted-recipients" in rule_ids


def test_class_constant_backed_public_route_message_post_is_reported(tmp_path: Path) -> None:
    """Class-scoped public route auth should not hide chatter endpoints."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    COMMENT_ROUTE = '/ticket/comment'
    AUTH_BASE = 'public'
    COMMENT_AUTH = AUTH_BASE

    @http.route(COMMENT_ROUTE, auth=COMMENT_AUTH)
    def comment(self, **kwargs):
        ticket = request.env['helpdesk.ticket'].sudo().browse(kwargs.get('id'))
        return ticket.sudo().message_post(
            body=kwargs.get('body'),
            partner_ids=kwargs.get('partner_ids'),
        )
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-chatter-public-route-send" in rule_ids
    assert "odoo-mail-chatter-sudo-post" in rule_ids
    assert "odoo-mail-tainted-body" in rule_ids
    assert "odoo-mail-tainted-recipients" in rule_ids


def test_class_constant_static_unpack_public_route_message_post_is_reported(tmp_path: Path) -> None:
    """Class-scoped **route options should not hide public chatter endpoints."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    COMMENT_AUTH = 'public'
    ROUTE_OPTIONS = {'route': '/ticket/comment', 'auth': COMMENT_AUTH}

    @http.route(**ROUTE_OPTIONS)
    def comment(self, **kwargs):
        ticket = request.env['helpdesk.ticket'].sudo().browse(kwargs.get('id'))
        return ticket.sudo().message_post(
            body=kwargs.get('body'),
            partner_ids=kwargs.get('partner_ids'),
        )
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-chatter-public-route-send" in rule_ids
    assert "odoo-mail-chatter-sudo-post" in rule_ids
    assert "odoo-mail-tainted-body" in rule_ids
    assert "odoo-mail-tainted-recipients" in rule_ids


def test_keyword_constant_backed_none_mail_followers_mutation_is_critical(tmp_path: Path) -> None:
    """Keyword route constants with auth='none' should keep follower mutations critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "followers.py").write_text(
        """
from odoo import http
from odoo.http import request

FOLLOWERS_ROUTE = '/public/followers'
FOLLOWERS_AUTH = 'none'

class Followers(http.Controller):
    @http.route(route=FOLLOWERS_ROUTE, auth=FOLLOWERS_AUTH)
    def followers(self, **kwargs):
        return request.env['mail.followers'].sudo().create({
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
            'partner_id': kwargs.get('partner_id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)

    assert any(f.rule_id == "odoo-mail-followers-public-route-mutation" and f.severity == "critical" for f in findings)
    assert any(f.rule_id == "odoo-mail-followers-tainted-mutation" and f.severity == "critical" for f in findings)


def test_request_alias_public_message_post_is_reported(tmp_path: Path) -> None:
    """Request aliases should still taint chatter body and recipients."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/ticket/comment', auth='public')
    def comment(self):
        params = req.get_http_params()
        ticket = req.env['helpdesk.ticket'].sudo().browse(params.get('id'))
        return ticket.message_post(
            body=params.get('body'),
            partner_ids=params.get('partner_ids'),
        )
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-chatter-public-route-send" in rule_ids
    assert "odoo-mail-tainted-body" in rule_ids
    assert "odoo-mail-tainted-recipients" in rule_ids


def test_flags_mail_mail_create_from_public_route(tmp_path: Path) -> None:
    """Public routes creating mail.mail records are spam/recipient review leads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "mail.py").write_text(
        """
from odoo import http
from odoo.http import request

class Mail(http.Controller):
    @http.route('/contact/send', auth='none')
    def send_contact(self, **kwargs):
        return request.env['mail.mail'].create({
            'email_to': kwargs.get('email_to'),
            'subject': kwargs.get('subject'),
            'body_html': kwargs.get('body'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-create-public-route" in rule_ids
    assert "odoo-mail-tainted-recipients" in rule_ids
    assert "odoo-mail-tainted-body" in rule_ids


def test_flags_template_sudo_send_and_force_send(tmp_path: Path) -> None:
    """Sudo and force_send on mail templates deserve explicit review."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def action_send(self):
        template = self.env.ref('sale.email_template_edi_sale')
        template.sudo().send_mail(self.id, force_send=True)
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-send-sudo" in rule_ids
    assert "odoo-mail-force-send" in rule_ids


def test_constant_backed_template_force_send_is_reported(tmp_path: Path) -> None:
    """Constant-backed force_send values should not hide synchronous sends."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
FORCE_SEND = True

class Sale:
    def action_send(self):
        template = self.env.ref('sale.email_template_edi_sale')
        template.send_mail(self.id, force_send=FORCE_SEND)
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)

    assert any(f.rule_id == "odoo-mail-force-send" for f in findings)


def test_class_constant_backed_template_force_send_is_reported(tmp_path: Path) -> None:
    """Class-scoped force_send values should not hide synchronous sends."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
class Sale:
    FORCE_SEND = True

    def action_send(self):
        template = self.env.ref('sale.email_template_edi_sale')
        template.send_mail(self.id, force_send=FORCE_SEND)
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)

    assert any(f.rule_id == "odoo-mail-force-send" for f in findings)


def test_flags_with_user_superuser_message_post(tmp_path: Path) -> None:
    """with_user(SUPERUSER_ID) chatter posts should be treated as elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "message.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class Message(models.Model):
    _name = 'x.message'

    def post(self):
        return self.with_user(SUPERUSER_ID).message_post(body='Internal update')
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-chatter-sudo-post" in rule_ids


def test_constant_with_user_message_post_is_reported(tmp_path: Path) -> None:
    """Constant-backed superuser IDs should still mark chatter posts elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "message.py").write_text(
        """
ROOT_UID = 1

class Message:
    def post(self):
        return self.with_user(ROOT_UID).message_post(body='Internal update')
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-chatter-sudo-post" in rule_ids


def test_flags_keyword_with_user_superuser_message_post(tmp_path: Path) -> None:
    """Keyword with_user(uid=SUPERUSER_ID) chatter posts are elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "message.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class Message(models.Model):
    _name = 'x.message'

    def post(self):
        return self.with_user(uid=SUPERUSER_ID).message_post(body='Internal update')
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-chatter-sudo-post" in rule_ids


def test_flags_env_ref_admin_with_user_message_post(tmp_path: Path) -> None:
    """with_user(env.ref('base.user_admin')) chatter posts are elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "message.py").write_text(
        """
from odoo import models

class Message(models.Model):
    _name = 'x.message'

    def post(self):
        return self.with_user(self.env.ref('base.user_admin')).message_post(body='Internal update')
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-chatter-sudo-post" in rule_ids


def test_flags_aliased_with_user_one_template_send(tmp_path: Path) -> None:
    """with_user(1) posture on mail template sends should survive aliases."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def action_send(self):
        template = self.env.ref('sale.email_template_edi_sale').with_user(1)
        template.send_mail(self.id, force_send=True)
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-send-sudo" in rule_ids
    assert "odoo-mail-force-send" in rule_ids


def test_flags_aliased_env_ref_root_template_send(tmp_path: Path) -> None:
    """with_user(env.ref('base.user_root')) posture should survive template aliases."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def action_send(self):
        template = self.env.ref('sale.email_template_edi_sale').with_user(self.env.ref('base.user_root'))
        template.send_mail(self.id, force_send=True)
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-send-sudo" in rule_ids
    assert "odoo-mail-force-send" in rule_ids


def test_flags_aliased_template_sudo_send(tmp_path: Path) -> None:
    """Sudo posture on mail template sends should survive local aliases."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def action_send(self):
        template = self.env.ref('sale.email_template_edi_sale').sudo()
        template.send_mail(self.id, force_send=True)
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-send-sudo" in rule_ids
    assert "odoo-mail-force-send" in rule_ids


def test_flags_tuple_unpacked_template_sudo_send_and_tainted_values(tmp_path: Path) -> None:
    """Tuple-unpacked template aliases and request-derived email values should be tracked."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "mail.py").write_text(
        """
from odoo import http
from odoo.http import request

class Mail(http.Controller):
    @http.route('/public/template/send', auth='public')
    def send_template(self, **kwargs):
        template, email_to = request.env.ref('sale.email_template_edi_sale').sudo(), kwargs.get('email_to')
        body, static_subject = kwargs.get('body'), 'Subject'
        return template.send_mail(
            int(kwargs.get('id')),
            force_send=True,
            email_values={
                'email_to': email_to,
                'subject': static_subject,
                'body_html': body,
            },
        )
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-send-public-route" in rule_ids
    assert "odoo-mail-send-sudo" in rule_ids
    assert "odoo-mail-force-send" in rule_ids
    assert "odoo-mail-tainted-recipients" in rule_ids
    assert "odoo-mail-tainted-body" in rule_ids


def test_flags_starred_rest_template_sudo_send_and_tainted_values(tmp_path: Path) -> None:
    """Starred-rest template aliases and request-derived email values should be tracked."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "mail.py").write_text(
        """
from odoo import http
from odoo.http import request

class Mail(http.Controller):
    @http.route('/public/template/send', auth='public')
    def send_template(self, **kwargs):
        marker, *items, tail = (
            'x',
            request.env.ref('sale.email_template_edi_sale').sudo(),
            kwargs.get('email_to'),
            kwargs.get('body'),
            'end',
        )
        template = items[0]
        email_to = items[1]
        body = items[2]
        return template.send_mail(
            int(kwargs.get('id')),
            force_send=True,
            email_values={
                'email_to': email_to,
                'body_html': body,
            },
        )
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_mail_chatter(tmp_path)}

    assert "odoo-mail-send-public-route" in rule_ids
    assert "odoo-mail-send-sudo" in rule_ids
    assert "odoo-mail-force-send" in rule_ids
    assert "odoo-mail-tainted-recipients" in rule_ids
    assert "odoo-mail-tainted-body" in rule_ids


def test_flags_send_mail_tainted_email_values(tmp_path: Path) -> None:
    """send_mail email_values can override template recipients and body."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "mail.py").write_text(
        """
from odoo import http
from odoo.http import request

class Mail(http.Controller):
    @http.route('/public/template/send', auth='public')
    def send_template(self, **kwargs):
        template = request.env.ref('sale.email_template_edi_sale').sudo()
        return template.send_mail(
            int(kwargs.get('id')),
            email_values={
                'email_to': kwargs.get('email_to'),
                'body_html': kwargs.get('body'),
            },
        )
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-send-public-route" in rule_ids
    assert "odoo-mail-tainted-recipients" in rule_ids
    assert "odoo-mail-tainted-body" in rule_ids


def test_constant_email_values_send_mail_are_reported(tmp_path: Path) -> None:
    """Constant email_values dictionaries should still expose body and recipient fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "mail.py").write_text(
        """
EMAIL_TO = 'ops@example.com'
EMAIL_VALUES = {
    'email_to': EMAIL_TO,
    'body_html': 'reset_password_token issued',
}

class Mail:
    def send_template(self):
        template = self.env.ref('sale.email_template_edi_sale')
        return template.send_mail(self.id, email_values=EMAIL_VALUES)
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-sensitive-body" in rule_ids


def test_flags_public_tainted_follower_subscription(tmp_path: Path) -> None:
    """Public routes should not subscribe request-selected followers."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "followers.py").write_text(
        """
from odoo import http
from odoo.http import request

class Followers(http.Controller):
    @http.route('/ticket/follow', auth='public', csrf=False)
    def follow(self, **kwargs):
        ticket = request.env['helpdesk.ticket'].sudo().browse(kwargs.get('id'))
        return ticket.message_subscribe(
            partner_ids=kwargs.get('partner_ids'),
            subtype_ids=kwargs.get('subtype_ids'),
        )
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-public-follower-subscribe" in rule_ids
    assert "odoo-mail-tainted-follower-subscribe" in rule_ids


def test_flags_body_argument_message_post(tmp_path: Path) -> None:
    """Body-shaped method arguments should be treated as caller-controlled."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "message.py").write_text(
        """
from odoo import models

class Message(models.Model):
    _name = 'x.message'

    def post(self, body):
        return self.message_post(body=body)
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)

    assert any(f.rule_id == "odoo-mail-tainted-body" for f in findings)


def test_reassigned_body_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a request body alias for safe content should clear taint."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "message.py").write_text(
        """
from odoo import models

class Message(models.Model):
    _name = 'x.message'

    def post(self, **kwargs):
        body = kwargs.get('body')
        body = 'Internal update'
        return self.message_post(body=body)
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)

    assert not any(f.rule_id == "odoo-mail-tainted-body" for f in findings)


def test_looped_partner_id_from_request_is_tainted(tmp_path: Path) -> None:
    """Loop variables derived from request recipient lists should stay tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "followers.py").write_text(
        """
from odoo import http

class Followers(http.Controller):
    @http.route('/ticket/follow', auth='user')
    def follow(self, **kwargs):
        for partner_id in kwargs.get('partner_ids'):
            self.env['helpdesk.ticket'].browse(1).message_subscribe(partner_ids=[partner_id])
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)

    assert any(f.rule_id == "odoo-mail-tainted-follower-subscribe" for f in findings)


def test_safe_loop_reassignment_clears_mail_taint(tmp_path: Path) -> None:
    """Loop targets should not remain tainted after rebinding from safe data."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "message.py").write_text(
        """
from odoo import models

class Message(models.Model):
    _name = 'x.message'

    def post(self, **kwargs):
        for body in [kwargs.get('body')]:
            pass
        for body in ['Internal update']:
            self.message_post(body=body)
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)

    assert not any(f.rule_id == "odoo-mail-tainted-body" for f in findings)


def test_comprehension_derived_mail_recipients_are_tainted(tmp_path: Path) -> None:
    """Comprehensions carrying request data into mail recipients should be reported."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "mail.py").write_text(
        """
from odoo import http
from odoo.http import request

class Mail(http.Controller):
    @http.route('/public/template/send', auth='public')
    def send_template(self, **kwargs):
        template = request.env.ref('sale.email_template_edi_sale')
        recipients = [email for email in kwargs.get('emails')]
        return template.send_mail(
            int(kwargs.get('id')),
            email_values={'email_to': ','.join(recipients)},
        )
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)

    assert any(f.rule_id == "odoo-mail-tainted-recipients" for f in findings)


def test_comprehension_filter_derived_mail_recipients_are_tainted(tmp_path: Path) -> None:
    """Request-only comprehension filters should taint generated mail recipients."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "mail.py").write_text(
        """
from odoo import http
from odoo.http import request

class Mail(http.Controller):
    @http.route('/public/template/send', auth='public')
    def send_template(self, **kwargs):
        template = request.env.ref('sale.email_template_edi_sale')
        recipients = ['ops@example.com' for _ in range(1) if kwargs.get('emails')]
        return template.send_mail(
            int(kwargs.get('id')),
            email_values={'email_to': ','.join(recipients)},
        )
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)

    assert any(f.rule_id == "odoo-mail-tainted-recipients" for f in findings)


def test_named_expression_derived_mail_recipients_are_tainted(tmp_path: Path) -> None:
    """Walrus-bound mail recipients should remain tainted after the condition."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "mail.py").write_text(
        """
from odoo import http
from odoo.http import request

class Mail(http.Controller):
    @http.route('/public/template/send', auth='public')
    def send_template(self, **kwargs):
        template = request.env.ref('sale.email_template_edi_sale')
        if recipient := kwargs.get('email'):
            return template.send_mail(
                int(kwargs.get('id')),
                email_values={'email_to': recipient},
            )
        return None
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)

    assert any(f.rule_id == "odoo-mail-tainted-recipients" for f in findings)


def test_boolop_derived_mail_recipients_are_tainted(tmp_path: Path) -> None:
    """Boolean fallback expressions should keep mail recipients tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "mail.py").write_text(
        """
from odoo import http
from odoo.http import request

class Mail(http.Controller):
    @http.route('/public/template/send', auth='public')
    def send_template(self, **kwargs):
        template = request.env.ref('sale.email_template_edi_sale')
        recipient = kwargs.get('email') or 'ops@example.com'
        return template.send_mail(
            int(kwargs.get('id')),
            email_values={'email_to': recipient},
        )
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)

    assert any(f.rule_id == "odoo-mail-tainted-recipients" for f in findings)


def test_flags_route_path_id_follower_subscription(tmp_path: Path) -> None:
    """Route path IDs can select records and followers even without kwargs."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "followers.py").write_text(
        """
from odoo import http
from odoo.http import request

class Followers(http.Controller):
    @http.route('/public/orders/<int:order_id>/follow/<int:partner_id>', auth='public', csrf=False)
    def follow_order(self, order_id, partner_id):
        order = request.env['sale.order'].sudo().browse(order_id)
        return order.message_subscribe(partner_ids=[partner_id])
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-public-follower-subscribe" in rule_ids
    assert "odoo-mail-tainted-follower-subscribe" in rule_ids


def test_flags_sensitive_model_follower_subscription(tmp_path: Path) -> None:
    """Follower subscriptions on sensitive models can expose private record updates."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "followers.py").write_text(
        """
from odoo import models

class Followers(models.Model):
    _name = 'x.followers'

    def subscribe_provider_watchers(self):
        provider = self.env['payment.provider'].browse(1)
        return provider.message_subscribe(partner_ids=[self.env.user.partner_id.id])
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)

    assert any(f.rule_id == "odoo-mail-sensitive-model-follower-subscribe" for f in findings)


def test_flags_public_mail_followers_sudo_tainted_mutation(tmp_path: Path) -> None:
    """Raw mail.followers writes are persistent notification exposure."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "followers.py").write_text(
        """
from odoo import http
from odoo.http import request

class Followers(http.Controller):
    @http.route('/public/followers', auth='public', csrf=False)
    def followers(self, **kwargs):
        return request.env['mail.followers'].sudo().create({
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
            'partner_id': kwargs.get('partner_id'),
            'subtype_ids': kwargs.get('subtype_ids'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-followers-public-route-mutation" in rule_ids
    assert "odoo-mail-followers-sudo-mutation" in rule_ids
    assert "odoo-mail-followers-tainted-mutation" in rule_ids


def test_flags_aliased_with_user_one_mail_followers_mutation(tmp_path: Path) -> None:
    """with_user(1) mail.followers aliases should keep elevated posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "followers.py").write_text(
        """
class Followers:
    def follow(self, values):
        Followers = self.env['mail.followers'].with_user(1)
        return Followers.create(values)
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-followers-sudo-mutation" in rule_ids


def test_request_alias_mail_followers_tainted_mutation(tmp_path: Path) -> None:
    """Request aliases should taint raw mail.followers mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "followers.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Followers(http.Controller):
    @http.route('/public/followers', auth='public', csrf=False)
    def followers(self):
        params = req.params
        return req.env['mail.followers'].sudo().create({
            'res_model': params.get('model'),
            'res_id': params.get('id'),
            'partner_id': params.get('partner_id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-followers-public-route-mutation" in rule_ids
    assert "odoo-mail-followers-sudo-mutation" in rule_ids
    assert "odoo-mail-followers-tainted-mutation" in rule_ids


def test_flags_sensitive_model_mail_followers_mutation(tmp_path: Path) -> None:
    """Raw mail.followers writes to sensitive models deserve review even with static input."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "followers.py").write_text(
        """
from odoo import models

class Followers(models.Model):
    _name = 'x.followers'

    def follow_order(self):
        return self.env['mail.followers'].create({
            'res_model': 'sale.order',
            'res_id': 1,
            'partner_id': self.env.user.partner_id.id,
        })
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)

    assert any(f.rule_id == "odoo-mail-followers-sensitive-model-mutation" for f in findings)


def test_constant_backed_sensitive_model_mail_followers_mutation(tmp_path: Path) -> None:
    """Constant-backed follower res_model values should not hide sensitive targets."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "followers.py").write_text(
        """
FOLLOWED_MODEL = 'sale.order'

class Followers:
    def follow_order(self):
        return self.env['mail.followers'].create({
            'res_model': FOLLOWED_MODEL,
            'res_id': 1,
            'partner_id': self.env.user.partner_id.id,
        })
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)

    assert any(f.rule_id == "odoo-mail-followers-sensitive-model-mutation" for f in findings)


def test_constant_dict_sensitive_model_mail_followers_mutation(tmp_path: Path) -> None:
    """Constant follower value dictionaries should still expose sensitive res_model values."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "followers.py").write_text(
        """
FOLLOWED_MODEL = 'sale.order'
FOLLOW_VALUES = {
    'res_model': FOLLOWED_MODEL,
    'res_id': 1,
    'partner_id': 2,
}

class Followers:
    def follow_order(self):
        return self.env['mail.followers'].create(FOLLOW_VALUES)
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)

    assert any(f.rule_id == "odoo-mail-followers-sensitive-model-mutation" for f in findings)


def test_class_constant_dict_sensitive_model_mail_followers_mutation(tmp_path: Path) -> None:
    """Class-scoped follower value dictionaries should expose sensitive res_model values."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "followers.py").write_text(
        """
class Followers:
    FOLLOWED_MODEL = 'sale.order'
    FOLLOW_VALUES = {
        'res_model': FOLLOWED_MODEL,
        'res_id': 1,
        'partner_id': 2,
    }

    def follow_order(self):
        return self.env['mail.followers'].create(FOLLOW_VALUES)
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)

    assert any(f.rule_id == "odoo-mail-followers-sensitive-model-mutation" for f in findings)


def test_flags_route_path_id_mail_followers_mutation(tmp_path: Path) -> None:
    """Raw mail.followers route IDs should be treated as request-controlled."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "followers.py").write_text(
        """
from odoo import http
from odoo.http import request

class Followers(http.Controller):
    @http.route('/public/orders/<int:order_id>/followers/<int:partner_id>', auth='public', csrf=False)
    def followers(self, order_id, partner_id):
        return request.env['mail.followers'].sudo().create({
            'res_model': 'sale.order',
            'res_id': order_id,
            'partner_id': partner_id,
        })
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-followers-public-route-mutation" in rule_ids
    assert "odoo-mail-followers-sudo-mutation" in rule_ids
    assert "odoo-mail-followers-tainted-mutation" in rule_ids


def test_flags_aliased_public_mail_followers_sudo_tainted_mutation(tmp_path: Path) -> None:
    """Raw mail.followers aliases should still be classified as follower mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "followers.py").write_text(
        """
from odoo import http
from odoo.http import request

class Followers(http.Controller):
    @http.route('/public/followers', auth='public', csrf=False)
    def followers(self, **kwargs):
        Followers = request.env['mail.followers'].sudo()
        return Followers.create({
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
            'partner_id': kwargs.get('partner_id'),
            'subtype_ids': kwargs.get('subtype_ids'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-followers-public-route-mutation" in rule_ids
    assert "odoo-mail-followers-sudo-mutation" in rule_ids
    assert "odoo-mail-followers-tainted-mutation" in rule_ids


def test_flags_tuple_unpacked_public_mail_followers_sudo_tainted_mutation(tmp_path: Path) -> None:
    """Tuple-unpacked raw mail.followers aliases should keep model, sudo, and taint state."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "followers.py").write_text(
        """
from odoo import http
from odoo.http import request

class Followers(http.Controller):
    @http.route('/public/followers', auth='public', csrf=False)
    def followers(self, **kwargs):
        Followers, partner_id = request.env['mail.followers'].sudo(), kwargs.get('partner_id')
        res_model, res_id = kwargs.get('model'), kwargs.get('id')
        return Followers.create({
            'res_model': res_model,
            'res_id': res_id,
            'partner_id': partner_id,
        })
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-followers-public-route-mutation" in rule_ids
    assert "odoo-mail-followers-sudo-mutation" in rule_ids
    assert "odoo-mail-followers-tainted-mutation" in rule_ids


def test_flags_named_expression_public_mail_followers_sudo_tainted_mutation(tmp_path: Path) -> None:
    """Walrus-bound raw mail.followers aliases should keep model, sudo, and taint state."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "followers.py").write_text(
        """
from odoo import http
from odoo.http import request

class Followers(http.Controller):
    @http.route('/public/followers', auth='public', csrf=False)
    def followers(self, **kwargs):
        if Followers := request.env['mail.followers'].sudo():
            return Followers.create({
                'res_model': kwargs.get('model'),
                'res_id': kwargs.get('id'),
                'partner_id': kwargs.get('partner_id'),
            })
        return request.not_found()
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-followers-public-route-mutation" in rule_ids
    assert "odoo-mail-followers-sudo-mutation" in rule_ids
    assert "odoo-mail-followers-tainted-mutation" in rule_ids


def test_flags_starred_public_mail_followers_sudo_tainted_mutation(tmp_path: Path) -> None:
    """Starred raw mail.followers aliases should keep model, sudo, and taint state."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "followers.py").write_text(
        """
from odoo import http
from odoo.http import request

class Followers(http.Controller):
    @http.route('/public/followers', auth='public', csrf=False)
    def followers(self, **kwargs):
        *Followers, partner_id = request.env['mail.followers'].sudo(), kwargs.get('partner_id')
        return Followers.create({
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
            'partner_id': partner_id,
        })
""",
        encoding="utf-8",
    )

    findings = scan_mail_chatter(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-mail-followers-public-route-mutation" in rule_ids
    assert "odoo-mail-followers-sudo-mutation" in rule_ids
    assert "odoo-mail-followers-tainted-mutation" in rule_ids


def test_flags_starred_rest_public_mail_followers_sudo_tainted_mutation(tmp_path: Path) -> None:
    """Starred-rest raw mail.followers aliases should keep model, sudo, and taint state."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "followers.py").write_text(
        """
from odoo import http
from odoo.http import request

class Followers(http.Controller):
    @http.route('/public/followers', auth='public', csrf=False)
    def followers(self, **kwargs):
        marker, *items, tail = (
            'x',
            request.env['mail.followers'].sudo(),
            kwargs.get('partner_id'),
            kwargs.get('id'),
            'end',
        )
        Followers = items[0]
        partner_id = items[1]
        res_id = items[2]
        return Followers.create({
            'res_model': kwargs.get('model'),
            'res_id': res_id,
            'partner_id': partner_id,
        })
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_mail_chatter(tmp_path)}

    assert "odoo-mail-followers-public-route-mutation" in rule_ids
    assert "odoo-mail-followers-sudo-mutation" in rule_ids
    assert "odoo-mail-followers-tainted-mutation" in rule_ids


def test_safe_internal_message_is_ignored(tmp_path: Path) -> None:
    """Static internal chatter posts should avoid scanner noise."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "task.py").write_text(
        """
from odoo import models

class Task(models.Model):
    _name = 'x.task'

    def action_done(self):
        return self.message_post(body='Task closed')
""",
        encoding="utf-8",
    )

    assert scan_mail_chatter(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_mail.py").write_text(
        """
class Mail(models.Model):
    def send(self, **kwargs):
        return self.sudo().message_post(body=kwargs.get('body'))
""",
        encoding="utf-8",
    )

    assert scan_mail_chatter(tmp_path) == []
