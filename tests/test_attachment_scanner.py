"""Tests for Odoo attachment metadata scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.attachment_scanner import scan_attachments


def test_public_route_tainted_attachment_create_is_reported(tmp_path: Path) -> None:
    """Public uploads must not choose attachment ownership metadata."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/attach', auth='public', csrf=False)
    def attach(self, **kwargs):
        return request.env['ir.attachment'].sudo().create({
            'name': kwargs.get('name'),
            'datas': kwargs.get('payload'),
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
            'public': True,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-public-route-mutation" in rule_ids
    assert "odoo-attachment-sudo-mutation" in rule_ids
    assert "odoo-attachment-tainted-res-model" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids


def test_request_alias_attachment_create_metadata_is_reported(tmp_path: Path) -> None:
    """Aliased Odoo request imports should still seed attachment metadata taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/public/attach', auth='public', csrf=False)
    def attach(self):
        payload = req.get_http_params()
        return req.env['ir.attachment'].sudo().create({
            'name': 'x.pdf',
            'datas': payload.get('payload'),
            'res_model': payload.get('model'),
            'res_id': payload.get('id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-public-route-mutation" in rule_ids
    assert "odoo-attachment-sudo-mutation" in rule_ids
    assert "odoo-attachment-tainted-res-model" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids


def test_imported_route_decorator_public_attachment_create_is_reported(tmp_path: Path) -> None:
    """Imported route decorators should still expose public attachment mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request, route

class Controller(http.Controller):
    @route('/public/attach', auth='public', csrf=False)
    def attach(self, **kwargs):
        return request.env['ir.attachment'].sudo().create({
            'name': kwargs.get('name'),
            'datas': kwargs.get('payload'),
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
            'public': True,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-public-route-mutation" in rule_ids
    assert "odoo-attachment-sudo-mutation" in rule_ids
    assert "odoo-attachment-tainted-res-model" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids


def test_aliased_imported_route_decorator_public_attachment_create_is_reported(tmp_path: Path) -> None:
    """Aliased imported route decorators should expose public attachment mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request, route as odoo_route

class Controller(http.Controller):
    @odoo_route('/public/attach', auth='public', csrf=False)
    def attach(self, **kwargs):
        return request.env['ir.attachment'].sudo().create({
            'name': kwargs.get('name'),
            'datas': kwargs.get('payload'),
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
            'public': True,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-public-route-mutation" in rule_ids
    assert "odoo-attachment-tainted-res-model" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids


def test_aliased_http_module_public_attachment_create_is_reported(tmp_path: Path) -> None:
    """Aliased Odoo http module imports should expose public attachment mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http as odoo_http
from odoo.http import request

class Controller(odoo_http.Controller):
    @odoo_http.route('/public/attach', auth='public', csrf=False)
    def attach(self, **kwargs):
        return request.env['ir.attachment'].sudo().create({
            'name': kwargs.get('name'),
            'datas': kwargs.get('payload'),
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
            'public': True,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-public-route-mutation" in rule_ids
    assert "odoo-attachment-sudo-mutation" in rule_ids
    assert "odoo-attachment-tainted-res-model" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids


def test_imported_odoo_http_module_public_attachment_create_is_reported(tmp_path: Path) -> None:
    """Direct odoo.http imports should expose public attachment mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
import odoo.http as odoo_http

class Controller(odoo_http.Controller):
    @odoo_http.route('/public/attach', auth='public', csrf=False)
    def attach(self):
        payload = odoo_http.request.get_http_params()
        return odoo_http.request.env['ir.attachment'].sudo().create({
            'name': 'x.pdf',
            'datas': payload.get('payload'),
            'res_model': payload.get('model'),
            'res_id': payload.get('id'),
            'public': True,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-public-route-mutation" in rule_ids
    assert "odoo-attachment-sudo-mutation" in rule_ids
    assert "odoo-attachment-tainted-res-model" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids


def test_imported_odoo_module_public_attachment_create_is_reported(tmp_path: Path) -> None:
    """Direct odoo imports should expose public attachment mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
import odoo as od

class Controller(od.http.Controller):
    @od.http.route('/public/attach', auth='public', csrf=False)
    def attach(self):
        payload = od.http.request.get_http_params()
        return od.http.request.env['ir.attachment'].sudo().create({
            'name': 'x.pdf',
            'datas': payload.get('payload'),
            'res_model': payload.get('model'),
            'res_id': payload.get('id'),
            'public': True,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-public-route-mutation" in rule_ids
    assert "odoo-attachment-sudo-mutation" in rule_ids
    assert "odoo-attachment-tainted-res-model" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids


def test_active_content_attachment_create_is_reported(tmp_path: Path) -> None:
    """Browser-active attachment types need inline-serving review."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
from odoo import models

class AttachmentBuilder(models.Model):
    _name = 'x.attachment.builder'

    def build(self, payload):
        return self.env['ir.attachment'].create({
            'name': 'preview.html',
            'datas': payload,
            'mimetype': 'text/html',
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(
        finding.rule_id == "odoo-attachment-active-content"
        and finding.severity == "medium"
        and "mimetype=text/html" in finding.message
        and "name=preview.html" in finding.message
        for finding in findings
    )


def test_public_active_content_attachment_create_is_critical(tmp_path: Path) -> None:
    """Public routes creating public active content are high-impact XSS leads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/svg', auth='public', csrf=False)
    def build_svg(self, **kwargs):
        return request.env['ir.attachment'].sudo().create({
            'name': 'badge.svg',
            'datas': kwargs.get('payload'),
            'mimetype': 'image/svg+xml',
            'public': True,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(
        finding.rule_id == "odoo-attachment-active-content"
        and finding.severity == "critical"
        and "mimetype=image/svg+xml" in finding.message
        for finding in findings
    )


def test_active_content_attachment_write_is_reported(tmp_path: Path) -> None:
    """Attachment writes can turn an existing file into browser-active content."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
from odoo import models

class AttachmentBuilder(models.Model):
    _name = 'x.attachment.builder'

    def publish_script(self, attachment_id):
        attachment = self.env['ir.attachment'].browse(attachment_id)
        return attachment.write({
            'name': 'snippet.js',
            'mimetype': 'application/javascript',
            'public': True,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(
        finding.rule_id == "odoo-attachment-active-content"
        and finding.severity == "high"
        and finding.sink.endswith(".write")
        for finding in findings
    )


def test_sensitive_attachment_filename_create_is_reported(tmp_path: Path) -> None:
    """Attachment filenames should not contain token or secret-shaped material."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
from odoo import models

class AttachmentBuilder(models.Model):
    _name = 'x.attachment.builder'

    def build(self, payload):
        filename = 'invoice-access_token-static.pdf'
        return self.env['ir.attachment'].create({
            'name': filename,
            'datas_fname': 'backup-client_secret.txt',
            'datas': payload,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(
        finding.rule_id == "odoo-attachment-sensitive-filename"
        and finding.severity == "high"
        and "name=invoice-access_token-static.pdf" in finding.message
        and "datas_fname=backup-client_secret.txt" in finding.message
        for finding in findings
    )


def test_sensitive_attachment_filename_write_is_reported(tmp_path: Path) -> None:
    """Attachment writes should not rename files to token-shaped names."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
from odoo import models

class AttachmentBuilder(models.Model):
    _name = 'x.attachment.builder'

    def rename(self, attachment_id):
        attachment = self.env['ir.attachment'].browse(attachment_id)
        return attachment.write({'name': 'reset_password_token.pdf'})
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(
        finding.rule_id == "odoo-attachment-sensitive-filename"
        and finding.severity == "high"
        and finding.sink.endswith(".write")
        for finding in findings
    )


def test_tainted_attachment_url_create_is_reported(tmp_path: Path) -> None:
    """Request-controlled URL attachments should not trust arbitrary link targets."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/link', auth='public', csrf=False)
    def link(self, **kwargs):
        return request.env['ir.attachment'].create({
            'name': 'partner-document',
            'type': 'url',
            'url': kwargs.get('target'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(
        finding.rule_id == "odoo-attachment-tainted-url"
        and finding.severity == "critical"
        and finding.sink.endswith(".create")
        for finding in findings
    )


def test_tainted_attachment_url_write_is_reported(tmp_path: Path) -> None:
    """Attachment URL writes should not accept untrusted link targets."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
from odoo import models

class AttachmentBuilder(models.Model):
    _name = 'x.attachment.builder'

    def update_link(self, attachment_id, **kwargs):
        attachment = self.env['ir.attachment'].browse(attachment_id)
        return attachment.write({'type': 'url', 'url': kwargs.get('target')})
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(
        finding.rule_id == "odoo-attachment-tainted-url"
        and finding.severity == "high"
        and finding.sink.endswith(".write")
        for finding in findings
    )


def test_unsafe_attachment_url_scheme_create_is_reported(tmp_path: Path) -> None:
    """URL attachments should not store executable link schemes."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
from odoo import models

class AttachmentBuilder(models.Model):
    _name = 'x.attachment.builder'

    def build_link(self):
        return self.env['ir.attachment'].create({
            'name': 'script-link',
            'type': 'url',
            'url': 'javascript:alert(document.domain)',
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(
        finding.rule_id == "odoo-attachment-unsafe-url-scheme"
        and finding.severity == "high"
        and "javascript:alert(document.domain)" in finding.message
        for finding in findings
    )


def test_unsafe_attachment_url_scheme_write_is_reported(tmp_path: Path) -> None:
    """Attachment URL writes should catch constant-backed dangerous schemes."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
from odoo import models

UNSAFE_URL = 'data:image/svg+xml,<svg onload=alert(1)>'

class AttachmentBuilder(models.Model):
    _name = 'x.attachment.builder'

    def update_link(self, attachment_id):
        attachment = self.env['ir.attachment'].browse(attachment_id)
        return attachment.write({'type': 'url', 'url': UNSAFE_URL})
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(
        finding.rule_id == "odoo-attachment-unsafe-url-scheme"
        and finding.severity == "high"
        and finding.sink.endswith(".write")
        for finding in findings
    )


def test_non_odoo_route_decorator_public_attachment_create_is_ignored(tmp_path: Path) -> None:
    """Local route-like decorators should not create Odoo route context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo.http import request

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class Controller:
    @router.route('/public/attach', auth='public', csrf=False)
    def attach(self, **kwargs):
        return request.env['ir.attachment'].sudo().create({
            'name': kwargs.get('name'),
            'datas': kwargs.get('payload'),
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
            'public': True,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert not any(f.rule_id == "odoo-attachment-public-route-mutation" for f in findings)
    assert any(f.rule_id == "odoo-attachment-sudo-mutation" for f in findings)


def test_constant_backed_public_attachment_create_is_reported(tmp_path: Path) -> None:
    """Constant-backed public route metadata should not hide attachment mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

ATTACH_ROUTES = ['/public/attach']
ATTACH_AUTH = 'public'
ATTACH_CSRF = False

class Controller(http.Controller):
    @http.route(ATTACH_ROUTES, auth=ATTACH_AUTH, csrf=ATTACH_CSRF)
    def attach(self, **kwargs):
        return request.env['ir.attachment'].sudo().create({
            'name': kwargs.get('name'),
            'datas': kwargs.get('payload'),
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-public-route-mutation" in rule_ids
    assert "odoo-attachment-sudo-mutation" in rule_ids
    assert "odoo-attachment-tainted-res-model" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids
    assert any(
        f.rule_id == "odoo-attachment-tainted-res-model" and f.severity == "critical" and f.route == "/public/attach"
        for f in findings
    )


def test_class_constant_backed_public_attachment_create_is_reported(tmp_path: Path) -> None:
    """Class-scoped public route metadata should not hide attachment mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    ATTACH_ROUTE = '/public/attach'
    ATTACH_ROUTES = [ATTACH_ROUTE]
    AUTH_BASE = 'public'
    ATTACH_AUTH = AUTH_BASE
    ATTACH_CSRF = False

    @http.route(ATTACH_ROUTES, auth=ATTACH_AUTH, csrf=ATTACH_CSRF)
    def attach(self, **kwargs):
        return request.env['ir.attachment'].sudo().create({
            'name': kwargs.get('name'),
            'datas': kwargs.get('payload'),
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-public-route-mutation" in rule_ids
    assert "odoo-attachment-sudo-mutation" in rule_ids
    assert "odoo-attachment-tainted-res-model" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids
    assert any(
        f.rule_id == "odoo-attachment-tainted-res-model" and f.severity == "critical" and f.route == "/public/attach"
        for f in findings
    )


def test_static_unpack_public_attachment_create_is_reported(tmp_path: Path) -> None:
    """Static **route options should keep public attachment mutations critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

ATTACH_OPTIONS = {'route': '/public/attach/unpacked-options', 'auth': 'public', 'csrf': False}

class Controller(http.Controller):
    @http.route(**ATTACH_OPTIONS)
    def attach(self, **kwargs):
        return request.env['ir.attachment'].sudo().create({
            'name': kwargs.get('name'),
            'datas': kwargs.get('payload'),
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(
        f.rule_id == "odoo-attachment-public-route-mutation"
        and f.severity == "critical"
        and f.route == "/public/attach/unpacked-options"
        for f in findings
    )
    assert any(
        f.rule_id == "odoo-attachment-tainted-res-model"
        and f.severity == "critical"
        and f.route == "/public/attach/unpacked-options"
        for f in findings
    )


def test_nested_static_unpack_public_attachment_create_is_reported(tmp_path: Path) -> None:
    """Nested static **route options should keep public attachment mutations critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

BASE_OPTIONS = {'auth': 'public', 'csrf': False}
ATTACH_OPTIONS = {**BASE_OPTIONS, 'route': '/public/attach/unpacked-options'}

class Controller(http.Controller):
    @http.route(**ATTACH_OPTIONS)
    def attach(self, **kwargs):
        return request.env['ir.attachment'].sudo().create({
            'name': kwargs.get('name'),
            'datas': kwargs.get('payload'),
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(
        f.rule_id == "odoo-attachment-public-route-mutation"
        and f.severity == "critical"
        and f.route == "/public/attach/unpacked-options"
        for f in findings
    )
    assert any(
        f.rule_id == "odoo-attachment-tainted-res-model"
        and f.severity == "critical"
        and f.route == "/public/attach/unpacked-options"
        for f in findings
    )


def test_dict_union_static_unpack_public_attachment_create_is_reported(tmp_path: Path) -> None:
    """Dict-union **route options should keep public attachment mutations critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

BASE_OPTIONS = {'auth': 'public', 'csrf': False}
ATTACH_OPTIONS = BASE_OPTIONS | {'route': '/public/attach/unpacked-options'}

class Controller(http.Controller):
    @http.route(**ATTACH_OPTIONS)
    def attach(self, **kwargs):
        return request.env['ir.attachment'].sudo().create({
            'name': kwargs.get('name'),
            'datas': kwargs.get('payload'),
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(
        f.rule_id == "odoo-attachment-public-route-mutation"
        and f.severity == "critical"
        and f.route == "/public/attach/unpacked-options"
        for f in findings
    )
    assert any(
        f.rule_id == "odoo-attachment-tainted-res-model"
        and f.severity == "critical"
        and f.route == "/public/attach/unpacked-options"
        for f in findings
    )


def test_class_constant_static_unpack_public_attachment_create_is_reported(tmp_path: Path) -> None:
    """Class-scoped static **route options should keep public attachment mutations critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    ATTACH_OPTIONS = {'route': '/public/attach/unpacked-options', 'auth': 'public', 'csrf': False}

    @http.route(**ATTACH_OPTIONS)
    def attach(self, **kwargs):
        return request.env['ir.attachment'].sudo().create({
            'name': kwargs.get('name'),
            'datas': kwargs.get('payload'),
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(
        f.rule_id == "odoo-attachment-public-route-mutation"
        and f.severity == "critical"
        and f.route == "/public/attach/unpacked-options"
        for f in findings
    )
    assert any(
        f.rule_id == "odoo-attachment-tainted-res-model"
        and f.severity == "critical"
        and f.route == "/public/attach/unpacked-options"
        for f in findings
    )


def test_keyword_constant_backed_none_attachment_write_is_critical(tmp_path: Path) -> None:
    """Keyword route constants with auth='none' should keep attachment writes critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

ATTACH_ROUTE = '/public/attach/update'
ATTACH_AUTH = 'none'

class Controller(http.Controller):
    @http.route(route=ATTACH_ROUTE, auth=ATTACH_AUTH)
    def update_attachment(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(kwargs.get('id'))
        return attachment.write({
            'public': True,
            'res_id': kwargs.get('res_id'),
            'access_token': kwargs.get('token'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(
        f.rule_id == "odoo-attachment-public-write" and f.severity == "critical" and f.route == "/public/attach/update"
        for f in findings
    )
    assert any(
        f.rule_id == "odoo-attachment-tainted-access-token-write"
        and f.severity == "critical"
        and f.route == "/public/attach/update"
        for f in findings
    )


def test_public_orphan_and_sensitive_attachment_are_reported(tmp_path: Path) -> None:
    """Public attachments need either safe binding or explicit review."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
class AttachmentHelper:
    def create_public_invoice(self):
        self.env['ir.attachment'].create({
            'name': 'invoice.pdf',
            'datas': self.payload,
            'res_model': 'account.move',
            'public': True,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-public-orphan" in rule_ids
    assert "odoo-attachment-public-sensitive-binding" in rule_ids


def test_constant_backed_public_sensitive_attachment_is_reported(tmp_path: Path) -> None:
    """Constant-backed public flags and model names should not hide risky bindings."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
PUBLIC_ATTACHMENT = True
ATTACH_MODEL = 'account.move'

class AttachmentHelper:
    def create_public_invoice(self):
        self.env['ir.attachment'].create({
            'name': 'invoice.pdf',
            'datas': self.payload,
            'res_model': ATTACH_MODEL,
            'public': PUBLIC_ATTACHMENT,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-public-orphan" in rule_ids
    assert "odoo-attachment-public-sensitive-binding" in rule_ids


def test_recursive_constant_backed_public_sensitive_attachment_is_reported(tmp_path: Path) -> None:
    """Recursive constants should not hide public sensitive attachment bindings."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
PUBLIC_VALUE = True
PUBLIC_ATTACHMENT = PUBLIC_VALUE
BASE_MODEL = 'account.move'
ATTACH_MODEL = BASE_MODEL

class AttachmentHelper:
    def create_public_invoice(self):
        self.env['ir.attachment'].create({
            'name': 'invoice.pdf',
            'datas': self.payload,
            'res_model': ATTACH_MODEL,
            'public': PUBLIC_ATTACHMENT,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-public-orphan" in rule_ids
    assert "odoo-attachment-public-sensitive-binding" in rule_ids


def test_class_constant_public_sensitive_attachment_is_reported(tmp_path: Path) -> None:
    """Class-scoped attachment constants should not hide risky public bindings."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
from odoo import SUPERUSER_ID

class AttachmentHelper:
    ATTACHMENT_MODEL = 'ir.attachment'
    ROOT = SUPERUSER_ID
    PUBLIC_ATTACHMENT = True
    ATTACH_MODEL = 'account.move'

    def create_public_invoice(self):
        attachments = self.env[ATTACHMENT_MODEL].with_user(ROOT)
        attachments.create({
            'name': 'invoice.pdf',
            'datas': self.payload,
            'res_model': ATTACH_MODEL,
            'public': PUBLIC_ATTACHMENT,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-sudo-mutation" in rule_ids
    assert "odoo-attachment-public-orphan" in rule_ids
    assert "odoo-attachment-public-sensitive-binding" in rule_ids


def test_local_constant_public_sensitive_attachment_is_reported(tmp_path: Path) -> None:
    """Function-local attachment constants should not hide risky public bindings."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
from odoo import SUPERUSER_ID

class AttachmentHelper:
    def create_public_invoice(self):
        attachment_model = 'ir.attachment'
        root = SUPERUSER_ID
        public_attachment = True
        attach_model = 'account.move'
        attachments = self.env[attachment_model].with_user(root)
        attachments.create({
            'name': 'invoice.pdf',
            'datas': self.payload,
            'res_model': attach_model,
            'public': public_attachment,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-sudo-mutation" in rule_ids
    assert "odoo-attachment-public-orphan" in rule_ids
    assert "odoo-attachment-public-sensitive-binding" in rule_ids


def test_public_security_model_attachment_bindings_are_reported(tmp_path: Path) -> None:
    """Public attachments bound to security/payment records should be critical."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
class AttachmentHelper:
    def create_public_security_docs(self):
        self.env['ir.attachment'].create({
            'name': 'params.txt',
            'datas': self.payload,
            'res_model': 'ir.config_parameter',
            'res_id': self.param_id.id,
            'public': True,
        })
        self.env['ir.attachment'].create({
            'name': 'provider.txt',
            'datas': self.payload,
            'res_model': 'payment.provider',
            'res_id': self.provider_id.id,
            'public': True,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    sensitive_bindings = [
        finding for finding in findings if finding.rule_id == "odoo-attachment-public-sensitive-binding"
    ]

    assert len(sensitive_bindings) == 2
    assert {finding.severity for finding in sensitive_bindings} == {"critical"}


def test_tainted_attachment_lookup_is_reported(tmp_path: Path) -> None:
    """Request-selected attachment records require explicit access review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/download', auth='user')
    def download(self, **kwargs):
        return request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(f.rule_id == "odoo-attachment-tainted-lookup" for f in findings)


def test_route_path_id_attachment_lookup_is_reported(tmp_path: Path) -> None:
    """Route path IDs should be treated as request-controlled attachment selectors."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/download/<int:attachment_id>', auth='public')
    def download(self, attachment_id):
        return request.env['ir.attachment'].sudo().browse(attachment_id)
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(f.rule_id == "odoo-attachment-tainted-lookup" and f.severity == "high" for f in findings)


def test_tainted_attachment_search_count_lookup_is_reported(tmp_path: Path) -> None:
    """Attachment count endpoints can expose private file existence from request-derived selectors."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/attach/count', auth='public')
    def count(self, **kwargs):
        return request.env['ir.attachment'].sudo().search_count([
            ('res_model', '=', kwargs.get('model')),
            ('res_id', '=', kwargs.get('res_id')),
        ])
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(
        f.rule_id == "odoo-attachment-tainted-lookup" and f.severity == "high" and f.sink.endswith("search_count")
        for f in findings
    )


def test_unpacked_sudo_attachment_alias_and_metadata_are_reported(tmp_path: Path) -> None:
    """Unpacked attachment model aliases and request metadata should stay visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/attach/unpacked', auth='public', csrf=False)
    def attach(self, **kwargs):
        Attachments, res_id = (request.env['ir.attachment'].sudo(), kwargs.get('id'))
        return Attachments.create({
            'name': 'x.pdf',
            'datas': kwargs.get('payload'),
            'res_model': 'sale.order',
            'res_id': res_id,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-public-route-mutation" in rule_ids
    assert "odoo-attachment-sudo-mutation" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids


def test_with_user_superuser_attachment_mutation_is_reported(tmp_path: Path) -> None:
    """Attachment mutations through with_user(SUPERUSER_ID) should be elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
from odoo import SUPERUSER_ID

class AttachmentHelper:
    def create_attachment(self, values):
        return self.env['ir.attachment'].with_user(SUPERUSER_ID).create(values)
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-sudo-mutation" in rule_ids


def test_import_aliased_superuser_attachment_mutation_is_reported(tmp_path: Path) -> None:
    """Imported SUPERUSER_ID aliases should keep attachment mutations elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
from odoo import SUPERUSER_ID as ROOT_UID

class AttachmentHelper:
    def create_attachment(self, values):
        return self.env['ir.attachment'].with_user(ROOT_UID).create(values)
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-sudo-mutation" in rule_ids


def test_keyword_with_user_superuser_attachment_mutation_is_reported(tmp_path: Path) -> None:
    """Keyword with_user(user=SUPERUSER_ID) attachment mutations are elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
from odoo import SUPERUSER_ID

class AttachmentHelper:
    def create_attachment(self, values):
        return self.env['ir.attachment'].with_user(user=SUPERUSER_ID).create(values)
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-sudo-mutation" in rule_ids


def test_aliased_with_user_one_attachment_mutation_is_reported(tmp_path: Path) -> None:
    """A with_user(1) attachment alias should keep its elevated posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
class AttachmentHelper:
    def create_attachment(self, values):
        Attachments = self.env['ir.attachment'].with_user(1)
        return Attachments.create(values)
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-sudo-mutation" in rule_ids


def test_constant_with_user_attachment_mutation_is_reported(tmp_path: Path) -> None:
    """Constant-backed superuser IDs should still mark attachment mutations elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
ROOT_UID = 1

class AttachmentHelper:
    def create_attachment(self, values):
        return self.env['ir.attachment'].with_user(ROOT_UID).create(values)
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-sudo-mutation" in rule_ids


def test_env_ref_admin_attachment_mutation_is_reported(tmp_path: Path) -> None:
    """with_user(env.ref('base.user_admin')) attachment aliases are elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
class AttachmentHelper:
    def create_attachment(self, values):
        Attachments = self.env['ir.attachment'].with_user(self.env.ref('base.user_admin'))
        return Attachments.create(values)
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-sudo-mutation" in rule_ids


def test_starred_unpacked_sudo_attachment_alias_and_metadata_are_reported(tmp_path: Path) -> None:
    """Starred attachment aliases and request metadata should stay visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/upload', auth='public', csrf=False)
    def upload(self, **kwargs):
        _, *items = ('fixed', request.env['ir.attachment'].sudo(), kwargs.get('id'))
        Attachments = items[0]
        res_id = items[1]
        return Attachments.create({
            'name': 'x',
            'res_model': 'sale.order',
            'res_id': res_id,
            'datas': kwargs.get('data'),
        })
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_attachments(tmp_path)}

    assert "odoo-attachment-public-route-mutation" in rule_ids
    assert "odoo-attachment-sudo-mutation" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids


def test_starred_unpacked_attachment_lookup_is_reported(tmp_path: Path) -> None:
    """Starred request ID aliases should remain tainted for attachment lookup."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/download', auth='public')
    def download(self, **kwargs):
        _, *ids = ('fixed', kwargs.get('id'))
        attachment_id = ids[0]
        return request.env['ir.attachment'].sudo().browse(attachment_id)
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(f.rule_id == "odoo-attachment-tainted-lookup" and f.severity == "high" for f in findings)


def test_walrus_sudo_attachment_alias_and_metadata_are_reported(tmp_path: Path) -> None:
    """Walrus-bound attachment aliases should keep mutation and metadata visibility."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/attach/walrus', auth='public', csrf=False)
    def attach(self, **kwargs):
        if Attachments := request.env['ir.attachment'].sudo():
            return Attachments.create({
                'name': 'x.pdf',
                'datas': kwargs.get('payload'),
                'res_model': kwargs.get('model'),
                'res_id': kwargs.get('id'),
            })
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_attachments(tmp_path)}

    assert "odoo-attachment-public-route-mutation" in rule_ids
    assert "odoo-attachment-sudo-mutation" in rule_ids
    assert "odoo-attachment-tainted-res-model" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids


def test_walrus_attachment_values_alias_metadata_is_reported(tmp_path: Path) -> None:
    """Walrus-bound attachment value dictionaries should be resolved at create()."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/attach/walrus-values', auth='public', csrf=False)
    def attach(self, **kwargs):
        if vals := {
            'name': 'x.pdf',
            'datas': kwargs.get('payload'),
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
            'public': True,
        }:
            return request.env['ir.attachment'].sudo().create(vals)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_attachments(tmp_path)}

    assert "odoo-attachment-public-route-mutation" in rule_ids
    assert "odoo-attachment-sudo-mutation" in rule_ids
    assert "odoo-attachment-tainted-res-model" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids


def test_walrus_reassigned_attachment_values_alias_is_not_stale(tmp_path: Path) -> None:
    """Walrus-bound attachment value aliases should clear when reassigned to static data."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/attach/walrus-reassigned', auth='public', csrf=False)
    def attach(self, **kwargs):
        if vals := {
            'name': 'x.pdf',
            'datas': kwargs.get('payload'),
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
            'public': True,
        }:
            vals = {'name': 'safe.pdf', 'res_model': 'sale.order', 'res_id': 1}
            return request.env['ir.attachment'].create(vals)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_attachments(tmp_path)}

    assert "odoo-attachment-tainted-res-model" not in rule_ids
    assert "odoo-attachment-tainted-res-id" not in rule_ids
    assert "odoo-attachment-public-orphan" not in rule_ids


def test_read_group_attachment_lookup_is_reported(tmp_path: Path) -> None:
    """Grouped attachment metadata queries can expose request-selected records."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/attachment-stats', auth='public')
    def attachment_stats(self, **kwargs):
        return request.env['ir.attachment'].sudo().read_group(
            [('res_model', '=', kwargs.get('model')), ('res_id', '=', int(kwargs.get('id')))],
            ['id:count'],
            ['mimetype'],
        )
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(
        f.rule_id == "odoo-attachment-tainted-lookup" and f.severity == "high" and f.sink.endswith(".read_group")
        for f in findings
    )


def test_reassigned_attachment_model_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned attachment aliases should not keep attachment-model state."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
class AttachmentHelper:
    def create_partner(self, values):
        Attachments = self.env['ir.attachment'].sudo()
        Attachments = self.env['res.partner']
        return Attachments.create(values)
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert not any(f.rule_id == "odoo-attachment-sudo-mutation" for f in findings)


def test_public_route_path_id_attachment_create_metadata_is_reported(tmp_path: Path) -> None:
    """Route path IDs should taint attachment create ownership metadata."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/orders/<int:order_id>/attach', auth='public', csrf=False)
    def attach(self, order_id):
        return request.env['ir.attachment'].sudo().create({
            'name': 'x.pdf',
            'datas': request.params.get('payload'),
            'res_model': 'sale.order',
            'res_id': order_id,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-public-route-mutation" in rule_ids
    assert "odoo-attachment-sudo-mutation" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids


def test_comprehension_derived_attachment_lookup_is_reported(tmp_path: Path) -> None:
    """Comprehension-derived IDs should remain tainted for attachment lookup."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/download', auth='public')
    def download(self, **kwargs):
        ids = [value for value in kwargs.get('ids')]
        return request.env['ir.attachment'].sudo().browse(ids[0])
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(f.rule_id == "odoo-attachment-tainted-lookup" for f in findings)


def test_comprehension_filter_derived_attachment_lookup_is_reported(tmp_path: Path) -> None:
    """Request-derived comprehension filters should taint attachment lookups."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/download', auth='public')
    def download(self, **kwargs):
        attachment_id = kwargs.get('id')
        ids = [1 for marker in ['x'] if attachment_id]
        return request.env['ir.attachment'].sudo().browse(ids[0])
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(f.rule_id == "odoo-attachment-tainted-lookup" for f in findings)


def test_named_expression_derived_attachment_lookup_is_reported(tmp_path: Path) -> None:
    """Walrus-bound attachment IDs should remain tainted after the condition."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/download', auth='public')
    def download(self, **kwargs):
        if attachment_id := kwargs.get('id'):
            return request.env['ir.attachment'].sudo().browse(int(attachment_id))
        return request.env['ir.attachment']
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(f.rule_id == "odoo-attachment-tainted-lookup" for f in findings)


def test_boolop_derived_attachment_lookup_is_reported(tmp_path: Path) -> None:
    """Boolean fallback expressions should not hide request-selected attachments."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/download', auth='public')
    def download(self, **kwargs):
        attachment_id = kwargs.get('id') or self.env.user.partner_id.id
        return request.env['ir.attachment'].sudo().browse(int(attachment_id))
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(f.rule_id == "odoo-attachment-tainted-lookup" for f in findings)


def test_keyword_values_attachment_create_metadata_is_reported(tmp_path: Path) -> None:
    """Attachment create dictionaries passed by keyword should be inspected."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/attach/keyword', auth='public', csrf=False)
    def attach(self, **kwargs):
        return request.env['ir.attachment'].sudo().create(vals={
            'name': 'x.pdf',
            'datas': kwargs.get('payload'),
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-tainted-res-model" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids


def test_local_values_alias_attachment_create_metadata_is_reported(tmp_path: Path) -> None:
    """Local attachment value aliases should be inspected for risky metadata."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/attach/alias', auth='public', csrf=False)
    def attach(self, **kwargs):
        vals = {
            'name': 'x.pdf',
            'datas': kwargs.get('payload'),
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
            'public': True,
        }
        copied = vals
        return request.env['ir.attachment'].sudo().create(copied)
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-tainted-res-model" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids
    assert "odoo-attachment-public-route-mutation" in rule_ids


def test_incremental_attachment_values_alias_metadata_is_reported(tmp_path: Path) -> None:
    """Attachment value dictionaries populated in steps should keep metadata checks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/attach/incremental', auth='public', csrf=False)
    def attach(self, **kwargs):
        vals = {'name': 'x.pdf', 'datas': kwargs.get('payload')}
        vals['res_model'] = kwargs.get('model')
        vals['res_id'] = kwargs.get('id')
        return request.env['ir.attachment'].sudo().create(vals)
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-tainted-res-model" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids


def test_updated_attachment_values_alias_metadata_is_reported(tmp_path: Path) -> None:
    """dict.update calls should not hide risky attachment ownership metadata."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/attach/update', auth='public', csrf=False)
    def attach(self, **kwargs):
        vals = {'name': 'x.pdf', 'datas': kwargs.get('payload')}
        vals.update({
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('id'),
            'public': True,
        })
        return request.env['ir.attachment'].sudo().create(vals)
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-tainted-res-model" in rule_ids
    assert "odoo-attachment-tainted-res-id" in rule_ids
    assert "odoo-attachment-public-route-mutation" in rule_ids


def test_comprehension_filter_derived_attachment_create_metadata_is_reported(tmp_path: Path) -> None:
    """Request-derived comprehension filters should taint attachment create metadata."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/attach/filter', auth='public', csrf=False)
    def attach(self, **kwargs):
        requested = kwargs.get('model')
        models = ['sale.order' for marker in ['x'] if requested]
        return request.env['ir.attachment'].sudo().create({
            'name': 'x.pdf',
            'datas': kwargs.get('payload'),
            'res_model': models[0],
            'res_id': self.env.user.partner_id.id,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(f.rule_id == "odoo-attachment-tainted-res-model" for f in findings)


def test_public_route_attachment_write_metadata_is_reported(tmp_path: Path) -> None:
    """Public attachment writes can expose or rebind existing files."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/attach/update', auth='public', csrf=False)
    def update_attachment(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(kwargs.get('id'))
        return attachment.write({
            'public': True,
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('res_id'),
            'access_token': kwargs.get('token'),
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-public-write" in rule_ids
    assert "odoo-attachment-tainted-res-model-write" in rule_ids
    assert "odoo-attachment-tainted-res-id-write" in rule_ids
    assert "odoo-attachment-tainted-access-token-write" in rule_ids


def test_constant_backed_public_attachment_write_is_reported(tmp_path: Path) -> None:
    """Constant-backed public flags should not hide attachment write exposure."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
PUBLIC_ATTACHMENT = True

class AttachmentHelper:
    def publish_attachment(self, attachment_id):
        attachment = self.env['ir.attachment'].browse(attachment_id)
        return attachment.write({'public': PUBLIC_ATTACHMENT})
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(f.rule_id == "odoo-attachment-public-write" for f in findings)


def test_local_constant_public_attachment_write_is_reported(tmp_path: Path) -> None:
    """Function-local public flags should not hide attachment write exposure."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
class AttachmentHelper:
    def publish_attachment(self, attachment_id):
        public_attachment = True
        attachment = self.env['ir.attachment'].browse(attachment_id)
        return attachment.write({'public': public_attachment})
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(f.rule_id == "odoo-attachment-public-write" for f in findings)


def test_local_values_alias_attachment_write_metadata_is_reported(tmp_path: Path) -> None:
    """Local attachment write value aliases should be inspected for rebind metadata."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/attach/update/alias', auth='public', csrf=False)
    def update_attachment(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(kwargs.get('id'))
        vals = {
            'public': True,
            'res_model': kwargs.get('model'),
            'res_id': kwargs.get('res_id'),
            'access_token': kwargs.get('token'),
        }
        return attachment.write(vals)
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-public-write" in rule_ids
    assert "odoo-attachment-tainted-res-model-write" in rule_ids
    assert "odoo-attachment-tainted-res-id-write" in rule_ids
    assert "odoo-attachment-tainted-access-token-write" in rule_ids


def test_comprehension_filter_derived_attachment_write_metadata_is_reported(tmp_path: Path) -> None:
    """Request-derived comprehension filters should taint attachment write metadata."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/attach/filter/write', auth='public', csrf=False)
    def update_attachment(self, **kwargs):
        requested = kwargs.get('res_id')
        res_ids = [self.env.user.partner_id.id for marker in ['x'] if requested]
        attachment = request.env['ir.attachment'].sudo().browse(kwargs.get('id'))
        return attachment.write({'res_id': res_ids[0]})
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(f.rule_id == "odoo-attachment-tainted-res-id-write" for f in findings)


def test_public_route_path_id_attachment_write_metadata_is_reported(tmp_path: Path) -> None:
    """Route path IDs should taint attachment write ownership metadata."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/orders/<int:order_id>/attach/<int:attachment_id>', auth='public', csrf=False)
    def update_attachment(self, order_id, attachment_id):
        attachment = request.env['ir.attachment'].sudo().browse(attachment_id)
        return attachment.write({
            'res_model': 'sale.order',
            'res_id': order_id,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-attachment-public-route-mutation" in rule_ids
    assert "odoo-attachment-sudo-mutation" in rule_ids
    assert "odoo-attachment-tainted-lookup" in rule_ids
    assert "odoo-attachment-tainted-res-id-write" in rule_ids


def test_aliased_attachment_write_access_token_is_reported(tmp_path: Path) -> None:
    """Aliased attachment recordsets should keep write metadata checks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/attach/token', auth='user')
    def set_token(self, **kwargs):
        Attachments = request.env['ir.attachment']
        attachment = Attachments.browse(kwargs.get('id'))
        return attachment.write(vals={'access_token': kwargs.get('token')})
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert any(f.rule_id == "odoo-attachment-tainted-access-token-write" and f.severity == "high" for f in findings)


def test_safe_private_attachment_binding_is_ignored(tmp_path: Path) -> None:
    """Private attachments with fixed model and owned record IDs should stay quiet."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "attachments.py").write_text(
        """
class AttachmentHelper:
    def attach_to_self(self):
        return self.env['ir.attachment'].create({
            'name': 'private.pdf',
            'datas': self.payload,
            'res_model': 'sale.order',
            'res_id': self.id,
        })
""",
        encoding="utf-8",
    )

    assert scan_attachments(tmp_path) == []


def test_reassigned_res_id_name_is_not_permanently_tainted(tmp_path: Path) -> None:
    """Metadata-like local names should not stay tainted after safe reassignment."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "attachments.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/attach', auth='user')
    def attach(self, **kwargs):
        res_id = kwargs.get('id')
        res_id = self.env.user.partner_id.id
        return request.env['ir.attachment'].create({
            'name': 'private.pdf',
            'datas': kwargs.get('payload'),
            'res_model': 'res.partner',
            'res_id': res_id,
        })
""",
        encoding="utf-8",
    )

    findings = scan_attachments(tmp_path)

    assert not any(f.rule_id == "odoo-attachment-tainted-res-id" for f in findings)
