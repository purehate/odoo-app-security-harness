"""Tests for Odoo binary/download response scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.binary_download_scanner import scan_binary_downloads


def test_flags_public_attachment_datas_response(tmp_path: Path) -> None:
    """Public routes returning attachment datas need explicit access review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
import base64
from odoo import http
from odoo.http import request

class Download(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        payload = base64.b64decode(attachment.datas)
        return request.make_response(payload)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(f.rule_id == "odoo-binary-attachment-data-response" for f in findings)


def test_imported_route_decorator_public_attachment_datas_response(tmp_path: Path) -> None:
    """Imported route decorators should still expose public binary downloads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
import base64
from odoo import http
from odoo.http import request, route

class Download(http.Controller):
    @route('/public/download', auth='public')
    def download(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        payload = base64.b64decode(attachment.datas)
        return request.make_response(payload)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(f.rule_id == "odoo-binary-attachment-data-response" for f in findings)


def test_aliased_imported_route_decorator_public_attachment_datas_response(tmp_path: Path) -> None:
    """Aliased imported route decorators should preserve public binary severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request, route as odoo_route

class Download(http.Controller):
    @odoo_route('/public/download', auth='public')
    def download(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        return request.make_response(attachment.datas)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response" and f.severity == "high"
        for f in findings
    )


def test_aliased_http_module_public_attachment_datas_response(tmp_path: Path) -> None:
    """Aliased Odoo http module imports should preserve public binary severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http as odoo_http
from odoo.http import request

class Download(odoo_http.Controller):
    @odoo_http.route('/public/download', auth='public')
    def download(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        return request.make_response(attachment.datas)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response" and f.severity == "high"
        for f in findings
    )


def test_non_odoo_route_decorator_attachment_datas_response_is_not_public(tmp_path: Path) -> None:
    """Local route-like decorators should not create public Odoo route context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo.http import request

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class Download:
    @router.route('/public/download', auth='public')
    def download(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        return request.make_response(attachment.datas)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert not any(
        f.rule_id == "odoo-binary-attachment-data-response" and f.severity == "high"
        for f in findings
    )
    assert any(
        f.rule_id == "odoo-binary-attachment-data-response" and f.severity == "medium"
        for f in findings
    )


def test_constant_backed_public_attachment_datas_response(tmp_path: Path) -> None:
    """Constant-backed public route auth should keep binary response severity high."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
import base64
from odoo import http
from odoo.http import request

DOWNLOAD_ROUTES = ['/public/download', '/public/download/alt']
DOWNLOAD_AUTH = 'public'

class Download(http.Controller):
    @http.route(DOWNLOAD_ROUTES, auth=DOWNLOAD_AUTH)
    def download(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        payload = base64.b64decode(attachment.datas)
        return request.make_response(payload)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response" and f.severity == "high" for f in findings
    )


def test_static_unpack_public_attachment_datas_response(tmp_path: Path) -> None:
    """Static **route options should preserve public binary response severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

ROUTE_OPTIONS = {'auth': 'public', 'type': 'http'}

class Download(http.Controller):
    @http.route('/public/download', **ROUTE_OPTIONS)
    def download(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        return request.make_response(attachment.datas)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response" and f.severity == "high" for f in findings
    )


def test_keyword_constant_backed_none_binary_content_args(tmp_path: Path) -> None:
    """Constant-backed auth='none' should escalate tainted binary_content inputs."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

DOWNLOAD_ROUTE = '/public/binary'
DOWNLOAD_AUTH = 'none'

class Download(http.Controller):
    @http.route(route=DOWNLOAD_ROUTE, auth=DOWNLOAD_AUTH)
    def download(self, **kwargs):
        return request.env['ir.http'].binary_content(
            model=kwargs.get('model'),
            id=kwargs.get('id'),
            field='datas',
        )
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-tainted-binary-content-args" and f.severity == "high" for f in findings
    )


def test_constant_alias_public_auth_and_attachment_model_response(tmp_path: Path) -> None:
    """Recursive constants should expose public attachment model downloads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

ATTACHMENT_MODEL = 'ir.attachment'
DOWNLOAD_MODEL = ATTACHMENT_MODEL
PUBLIC_AUTH = 'public'
DOWNLOAD_AUTH = PUBLIC_AUTH

class Download(http.Controller):
    @http.route('/public/download', auth=DOWNLOAD_AUTH)
    def download(self, **kwargs):
        attachment = request.env[DOWNLOAD_MODEL].sudo().browse(int(kwargs.get('id')))
        return request.make_response(attachment.datas)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response"
        and f.severity == "high"
        and f.sink == "request.make_response"
        for f in findings
    )


def test_class_constant_alias_public_auth_and_attachment_model_response(tmp_path: Path) -> None:
    """Class-scoped constants should expose public attachment model downloads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Download(http.Controller):
    ATTACHMENT_MODEL = 'ir.attachment'
    DOWNLOAD_MODEL = ATTACHMENT_MODEL
    PUBLIC_AUTH = 'public'
    DOWNLOAD_AUTH = PUBLIC_AUTH

    @http.route('/public/download', auth=DOWNLOAD_AUTH)
    def download(self, **kwargs):
        attachment = request.env[DOWNLOAD_MODEL].sudo().browse(int(kwargs.get('id')))
        return request.make_response(attachment.datas)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response"
        and f.severity == "high"
        and f.sink == "request.make_response"
        for f in findings
    )


def test_class_constant_static_unpack_public_attachment_datas_response(tmp_path: Path) -> None:
    """Class-scoped static **route options should preserve public binary response severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Download(http.Controller):
    ROUTE_OPTIONS = {'auth': 'public', 'type': 'http'}
    ATTACHMENT_MODEL = 'ir.attachment'

    @http.route('/public/download', **ROUTE_OPTIONS)
    def download(self, **kwargs):
        attachment = request.env[ATTACHMENT_MODEL].sudo().browse(int(kwargs.get('id')))
        return request.make_response(attachment.datas)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response"
        and f.severity == "high"
        and f.sink == "request.make_response"
        for f in findings
    )


def test_local_constant_alias_attachment_model_response(tmp_path: Path) -> None:
    """Function-local model constants should expose attachment downloads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Download(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        attachment_model = 'ir.attachment'
        attachment = request.env[attachment_model].sudo().browse(int(kwargs.get('id')))
        return request.make_response(attachment.datas)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response"
        and f.severity == "high"
        and f.sink == "request.make_response"
        for f in findings
    )


def test_flags_aliased_public_attachment_datas_response(tmp_path: Path) -> None:
    """Attachment aliases should not hide binary response payloads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
import base64
from odoo import http
from odoo.http import request

class Download(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        Attachments = request.env['ir.attachment'].sudo()
        attachment = Attachments.browse(int(kwargs.get('id')))
        payload = base64.b64decode(attachment.datas)
        return request.make_response(payload)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(f.rule_id == "odoo-binary-attachment-data-response" for f in findings)


def test_request_alias_attachment_datas_response(tmp_path: Path) -> None:
    """Aliased Odoo request imports should still expose binary response factories."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Download(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        attachment = req.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        return req.make_response(attachment.datas)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(f.rule_id == "odoo-binary-attachment-data-response" and f.sink == "req.make_response" for f in findings)


def test_flags_copied_attachment_record_alias_response(tmp_path: Path) -> None:
    """Copied attachment record aliases should keep binary payload tracking."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Download(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        copy = attachment
        return request.make_response(copy.datas)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response" and f.sink == "request.make_response" for f in findings
    )


def test_flags_unpacked_attachment_alias_and_payload_response(tmp_path: Path) -> None:
    """Tuple-unpacked attachment model aliases should keep binary payload tracking."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Download(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        Attachments, attachment_id = (request.env['ir.attachment'].sudo(), kwargs.get('id'))
        attachment = Attachments.browse(attachment_id)
        payload = attachment.datas
        return request.make_response(payload)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response" and f.sink == "request.make_response" for f in findings
    )


def test_flags_named_expression_attachment_alias_response(tmp_path: Path) -> None:
    """Walrus-bound attachment aliases should keep binary payload tracking."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Download(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        if attachment := request.env['ir.attachment'].sudo().browse(int(kwargs.get('id'))):
            return request.make_response(attachment.datas)
        return request.not_found()
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response" and f.sink == "request.make_response" for f in findings
    )


def test_flags_starred_attachment_alias_response(tmp_path: Path) -> None:
    """Starred attachment aliases should keep binary payload tracking."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Download(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        *attachment, marker = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id'))), 'x'
        return request.make_response(attachment.datas)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response" and f.sink == "request.make_response" for f in findings
    )


def test_flags_starred_rest_attachment_payload_response(tmp_path: Path) -> None:
    """Attachment payloads later in starred-rest collections should remain binary."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Download(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        label, *items = 'x', b'ok', attachment.datas
        payload = items[1]
        return request.make_response(payload)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response" and f.sink == "request.make_response" for f in findings
    )


def test_flags_starred_rest_attachment_model_alias_response(tmp_path: Path) -> None:
    """Attachment model aliases later in starred-rest collections should remain visible."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Download(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        label, *items = 'x', request.env['ir.attachment'].sudo(), kwargs.get('id')
        Attachments = items[0]
        attachment = Attachments.browse(items[1])
        return request.make_response(attachment.datas)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response" and f.sink == "request.make_response" for f in findings
    )


def test_flags_attachment_datas_in_json_response(tmp_path: Path) -> None:
    """JSON response wrappers should not hide raw attachment payloads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Download(http.Controller):
    @http.route('/public/download-json', auth='public', type='json')
    def download_json(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        payload = attachment.datas
        return request.make_json_response({'data': payload})
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response"
        and f.severity == "high"
        and f.sink == "request.make_json_response"
        for f in findings
    )


def test_flags_attachment_raw_response(tmp_path: Path) -> None:
    """ir.attachment raw payloads are equivalent to datas for download review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Download(http.Controller):
    @http.route('/public/raw-download', auth='public')
    def raw_download(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        return request.make_response(attachment.raw)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response"
        and f.severity == "high"
        and f.sink == "request.make_response"
        for f in findings
    )


def test_reassigned_binary_payload_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned binary payload aliases should not keep attachment-data state."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Download(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        payload = attachment.datas
        payload = b'ok'
        return request.make_response(payload)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert not any(f.rule_id == "odoo-binary-attachment-data-response" for f in findings)


def test_flags_attachment_db_datas_response(tmp_path: Path) -> None:
    """Legacy db_datas payloads should stay visible as binary download bodies."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http

class Download(http.Controller):
    @http.route('/download-db-datas', auth='user')
    def db_datas_download(self, **kwargs):
        Attachments = self.env['ir.attachment']
        attachment = Attachments.browse(kwargs.get('id'))
        return attachment.db_datas
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response" and f.severity == "medium" and f.sink == "return"
        for f in findings
    )


def test_flags_imported_make_json_response_binary_payload(tmp_path: Path) -> None:
    """Imported JSON response helpers need the same binary payload review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import make_json_response, request

class Download(http.Controller):
    @http.route('/download-json', auth='user', type='json')
    def download_json(self, **kwargs):
        attachment = request.env['ir.attachment'].browse(int(kwargs.get('id')))
        return make_json_response({'data': attachment.datas})
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response"
        and f.severity == "medium"
        and f.sink == "make_json_response"
        for f in findings
    )


def test_flags_aliased_imported_make_response_binary_payload(tmp_path: Path) -> None:
    """Aliased response helpers should still expose attachment payload downloads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import make_response as odoo_response, request

class Download(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        return odoo_response(attachment.datas)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response"
        and f.severity == "high"
        and f.sink == "odoo_response"
        for f in findings
    )


def test_flags_keyword_binary_response_payload(tmp_path: Path) -> None:
    """Keyword response bodies should not hide attachment payload downloads."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Download(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        return request.make_response(response=attachment.datas)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-attachment-data-response"
        and f.severity == "high"
        and f.sink == "request.make_response"
        for f in findings
    )


def test_flags_sudo_binary_content_with_tainted_arguments(tmp_path: Path) -> None:
    """Request-controlled ir.http.binary_content calls can bypass model boundaries."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "binary.py").write_text(
        """
from odoo import http
from odoo.http import request

class Binary(http.Controller):
    @http.route('/public/binary', auth='public')
    def binary(self, **kwargs):
        return request.env['ir.http'].sudo().binary_content(
            model=kwargs.get('model'),
            id=kwargs.get('id'),
            field='datas',
        )
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-binary-ir-http-binary-content-sudo" in rule_ids
    assert "odoo-binary-tainted-binary-content-args" in rule_ids


def test_request_alias_sudo_binary_content_with_tainted_arguments(tmp_path: Path) -> None:
    """Aliased Odoo request imports should still seed binary_content taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "binary.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Binary(http.Controller):
    @http.route('/public/binary', auth='public')
    def binary(self):
        payload = req.get_http_params()
        return req.env['ir.http'].sudo().binary_content(
            model=payload.get('model'),
            id=payload.get('id'),
            field='datas',
        )
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-binary-ir-http-binary-content-sudo" in rule_ids
    assert "odoo-binary-tainted-binary-content-args" in rule_ids


def test_flags_superuser_binary_content_with_tainted_arguments(tmp_path: Path) -> None:
    """with_user(SUPERUSER_ID) binary_content calls can bypass model boundaries."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "binary.py").write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class Binary(http.Controller):
    @http.route('/public/binary', auth='public')
    def binary(self, **kwargs):
        return request.env['ir.http'].with_user(SUPERUSER_ID).binary_content(
            model=kwargs.get('model'),
            id=kwargs.get('id'),
            field='datas',
        )
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-binary-ir-http-binary-content-sudo" in rule_ids
    assert "odoo-binary-tainted-binary-content-args" in rule_ids


def test_flags_keyword_superuser_binary_content_with_tainted_arguments(tmp_path: Path) -> None:
    """Keyword with_user(user=SUPERUSER_ID) binary_content calls are elevated."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "binary.py").write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class Binary(http.Controller):
    @http.route('/public/binary', auth='public')
    def binary(self, **kwargs):
        return request.env['ir.http'].with_user(user=SUPERUSER_ID).binary_content(
            model=kwargs.get('model'),
            id=kwargs.get('id'),
            field='datas',
        )
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-binary-ir-http-binary-content-sudo" in rule_ids
    assert "odoo-binary-tainted-binary-content-args" in rule_ids


def test_flags_constant_alias_superuser_binary_content_with_tainted_arguments(tmp_path: Path) -> None:
    """Recursive superuser aliases should keep with_user binary_content elevated."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "binary.py").write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

ROOT_USER = SUPERUSER_ID
BINARY_USER = ROOT_USER

class Binary(http.Controller):
    @http.route('/public/binary', auth='public')
    def binary(self, **kwargs):
        return request.env['ir.http'].with_user(BINARY_USER).binary_content(
            model=kwargs.get('model'),
            id=kwargs.get('id'),
            field='datas',
        )
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-binary-ir-http-binary-content-sudo" in rule_ids
    assert "odoo-binary-tainted-binary-content-args" in rule_ids


def test_flags_local_constant_alias_superuser_binary_content_with_tainted_arguments(tmp_path: Path) -> None:
    """Function-local superuser aliases should keep with_user binary_content elevated."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "binary.py").write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class Binary(http.Controller):
    @http.route('/public/binary', auth='public')
    def binary(self, **kwargs):
        root_user = SUPERUSER_ID
        return request.env['ir.http'].with_user(root_user).binary_content(
            model=kwargs.get('model'),
            id=kwargs.get('id'),
            field='datas',
        )
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-binary-ir-http-binary-content-sudo" in rule_ids
    assert "odoo-binary-tainted-binary-content-args" in rule_ids


def test_flags_env_ref_root_binary_content_with_tainted_arguments(tmp_path: Path) -> None:
    """with_user(env.ref('base.user_root')) binary_content calls are elevated."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "binary.py").write_text(
        """
from odoo import http
from odoo.http import request

class Binary(http.Controller):
    @http.route('/public/binary', auth='public')
    def binary(self, **kwargs):
        return request.env['ir.http'].with_user(request.env.ref('base.user_root')).binary_content(
            model=kwargs.get('model'),
            id=kwargs.get('id'),
            field='datas',
        )
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-binary-ir-http-binary-content-sudo" in rule_ids
    assert "odoo-binary-tainted-binary-content-args" in rule_ids


def test_flags_keyword_wrapped_binary_content_arguments(tmp_path: Path) -> None:
    """Tainted values wrapped in keyword containers should still reach binary_content."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "binary.py").write_text(
        """
from odoo import http
from odoo.http import request

class Binary(http.Controller):
    @http.route('/public/binary', auth='public')
    def binary(self, **kwargs):
        model = dict(value=kwargs.get('model'))
        return request.env['ir.http'].sudo().binary_content(
            model=model.get('value'),
            id=kwargs.get('id'),
            field='datas',
        )
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-binary-ir-http-binary-content-sudo" in rule_ids
    assert "odoo-binary-tainted-binary-content-args" in rule_ids


def test_flags_aliased_sudo_binary_content_with_tainted_arguments(tmp_path: Path) -> None:
    """sudo ir.http aliases should still mark binary_content as privileged."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "binary.py").write_text(
        """
from odoo import http
from odoo.http import request

class Binary(http.Controller):
    @http.route('/public/binary', auth='public')
    def binary(self, **kwargs):
        Http = request.env['ir.http'].sudo()
        return Http.binary_content(
            model=kwargs.get('model'),
            id=kwargs.get('id'),
            field='datas',
        )
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-binary-ir-http-binary-content-sudo" in rule_ids
    assert "odoo-binary-tainted-binary-content-args" in rule_ids


def test_flags_aliased_superuser_binary_content_with_tainted_arguments(tmp_path: Path) -> None:
    """with_user(1) ir.http aliases should still mark binary_content as privileged."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "binary.py").write_text(
        """
from odoo import http
from odoo.http import request

class Binary(http.Controller):
    @http.route('/public/binary', auth='public')
    def binary(self, **kwargs):
        Http = request.env['ir.http'].with_user(1)
        return Http.binary_content(
            model=kwargs.get('model'),
            id=kwargs.get('id'),
            field='datas',
        )
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-binary-ir-http-binary-content-sudo" in rule_ids
    assert "odoo-binary-tainted-binary-content-args" in rule_ids


def test_flags_route_path_id_binary_content_arguments(tmp_path: Path) -> None:
    """Route path IDs should be treated as request-controlled binary_content inputs."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "binary.py").write_text(
        """
from odoo import http
from odoo.http import request

class Binary(http.Controller):
    @http.route('/public/document/<int:document_id>', auth='public')
    def binary(self, document_id):
        return request.env['ir.http'].sudo().binary_content(
            model='ir.attachment',
            id=document_id,
            field='datas',
        )
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-binary-ir-http-binary-content-sudo" in rule_ids
    assert "odoo-binary-tainted-binary-content-args" in rule_ids


def test_flags_comprehension_filter_binary_content_arguments(tmp_path: Path) -> None:
    """Request-derived comprehension filters should taint binary_content arguments."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "binary.py").write_text(
        """
from odoo import http
from odoo.http import request

class Binary(http.Controller):
    @http.route('/public/binary', auth='public')
    def binary(self, **kwargs):
        requested = kwargs.get('id')
        ids = [1 for marker in ['x'] if requested]
        return request.env['ir.http'].sudo().binary_content(
            model='ir.attachment',
            id=ids[0],
            field='datas',
        )
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-binary-ir-http-binary-content-sudo" in rule_ids
    assert "odoo-binary-tainted-binary-content-args" in rule_ids


def test_flags_named_expression_binary_content_arguments(tmp_path: Path) -> None:
    """Walrus-bound binary_content IDs should remain tainted after the condition."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "binary.py").write_text(
        """
from odoo import http
from odoo.http import request

class Binary(http.Controller):
    @http.route('/public/binary', auth='public')
    def binary(self, **kwargs):
        if document_id := kwargs.get('id'):
            return request.env['ir.http'].sudo().binary_content(
                model='ir.attachment',
                id=document_id,
                field='datas',
            )
        return None
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-binary-ir-http-binary-content-sudo" in rule_ids
    assert "odoo-binary-tainted-binary-content-args" in rule_ids


def test_flags_boolop_binary_content_arguments(tmp_path: Path) -> None:
    """Boolean fallback expressions should not hide binary_content selectors."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "binary.py").write_text(
        """
from odoo import http
from odoo.http import request

class Binary(http.Controller):
    @http.route('/public/binary', auth='public')
    def binary(self, **kwargs):
        document_id = kwargs.get('id') or self.env.user.partner_id.id
        return request.env['ir.http'].sudo().binary_content(
            model='ir.attachment',
            id=document_id,
            field='datas',
        )
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-binary-ir-http-binary-content-sudo" in rule_ids
    assert "odoo-binary-tainted-binary-content-args" in rule_ids


def test_flags_tainted_web_content_redirect(tmp_path: Path) -> None:
    """Redirects into /web/content should not be assembled from raw request IDs."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http
from odoo.http import request

class Redirect(http.Controller):
    @http.route('/public/content', auth='public')
    def content(self, **kwargs):
        return request.redirect('/web/content/%s?download=1' % kwargs.get('id'))
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(f.rule_id == "odoo-binary-tainted-web-content-redirect" for f in findings)


def test_flags_constant_alias_tainted_web_content_redirect(tmp_path: Path) -> None:
    """Recursive constants should not hide /web/content redirect targets."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http
from odoo.http import request

WEB_CONTENT_URL = '/web/content/%s?download=1'
DOWNLOAD_URL = WEB_CONTENT_URL

class Redirect(http.Controller):
    @http.route('/public/content', auth='public')
    def content(self, **kwargs):
        return request.redirect(DOWNLOAD_URL % kwargs.get('id'))
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(f.rule_id == "odoo-binary-tainted-web-content-redirect" for f in findings)


def test_flags_local_constant_alias_tainted_web_content_redirect(tmp_path: Path) -> None:
    """Function-local constants should not hide /web/content redirect targets."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http
from odoo.http import request

class Redirect(http.Controller):
    @http.route('/public/content', auth='public')
    def content(self, **kwargs):
        download_url = '/web/content/%s?download=1'
        return request.redirect(download_url % kwargs.get('id'))
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(f.rule_id == "odoo-binary-tainted-web-content-redirect" for f in findings)


def test_flags_keyword_tainted_web_content_redirect(tmp_path: Path) -> None:
    """Keyword redirect locations should still be inspected for web content leaks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http
from odoo.http import request

class Redirect(http.Controller):
    @http.route('/public/content', auth='public')
    def content(self, **kwargs):
        return request.redirect(location='/web/content/%s?download=1' % kwargs.get('id'))
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(f.rule_id == "odoo-binary-tainted-web-content-redirect" for f in findings)


def test_flags_alias_keyword_tainted_web_content_redirects(tmp_path: Path) -> None:
    """Common redirect keyword aliases should still expose web content redirects."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http
from odoo.http import request

class Redirect(http.Controller):
    @http.route('/public/content', auth='public')
    def content(self, **kwargs):
        if kwargs.get('mode') == 'target':
            return request.redirect(target_url='/web/content/%s?download=1' % kwargs.get('id'))
        if kwargs.get('mode') == 'next':
            return request.redirect(next_url='/web/image/%s' % kwargs.get('image_id'))
        return request.redirect(success_url='/web/content/%s?download=1' % kwargs.get('fallback_id'))
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert sum(1 for finding in findings if finding.rule_id == "odoo-binary-tainted-web-content-redirect") == 3


def test_flags_route_path_id_web_content_redirect(tmp_path: Path) -> None:
    """Route path IDs should stay tainted when building /web/content redirects."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http
from odoo.http import request

class Redirect(http.Controller):
    @http.route('/public/order/<int:order_id>/download', auth='public')
    def content(self, order_id):
        return request.redirect('/web/content/%s?download=1' % order_id)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(f.rule_id == "odoo-binary-tainted-web-content-redirect" for f in findings)


def test_flags_comprehension_derived_web_content_redirect(tmp_path: Path) -> None:
    """Comprehension-derived IDs should stay tainted in web content redirects."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http
from odoo.http import request

class Redirect(http.Controller):
    @http.route('/public/content', auth='public')
    def content(self, **kwargs):
        ids = [value for value in kwargs.get('ids')]
        return request.redirect('/web/content/%s?download=1' % ids[0])
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(f.rule_id == "odoo-binary-tainted-web-content-redirect" for f in findings)


def test_flags_comprehension_filter_derived_web_content_redirect(tmp_path: Path) -> None:
    """Request-derived comprehension filters should taint web content redirects."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http
from odoo.http import request

class Redirect(http.Controller):
    @http.route('/public/content', auth='public')
    def content(self, **kwargs):
        requested = kwargs.get('id')
        ids = [1 for marker in ['x'] if requested]
        return request.redirect('/web/content/%s?download=1' % ids[0])
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(f.rule_id == "odoo-binary-tainted-web-content-redirect" for f in findings)


def test_flags_comprehension_binary_payload_response(tmp_path: Path) -> None:
    """Comprehension-wrapped attachment datas should still be treated as binary response data."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Download(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        payloads = [payload for payload in [attachment.datas]]
        return request.make_response(payloads[0])
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(f.rule_id == "odoo-binary-attachment-data-response" for f in findings)


def test_flags_comprehension_filter_binary_payload_response(tmp_path: Path) -> None:
    """Binary payloads in comprehension filters should taint response bodies."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Download(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        payloads = [b'ok' for marker in ['x'] if attachment.datas]
        return request.make_response(payloads[0])
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(f.rule_id == "odoo-binary-attachment-data-response" for f in findings)


def test_flags_ifexp_binary_payload_response(tmp_path: Path) -> None:
    """Conditional binary payload aliases should still taint response bodies."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "download.py").write_text(
        """
from odoo import http
from odoo.http import request

class Download(http.Controller):
    @http.route('/public/download', auth='public')
    def download(self, **kwargs):
        attachment = request.env['ir.attachment'].sudo().browse(int(kwargs.get('id')))
        payload = attachment.datas if kwargs.get('raw') else b'ok'
        return request.make_response(payload)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(f.rule_id == "odoo-binary-attachment-data-response" for f in findings)


def test_flags_tainted_content_disposition_filename(tmp_path: Path) -> None:
    """Download filenames should not come straight from request parameters."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "headers.py").write_text(
        """
from odoo import http
from odoo.http import content_disposition

class Headers(http.Controller):
    @http.route('/download', auth='user')
    def download(self, **kwargs):
        return content_disposition(kwargs.get('filename'))
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(f.rule_id == "odoo-binary-tainted-content-disposition" for f in findings)


def test_flags_aliased_content_disposition_filename(tmp_path: Path) -> None:
    """Aliased content_disposition imports should still inspect filenames."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "headers.py").write_text(
        """
from odoo import http
from odoo.http import content_disposition as download_name

class Headers(http.Controller):
    @http.route('/download', auth='user')
    def download(self, **kwargs):
        return download_name(kwargs.get('filename'))
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(
        f.rule_id == "odoo-binary-tainted-content-disposition" and f.sink == "download_name"
        for f in findings
    )


def test_flags_comprehension_filter_content_disposition_filename(tmp_path: Path) -> None:
    """Request-derived comprehension filters should taint download filenames."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "headers.py").write_text(
        """
from odoo import http
from odoo.http import content_disposition

class Headers(http.Controller):
    @http.route('/download', auth='user')
    def download(self, **kwargs):
        requested = kwargs.get('filename')
        filenames = ['export.csv' for marker in ['x'] if requested]
        return content_disposition(filenames[0])
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert any(f.rule_id == "odoo-binary-tainted-content-disposition" for f in findings)


def test_reassigned_filename_name_is_not_permanently_tainted(tmp_path: Path) -> None:
    """Filename-like local names should not stay tainted after safe reassignment."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "headers.py").write_text(
        """
from odoo import http
from odoo.http import content_disposition

class Headers(http.Controller):
    @http.route('/download', auth='user')
    def download(self, **kwargs):
        filename = kwargs.get('filename')
        filename = 'export.csv'
        return content_disposition(filename)
""",
        encoding="utf-8",
    )

    findings = scan_binary_downloads(tmp_path)

    assert not any(f.rule_id == "odoo-binary-tainted-content-disposition" for f in findings)


def test_safe_binary_response_is_ignored(tmp_path: Path) -> None:
    """Static binary responses should not produce Odoo download findings."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "safe.py").write_text(
        """
from odoo import http
from odoo.http import request

class Download(http.Controller):
    @http.route('/download', auth='user')
    def download(self):
        return request.make_response(b'ok')
""",
        encoding="utf-8",
    )

    assert scan_binary_downloads(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Python fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_download.py").write_text(
        "def test_download(**kwargs):\n    return '/web/content/%s' % kwargs.get('id')\n",
        encoding="utf-8",
    )

    assert scan_binary_downloads(tmp_path) == []
