"""Tests for file upload/filesystem scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.file_upload_scanner import FileUploadScanner, scan_file_uploads


def test_tainted_open_write_path_is_reported(tmp_path: Path) -> None:
    """Writing to request-controlled filenames should be reported."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(**kwargs):
    filename = kwargs.get('filename')
    with open(filename, 'wb') as handle:
        handle.write(b'data')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-tainted-path-write" for f in findings)


def test_tainted_open_constant_write_mode_is_reported(tmp_path: Path) -> None:
    """Write-mode constants should not hide request-controlled path writes."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
WRITE_MODE = 'wb'

def upload(**kwargs):
    filename = kwargs.get('filename')
    with open(filename, WRITE_MODE) as handle:
        handle.write(b'data')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-tainted-path-write" for f in findings)


def test_tainted_open_recursive_constant_write_mode_is_reported(tmp_path: Path) -> None:
    """Recursive write-mode constants should not hide request-controlled path writes."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
BASE_WRITE_MODE = 'wb'
WRITE_MODE = BASE_WRITE_MODE

def upload(**kwargs):
    filename = kwargs.get('filename')
    with open(filename, WRITE_MODE) as handle:
        handle.write(b'data')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-tainted-path-write" for f in findings)


def test_tainted_open_local_constant_write_mode_is_reported(tmp_path: Path) -> None:
    """Function-local write-mode constants should not hide request-controlled path writes."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(**kwargs):
    write_mode = 'wb'
    filename = kwargs.get('filename')
    with open(filename, write_mode) as handle:
        handle.write(b'data')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-tainted-path-write" for f in findings)


def test_request_alias_tainted_open_write_path_is_reported(tmp_path: Path) -> None:
    """Aliased Odoo request params should taint upload filesystem paths."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
from odoo.http import request as req

def upload():
    filename = req.params.get('filename')
    with open(filename, 'wb') as handle:
        handle.write(b'data')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-tainted-path-write" for f in findings)


def test_base64_upload_decode_is_reported(tmp_path: Path) -> None:
    """Decoded request-derived base64 payloads need size/type review."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import base64

def upload(**kwargs):
    payload = kwargs.get('payload')
    decoded = base64.b64decode(payload)
    return decoded
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-base64-decode" for f in findings)


def test_aliased_base64_upload_decode_is_reported(tmp_path: Path) -> None:
    """Aliased base64 imports should not hide decoded upload review leads."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import base64 as b64

def upload(**kwargs):
    payload = kwargs.get('payload')
    return b64.b64decode(payload)
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-base64-decode" for f in findings)


def test_imported_base64_decode_alias_attachment_is_reported(tmp_path: Path) -> None:
    """Imported decode aliases should keep attachment payloads request-tainted."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
from base64 import b64decode as decode_upload

def upload(self, **kwargs):
    payload = decode_upload(kwargs.get('payload'))
    return self.env['ir.attachment'].create({'name': 'x.bin', 'datas': payload})
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-file-upload-base64-decode" in rule_ids
    assert "odoo-file-upload-attachment-from-request" in rule_ids


def test_attachment_create_from_request_is_reported(tmp_path: Path) -> None:
    """Request-derived attachment data should be review-visible."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(self, **kwargs):
    payload = kwargs.get('payload')
    return self.env['ir.attachment'].create({'name': 'x.bin', 'datas': payload})
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-attachment-from-request" for f in findings)


def test_request_alias_attachment_create_from_request_is_reported(tmp_path: Path) -> None:
    """Aliased JSON request payloads should taint attachment data."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
from odoo.http import request as req

def upload(self):
    payload = req.get_json_data().get('payload')
    return self.env['ir.attachment'].create({'name': 'x.bin', 'datas': payload})
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-attachment-from-request" for f in findings)


def test_reassigned_upload_alias_is_not_stale_for_attachment(tmp_path: Path) -> None:
    """Reusing a request upload alias for safe static data should clear taint."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(self, **kwargs):
    payload = kwargs.get('payload')
    payload = 'safe'
    return self.env['ir.attachment'].create({'name': 'x.txt', 'datas': payload})
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-file-upload-attachment-from-request" for f in findings)


def test_aliased_attachment_create_from_request_is_reported(tmp_path: Path) -> None:
    """Attachment creates should stay visible when the model recordset is aliased."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(self, **kwargs):
    Attachments = self.env['ir.attachment']
    return Attachments.create({'name': 'x.bin', 'datas': kwargs.get('payload')})
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-attachment-from-request" for f in findings)


def test_inline_decoded_attachment_create_from_request_is_reported(tmp_path: Path) -> None:
    """Inline base64 decoding should remain request-tainted in attachment values."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import base64

def upload(self, **kwargs):
    return self.env['ir.attachment'].create({
        'name': 'x.bin',
        'datas': base64.b64decode(kwargs.get('payload')),
    })
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-file-upload-base64-decode" in rule_ids
    assert "odoo-file-upload-attachment-from-request" in rule_ids


def test_starred_decoded_attachment_create_from_request_is_reported(tmp_path: Path) -> None:
    """Starred unpacking should keep decoded upload aliases tainted for attachments."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import base64

def upload(self, **kwargs):
    _, *payloads = ('fixed', base64.b64decode(kwargs.get('payload')))
    return self.env['ir.attachment'].create({'name': 'x.bin', 'datas': payloads[0]})
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-file-upload-base64-decode" in rule_ids
    assert "odoo-file-upload-attachment-from-request" in rule_ids


def test_reassigned_decoded_upload_alias_is_not_stale(tmp_path: Path) -> None:
    """Decoded upload aliases should clear when reassigned to safe data."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import base64

def upload(self, **kwargs):
    payload = base64.b64decode(kwargs.get('payload'))
    payload = 'safe'
    return self.env['ir.attachment'].create({'name': 'x.txt', 'datas': payload})
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-file-upload-attachment-from-request" for f in findings)


def test_walrus_decoded_upload_attachment_is_reported(tmp_path: Path) -> None:
    """Walrus-bound decoded uploads should stay tainted for attachment creates."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import base64

def upload(self, **kwargs):
    if payload := base64.b64decode(kwargs.get('payload')):
        return self.env['ir.attachment'].create({'name': 'x.bin', 'datas': payload})
    return False
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-file-upload-base64-decode" in rule_ids
    assert "odoo-file-upload-attachment-from-request" in rule_ids


def test_public_attachment_create_is_reported(tmp_path: Path) -> None:
    """Uploaded content should not become public without explicit review."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(self, **kwargs):
    payload = kwargs.get('payload')
    return self.env['ir.attachment'].create({'name': 'x.bin', 'datas': payload, 'public': True})
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-public-attachment-create" for f in findings)


def test_public_attachment_create_constant_is_reported(tmp_path: Path) -> None:
    """public=True constants should not hide world-readable attachment creation."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
PUBLIC_ATTACHMENT = True

def upload(self, **kwargs):
    payload = kwargs.get('payload')
    return self.env['ir.attachment'].create({'name': 'x.bin', 'datas': payload, 'public': PUBLIC_ATTACHMENT})
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-public-attachment-create" for f in findings)


def test_public_attachment_create_recursive_constant_is_reported(tmp_path: Path) -> None:
    """Recursive public=True constants should not hide public attachment creation."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
PUBLIC_VALUE = True
PUBLIC_ATTACHMENT = PUBLIC_VALUE

def upload(self, **kwargs):
    payload = kwargs.get('payload')
    return self.env['ir.attachment'].create({'name': 'x.bin', 'datas': payload, 'public': PUBLIC_ATTACHMENT})
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-public-attachment-create" for f in findings)


def test_public_attachment_create_local_constant_is_reported(tmp_path: Path) -> None:
    """Function-local public=True constants should not hide public attachment creation."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(self, **kwargs):
    public_attachment = True
    payload = kwargs.get('payload')
    return self.env['ir.attachment'].create({'name': 'x.bin', 'datas': payload, 'public': public_attachment})
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-public-attachment-create" for f in findings)


def test_attachment_create_local_constant_model_is_reported(tmp_path: Path) -> None:
    """Function-local model constants should not hide attachment creates."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(self, **kwargs):
    attachment_model = 'ir.attachment'
    payload = kwargs.get('payload')
    return self.env[attachment_model].create({'name': 'x.bin', 'datas': payload})
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-attachment-from-request" for f in findings)


def test_aliased_attachment_values_from_request_are_reported(tmp_path: Path) -> None:
    """Aliased attachment value dictionaries should not hide uploaded request data."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(self, **kwargs):
    vals = {'name': kwargs.get('filename'), 'datas': kwargs.get('payload'), 'public': True}
    return self.env['ir.attachment'].sudo().create(vals)
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-file-upload-attachment-from-request" in rule_ids
    assert "odoo-file-upload-public-attachment-create" in rule_ids


def test_copied_attachment_values_alias_from_request_is_reported(tmp_path: Path) -> None:
    """Copied attachment value aliases should preserve uploaded request data."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(self, **kwargs):
    vals = {'name': kwargs.get('filename'), 'datas': kwargs.get('payload'), 'public': True}
    copied = vals
    return self.env['ir.attachment'].sudo().create(copied)
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-file-upload-attachment-from-request" in rule_ids
    assert "odoo-file-upload-public-attachment-create" in rule_ids


def test_reassigned_attachment_values_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing attachment values aliases for static data should clear upload state."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(self, **kwargs):
    vals = {'name': kwargs.get('filename'), 'datas': kwargs.get('payload'), 'public': True}
    vals = {'name': 'safe.txt', 'datas': 'c2FmZQ=='}
    return self.env['ir.attachment'].create(vals)
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-file-upload-attachment-from-request" for f in findings)
    assert not any(f.rule_id == "odoo-file-upload-public-attachment-create" for f in findings)


def test_walrus_attachment_model_create_from_request_is_reported(tmp_path: Path) -> None:
    """Walrus-bound attachment recordsets should preserve create() detection."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(self, **kwargs):
    if Attachments := self.env['ir.attachment']:
        return Attachments.create({'name': 'x.bin', 'datas': kwargs.get('payload')})
    return False
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-attachment-from-request" for f in findings)


def test_walrus_attachment_values_from_request_are_reported(tmp_path: Path) -> None:
    """Walrus-bound attachment value dictionaries should be resolved at create()."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(self, **kwargs):
    if vals := {'name': kwargs.get('filename'), 'datas': kwargs.get('payload'), 'public': True}:
        return self.env['ir.attachment'].sudo().create(vals)
    return False
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-file-upload-attachment-from-request" in rule_ids
    assert "odoo-file-upload-public-attachment-create" in rule_ids


def test_walrus_reassigned_attachment_values_alias_is_not_stale(tmp_path: Path) -> None:
    """Walrus rebinding should clear stale attachment value aliases."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(self, **kwargs):
    if vals := {'name': kwargs.get('filename'), 'datas': kwargs.get('payload'), 'public': True}:
        vals = {'name': 'safe.txt', 'datas': 'c2FmZQ=='}
        return self.env['ir.attachment'].create(vals)
    return False
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-file-upload-attachment-from-request" for f in findings)
    assert not any(f.rule_id == "odoo-file-upload-public-attachment-create" for f in findings)


def test_zip_extractall_from_uploaded_archive_is_reported(tmp_path: Path) -> None:
    """Uploaded zip archives should not be extracted without member path validation."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import zipfile

def upload(**kwargs):
    archive = zipfile.ZipFile(kwargs.get('upload'))
    return archive.extractall('/tmp/import')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-file-upload-archive-extraction"
        and f.severity == "critical"
        and f.sink == "archive.extractall"
        for f in findings
    )


def test_starred_uploaded_archive_extractall_is_reported(tmp_path: Path) -> None:
    """Starred unpacking should keep uploaded archive aliases tainted."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import zipfile

def upload(**kwargs):
    _, *archives = ('fixed', zipfile.ZipFile(kwargs.get('upload')))
    return archives[0].extractall('/tmp/import')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-archive-extraction" and f.severity == "critical" for f in findings)


def test_starred_rest_uploaded_archive_extractall_is_reported(tmp_path: Path) -> None:
    """Starred-rest archive aliases should keep every collected upload archive visible."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import zipfile

def upload(**kwargs):
    marker, *archives, tail = 'fixed', object(), zipfile.ZipFile(kwargs.get('upload')), object()
    return archives[1].extractall('/tmp/import')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-archive-extraction" and f.severity == "critical" for f in findings)


def test_walrus_uploaded_archive_extractall_is_reported(tmp_path: Path) -> None:
    """Walrus-bound uploaded archives should be treated as tainted archives."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import zipfile

def upload(**kwargs):
    if archive := zipfile.ZipFile(kwargs.get('upload')):
        return archive.extractall('/tmp/import')
    return False
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-archive-extraction" and f.severity == "critical" for f in findings)


def test_imported_tar_open_extract_alias_is_reported(tmp_path: Path) -> None:
    """Imported tarfile aliases should keep archive extraction visible."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
from tarfile import open as open_tar

def upload(attachment):
    archive = open_tar(fileobj=attachment)
    return archive.extract(path='/tmp/import')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-archive-extraction" and f.severity == "critical" for f in findings)


def test_direct_zipfile_extractall_is_reported(tmp_path: Path) -> None:
    """Direct ZipFile(...).extractall calls should not hide traversal risk."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
from zipfile import ZipFile

def import_archive(path):
    return ZipFile(path).extractall('/tmp/import')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-archive-extraction" and f.sink == "ZipFile.extractall" for f in findings)


def test_secure_filename_only_upload_write_is_reported(tmp_path: Path) -> None:
    """secure_filename alone should not hide incomplete upload path validation."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
from werkzeug.utils import secure_filename

def upload(**kwargs):
    name = secure_filename(kwargs.get('filename'))
    with open('/srv/odoo/uploads/' + name, 'wb') as handle:
        handle.write(kwargs.get('payload'))
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-secure-filename-only" and f.sink == "open" for f in findings)


def test_aliased_secure_filename_path_write_is_reported(tmp_path: Path) -> None:
    """Module aliases should not hide secure_filename-only upload writes."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import werkzeug.utils as wz_utils

def upload(**kwargs):
    destination = '/srv/odoo/uploads/%s' % wz_utils.secure_filename(kwargs.get('filename'))
    return destination.write_text(kwargs.get('payload'))
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-file-upload-secure-filename-only" and f.sink == "destination.write_text" for f in findings
    )


def test_boolop_secure_filename_path_write_is_reported(tmp_path: Path) -> None:
    """Boolean fallback expressions should keep secure_filename-only review visible."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
from werkzeug.utils import secure_filename

def upload(**kwargs):
    name = secure_filename(kwargs.get('filename')) or 'upload.bin'
    with open('/srv/odoo/uploads/' + name, 'wb') as handle:
        handle.write(kwargs.get('payload'))
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-secure-filename-only" and f.sink == "open" for f in findings)


def test_starred_secure_filename_path_write_is_reported(tmp_path: Path) -> None:
    """Starred unpacking should preserve secure_filename-only path aliases."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
from werkzeug.utils import secure_filename

def upload(**kwargs):
    _, *names = ('fixed', secure_filename(kwargs.get('filename')))
    with open('/srv/odoo/uploads/' + names[0], 'wb') as handle:
        handle.write(kwargs.get('payload'))
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-secure-filename-only" and f.sink == "open" for f in findings)


def test_walrus_secure_filename_path_write_is_reported(tmp_path: Path) -> None:
    """Walrus-bound secure_filename results should keep upload path review visible."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
from werkzeug.utils import secure_filename

def upload(**kwargs):
    if name := secure_filename(kwargs.get('filename')):
        with open('/srv/odoo/uploads/' + name, 'wb') as handle:
            handle.write(kwargs.get('payload'))
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-secure-filename-only" and f.sink == "open" for f in findings)


def test_tempfile_mktemp_with_upload_input_is_reported(tmp_path: Path) -> None:
    """Upload-derived mktemp paths are race-prone and should be review-visible."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
from tempfile import mktemp as upload_temp_name

def upload(**kwargs):
    return upload_temp_name(prefix=kwargs.get('filename'))
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-unsafe-tempfile" and f.severity == "high" for f in findings)


def test_unpacked_and_comprehension_paths_are_reported(tmp_path: Path) -> None:
    """Request-derived paths should remain tainted through unpacking and comprehensions."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(**kwargs):
    _, filename = ('fixed', kwargs.get('filename'))
    paths = [filename for value in kwargs.get('files')]
    with open(paths[0], 'wb') as handle:
        handle.write(b'data')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-tainted-path-write" for f in findings)


def test_starred_unpacked_upload_path_is_reported(tmp_path: Path) -> None:
    """Starred unpacking should keep request-derived upload paths tainted."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(**kwargs):
    _, *paths = ('fixed', kwargs.get('filename'))
    with open(paths[0], 'wb') as handle:
        handle.write(b'data')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-tainted-path-write" for f in findings)


def test_starred_rest_upload_path_is_reported(tmp_path: Path) -> None:
    """Starred-rest upload paths should remain tainted when not first in the rest list."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(**kwargs):
    marker, *paths, tail = 'fixed', '/srv/odoo/uploads/fixed.bin', kwargs.get('filename'), 'end'
    with open(paths[1], 'wb') as handle:
        handle.write(b'data')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-tainted-path-write" for f in findings)


def test_loop_derived_upload_path_is_reported(tmp_path: Path) -> None:
    """Loop variables from request-derived paths should stay tainted."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(**kwargs):
    for filename in kwargs.get('filenames'):
        with open(filename, 'wb') as handle:
            handle.write(b'data')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-tainted-path-write" for f in findings)


def test_safe_loop_reassignment_clears_upload_path_taint(tmp_path: Path) -> None:
    """Safe loop targets should clear stale filename taint before filesystem writes."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(**kwargs):
    filename = kwargs.get('filename')
    for filename in ['/srv/odoo/uploads/fixed.bin']:
        with open(filename, 'wb') as handle:
            handle.write(b'data')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-file-upload-tainted-path-write" for f in findings)


def test_comprehension_filter_derived_upload_path_is_reported(tmp_path: Path) -> None:
    """Tainted comprehension filters should keep upload path aliases tainted."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(**kwargs):
    paths = ['/srv/odoo/uploads/fixed.bin' for value in [1] if kwargs.get('filename')]
    with open(paths[0], 'wb') as handle:
        handle.write(b'data')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-tainted-path-write" for f in findings)


def test_named_expression_derived_upload_path_is_reported(tmp_path: Path) -> None:
    """Walrus-bound upload paths should remain tainted after the condition."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(**kwargs):
    if path := kwargs.get('filename'):
        with open(path, 'wb') as handle:
            handle.write(kwargs.get('payload'))
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-tainted-path-write" for f in findings)


def test_boolop_derived_upload_path_is_reported(tmp_path: Path) -> None:
    """Boolean fallback expressions should not hide request-controlled paths."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
def upload(**kwargs):
    path = kwargs.get('filename') or '/srv/odoo/uploads/fixed.bin'
    with open(path, 'wb') as handle:
        handle.write(kwargs.get('payload'))
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-tainted-path-write" for f in findings)


def test_aliased_shutil_move_destination_is_reported(tmp_path: Path) -> None:
    """Aliased shutil write sinks should still flag request-controlled destinations."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
from shutil import move as move_file

def upload(source, **kwargs):
    destination = kwargs.get('filename')
    return move_file(source, destination)
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-tainted-path-write" for f in findings)


def test_route_path_filename_is_tainted_for_upload_write(tmp_path: Path) -> None:
    """Odoo route path parameters are request-controlled filesystem input."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
from odoo import http

class UploadController(http.Controller):
    @http.route('/public/upload/<path:destination>', auth='public', csrf=False)
    def upload_to_path(self, destination):
        with open(destination, 'wb') as handle:
            handle.write(b'data')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-tainted-path-write" for f in findings)


def test_aliased_imported_route_path_parameter_is_tainted_for_upload_write(tmp_path: Path) -> None:
    """Aliased imported route decorators should make path parameters request-controlled."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
from odoo import http
from odoo.http import route as odoo_route

class UploadController(http.Controller):
    @odoo_route('/public/upload/<path:destination>', auth='public', csrf=False)
    def upload_to_path(self, destination):
        with open(destination, 'wb') as handle:
            handle.write(b'data')
""",
        encoding="utf-8",
    )

    findings = FileUploadScanner(py).scan_file()

    assert any(f.rule_id == "odoo-file-upload-tainted-path-write" for f in findings)


def test_repository_scan_finds_upload_handlers(tmp_path: Path) -> None:
    """Repository scanner should include addon Python files and skip tests."""
    controllers = tmp_path / "module" / "controllers"
    tests = tmp_path / "tests"
    controllers.mkdir(parents=True)
    tests.mkdir()
    (controllers / "upload.py").write_text(
        "def upload(**kwargs):\n    open(kwargs.get('filename'), 'w').write('x')\n",
        encoding="utf-8",
    )
    (tests / "test_upload.py").write_text(
        "def test_upload(**kwargs):\n    open(kwargs.get('filename'), 'w').write('x')\n",
        encoding="utf-8",
    )

    findings = scan_file_uploads(tmp_path)

    assert len([f for f in findings if f.rule_id == "odoo-file-upload-tainted-path-write"]) == 1
