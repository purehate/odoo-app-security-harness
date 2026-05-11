"""Tests for Odoo field security metadata scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.field_security_scanner import scan_field_security


def test_flags_sensitive_field_without_groups(tmp_path: Path) -> None:
    """Credential-like fields should not be globally readable by default."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "connector.py").write_text(
        """
from odoo import fields, models

class Connector(models.Model):
    _name = 'x.connector'

    api_key = fields.Char()
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)

    assert any(f.rule_id == "odoo-field-sensitive-no-groups" for f in findings)


def test_flags_common_integration_secret_field_names(tmp_path: Path) -> None:
    """Integration token/secret aliases should get sensitive-field review."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "connector.py").write_text(
        """
from odoo import fields, models

class Connector(models.Model):
    _name = 'x.connector'

    oauth_token = fields.Char()
    jwt_secret = fields.Char()
    webhook_secret = fields.Char()
    hmac_secret = fields.Char()
    totp_secret = fields.Char()
    license_key = fields.Char()
    access_key = fields.Char()
    session_token = fields.Char()
    csrf_token = fields.Char()
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)
    fields = {finding.field for finding in findings if finding.rule_id == "odoo-field-sensitive-no-groups"}

    assert {
        "oauth_token",
        "jwt_secret",
        "webhook_secret",
        "hmac_secret",
        "totp_secret",
        "license_key",
        "access_key",
        "session_token",
        "csrf_token",
    } <= fields


def test_flags_direct_field_constructor_sensitive_field(tmp_path: Path) -> None:
    """Directly imported field constructors should still be scanned."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "connector.py").write_text(
        """
from odoo import models
from odoo.fields import Char

class Connector(models.Model):
    _name = 'x.connector'

    api_key = Char()
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)

    assert any(f.rule_id == "odoo-field-sensitive-no-groups" for f in findings)


def test_flags_direct_model_base_sensitive_field(tmp_path: Path) -> None:
    """Direct Model bases should not hide sensitive fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "connector.py").write_text(
        """
from odoo import fields
from odoo.models import Model

class Connector(Model):
    _name = 'x.connector'

    api_key = fields.Char()
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)

    assert any(f.rule_id == "odoo-field-sensitive-no-groups" for f in findings)


def test_flags_annotated_sensitive_field_without_groups(tmp_path: Path) -> None:
    """Annotated Odoo field declarations should be scanned."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "connector.py").write_text(
        """
from odoo import fields, models

class Connector(models.Model):
    _name = 'x.connector'

    api_key: fields.Char = fields.Char()
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)

    assert any(f.rule_id == "odoo-field-sensitive-no-groups" for f in findings)


def test_flags_sensitive_field_with_public_groups(tmp_path: Path) -> None:
    """Sensitive fields assigned to portal/public groups are high-risk leaks."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "token.py").write_text(
        """
from odoo import fields, models

class Token(models.Model):
    _name = 'x.token'

    access_token = fields.Char(groups='base.group_portal')
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)

    assert any(f.rule_id == "odoo-field-sensitive-public-groups" for f in findings)


def test_flags_constant_backed_sensitive_field_with_public_groups(tmp_path: Path) -> None:
    """Constant-backed field groups should still expose public/portal sensitive fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "token.py").write_text(
        """
from odoo import fields, models

PUBLIC_GROUPS = 'base.group_portal'

class Token(models.Model):
    _name = 'x.token'

    access_token = fields.Char(groups=PUBLIC_GROUPS)
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)

    assert any(f.rule_id == "odoo-field-sensitive-public-groups" for f in findings)


def test_flags_constant_alias_sensitive_field_with_public_groups(tmp_path: Path) -> None:
    """Constant-to-constant field group aliases should still expose public sensitive fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "token.py").write_text(
        """
from odoo import fields, models

PORTAL_GROUP = 'base.group_portal'
PUBLIC_GROUPS = PORTAL_GROUP

class Token(models.Model):
    _name = 'x.token'

    access_token = fields.Char(groups=PUBLIC_GROUPS)
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)

    assert any(f.rule_id == "odoo-field-sensitive-public-groups" for f in findings)


def test_flags_class_constant_alias_sensitive_field_with_public_groups(tmp_path: Path) -> None:
    """Class-scoped field group aliases should still expose public sensitive fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "token.py").write_text(
        """
from odoo import fields, models

class Token(models.Model):
    MODEL_NAME = 'x.token'
    PORTAL_GROUP = 'base.group_portal'
    PUBLIC_GROUPS = PORTAL_GROUP
    _name = MODEL_NAME

    access_token = fields.Char(groups=PUBLIC_GROUPS)
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)

    assert any(
        f.rule_id == "odoo-field-sensitive-public-groups" and f.model == "x.token"
        for f in findings
    )


def test_flags_nested_static_unpack_sensitive_field_with_public_groups(tmp_path: Path) -> None:
    """Nested static field option dictionaries should still expose public groups."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "token.py").write_text(
        """
from odoo import fields, models

PORTAL_GROUP = 'base.group_portal'
BASE_OPTIONS = {'groups': PORTAL_GROUP}
FIELD_OPTIONS = {**BASE_OPTIONS}

class Token(models.Model):
    _name = 'x.token'

    access_token = fields.Char(**FIELD_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)

    assert any(f.rule_id == "odoo-field-sensitive-public-groups" for f in findings)


def test_flags_sensitive_indexed_field(tmp_path: Path) -> None:
    """Indexed credential-like fields deserve explicit DB exposure review."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "credential.py").write_text(
        """
from odoo import fields, models

class Credential(models.Model):
    _name = 'x.credential'

    api_key = fields.Char(groups='base.group_system', index=True)
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)

    assert any(f.rule_id == "odoo-field-sensitive-indexed" for f in findings)


def test_flags_sensitive_tracked_field(tmp_path: Path) -> None:
    """Credential-like fields should not leak through mail tracking."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "credential.py").write_text(
        """
from odoo import fields, models

class Credential(models.Model):
    _name = 'x.credential'

    api_token = fields.Char(groups='base.group_system', copy=False, tracking=True)
    legacy_secret = fields.Char(groups='base.group_system', copy=False, track_visibility='onchange')
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)
    tracked = [finding for finding in findings if finding.rule_id == "odoo-field-sensitive-tracking"]

    assert len(tracked) == 2


def test_flags_sensitive_copyable_field(tmp_path: Path) -> None:
    """Duplicating business records should not clone credentials or tokens."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "credential.py").write_text(
        """
from odoo import fields, models

class Credential(models.Model):
    _name = 'x.credential'

    refresh_token = fields.Char(groups='base.group_system')
    client_secret = fields.Char(groups='base.group_system', copy=True)
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)
    copyable = [finding for finding in findings if finding.rule_id == "odoo-field-sensitive-copyable"]

    assert len(copyable) == 2


def test_constant_backed_copy_false_suppresses_sensitive_copyable(tmp_path: Path) -> None:
    """Constant-backed copy=False should suppress sensitive copy findings."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "credential.py").write_text(
        """
from odoo import fields, models

ADMIN_GROUPS = 'base.group_system'
NO_COPY = False

class Credential(models.Model):
    _name = 'x.credential'

    refresh_token = fields.Char(groups=ADMIN_GROUPS, copy=NO_COPY)
""",
        encoding="utf-8",
    )

    assert scan_field_security(tmp_path) == []


def test_flags_compute_sudo_and_sensitive_related_field(tmp_path: Path) -> None:
    """Sudo-computed and sensitive related fields need explicit review."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "projection.py").write_text(
        """
from odoo import fields, models

class Projection(models.Model):
    _name = 'x.projection'

    user_id = fields.Many2one('res.users')
    secret_count = fields.Integer(compute='_compute_secret_count', compute_sudo=True)
    partner_token = fields.Char(related='user_id.partner_id.signup_token')
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-field-compute-sudo-sensitive" in rule_ids
    assert "odoo-field-related-sensitive-no-admin-groups" in rule_ids


def test_flags_constant_backed_compute_sudo_and_related_field(tmp_path: Path) -> None:
    """Constant-backed compute_sudo and related paths should still be reviewed."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "projection.py").write_text(
        """
from odoo import fields, models

SUDO_COMPUTE = True
RELATED_TOKEN = 'user_id.partner_id.signup_token'

class Projection(models.Model):
    _name = 'x.projection'

    user_id = fields.Many2one('res.users')
    secret_count = fields.Integer(compute='_compute_secret_count', compute_sudo=SUDO_COMPUTE)
    partner_token = fields.Char(related=RELATED_TOKEN)
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-field-compute-sudo-sensitive" in rule_ids
    assert "odoo-field-related-sensitive-no-admin-groups" in rule_ids


def test_flags_class_constant_backed_compute_sudo_and_related_field(tmp_path: Path) -> None:
    """Class-scoped compute_sudo and related aliases should still be reviewed."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "projection.py").write_text(
        """
from odoo import fields, models

class Projection(models.Model):
    MODEL_NAME = 'x.projection'
    SUDO_BASE = True
    SUDO_COMPUTE = SUDO_BASE
    RELATED_BASE = 'user_id.partner_id.signup_token'
    RELATED_TOKEN = RELATED_BASE
    _name = MODEL_NAME

    user_id = fields.Many2one('res.users')
    secret_count = fields.Integer(compute='_compute_secret_count', compute_sudo=SUDO_COMPUTE)
    partner_token = fields.Char(related=RELATED_TOKEN)
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-field-compute-sudo-sensitive" in rule_ids
    assert "odoo-field-related-sensitive-no-admin-groups" in rule_ids
    assert any(f.model == "x.projection" for f in findings)


def test_flags_scalar_compute_sudo_without_admin_groups(tmp_path: Path) -> None:
    """Sudo-computed scalar fields can project private data unless admin-only."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "projection.py").write_text(
        """
from odoo import fields, models

class Projection(models.Model):
    _name = 'x.projection'

    private_summary = fields.Char(compute='_compute_private_summary', compute_sudo=True)
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)

    assert any(f.rule_id == "odoo-field-compute-sudo-scalar-no-admin-groups" for f in findings)


def test_flags_binary_attachment_disabled(tmp_path: Path) -> None:
    """Binary fields with attachment=False deserve storage/access review."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "blob.py").write_text(
        """
from odoo import fields, models

class Blob(models.Model):
    _name = 'x.blob'

    payload = fields.Binary(attachment=False)
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)

    assert any(f.rule_id == "odoo-field-binary-db-storage" for f in findings)


def test_flags_html_field_sanitizer_disabled(tmp_path: Path) -> None:
    """Stored HTML fields should not disable Odoo sanitizer protections."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "page.py").write_text(
        """
from odoo import fields, models

class Page(models.Model):
    _name = 'x.page'

    raw_body = fields.Html(sanitize=False)
    loose_body = fields.Html(sanitize_tags=False, sanitize_attributes=False)
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)
    sanitizer_disabled = [finding for finding in findings if finding.rule_id == "odoo-field-html-sanitizer-disabled"]

    assert len(sanitizer_disabled) == 2
    assert {finding.severity for finding in sanitizer_disabled} == {"critical", "high"}


def test_flags_constant_backed_html_field_sanitizer_disabled(tmp_path: Path) -> None:
    """Constant-backed sanitizer flags should not hide unsafe HTML fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "page.py").write_text(
        """
from odoo import fields, models

SANITIZE = False

class Page(models.Model):
    _name = 'x.page'

    raw_body = fields.Html(sanitize=SANITIZE)
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)

    assert any(f.rule_id == "odoo-field-html-sanitizer-disabled" for f in findings)


def test_flags_constant_alias_html_field_sanitizer_disabled(tmp_path: Path) -> None:
    """Constant-to-constant sanitizer aliases should still expose unsafe HTML fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "page.py").write_text(
        """
from odoo import fields, models

DISABLED = False
SANITIZE = DISABLED

class Page(models.Model):
    _name = 'x.page'

    raw_body = fields.Html(sanitize=SANITIZE)
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)

    assert any(f.rule_id == "odoo-field-html-sanitizer-disabled" for f in findings)


def test_flags_class_constant_alias_html_field_sanitizer_disabled(tmp_path: Path) -> None:
    """Class-scoped sanitizer aliases should still expose unsafe HTML fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "page.py").write_text(
        """
from odoo import fields, models

class Page(models.Model):
    MODEL_NAME = 'x.page'
    DISABLED = False
    SANITIZE = DISABLED
    _name = MODEL_NAME

    raw_body = fields.Html(sanitize=SANITIZE)
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)

    assert any(
        f.rule_id == "odoo-field-html-sanitizer-disabled" and f.model == "x.page"
        for f in findings
    )


def test_flags_html_sanitize_override_without_admin_groups(tmp_path: Path) -> None:
    """Sanitizer override should not be available through broadly readable fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "page.py").write_text(
        """
from odoo import fields, models

class Page(models.Model):
    _name = 'x.page'

    body = fields.Html(sanitize_overridable=True, groups='base.group_user')
""",
        encoding="utf-8",
    )

    findings = scan_field_security(tmp_path)

    assert any(f.rule_id == "odoo-field-html-sanitize-overridable-no-admin-groups" for f in findings)


def test_safe_admin_restricted_sensitive_fields_are_ignored(tmp_path: Path) -> None:
    """Admin-only sensitive fields should avoid field-security noise."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "safe.py").write_text(
        """
from odoo import fields, models

class Safe(models.Model):
    _name = 'x.safe'

    api_secret = fields.Char(groups='base.group_system', copy=False)
    related_secret = fields.Char(related='user_id.api_key', groups='base.group_system')
    computed_token = fields.Char(compute='_compute_token', groups='base.group_system')
""",
        encoding="utf-8",
    )

    assert scan_field_security(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Field fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_field.py").write_text(
        """
from odoo import fields, models

class Connector(models.Model):
    api_key = fields.Char()
""",
        encoding="utf-8",
    )

    assert scan_field_security(tmp_path) == []
