"""Tests for Odoo model-structure scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.model_scanner import ModelStructureScanner, scan_models


def _write_model(tmp_path: Path, source: str) -> Path:
    model = tmp_path / "addons" / "test_module" / "models" / "thing.py"
    model.parent.mkdir(parents=True)
    model.write_text(source, encoding="utf-8")
    return model


def test_secret_like_field_should_not_be_copyable(tmp_path: Path) -> None:
    """Token/secret fields should set copy=False."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class Thing(models.Model):
    _name = 'x.thing'
    access_token = fields.Char()
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-secret-copyable" for f in findings)


def test_broad_secret_like_field_should_not_be_copyable(tmp_path: Path) -> None:
    """Key-shaped secret fields should also set copy=False."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class Thing(models.Model):
    _name = 'x.thing'
    license_key = fields.Char()
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-secret-copyable" and f.field == "license_key" for f in findings)


def test_direct_field_constructor_secret_like_field_should_not_be_copyable(tmp_path: Path) -> None:
    """Directly imported field constructors should still be scanned."""
    model = _write_model(
        tmp_path,
        """
from odoo import models
from odoo.fields import Char

class Thing(models.Model):
    _name = 'x.thing'
    access_token = Char()
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-secret-copyable" for f in findings)


def test_aliased_odoo_fields_module_secret_like_field_should_not_be_copyable(tmp_path: Path) -> None:
    """Aliased Odoo fields modules should still be scanned."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields as odoo_fields, models

class Thing(models.Model):
    _name = 'x.thing'
    access_token = odoo_fields.Char()
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-secret-copyable" for f in findings)


def test_imported_odoo_fields_module_secret_like_field_should_not_be_copyable(tmp_path: Path) -> None:
    """Direct odoo.fields imports should still be scanned."""
    model = _write_model(
        tmp_path,
        """
from odoo import models
import odoo.fields as odoo_fields

class Thing(models.Model):
    _name = 'x.thing'
    access_token = odoo_fields.Char()
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-secret-copyable" for f in findings)


def test_imported_odoo_module_fields_secret_like_field_should_not_be_copyable(tmp_path: Path) -> None:
    """Direct odoo module imports should still expose field declarations."""
    model = _write_model(
        tmp_path,
        """
import odoo as od

class Thing(od.models.Model):
    _name = 'x.thing'
    access_token = od.fields.Char()
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-secret-copyable" for f in findings)


def test_direct_model_base_secret_like_field_should_not_be_copyable(tmp_path: Path) -> None:
    """Direct Model bases should not hide model field findings."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields
from odoo.models import Model

class Thing(Model):
    _name = 'x.thing'
    access_token = fields.Char()
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-secret-copyable" for f in findings)


def test_annotated_secret_like_field_should_not_be_copyable(tmp_path: Path) -> None:
    """Annotated Odoo field declarations should be scanned."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class Thing(models.Model):
    _name = 'x.thing'
    access_token: fields.Char = fields.Char()
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-secret-copyable" for f in findings)


def test_secret_like_field_copy_false_is_allowed(tmp_path: Path) -> None:
    """copy=False should suppress the token-copy finding."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class Thing(models.Model):
    _name = 'x.thing'
    access_token = fields.Char(copy=False)
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert not any(f.rule_id == "odoo-model-secret-copyable" for f in findings)


def test_constant_backed_copy_false_suppresses_secret_copyable(tmp_path: Path) -> None:
    """Simple module constants should be resolved in field keyword checks."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

COPY_FIELD = False

class Thing(models.Model):
    _name = 'x.thing'
    access_token = fields.Char(copy=COPY_FIELD)
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert not any(f.rule_id == "odoo-model-secret-copyable" for f in findings)


def test_recursive_constant_backed_copy_false_suppresses_secret_copyable(tmp_path: Path) -> None:
    """Chained constants should be resolved in field keyword checks."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

COPY_DISABLED = False
COPY_FIELD = COPY_DISABLED

class Thing(models.Model):
    _name = 'x.thing'
    access_token = fields.Char(copy=COPY_FIELD)
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert not any(f.rule_id == "odoo-model-secret-copyable" for f in findings)


def test_nested_static_unpack_copy_false_suppresses_secret_copyable(tmp_path: Path) -> None:
    """Nested static field option dictionaries should drive copy checks."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

BASE_OPTIONS = {'copy': False}
FIELD_OPTIONS = {**BASE_OPTIONS}

class Thing(models.Model):
    _name = 'x.thing'
    access_token = fields.Char(**FIELD_OPTIONS)
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert not any(f.rule_id == "odoo-model-secret-copyable" for f in findings)


def test_log_access_disabled_is_reported(tmp_path: Path) -> None:
    """Persistent models should not silently disable Odoo audit metadata."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class Ledger(models.Model):
    _name = 'x.ledger'
    _log_access = False

    name = fields.Char()
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-log-access-disabled" for f in findings)


def test_auto_false_manual_sql_model_is_reported(tmp_path: Path) -> None:
    """Manually managed SQL-backed models need explicit review."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class SalesReport(models.Model):
    _name = 'x.sales.report'
    _auto = False

    amount_total = fields.Monetary(currency_field='currency_id')
    currency_id = fields.Many2one('res.currency')
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-auto-false-manual-sql" for f in findings)


def test_constant_backed_auto_false_manual_sql_model_is_reported(tmp_path: Path) -> None:
    """Constant-backed _auto=False should not hide manual SQL-backed models."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

MANAGED_BY_ORM = False

class SalesReport(models.Model):
    _name = 'x.sales.report'
    _auto = MANAGED_BY_ORM

    amount_total = fields.Monetary(currency_field='currency_id')
    currency_id = fields.Many2one('res.currency')
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-auto-false-manual-sql" for f in findings)


def test_recursive_constant_backed_auto_false_manual_sql_model_is_reported(tmp_path: Path) -> None:
    """Chained _auto=False constants should not hide manual SQL-backed models."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

MANAGED_BY_SQL = False
MANAGED_BY_ORM = MANAGED_BY_SQL

class SalesReport(models.Model):
    _name = 'x.sales.report'
    _auto = MANAGED_BY_ORM

    amount_total = fields.Monetary(currency_field='currency_id')
    currency_id = fields.Many2one('res.currency')
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-auto-false-manual-sql" for f in findings)


def test_class_constant_backed_auto_false_manual_sql_model_is_reported(tmp_path: Path) -> None:
    """Class-scoped _auto=False aliases should not hide manual SQL-backed models."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class SalesReport(models.Model):
    MODEL_NAME = 'x.sales.report'
    MANAGED_BY_SQL = False
    MANAGED_BY_ORM = MANAGED_BY_SQL
    _name = MODEL_NAME
    _auto = MANAGED_BY_ORM

    amount_total = fields.Monetary(currency_field='currency_id')
    currency_id = fields.Many2one('res.currency')
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(
        f.rule_id == "odoo-model-auto-false-manual-sql" and f.model == "x.sales.report"
        for f in findings
    )


def test_constant_backed_log_access_disabled_is_reported(tmp_path: Path) -> None:
    """Simple constants should not hide disabled Odoo audit metadata."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

LOG_ACCESS = False

class Ledger(models.Model):
    _name = 'x.ledger'
    _log_access = LOG_ACCESS

    name = fields.Char()
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-log-access-disabled" for f in findings)


def test_recursive_constant_backed_log_access_disabled_is_reported(tmp_path: Path) -> None:
    """Chained constants should not hide disabled Odoo audit metadata."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

DISABLE_LOG_ACCESS = False
LOG_ACCESS = DISABLE_LOG_ACCESS

class Ledger(models.Model):
    _name = 'x.ledger'
    _log_access = LOG_ACCESS

    name = fields.Char()
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-log-access-disabled" for f in findings)


def test_annotated_log_access_false_is_reported(tmp_path: Path) -> None:
    """Annotated model metadata assignments should not hide disabled audit fields."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class Ledger(models.Model):
    _name = 'x.ledger'
    _log_access: bool = False

    name = fields.Char()
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-log-access-disabled" for f in findings)


def test_sensitive_rec_name_is_reported(tmp_path: Path) -> None:
    """Display names should not be derived from token or credential fields."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class ApiCredential(models.Model):
    _name = 'x.api.credential'
    _rec_name = 'api_key'

    api_key = fields.Char(copy=False, groups='base.group_system')
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-rec-name-sensitive" for f in findings)


def test_broad_sensitive_rec_name_is_reported(tmp_path: Path) -> None:
    """Display names should not use key-shaped secret fields."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class ApiCredential(models.Model):
    _name = 'x.api.credential'
    _rec_name = 'license_key'

    license_key = fields.Char(copy=False, groups='base.group_system')
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-rec-name-sensitive" and f.field == "license_key" for f in findings)


def test_constant_backed_sensitive_rec_name_is_reported(tmp_path: Path) -> None:
    """Constant-backed _rec_name metadata should still be reviewed."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

REC_NAME = 'api_key'

class ApiCredential(models.Model):
    _name = 'x.api.credential'
    _rec_name = REC_NAME

    api_key = fields.Char(copy=False, groups='base.group_system')
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-rec-name-sensitive" for f in findings)


def test_recursive_constant_backed_sensitive_rec_name_is_reported(tmp_path: Path) -> None:
    """Chained _rec_name metadata constants should still be reviewed."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

SECRET_DISPLAY = 'api_key'
REC_NAME = SECRET_DISPLAY

class ApiCredential(models.Model):
    _name = 'x.api.credential'
    _rec_name = REC_NAME

    api_key = fields.Char(copy=False, groups='base.group_system')
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-rec-name-sensitive" for f in findings)


def test_class_constant_backed_sensitive_rec_name_and_copy_false(tmp_path: Path) -> None:
    """Class-scoped aliases should drive display-name and copy checks."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class ApiCredential(models.Model):
    MODEL_NAME = 'x.api.credential'
    SECRET_DISPLAY = 'api_key'
    REC_NAME = SECRET_DISPLAY
    NO_COPY = False
    _name = MODEL_NAME
    _rec_name = REC_NAME

    api_key = fields.Char(copy=NO_COPY, groups='base.group_system')
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(
        f.rule_id == "odoo-model-rec-name-sensitive" and f.model == "x.api.credential"
        for f in findings
    )
    assert not any(f.rule_id == "odoo-model-secret-copyable" for f in findings)


def test_required_identifier_without_unique_constraint(tmp_path: Path) -> None:
    """Required business identifiers should have an obvious uniqueness guard."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class Thing(models.Model):
    _name = 'x.thing'
    code = fields.Char(required=True)
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-identifier-missing-unique" for f in findings)


def test_required_identifier_with_unique_constraint_is_allowed(tmp_path: Path) -> None:
    """A visible unique SQL constraint should suppress the identifier finding."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class Thing(models.Model):
    _name = 'x.thing'
    code = fields.Char(required=True)
    _sql_constraints = [
        ('code_unique', 'unique(code)', 'Code must be unique'),
    ]
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert not any(f.rule_id == "odoo-model-identifier-missing-unique" for f in findings)


def test_recursive_constant_required_identifier_without_unique_constraint(tmp_path: Path) -> None:
    """Chained required=True constants should keep identifier uniqueness review visible."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

REQUIRED_YES = True
CODE_REQUIRED = REQUIRED_YES

class Thing(models.Model):
    _name = 'x.thing'
    code = fields.Char(required=CODE_REQUIRED)
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-identifier-missing-unique" for f in findings)


def test_monetary_field_without_currency(tmp_path: Path) -> None:
    """Monetary fields need an obvious currency source."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class Thing(models.Model):
    _name = 'x.thing'
    amount_total = fields.Monetary()
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-monetary-missing-currency" for f in findings)


def test_recursive_constant_currency_field_suppresses_monetary_finding(tmp_path: Path) -> None:
    """Chained currency_field constants should suppress monetary currency noise."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

BASE_CURRENCY_FIELD = 'currency_ref_id'
CURRENCY_FIELD = BASE_CURRENCY_FIELD

class Thing(models.Model):
    _name = 'x.thing'
    amount_total = fields.Monetary(currency_field=CURRENCY_FIELD)
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert not any(f.rule_id == "odoo-model-monetary-missing-currency" for f in findings)


def test_delegated_inheritance_to_sensitive_model(tmp_path: Path) -> None:
    """_inherits wrappers around sensitive models need explicit review."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class PartnerWrapper(models.Model):
    _name = 'x.partner.wrapper'
    _inherits = {'res.partner': 'partner_id'}

    partner_id = fields.Many2one('res.partner', ondelete='set null')
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-model-delegated-sensitive-inherits" in rule_ids
    assert "odoo-model-delegated-link-not-required" in rule_ids


def test_recursive_constant_delegated_inheritance_to_sensitive_model(tmp_path: Path) -> None:
    """Chained _inherits constants should still reveal sensitive delegation."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

PARTNER_MODEL = 'res.partner'
DELEGATED_MODEL = PARTNER_MODEL
PARTNER_FIELD = 'partner_id'
INHERITS = {DELEGATED_MODEL: PARTNER_FIELD}

class PartnerWrapper(models.Model):
    _name = 'x.partner.wrapper'
    _inherits = INHERITS

    partner_id = fields.Many2one('res.partner', ondelete='set null')
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-model-delegated-sensitive-inherits" in rule_ids
    assert "odoo-model-delegated-link-not-required" in rule_ids


def test_class_constant_delegated_inheritance_to_sensitive_model(tmp_path: Path) -> None:
    """Class-scoped _inherits aliases should still reveal sensitive delegation."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class PartnerWrapper(models.Model):
    MODEL_NAME = 'x.partner.wrapper'
    PARTNER_MODEL = 'res.partner'
    DELEGATED_MODEL = PARTNER_MODEL
    PARTNER_FIELD = 'partner_id'
    INHERITS = {DELEGATED_MODEL: PARTNER_FIELD}
    _name = MODEL_NAME
    _inherits = INHERITS

    partner_id = fields.Many2one(PARTNER_MODEL, ondelete='set null')
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-model-delegated-sensitive-inherits" in rule_ids
    assert "odoo-model-delegated-link-not-required" in rule_ids
    assert any(f.model == "x.partner.wrapper" for f in findings)


def test_delegate_true_to_sensitive_model(tmp_path: Path) -> None:
    """delegate=True exposes related model fields through the wrapper model."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class UserWrapper(models.Model):
    _name = 'x.user.wrapper'

    user_id = fields.Many2one('res.users', delegate=True, required=True, ondelete='cascade')
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-delegate-sensitive-field" for f in findings)


def test_recursive_constant_delegate_true_to_sensitive_model(tmp_path: Path) -> None:
    """Chained relation/delegate constants should still reveal sensitive delegation."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

USER_MODEL = 'res.users'
TARGET_MODEL = USER_MODEL
DELEGATE_YES = True

class UserWrapper(models.Model):
    _name = 'x.user.wrapper'

    user_id = fields.Many2one(TARGET_MODEL, delegate=DELEGATE_YES, required=True, ondelete='cascade')
""",
    )

    findings = ModelStructureScanner(str(model)).scan_file()

    assert any(f.rule_id == "odoo-model-delegate-sensitive-field" for f in findings)


def test_safe_delegated_link_is_ignored(tmp_path: Path) -> None:
    """Non-sensitive delegated links with required cascade should not be noisy."""
    model = _write_model(
        tmp_path,
        """
from odoo import fields, models

class AssetWrapper(models.Model):
    _name = 'x.asset.wrapper'
    _inherits = {'x.asset': 'asset_id'}

    asset_id = fields.Many2one('x.asset', required=True, ondelete='cascade')
""",
    )

    assert ModelStructureScanner(str(model)).scan_file() == []


def test_repository_scan_skips_tests_directory(tmp_path: Path) -> None:
    """The scanner should ignore test fixtures."""
    test_model = tmp_path / "tests" / "test_model.py"
    test_model.parent.mkdir()
    test_model.write_text(
        """
from odoo import fields, models

class Thing(models.Model):
    _name = 'x.thing'
    access_token = fields.Char()
""",
        encoding="utf-8",
    )

    assert scan_models(tmp_path) == []
