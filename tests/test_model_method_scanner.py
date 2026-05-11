"""Tests for risky Odoo model method behavior scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.model_method_scanner import scan_model_methods


def test_flags_onchange_sudo_mutation_and_http_no_timeout(tmp_path: Path) -> None:
    """Onchange methods should not perform privileged mutations or blocking HTTP calls."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import api, models
import requests

class Sale(models.Model):
    _name = 'x.sale'

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        self.env['sale.order'].sudo().write({'note': 'x'})
        requests.post(self.partner_id.callback_url)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-model-method-onchange-sudo-mutation" in rule_ids
    assert "odoo-model-method-onchange-http-no-timeout" in rule_ids


def test_flags_direct_model_base_and_imported_onchange(tmp_path: Path) -> None:
    """Direct Model bases and imported API decorators should still be scanned."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo.models import Model
from odoo.api import onchange

class Sale(Model):
    _name = 'x.sale'

    @onchange('partner_id')
    def _onchange_partner_id(self):
        self.env['sale.order'].sudo().write({'note': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" for f in findings)


def test_flags_aliased_onchange_sudo_mutation(tmp_path: Path) -> None:
    """Sudo recordset aliases inside onchange methods should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import api, models

class Sale(models.Model):
    _name = 'x.sale'

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        orders = self.env['sale.order'].sudo()
        orders.write({'note': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" for f in findings)


def test_flags_with_user_superuser_onchange_mutation(tmp_path: Path) -> None:
    """with_user(SUPERUSER_ID) mutations inside onchange methods should be elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import SUPERUSER_ID, api, models

class Sale(models.Model):
    _name = 'x.sale'

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        self.env['sale.order'].with_user(SUPERUSER_ID).write({'note': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" for f in findings)


def test_flags_keyword_with_user_superuser_onchange_mutation(tmp_path: Path) -> None:
    """Keyword with_user(user=SUPERUSER_ID) onchange mutations are elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import SUPERUSER_ID, api, models

class Sale(models.Model):
    _name = 'x.sale'

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        self.env['sale.order'].with_user(user=SUPERUSER_ID).write({'note': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" for f in findings)


def test_flags_aliased_with_user_one_onchange_mutation(tmp_path: Path) -> None:
    """with_user(1) aliases inside onchange methods should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import api, models

class Sale(models.Model):
    _name = 'x.sale'

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        orders = self.env['sale.order'].with_user(1)
        orders.write({'note': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" for f in findings)


def test_flags_constant_backed_with_user_onchange_mutation_and_model_name(tmp_path: Path) -> None:
    """Constant-backed model names and superuser IDs should not hide lifecycle sudo mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import api, models

SALE_MODEL = 'x.sale'
ROOT_UID = 1

class Sale(models.Model):
    _name = SALE_MODEL

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        orders = self.env['sale.order'].with_user(ROOT_UID)
        orders.write({'note': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(
        f.rule_id == "odoo-model-method-onchange-sudo-mutation" and f.model == "x.sale"
        for f in findings
    )


def test_flags_constant_alias_with_user_onchange_mutation_and_model_name(tmp_path: Path) -> None:
    """Constant-to-constant model names and superuser IDs should not hide sudo mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import api, models

BASE_MODEL = 'x.sale'
SALE_MODEL = BASE_MODEL
ADMIN_UID = 1
ROOT_UID = ADMIN_UID

class Sale(models.Model):
    _name = SALE_MODEL

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        orders = self.env['sale.order'].with_user(ROOT_UID)
        orders.write({'note': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(
        f.rule_id == "odoo-model-method-onchange-sudo-mutation" and f.model == "x.sale"
        for f in findings
    )


def test_flags_class_constant_alias_with_user_onchange_mutation_and_model_name(tmp_path: Path) -> None:
    """Class-scoped model names and superuser IDs should not hide sudo mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import api, models

class Sale(models.Model):
    BASE_MODEL = 'x.sale'
    SALE_MODEL = BASE_MODEL
    ADMIN_UID = 1
    ROOT_UID = ADMIN_UID
    _name = SALE_MODEL

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        orders = self.env['sale.order'].with_user(ROOT_UID)
        orders.write({'note': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(
        f.rule_id == "odoo-model-method-onchange-sudo-mutation" and f.model == "x.sale"
        for f in findings
    )


def test_flags_env_ref_admin_onchange_mutation(tmp_path: Path) -> None:
    """with_user(base.user_admin) mutations inside onchange methods are elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import api, models

class Sale(models.Model):
    _name = 'x.sale'

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        orders = self.env['sale.order'].with_user(self.env.ref('base.user_admin'))
        orders.write({'note': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" for f in findings)


def test_flags_tuple_unpacked_onchange_sudo_mutation(tmp_path: Path) -> None:
    """Tuple-unpacked sudo aliases inside onchange methods should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import api, models

class Sale(models.Model):
    _name = 'x.sale'

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        orders, partners = self.env['sale.order'].sudo(), self.env['res.partner'].sudo()
        partners.write({'comment': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" for f in findings)


def test_flags_named_expression_onchange_sudo_mutation(tmp_path: Path) -> None:
    """Walrus-bound sudo aliases inside onchange methods should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import api, models

class Sale(models.Model):
    _name = 'x.sale'

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        if orders := self.env['sale.order'].sudo():
            orders.write({'note': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" for f in findings)


def test_flags_starred_tuple_onchange_sudo_mutation(tmp_path: Path) -> None:
    """Starred sudo aliases inside onchange methods should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import api, models

class Sale(models.Model):
    _name = 'x.sale'

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        *orders, partner = self.env['sale.order'].sudo(), self.partner_id
        orders.write({'note': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" for f in findings)


def test_flags_starred_rest_onchange_sudo_mutation(tmp_path: Path) -> None:
    """Starred-rest sudo aliases inside onchange methods should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import api, models

class Sale(models.Model):
    _name = 'x.sale'

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        label, *items = self.name, self.env['sale.order'].sudo(), self.partner_id
        orders = items[0]
        orders.write({'note': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" for f in findings)


def test_does_not_overtaint_mixed_tuple_onchange_aliases(tmp_path: Path) -> None:
    """Mixed tuple assignments should only taint the target receiving sudo()."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import api, models

class Sale(models.Model):
    _name = 'x.sale'

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        orders, partner = self.env['sale.order'].sudo(), self.partner_id
        partner.write({'comment': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert not any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" for f in findings)


def test_does_not_overtaint_mixed_tuple_http_clients(tmp_path: Path) -> None:
    """Mixed tuple assignments should only mark actual HTTP client objects."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "compute.py").write_text(
        """
from odoo import api, models
import requests

class Feed(models.Model):
    _name = 'x.feed'

    @api.depends('url')
    def _compute_payload(self):
        session, callback = requests.Session(), self.callback
        callback.post(self.url)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert not any(f.rule_id == "odoo-model-method-compute-http-no-timeout" for f in findings)


def test_flags_aliased_http_imports_without_timeout(tmp_path: Path) -> None:
    """Aliased request modules and imported helpers should still be treated as HTTP calls."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "compute.py").write_text(
        """
from odoo import api, models
import requests as rq
from httpx import post as http_post

class Feed(models.Model):
    _name = 'x.feed'

    @api.depends('url')
    def _compute_payload(self):
        rq.get(self.url)
        http_post(self.callback_url)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-model-method-compute-http-no-timeout" in rule_ids


def test_flags_urllib_urlopen_without_timeout(tmp_path: Path) -> None:
    """urllib.request.urlopen in model methods should require a timeout."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "compute.py").write_text(
        """
from odoo import api, models
from urllib.request import urlopen
import urllib.request as urlreq

class Feed(models.Model):
    _name = 'x.feed'

    @api.depends('url')
    def _compute_payload(self):
        urlopen(self.url)
        urlreq.urlopen(self.callback_url, timeout=10)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert len([f for f in findings if f.rule_id == "odoo-model-method-compute-http-no-timeout"]) == 1


def test_flags_http_client_without_timeout(tmp_path: Path) -> None:
    """Session/client objects inside model methods can block workers too."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "constraint.py").write_text(
        """
from odoo import api, models
import requests

class Feed(models.Model):
    _name = 'x.feed'

    @api.constrains('url')
    def _check_url(self):
        client = requests.Session()
        client.post(self.url)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-constraint-http-no-timeout" for f in findings)


def test_flags_aiohttp_client_session_context_without_timeout(tmp_path: Path) -> None:
    """aiohttp ClientSession context aliases inside model methods should be tracked."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "compute.py").write_text(
        """
from odoo import api, models
import aiohttp

class Feed(models.Model):
    _name = 'x.feed'

    @api.depends('url')
    async def _compute_payload(self):
        async with aiohttp.ClientSession() as client:
            await client.get(self.url)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-compute-http-no-timeout" for f in findings)


def test_flags_head_without_timeout(tmp_path: Path) -> None:
    """Model methods should treat HEAD calls as outbound HTTP."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "compute.py").write_text(
        """
from odoo import api, models
import httpx

class Feed(models.Model):
    _name = 'x.feed'

    @api.depends('url')
    def _compute_payload(self):
        httpx.head(self.url)
        httpx.head(self.callback_url, timeout=10)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert len([f for f in findings if f.rule_id == "odoo-model-method-compute-http-no-timeout"]) == 1


def test_flags_named_expression_http_client_without_timeout(tmp_path: Path) -> None:
    """Walrus-bound HTTP client aliases should still be treated as blocking calls."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "constraint.py").write_text(
        """
from odoo import api, models
import requests

class Feed(models.Model):
    _name = 'x.feed'

    @api.constrains('url')
    def _check_url(self):
        if client := requests.Session():
            client.post(self.url)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-constraint-http-no-timeout" for f in findings)


def test_flags_starred_rest_http_client_without_timeout(tmp_path: Path) -> None:
    """Starred-rest HTTP client aliases should still be treated as blocking calls."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "constraint.py").write_text(
        """
from odoo import api, models
import requests

class Feed(models.Model):
    _name = 'x.feed'

    @api.constrains('url')
    def _check_url(self):
        label, *items = self.name, requests.Session(), self.callback
        client = items[0]
        client.post(self.url)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-constraint-http-no-timeout" for f in findings)


def test_flags_compute_dynamic_eval(tmp_path: Path) -> None:
    """Compute methods should not evaluate record-controlled expressions."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "compute.py").write_text(
        """
from odoo import api, models

class Rule(models.Model):
    _name = 'x.rule'

    @api.depends('expression')
    def _compute_result(self):
        for record in self:
            record.result = safe_eval(record.expression)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-dynamic-eval" for f in findings)


def test_flags_lifecycle_sensitive_model_mutation(tmp_path: Path) -> None:
    """Lifecycle methods mutating identity/config models are surprising side effects."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "side_effects.py").write_text(
        """
from odoo import api, fields, models

class SideEffects(models.Model):
    _name = 'x.side.effects'

    mirror = fields.Char(compute='_compute_mirror', inverse='_inverse_mirror')

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        self.env['res.users'].write({'active': False})

    @api.depends('name')
    def _compute_mirror(self):
        self.env['ir.config_parameter'].set_param('auth_signup.invitation_scope', 'b2c')

    @api.constrains('name')
    def _check_name(self):
        self.env['ir.rule'].unlink()

    def _inverse_mirror(self):
        self.env['res.groups'].create({'name': 'shadow'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-model-method-onchange-sensitive-model-mutation" in rule_ids
    assert "odoo-model-method-compute-sensitive-model-mutation" in rule_ids
    assert "odoo-model-method-constraint-sensitive-model-mutation" in rule_ids
    assert "odoo-model-method-inverse-sensitive-model-mutation" in rule_ids


def test_flags_constant_backed_lifecycle_sensitive_model_mutation(tmp_path: Path) -> None:
    """Constant-backed env model names should still flag lifecycle mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "side_effects.py").write_text(
        """
from odoo import api, fields, models

USERS_MODEL = 'res.users'
CONFIG_MODEL = 'ir.config_parameter'

class SideEffects(models.Model):
    _name = 'x.side.effects'

    mirror = fields.Char(compute='_compute_mirror')

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        self.env[USERS_MODEL].write({'active': False})

    @api.depends('name')
    def _compute_mirror(self):
        self.env[CONFIG_MODEL].set_param('auth_signup.invitation_scope', 'b2c')
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-model-method-onchange-sensitive-model-mutation" in rule_ids
    assert "odoo-model-method-compute-sensitive-model-mutation" in rule_ids


def test_flags_constant_alias_lifecycle_sensitive_model_mutation(tmp_path: Path) -> None:
    """Constant-to-constant env model names should still flag lifecycle mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "side_effects.py").write_text(
        """
from odoo import api, models

IDENTITY_MODEL = 'res.users'
USERS_MODEL = IDENTITY_MODEL

class SideEffects(models.Model):
    _name = 'x.side.effects'

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        self.env[USERS_MODEL].write({'active': False})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-onchange-sensitive-model-mutation" for f in findings)


def test_flags_class_constant_alias_lifecycle_sensitive_model_mutation(tmp_path: Path) -> None:
    """Class-scoped env model aliases should still flag lifecycle mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "side_effects.py").write_text(
        """
from odoo import api, models

class SideEffects(models.Model):
    BASE_MODEL = 'x.side.effects'
    EFFECTS_MODEL = BASE_MODEL
    IDENTITY_MODEL = 'res.users'
    USERS_MODEL = IDENTITY_MODEL
    _name = EFFECTS_MODEL

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        self.env[USERS_MODEL].write({'active': False})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(
        f.rule_id == "odoo-model-method-onchange-sensitive-model-mutation"
        and f.model == "x.side.effects"
        for f in findings
    )


def test_flags_constraint_sudo_mutation_by_name(tmp_path: Path) -> None:
    """Constraint-like methods should be detected by naming convention too."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "constraint.py").write_text(
        """
from odoo import models

class Partner(models.Model):
    _name = 'x.partner'

    def _check_partner(self):
        self.sudo().unlink()
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-constraint-sudo-mutation" for f in findings)


def test_ordinary_method_is_ignored(tmp_path: Path) -> None:
    """Ordinary helper methods should avoid model-method-specific noise."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "helper.py").write_text(
        """
from odoo import models

class Helper(models.Model):
    _name = 'x.helper'

    def action_sync(self):
        self.env['x.audit'].sudo().write({'ok': True})
""",
        encoding="utf-8",
    )

    assert scan_model_methods(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Model-method fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_model.py").write_text(
        """
from odoo import api, models

class Sale(models.Model):
    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        self.sudo().write({'x': 1})
""",
        encoding="utf-8",
    )

    assert scan_model_methods(tmp_path) == []
