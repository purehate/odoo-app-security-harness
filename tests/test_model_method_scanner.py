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


def test_flags_aliased_odoo_api_module_onchange(tmp_path: Path) -> None:
    """Aliased Odoo API modules should not hide model method decorators."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import api as odoo_api, models

class Sale(models.Model):
    _name = 'x.sale'

    @odoo_api.onchange('partner_id')
    def _onchange_partner_id(self):
        self.env['sale.order'].sudo().write({'note': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" for f in findings)


def test_flags_imported_odoo_api_module_onchange(tmp_path: Path) -> None:
    """Direct odoo.api module imports should not hide model method decorators."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
import odoo.api as odoo_api
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    @odoo_api.onchange('partner_id')
    def sync_partner(self):
        self.env['sale.order'].sudo().write({'note': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" for f in findings)


def test_flags_imported_odoo_module_api_onchange(tmp_path: Path) -> None:
    """Direct odoo module imports should not hide model method decorators."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
import odoo as od

class Sale(od.models.Model):
    _name = 'x.sale'

    @od.api.onchange('partner_id')
    def sync_partner(self):
        self.env['sale.order'].sudo().write({'note': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" for f in findings)


def test_flags_aliased_imported_onchange_decorator(tmp_path: Path) -> None:
    """Aliased direct model method decorator imports should remain visible."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models
from odoo.api import onchange as on_change

class Sale(models.Model):
    _name = 'x.sale'

    @on_change('partner_id')
    def sync_partner(self):
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


def test_flags_import_aliased_superuser_onchange_mutation(tmp_path: Path) -> None:
    """Aliased SUPERUSER_ID imports inside onchange methods should be elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import SUPERUSER_ID as ROOT_UID, api, models

class Sale(models.Model):
    _name = 'x.sale'

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        self.env['sale.order'].with_user(ROOT_UID).write({'note': 'x'})
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

    assert any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" and f.model == "x.sale" for f in findings)


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

    assert any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" and f.model == "x.sale" for f in findings)


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

    assert any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" and f.model == "x.sale" for f in findings)


def test_flags_local_constant_with_user_onchange_mutation(tmp_path: Path) -> None:
    """Function-local superuser IDs should not hide lifecycle sudo mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import api, models

class Sale(models.Model):
    _name = 'x.sale'

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        root_uid = 1
        orders = self.env['sale.order'].with_user(root_uid)
        orders.write({'note': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-onchange-sudo-mutation" for f in findings)


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


def test_flags_urllib_request_import_alias_without_timeout(tmp_path: Path) -> None:
    """from urllib import request aliases should count as outbound HTTP in model methods."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "compute.py").write_text(
        """
from odoo import api, models
from urllib import request as urlreq

class Feed(models.Model):
    _name = 'x.feed'

    @api.depends('url')
    def _compute_payload(self):
        urlreq.urlopen(self.url)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-compute-http-no-timeout" for f in findings)


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


def test_flags_model_method_http_timeout_none_as_unbounded(tmp_path: Path) -> None:
    """Model methods should treat timeout=None as no effective HTTP timeout."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "compute.py").write_text(
        """
from odoo import api, fields, models
import requests

class Feed(models.Model):
    _name = 'x.feed'
    status = fields.Char(compute='_compute_status')

    @api.depends('url')
    def _compute_status(self):
        requests.get(self.url, timeout=None)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-compute-http-no-timeout" for f in findings)


def test_flags_model_method_http_constant_timeout_none_as_unbounded(tmp_path: Path) -> None:
    """Model methods should resolve constants used for timeout values."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "compute.py").write_text(
        """
from odoo import api, fields, models
import requests

MODEL_TIMEOUT = None

class Feed(models.Model):
    _name = 'x.feed'
    status = fields.Char(compute='_compute_status')

    @api.depends('url')
    def _compute_status(self):
        requests.get(self.url, timeout=MODEL_TIMEOUT)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-compute-http-no-timeout" for f in findings)


def test_model_method_static_kwargs_timeout_is_not_reported(tmp_path: Path) -> None:
    """Static **kwargs dictionaries should satisfy model method HTTP timeout checks."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "compute.py").write_text(
        """
from odoo import api, fields, models
import requests

HTTP_OPTIONS = {'timeout': 10}

class Feed(models.Model):
    _name = 'x.feed'
    status = fields.Char(compute='_compute_status')

    @api.depends('url')
    def _compute_status(self):
        requests.get(self.url, **HTTP_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert not any(f.rule_id == "odoo-model-method-compute-http-no-timeout" for f in findings)


def test_model_method_dict_union_static_kwargs_timeout_is_not_reported(tmp_path: Path) -> None:
    """Dict-union static **kwargs should satisfy model method HTTP timeout checks."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "compute.py").write_text(
        """
from odoo import api, fields, models
import requests

BASE_OPTIONS = {'timeout': 10}
HTTP_OPTIONS = BASE_OPTIONS | {'headers': {}}

class Feed(models.Model):
    _name = 'x.feed'
    status = fields.Char(compute='_compute_status')

    @api.depends('url')
    def _compute_status(self):
        requests.get(self.url, **HTTP_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert not any(f.rule_id == "odoo-model-method-compute-http-no-timeout" for f in findings)


def test_model_method_updated_static_kwargs_timeout_is_not_reported(tmp_path: Path) -> None:
    """Updated static **kwargs should satisfy model method HTTP timeout checks."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "compute.py").write_text(
        """
from odoo import api, fields, models
import requests

HTTP_OPTIONS = {}
HTTP_OPTIONS.update({'timeout': 10})

class Feed(models.Model):
    _name = 'x.feed'
    status = fields.Char(compute='_compute_status')

    @api.depends('url')
    def _compute_status(self):
        requests.get(self.url, **HTTP_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert not any(f.rule_id == "odoo-model-method-compute-http-no-timeout" for f in findings)


def test_flags_tls_verification_disabled(tmp_path: Path) -> None:
    """Model methods should surface disabled TLS verification on outbound HTTP."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "constraint.py").write_text(
        """
from odoo import api, models
import requests

TLS_VERIFY = False

class Feed(models.Model):
    _name = 'x.feed'

    @api.constrains('url')
    def _check_url(self):
        return requests.get(self.url, timeout=10, verify=TLS_VERIFY)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-constraint-tls-verify-disabled" for f in findings)


def test_flags_tls_verification_disabled_static_kwargs(tmp_path: Path) -> None:
    """Static **kwargs dictionaries should not hide model method TLS verification disabling."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "constraint.py").write_text(
        """
from odoo import api, models
import requests

HTTP_OPTIONS = {'timeout': 10, 'verify': False}

class Feed(models.Model):
    _name = 'x.feed'

    @api.constrains('url')
    def _check_url(self):
        return requests.get(self.url, **HTTP_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-constraint-tls-verify-disabled" for f in findings)


def test_flags_tls_verification_disabled_dict_union_static_kwargs(tmp_path: Path) -> None:
    """Dict-union static **kwargs should not hide model method TLS disabling."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "constraint.py").write_text(
        """
from odoo import api, models
import requests

BASE_OPTIONS = {'timeout': 10}
HTTP_OPTIONS = BASE_OPTIONS | {'verify': False}

class Feed(models.Model):
    _name = 'x.feed'

    @api.constrains('url')
    def _check_url(self):
        return requests.get(self.url, **HTTP_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-constraint-tls-verify-disabled" for f in findings)


def test_flags_tls_verification_disabled_updated_static_kwargs(tmp_path: Path) -> None:
    """Updated static **kwargs should not hide model method TLS disabling."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "constraint.py").write_text(
        """
from odoo import api, models
import requests

HTTP_OPTIONS = {'timeout': 10}
HTTP_OPTIONS.update({'verify': False})

class Feed(models.Model):
    _name = 'x.feed'

    @api.constrains('url')
    def _check_url(self):
        return requests.get(self.url, **HTTP_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-constraint-tls-verify-disabled" for f in findings)


def test_flags_local_constant_tls_verification_disabled(tmp_path: Path) -> None:
    """Function-local verify=False kwargs should still flag lifecycle HTTP integrations."""
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
        verify_tls = False
        http_options = {'timeout': 10, 'verify': verify_tls}
        return requests.get(self.url, **http_options)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-constraint-tls-verify-disabled" for f in findings)


def test_flags_model_method_cleartext_http_urls(tmp_path: Path) -> None:
    """Lifecycle model methods should flag literal cleartext HTTP integration URLs."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "cleartext.py").write_text(
        """
from odoo import api, fields, models
import requests

CALLBACK_URL = 'http://hooks.example.test/onchange'
HTTP_OPTIONS = {'url': 'http://partner.example.test/compute', 'timeout': 10}

class Feed(models.Model):
    _name = 'x.feed'
    status = fields.Char(compute='_compute_status', inverse='_inverse_status')

    @api.onchange('url')
    def _onchange_url(self):
        requests.post(CALLBACK_URL, timeout=10)

    @api.depends('url')
    def _compute_status(self):
        requests.request('POST', **HTTP_OPTIONS)

    @api.constrains('url')
    def _check_url(self):
        requests.get('http://feeds.example.test/check', timeout=10)

    def _inverse_status(self):
        requests.get(url='http://feeds.example.test/inverse', timeout=10)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-model-method-onchange-cleartext-http-url" in rule_ids
    assert "odoo-model-method-compute-cleartext-http-url" in rule_ids
    assert "odoo-model-method-constraint-cleartext-http-url" in rule_ids
    assert "odoo-model-method-inverse-cleartext-http-url" in rule_ids


def test_flags_model_method_cleartext_http_url_dict_union_kwargs(tmp_path: Path) -> None:
    """Dict-union static url= kwargs should not hide model method cleartext URLs."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "cleartext.py").write_text(
        """
from odoo import api, fields, models
import requests

BASE_OPTIONS = {'url': 'http://partner.example.test/compute'}
HTTP_OPTIONS = BASE_OPTIONS | {'timeout': 10}

class Feed(models.Model):
    _name = 'x.feed'
    status = fields.Char(compute='_compute_status')

    @api.depends('url')
    def _compute_status(self):
        requests.request('POST', **HTTP_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)

    assert any(f.rule_id == "odoo-model-method-compute-cleartext-http-url" for f in findings)


def test_flags_model_method_url_embedded_credentials(tmp_path: Path) -> None:
    """Lifecycle model methods should flag credentials embedded in outbound URLs."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "url_credentials.py").write_text(
        """
from odoo import api, fields, models
import requests

CALLBACK_URL = 'https://integration_user:sk_live_1234567890abcdef@hooks.example.test/onchange'
HTTP_OPTIONS = {'url': 'https://token_1234567890abcdef@partner.example.test/compute', 'timeout': 10}

class Feed(models.Model):
    _name = 'x.feed'
    status = fields.Char(compute='_compute_status', inverse='_inverse_status')

    @api.onchange('url')
    def _onchange_url(self):
        requests.post(CALLBACK_URL, timeout=10)

    @api.depends('url')
    def _compute_status(self):
        requests.request('POST', **HTTP_OPTIONS)

    @api.constrains('url')
    def _check_url(self):
        requests.get('https://integration_user:sk_live_1234567890abcdef@feeds.example.test/check', timeout=10)

    def _inverse_status(self):
        requests.get(url='https://token_1234567890abcdef@feeds.example.test/inverse', timeout=10)
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-model-method-onchange-url-embedded-credentials" in rule_ids
    assert "odoo-model-method-compute-url-embedded-credentials" in rule_ids
    assert "odoo-model-method-constraint-url-embedded-credentials" in rule_ids
    assert "odoo-model-method-inverse-url-embedded-credentials" in rule_ids


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


def test_flags_aliased_safe_eval_in_compute_method(tmp_path: Path) -> None:
    """Aliased safe_eval imports should remain visible inside model lifecycle methods."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "compute.py").write_text(
        """
from odoo import api, models
from odoo.tools.safe_eval import safe_eval as run_eval

class Rule(models.Model):
    _name = 'x.rule'

    @api.depends('expression')
    def _compute_result(self):
        for record in self:
            record.result = run_eval(record.expression)
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
        f.rule_id == "odoo-model-method-onchange-sensitive-model-mutation" and f.model == "x.side.effects"
        for f in findings
    )


def test_flags_local_constant_lifecycle_sensitive_model_mutation(tmp_path: Path) -> None:
    """Function-local env model aliases should still flag lifecycle mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "side_effects.py").write_text(
        """
from odoo import api, models

class SideEffects(models.Model):
    _name = 'x.side.effects'

    @api.onchange('partner_id')
    def _onchange_partner_id(self):
        users_model = 'res.users'
        config_model = 'ir.config_parameter'
        self.env[users_model].write({'active': False})
        self.env[config_model].set_param('auth_signup.invitation_scope', 'b2c')
""",
        encoding="utf-8",
    )

    findings = scan_model_methods(tmp_path)
    sensitive_mutations = [
        finding for finding in findings if finding.rule_id == "odoo-model-method-onchange-sensitive-model-mutation"
    ]

    assert len(sensitive_mutations) == 2


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
