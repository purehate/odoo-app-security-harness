"""Tests for Odoo scheduled-job Python scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.scheduled_job_scanner import scan_scheduled_jobs


def test_xml_entities_are_not_expanded_into_scheduled_job_findings(tmp_path: Path) -> None:
    """XML entities must not synthesize cron-linked scheduled job findings."""
    data = tmp_path / "module" / "data"
    models = tmp_path / "module" / "models"
    data.mkdir(parents=True)
    models.mkdir(parents=True)
    (data / "cron.xml").write_text(
        """<!DOCTYPE odoo [
<!ENTITY cron_method "sync_now">
]>
<odoo>
  <record id="cron_entity" model="ir.cron">
    <field name="function">&cron_method;</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )
    (models / "sync.py").write_text(
        """
from odoo import models

class Sync(models.Model):
    _name = 'x.sync'

    def sync_now(self):
        return self.env['sale.order'].search([])
""",
        encoding="utf-8",
    )

    assert scan_scheduled_jobs(tmp_path) == []


def test_flags_xml_linked_cron_method_risks(tmp_path: Path) -> None:
    """Cron XML function names should make matching Python methods scheduled-job context."""
    data = tmp_path / "module" / "data"
    models = tmp_path / "module" / "models"
    data.mkdir(parents=True)
    models.mkdir(parents=True)
    (data / "cron.xml").write_text(
        """<odoo>
  <record id="cron_sync" model="ir.cron">
    <field name="function">fetch_partner_feed</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )
    (models / "partner.py").write_text(
        """
from odoo import models
import requests

class Partner(models.Model):
    _name = 'x.partner'

    def fetch_partner_feed(self):
        records = self.env['res.partner'].sudo().search([])
        requests.get(self.feed_url)
        records.sudo().write({'active': False})
        self.env.cr.commit()
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-scheduled-job-unbounded-search" in rule_ids
    assert "odoo-scheduled-job-sync-without-limit" in rule_ids
    assert "odoo-scheduled-job-http-no-timeout" in rule_ids
    assert "odoo-scheduled-job-sudo-mutation" in rule_ids
    assert "odoo-scheduled-job-manual-transaction" in rule_ids


def test_flags_csv_linked_cron_method_risks(tmp_path: Path) -> None:
    """Cron CSV function names should make matching Python methods scheduled-job context."""
    data = tmp_path / "module" / "data"
    models = tmp_path / "module" / "models"
    data.mkdir(parents=True)
    models.mkdir(parents=True)
    (data / "ir_cron.csv").write_text(
        "id,name,function\n"
        "cron_sync,Partner Sync,fetch_partner_feed\n",
        encoding="utf-8",
    )
    (models / "partner.py").write_text(
        """
from odoo import models
import requests

class Partner(models.Model):
    _name = 'x.partner'

    def fetch_partner_feed(self):
        records = self.env['res.partner'].sudo().search([])
        requests.get(self.feed_url)
        records.sudo().write({'active': False})
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-scheduled-job-unbounded-search" in rule_ids
    assert "odoo-scheduled-job-http-no-timeout" in rule_ids
    assert "odoo-scheduled-job-sudo-mutation" in rule_ids


def test_flags_cron_search_count_without_domain_or_limit(tmp_path: Path) -> None:
    """Recurring unbounded counts should be reviewed like unbounded reads."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def _cron_sync_order_totals(self):
        return self.env['sale.order'].sudo().search_count([])
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)
    unbounded = [finding for finding in findings if finding.rule_id == "odoo-scheduled-job-unbounded-search"]
    sync_without_limit = [
        finding for finding in findings if finding.rule_id == "odoo-scheduled-job-sync-without-limit"
    ]

    assert any(finding.severity == "medium" for finding in unbounded)
    assert sync_without_limit


def test_flags_cron_read_group_without_domain_or_limit(tmp_path: Path) -> None:
    """Recurring grouped reads still need batching when the domain is empty."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def _cron_sync_order_totals(self):
        return self.env['sale.order'].sudo().read_group([], ['amount_total:sum'], ['company_id'])
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)
    unbounded = [finding for finding in findings if finding.rule_id == "odoo-scheduled-job-unbounded-search"]
    sync_without_limit = [
        finding for finding in findings if finding.rule_id == "odoo-scheduled-job-sync-without-limit"
    ]

    assert any(finding.severity == "medium" and finding.sink.endswith(".read_group") for finding in unbounded)
    assert any(finding.sink.endswith(".read_group") for finding in sync_without_limit)


def test_flags_aliased_sudo_cron_mutation(tmp_path: Path) -> None:
    """Sudo-backed recordset aliases in cron methods should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def _cron_close_orders(self):
        orders = self.env['sale.order'].sudo().search([])
        orders.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-scheduled-job-unbounded-search" in rule_ids
    assert "odoo-scheduled-job-sudo-mutation" in rule_ids


def test_flags_with_user_superuser_cron_mutation(tmp_path: Path) -> None:
    """Superuser with_user mutations in cron methods should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class Sale(models.Model):
    _name = 'x.sale'

    def _cron_close_orders(self):
        self.env['sale.order'].with_user(SUPERUSER_ID).search([]).write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}
    unbounded = [finding for finding in findings if finding.rule_id == "odoo-scheduled-job-unbounded-search"]

    assert "odoo-scheduled-job-sudo-mutation" in rule_ids
    assert any(finding.severity == "medium" for finding in unbounded)


def test_flags_keyword_with_user_superuser_cron_mutation(tmp_path: Path) -> None:
    """Keyword with_user(uid=SUPERUSER_ID) cron mutations are elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class Sale(models.Model):
    _name = 'x.sale'

    def _cron_close_orders(self):
        self.env['sale.order'].with_user(uid=SUPERUSER_ID).search([]).write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}
    unbounded = [finding for finding in findings if finding.rule_id == "odoo-scheduled-job-unbounded-search"]

    assert "odoo-scheduled-job-sudo-mutation" in rule_ids
    assert any(finding.severity == "medium" for finding in unbounded)


def test_flags_aliased_with_user_one_cron_mutation(tmp_path: Path) -> None:
    """Aliased with_user(1) recordsets in cron methods should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def _cron_close_orders(self):
        orders = self.env['sale.order'].with_user(1).search([])
        orders.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-scheduled-job-unbounded-search" in rule_ids
    assert "odoo-scheduled-job-sudo-mutation" in rule_ids


def test_flags_constant_backed_with_user_cron_mutation(tmp_path: Path) -> None:
    """Constant-backed superuser IDs should not hide cron mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

ROOT_UID = 1

class Sale(models.Model):
    _name = 'x.sale'

    def _cron_close_orders(self):
        orders = self.env['sale.order'].with_user(ROOT_UID).search([])
        orders.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-scheduled-job-unbounded-search" in rule_ids
    assert "odoo-scheduled-job-sudo-mutation" in rule_ids


def test_flags_recursive_constant_backed_with_user_cron_mutation(tmp_path: Path) -> None:
    """Chained superuser ID aliases should not hide cron mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

ROOT_UID = 1
ADMIN_UID = ROOT_UID

class Sale(models.Model):
    _name = 'x.sale'

    def _cron_close_orders(self):
        orders = self.env['sale.order'].with_user(ADMIN_UID).search([])
        orders.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-scheduled-job-unbounded-search" in rule_ids
    assert "odoo-scheduled-job-sudo-mutation" in rule_ids


def test_flags_class_constant_backed_with_user_cron_mutation(tmp_path: Path) -> None:
    """Class-scoped superuser ID aliases should not hide cron mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'
    ROOT_UID = 1
    ADMIN_UID = ROOT_UID

    def _cron_close_orders(self):
        orders = self.env['sale.order'].with_user(ADMIN_UID).search([])
        orders.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-scheduled-job-unbounded-search" in rule_ids
    assert "odoo-scheduled-job-sudo-mutation" in rule_ids


def test_flags_env_ref_admin_cron_mutation(tmp_path: Path) -> None:
    """Aliased with_user(base.user_admin) recordsets in cron methods are elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def _cron_close_orders(self):
        orders = self.env['sale.order'].with_user(self.env.ref('base.user_admin')).search([])
        orders.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-scheduled-job-unbounded-search" in rule_ids
    assert "odoo-scheduled-job-sudo-mutation" in rule_ids


def test_flags_named_expression_sudo_cron_mutation(tmp_path: Path) -> None:
    """Walrus-bound sudo aliases in cron methods should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def _cron_close_orders(self):
        if orders := self.env['sale.order'].sudo().search([]):
            orders.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-scheduled-job-unbounded-search" in rule_ids
    assert "odoo-scheduled-job-sudo-mutation" in rule_ids


def test_flags_cron_named_method_without_xml(tmp_path: Path) -> None:
    """Conventional _cron methods should be scanned even when XML is not present."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "cleanup.py").write_text(
        """
from odoo import models

class Cleanup(models.Model):
    _name = 'x.cleanup'

    def _cron_cleanup(self):
        return safe_eval(self.expression)
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert any(f.rule_id == "odoo-scheduled-job-dynamic-eval" for f in findings)


def test_flags_cron_http_tls_verification_disabled(tmp_path: Path) -> None:
    """Recurring HTTP integrations should not disable TLS verification."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
from odoo import models
import requests

class Sync(models.Model):
    _name = 'x.sync'

    def _cron_sync_feed(self):
        return requests.get(self.feed_url, timeout=10, verify=False)
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert any(f.rule_id == "odoo-scheduled-job-tls-verify-disabled" for f in findings)


def test_flags_constant_backed_tls_verification_disabled(tmp_path: Path) -> None:
    """Constant-backed verify=False should still flag recurring HTTP integrations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
from odoo import models
import requests

TLS_VERIFY = False

class Sync(models.Model):
    _name = 'x.sync'

    def _cron_sync_feed(self):
        return requests.get(self.feed_url, timeout=10, verify=TLS_VERIFY)
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert any(f.rule_id == "odoo-scheduled-job-tls-verify-disabled" for f in findings)


def test_flags_recursive_constant_backed_tls_verification_disabled(tmp_path: Path) -> None:
    """Chained verify=False aliases should still flag recurring HTTP integrations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
from odoo import models
import requests

VERIFY_FALSE = False
TLS_VERIFY = VERIFY_FALSE

class Sync(models.Model):
    _name = 'x.sync'

    def _cron_sync_feed(self):
        return requests.get(self.feed_url, timeout=10, verify=TLS_VERIFY)
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert any(f.rule_id == "odoo-scheduled-job-tls-verify-disabled" for f in findings)


def test_flags_class_constant_backed_tls_verification_disabled(tmp_path: Path) -> None:
    """Class-scoped verify=False aliases should still flag recurring HTTP integrations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
from odoo import models
import requests

class Sync(models.Model):
    _name = 'x.sync'
    VERIFY_FALSE = False
    TLS_VERIFY = VERIFY_FALSE

    def _cron_sync_feed(self):
        return requests.get(self.feed_url, timeout=10, verify=TLS_VERIFY)
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert any(f.rule_id == "odoo-scheduled-job-tls-verify-disabled" for f in findings)


def test_flags_imported_http_function_without_timeout(tmp_path: Path) -> None:
    """Imported requests helpers should still count as outbound HTTP calls."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
from odoo import models
from requests import get as http_get

class Sync(models.Model):
    _name = 'x.sync'

    def _cron_sync_feed(self):
        return http_get(self.feed_url)
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert any(f.rule_id == "odoo-scheduled-job-http-no-timeout" for f in findings)


def test_flags_urllib_urlopen_without_timeout(tmp_path: Path) -> None:
    """Cron jobs should treat urllib.request.urlopen as outbound HTTP."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
from odoo import models
from urllib.request import urlopen
import urllib.request as urlreq

class Sync(models.Model):
    _name = 'x.sync'

    def _cron_sync_feed(self):
        urlopen(self.feed_url)
        return urlreq.urlopen(self.status_url, timeout=10)
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert sum(f.rule_id == "odoo-scheduled-job-http-no-timeout" for f in findings) == 1


def test_flags_urllib_request_import_alias_without_timeout(tmp_path: Path) -> None:
    """from urllib import request aliases should count as outbound HTTP."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
from odoo import models
from urllib import request as urlreq

class Sync(models.Model):
    _name = 'x.sync'

    def _cron_sync_feed(self):
        return urlreq.urlopen(self.feed_url)
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert any(f.rule_id == "odoo-scheduled-job-http-no-timeout" for f in findings)


def test_flags_http_module_alias_and_client_without_timeout(tmp_path: Path) -> None:
    """HTTP module aliases and session/client objects should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
from odoo import models
import requests as rq

class Sync(models.Model):
    _name = 'x.sync'

    def _cron_sync_feed(self):
        client = rq.Session()
        rq.post(self.feed_url, json={})
        return client.get(self.status_url)
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert sum(f.rule_id == "odoo-scheduled-job-http-no-timeout" for f in findings) == 2


def test_flags_aiohttp_client_session_context_without_timeout(tmp_path: Path) -> None:
    """Scheduled jobs should track aiohttp ClientSession context aliases."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
from odoo import models
import aiohttp

class Sync(models.Model):
    _name = 'x.sync'

    async def _cron_sync_feed(self):
        async with aiohttp.ClientSession() as client:
            await client.get(self.status_url)
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert any(f.rule_id == "odoo-scheduled-job-http-no-timeout" for f in findings)


def test_flags_head_without_timeout(tmp_path: Path) -> None:
    """Cron jobs should treat HEAD calls as outbound HTTP."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
from odoo import models
import httpx

class Sync(models.Model):
    _name = 'x.sync'

    def _cron_sync_feed(self):
        httpx.head(self.feed_url)
        return httpx.head(self.status_url, timeout=10)
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert sum(f.rule_id == "odoo-scheduled-job-http-no-timeout" for f in findings) == 1


def test_flags_http_timeout_none(tmp_path: Path) -> None:
    """Cron jobs should treat timeout=None as no effective HTTP timeout."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
from odoo import models
import requests

class Sync(models.Model):
    _name = 'x.sync'

    def _cron_sync_feed(self):
        return requests.post(self.feed_url, timeout=None)
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert any(f.rule_id == "odoo-scheduled-job-http-no-timeout" for f in findings)


def test_flags_http_constant_timeout_none(tmp_path: Path) -> None:
    """Cron jobs should resolve constants used for timeout values."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sync.py").write_text(
        """
from odoo import models
import requests

CRON_TIMEOUT = None

class Sync(models.Model):
    _name = 'x.sync'

    def _cron_sync_feed(self):
        return requests.post(self.feed_url, timeout=CRON_TIMEOUT)
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert any(f.rule_id == "odoo-scheduled-job-http-no-timeout" for f in findings)


def test_flags_tuple_unpacked_sudo_cron_mutation(tmp_path: Path) -> None:
    """Tuple-unpacked sudo aliases should still be recognized in cron methods."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def _cron_close_orders(self):
        orders, partner = self.env['sale.order'].sudo().search([]), self.env.user.partner_id
        orders.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert any(f.rule_id == "odoo-scheduled-job-sudo-mutation" for f in findings)


def test_flags_starred_rest_sudo_and_http_cron_aliases(tmp_path: Path) -> None:
    """Starred-rest sudo and HTTP aliases should still be recognized in cron methods."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models
import requests as rq

class Sale(models.Model):
    _name = 'x.sale'

    def _cron_close_orders(self):
        marker, *items, tail = 'x', self.env['sale.order'].sudo().search([]), rq.Session(), 'end'
        orders = items[0]
        client = items[1]
        orders.write({'state': 'done'})
        client.get(self.status_url)
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-scheduled-job-sudo-mutation" in rule_ids
    assert "odoo-scheduled-job-http-no-timeout" in rule_ids


def test_flags_sensitive_model_cron_mutation_without_sudo(tmp_path: Path) -> None:
    """Cron jobs mutating sensitive models deserve review even without inline sudo."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "identity.py").write_text(
        """
from odoo import models

class Identity(models.Model):
    _name = 'x.identity'

    def _cron_rotate_identity_state(self):
        self.env['res.users'].write({'active': False})
        self.env['ir.config_parameter'].set_param('auth.signup.allow_uninvited', 'False')
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)
    sensitive_mutations = [
        finding for finding in findings if finding.rule_id == "odoo-scheduled-job-sensitive-model-mutation"
    ]

    assert len(sensitive_mutations) == 2


def test_flags_constant_backed_sensitive_model_cron_mutation(tmp_path: Path) -> None:
    """Constant-backed env model names should still flag sensitive cron mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "identity.py").write_text(
        """
from odoo import models

USERS_MODEL = 'res.users'
CONFIG_MODEL = 'ir.config_parameter'

class Identity(models.Model):
    _name = 'x.identity'

    def _cron_rotate_identity_state(self):
        self.env[USERS_MODEL].write({'active': False})
        self.env[CONFIG_MODEL].set_param('auth.signup.allow_uninvited', 'False')
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert len(
        [finding for finding in findings if finding.rule_id == "odoo-scheduled-job-sensitive-model-mutation"]
    ) == 2


def test_flags_recursive_constant_backed_sensitive_model_cron_mutation(tmp_path: Path) -> None:
    """Chained env model-name aliases should still flag sensitive cron mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "identity.py").write_text(
        """
from odoo import models

USERS_MODEL = 'res.users'
TARGET_MODEL = USERS_MODEL

class Identity(models.Model):
    _name = 'x.identity'

    def _cron_rotate_identity_state(self):
        self.env[TARGET_MODEL].write({'active': False})
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert any(f.rule_id == "odoo-scheduled-job-sensitive-model-mutation" for f in findings)


def test_flags_class_constant_backed_sensitive_model_cron_mutation(tmp_path: Path) -> None:
    """Class-scoped env model-name aliases should still flag sensitive cron mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "identity.py").write_text(
        """
from odoo import models

class Identity(models.Model):
    _name = 'x.identity'
    USERS_MODEL = 'res.users'
    TARGET_MODEL = USERS_MODEL
    PARAMS_MODEL = 'ir.config_parameter'
    CONFIG_MODEL = PARAMS_MODEL

    def _cron_rotate_identity_state(self):
        self.env[TARGET_MODEL].write({'active': False})
        self.env[CONFIG_MODEL].set_param('auth.signup.allow_uninvited', 'False')
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)
    sensitive_mutations = [
        finding for finding in findings if finding.rule_id == "odoo-scheduled-job-sensitive-model-mutation"
    ]

    assert len(sensitive_mutations) == 2


def test_does_not_overtaint_mixed_tuple_cron_aliases(tmp_path: Path) -> None:
    """Mixed tuple assignments should not taint non-sudo or non-client neighbors."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models
import requests as rq

class Sale(models.Model):
    _name = 'x.sale'

    def _cron_close_orders(self):
        orders, partner = self.env['sale.order'].sudo(), self.env.user.partner_id
        client, callback = rq.Session(), self.callback
        partner.write({'comment': 'x'})
        callback.post(self.callback_url)
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert not any(f.rule_id == "odoo-scheduled-job-sudo-mutation" for f in findings)
    assert not any(f.rule_id == "odoo-scheduled-job-http-no-timeout" for f in findings)


def test_code_field_method_reference_is_collected(tmp_path: Path) -> None:
    """Cron code fields commonly call model.method(); collect that method name."""
    data = tmp_path / "module" / "data"
    models = tmp_path / "module" / "models"
    data.mkdir(parents=True)
    models.mkdir(parents=True)
    (data / "cron.xml").write_text(
        """<odoo>
  <record id="cron_sync" model="ir.cron">
    <field name="state">code</field>
    <field name="code">model.sync_now()</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )
    (models / "sync.py").write_text(
        """
from odoo import models

class Sync(models.Model):
    _name = 'x.sync'

    def sync_now(self):
        return self.env['sale.order'].search([])
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert any(f.rule_id == "odoo-scheduled-job-unbounded-search" for f in findings)


def test_csv_code_field_method_reference_is_collected(tmp_path: Path) -> None:
    """Cron CSV code fields commonly call model.method(); collect that method name."""
    data = tmp_path / "module" / "data"
    models = tmp_path / "module" / "models"
    data.mkdir(parents=True)
    models.mkdir(parents=True)
    (data / "ir.cron.csv").write_text(
        "id,name,state,code\n"
        "cron_sync,Sync,code,model.sync_now()\n",
        encoding="utf-8",
    )
    (models / "sync.py").write_text(
        """
from odoo import models

class Sync(models.Model):
    _name = 'x.sync'

    def sync_now(self):
        return self.env['sale.order'].search([])
""",
        encoding="utf-8",
    )

    findings = scan_scheduled_jobs(tmp_path)

    assert any(f.rule_id == "odoo-scheduled-job-unbounded-search" for f in findings)


def test_batched_cron_method_is_ignored(tmp_path: Path) -> None:
    """Batch-limited scheduled searches should not trigger unbounded-search rules."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "safe.py").write_text(
        """
from odoo import models
import requests

class Safe(models.Model):
    _name = 'x.safe'

    def _cron_sync_batch(self):
        records = self.search([], limit=100)
        requests.get(self.url, timeout=10)
        return records
""",
        encoding="utf-8",
    )

    assert scan_scheduled_jobs(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_cron.py").write_text(
        """
class Cron(models.Model):
    def _cron_cleanup(self):
        self.sudo().unlink()
""",
        encoding="utf-8",
    )

    assert scan_scheduled_jobs(tmp_path) == []
