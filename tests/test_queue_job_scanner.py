"""Tests for queue_job/delayed-job scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.queue_job_scanner import scan_queue_jobs


def test_flags_queue_job_sudo_mutation_eval_and_http_no_timeout(tmp_path: Path) -> None:
    """Decorated queue jobs should be scanned for privileged unsafe work."""
    module = tmp_path / "module" / "models"
    module.mkdir(parents=True)
    (module / "jobs.py").write_text(
        """
from odoo.addons.queue_job.job import job
import requests

class SaleJob(models.Model):
    @job
    def sync_queue(self, record):
        record.sudo().write({'state': 'done'})
        safe_eval(record.expression)
        requests.post(record.callback_url)
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-queue-job-sudo-mutation" in rule_ids
    assert "odoo-queue-job-dynamic-eval" in rule_ids
    assert "odoo-queue-job-http-no-timeout" in rule_ids


def test_flags_queue_job_aliases_for_sudo_and_http(tmp_path: Path) -> None:
    """Queue jobs should track sudo, HTTP module, and client aliases."""
    module = tmp_path / "module" / "models"
    module.mkdir(parents=True)
    (module / "jobs.py").write_text(
        """
from odoo.addons.queue_job.job import job
from requests import post as http_post
import requests as rq

class SaleJob(models.Model):
    @job
    def sync_queue(self, record):
        orders, client = record.sudo(), rq.Session()
        orders.write({'state': 'done'})
        rq.get(record.status_url)
        http_post(record.callback_url)
        client.delete(record.cleanup_url)
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-queue-job-sudo-mutation" in rule_ids
    assert sum(f.rule_id == "odoo-queue-job-http-no-timeout" for f in findings) == 3


def test_flags_queue_job_aiohttp_client_session_context(tmp_path: Path) -> None:
    """Queue jobs should track aiohttp ClientSession context aliases."""
    module = tmp_path / "module" / "models"
    module.mkdir(parents=True)
    (module / "jobs.py").write_text(
        """
from odoo.addons.queue_job.job import job
import aiohttp

class SaleJob(models.Model):
    @job
    async def sync_queue(self, record):
        async with aiohttp.ClientSession() as client:
            await client.post(record.callback_url)
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)

    assert any(f.rule_id == "odoo-queue-job-http-no-timeout" for f in findings)


def test_flags_queue_job_with_user_superuser_mutation(tmp_path: Path) -> None:
    """Queue jobs should treat with_user(SUPERUSER_ID) mutations as elevated."""
    module = tmp_path / "module" / "models"
    module.mkdir(parents=True)
    (module / "jobs.py").write_text(
        """
from odoo import SUPERUSER_ID
from odoo.addons.queue_job.job import job

class SaleJob(models.Model):
    @job
    def sync_queue(self, record):
        record.with_user(SUPERUSER_ID).write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-queue-job-sudo-mutation" in rule_ids


def test_flags_queue_job_keyword_with_user_superuser_mutation(tmp_path: Path) -> None:
    """Queue jobs should treat keyword with_user(uid=SUPERUSER_ID) as elevated."""
    module = tmp_path / "module" / "models"
    module.mkdir(parents=True)
    (module / "jobs.py").write_text(
        """
from odoo import SUPERUSER_ID
from odoo.addons.queue_job.job import job

class SaleJob(models.Model):
    @job
    def sync_queue(self, record):
        record.with_user(uid=SUPERUSER_ID).write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-queue-job-sudo-mutation" in rule_ids


def test_flags_queue_job_aliased_with_user_one_mutation(tmp_path: Path) -> None:
    """Queue jobs should track with_user(1) aliases as elevated."""
    module = tmp_path / "module" / "models"
    module.mkdir(parents=True)
    (module / "jobs.py").write_text(
        """
from odoo.addons.queue_job.job import job

class SaleJob(models.Model):
    @job
    def sync_queue(self, record):
        orders = record.with_user(1)
        orders.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-queue-job-sudo-mutation" in rule_ids


def test_flags_queue_job_recursive_constant_with_user_mutation(tmp_path: Path) -> None:
    """Chained superuser ID aliases should not hide elevated queue mutations."""
    module = tmp_path / "module" / "models"
    module.mkdir(parents=True)
    (module / "jobs.py").write_text(
        """
from odoo.addons.queue_job.job import job

ROOT_UID = 1
ADMIN_UID = ROOT_UID

class SaleJob(models.Model):
    @job
    def sync_queue(self, record):
        orders = record.with_user(ADMIN_UID)
        orders.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-queue-job-sudo-mutation" in rule_ids


def test_flags_queue_job_class_constant_with_user_mutation(tmp_path: Path) -> None:
    """Class-scoped superuser aliases should not hide elevated queue mutations."""
    module = tmp_path / "module" / "models"
    module.mkdir(parents=True)
    (module / "jobs.py").write_text(
        """
from odoo.addons.queue_job.job import job

class SaleJob(models.Model):
    ROOT_UID = 1
    ADMIN_UID = ROOT_UID

    @job
    def sync_queue(self, record):
        orders = record.with_user(ADMIN_UID)
        orders.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-queue-job-sudo-mutation" in rule_ids


def test_flags_queue_job_env_ref_root_mutation(tmp_path: Path) -> None:
    """Queue jobs should track with_user(base.user_root) aliases as elevated."""
    module = tmp_path / "module" / "models"
    module.mkdir(parents=True)
    (module / "jobs.py").write_text(
        """
from odoo.addons.queue_job.job import job

class SaleJob(models.Model):
    @job
    def sync_queue(self, record):
        orders = record.with_user(self.env.ref('base.user_root'))
        orders.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-queue-job-sudo-mutation" in rule_ids


def test_flags_queue_job_named_expression_aliases_for_sudo_and_http(tmp_path: Path) -> None:
    """Queue jobs should track walrus-bound sudo and HTTP client aliases."""
    module = tmp_path / "module" / "models"
    module.mkdir(parents=True)
    (module / "jobs.py").write_text(
        """
from odoo.addons.queue_job.job import job
import requests as rq

class SaleJob(models.Model):
    @job
    def sync_queue(self, record):
        if orders := record.sudo():
            orders.write({'state': 'done'})
        if client := rq.Session():
            client.delete(record.cleanup_url)
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-queue-job-sudo-mutation" in rule_ids
    assert "odoo-queue-job-http-no-timeout" in rule_ids


def test_flags_queue_job_starred_rest_aliases_for_sudo_and_http(tmp_path: Path) -> None:
    """Queue jobs should track starred-rest sudo and HTTP client aliases."""
    module = tmp_path / "module" / "models"
    module.mkdir(parents=True)
    (module / "jobs.py").write_text(
        """
from odoo.addons.queue_job.job import job
import requests as rq

class SaleJob(models.Model):
    @job
    def sync_queue(self, record):
        marker, *items, tail = 'x', record.sudo(), rq.Session(), 'end'
        orders = items[0]
        client = items[1]
        orders.write({'state': 'done'})
        client.delete(record.cleanup_url)
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-queue-job-sudo-mutation" in rule_ids
    assert "odoo-queue-job-http-no-timeout" in rule_ids


def test_does_not_overtaint_mixed_tuple_queue_aliases(tmp_path: Path) -> None:
    """Mixed tuple assignments should not taint non-sudo or non-client neighbors."""
    module = tmp_path / "module" / "models"
    module.mkdir(parents=True)
    (module / "jobs.py").write_text(
        """
from odoo.addons.queue_job.job import job
import requests as rq

class SaleJob(models.Model):
    @job
    def sync_queue(self, record):
        orders, partner = record.sudo(), record.partner_id
        client, callback = rq.Session(), record.callback
        partner.write({'comment': 'x'})
        callback.post(record.callback_url)
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)

    assert not any(f.rule_id == "odoo-queue-job-sudo-mutation" for f in findings)
    assert not any(f.rule_id == "odoo-queue-job-http-no-timeout" for f in findings)


def test_flags_queue_job_urllib_urlopen_without_timeout(tmp_path: Path) -> None:
    """Queue jobs should treat urllib.request.urlopen as outbound HTTP."""
    module = tmp_path / "module" / "models"
    module.mkdir(parents=True)
    (module / "jobs.py").write_text(
        """
from odoo.addons.queue_job.job import job
from urllib.request import urlopen
import urllib.request as urlreq

class SaleJob(models.Model):
    @job
    def sync_queue(self, record):
        urlopen(record.callback_url)
        urlreq.urlopen(record.status_url, timeout=10)
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)

    assert sum(f.rule_id == "odoo-queue-job-http-no-timeout" for f in findings) == 1


def test_flags_sensitive_model_queue_mutation_without_sudo(tmp_path: Path) -> None:
    """Queue jobs mutating sensitive models deserve review even without inline sudo."""
    module = tmp_path / "module" / "models"
    module.mkdir(parents=True)
    (module / "jobs.py").write_text(
        """
from odoo.addons.queue_job.job import job

class IdentityJob(models.Model):
    @job
    def sync_queue(self, payload):
        self.env['res.users'].write({'active': False})
        self.env['ir.config_parameter'].set_param('auth.signup.allow_uninvited', 'False')
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)
    sensitive_mutations = [
        finding for finding in findings if finding.rule_id == "odoo-queue-job-sensitive-model-mutation"
    ]

    assert len(sensitive_mutations) == 2


def test_flags_constant_backed_sensitive_model_queue_mutation(tmp_path: Path) -> None:
    """Constant-backed env model names should still flag sensitive queue mutations."""
    module = tmp_path / "module" / "models"
    module.mkdir(parents=True)
    (module / "jobs.py").write_text(
        """
from odoo.addons.queue_job.job import job

USERS_MODEL = 'res.users'
TARGET_MODEL = USERS_MODEL

class IdentityJob(models.Model):
    @job
    def sync_queue(self, payload):
        self.env[TARGET_MODEL].write({'active': False})
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)

    assert any(f.rule_id == "odoo-queue-job-sensitive-model-mutation" for f in findings)


def test_flags_class_constant_backed_sensitive_model_queue_mutation(tmp_path: Path) -> None:
    """Class-scoped env model names should still flag sensitive queue mutations."""
    module = tmp_path / "module" / "models"
    module.mkdir(parents=True)
    (module / "jobs.py").write_text(
        """
from odoo.addons.queue_job.job import job

class IdentityJob(models.Model):
    USERS_MODEL = 'res.users'
    TARGET_MODEL = USERS_MODEL

    @job
    def sync_queue(self, payload):
        self.env[TARGET_MODEL].write({'active': False})
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)

    assert any(f.rule_id == "odoo-queue-job-sensitive-model-mutation" for f in findings)


def test_flags_public_route_enqueue_without_identity_key(tmp_path: Path) -> None:
    """Public route enqueue sites need idempotency and abuse review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/sync', auth='public', csrf=False)
    def sync(self, **kwargs):
        self.env['sale.order'].with_delay().sync_order(kwargs.get('id'))
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-queue-job-missing-identity-key" in rule_ids
    assert "odoo-queue-job-public-enqueue" in rule_ids


def test_constant_backed_public_route_enqueue_without_identity_key(tmp_path: Path) -> None:
    """Constant-backed public route auth should not hide public queue enqueue sites."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http

SYNC_ROUTE = '/sync'
SYNC_AUTH = 'public'

class Controller(http.Controller):
    @http.route(SYNC_ROUTE, auth=SYNC_AUTH, csrf=False)
    def sync(self, **kwargs):
        self.env['sale.order'].with_delay().sync_order(kwargs.get('id'))
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-queue-job-missing-identity-key" in rule_ids
    assert "odoo-queue-job-public-enqueue" in rule_ids


def test_recursive_constant_backed_public_route_enqueue_without_identity_key(tmp_path: Path) -> None:
    """Chained public route auth constants should not hide public queue enqueue sites."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http

PUBLIC_AUTH = 'public'
SYNC_AUTH = PUBLIC_AUTH

class Controller(http.Controller):
    @http.route('/sync', auth=SYNC_AUTH, csrf=False)
    def sync(self, **kwargs):
        self.env['sale.order'].with_delay().sync_order(kwargs.get('id'))
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-queue-job-missing-identity-key" in rule_ids
    assert "odoo-queue-job-public-enqueue" in rule_ids


def test_class_constant_static_unpack_public_route_enqueue_without_identity_key(tmp_path: Path) -> None:
    """Class-scoped route option unpacking should keep public queue enqueue context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http

class Controller(http.Controller):
    SYNC_ROUTE = '/sync'
    SYNC_AUTH = 'public'
    ROUTE_OPTIONS = {'route': SYNC_ROUTE, 'auth': SYNC_AUTH, 'csrf': False}

    @http.route(**ROUTE_OPTIONS)
    def sync(self, **kwargs):
        self.env['sale.order'].with_delay().sync_order(kwargs.get('id'))
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-queue-job-missing-identity-key" in rule_ids
    assert "odoo-queue-job-public-enqueue" in rule_ids


def test_flags_imported_route_decorator_public_enqueue(tmp_path: Path) -> None:
    """Directly imported route decorators should keep public route context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import route

class Controller(http.Controller):
    @route('/sync', auth='public', csrf=False)
    def sync(self, **kwargs):
        self.env['sale.order'].with_delay().sync_order(kwargs.get('id'))
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-queue-job-missing-identity-key" in rule_ids
    assert "odoo-queue-job-public-enqueue" in rule_ids


def test_flags_public_route_chained_enqueue_without_identity_key(tmp_path: Path) -> None:
    """Calls chained after with_delay should still be treated as enqueue sites."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http

class Controller(http.Controller):
    @http.route('/sync', auth='public', csrf=False)
    def sync(self, **kwargs):
        self.env['sale.order'].with_delay(priority=5).sync_order(kwargs.get('id'))
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-queue-job-missing-identity-key" in rule_ids
    assert "odoo-queue-job-public-enqueue" in rule_ids


def test_identity_key_suppresses_duplicate_enqueue_finding(tmp_path: Path) -> None:
    """Enqueue sites with identity_key should avoid duplicate-job noise."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
def enqueue(record):
    record.with_delay(identity_key='sale:%s' % record.id).sync_order()
""",
        encoding="utf-8",
    )

    findings = scan_queue_jobs(tmp_path)

    assert not any(f.rule_id == "odoo-queue-job-missing-identity-key" for f in findings)


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Queue fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_jobs.py").write_text(
        """
def enqueue(record):
    record.with_delay().sync_order()
""",
        encoding="utf-8",
    )

    assert scan_queue_jobs(tmp_path) == []
