"""Tests for loose Python and server-action scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.server_action_scanner import LoosePythonScanner, scan_loose_python


def test_xml_entities_are_not_expanded_into_server_action_findings(tmp_path: Path) -> None:
    """XML entities must not synthesize loose Python server action findings."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "server_actions.xml").write_text(
        """<!DOCTYPE odoo [
<!ENTITY action_state "code">
]>
<odoo>
  <record id="action_entity" model="ir.actions.server">
    <field name="state">&action_state;</field>
    <field name="code">eval(record.expression)</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_loose_python(tmp_path) == []


def test_server_action_detects_interpolated_sql(tmp_path: Path) -> None:
    """Server-action SQL should not be built through interpolation."""
    script = tmp_path / "cleanup.py"
    script.write_text(
        """
query = "DELETE FROM %s" % model_name
env.cr.execute(query)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-sql-injection" for f in findings)


def test_server_action_tracks_unpacked_interpolated_sql(tmp_path: Path) -> None:
    """Tuple-unpacked SQL variables should still be considered unsafe."""
    script = tmp_path / "cleanup.py"
    script.write_text(
        """
query, params = "DELETE FROM %s" % model_name, []
env.cr.execute(query)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-sql-injection" for f in findings)


def test_server_action_tracks_starred_rest_sql_alias(tmp_path: Path) -> None:
    """Starred-rest SQL aliases should still be considered unsafe."""
    script = tmp_path / "cleanup.py"
    script.write_text(
        """
marker, *items, tail = "x", "DELETE FROM %s" % model_name, [], "end"
query = items[0]
env.cr.execute(query)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-sql-injection" for f in findings)


def test_server_action_reassigned_sql_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned SQL aliases should not keep unsafe interpolation state."""
    script = tmp_path / "cleanup.py"
    script.write_text(
        """
query = "DELETE FROM %s" % model_name
query = "SELECT 1"
env.cr.execute(query)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert not any(f.rule_id == "odoo-loose-python-sql-injection" for f in findings)


def test_server_action_tracks_annotated_interpolated_sql(tmp_path: Path) -> None:
    """Annotated SQL variables should still be considered unsafe."""
    script = tmp_path / "cleanup.py"
    script.write_text(
        """
query: str = "DELETE FROM %s" % model_name
env.cr.execute(query)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-sql-injection" for f in findings)


def test_server_action_annotated_reassigned_sql_alias_is_not_stale(tmp_path: Path) -> None:
    """Annotated SQL aliases should clear when rebound to safe values."""
    script = tmp_path / "cleanup.py"
    script.write_text(
        """
query: str = "DELETE FROM %s" % model_name
query: str = "SELECT 1"
env.cr.execute(query)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert not any(f.rule_id == "odoo-loose-python-sql-injection" for f in findings)


def test_server_action_tracks_walrus_interpolated_sql(tmp_path: Path) -> None:
    """Assignment-expression SQL aliases should still be considered unsafe."""
    script = tmp_path / "cleanup.py"
    script.write_text(
        """
if query := "DELETE FROM %s" % model_name:
    env.cr.execute(query)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-sql-injection" for f in findings)


def test_server_action_detects_eval_and_safe_eval(tmp_path: Path) -> None:
    """Dynamic evaluation in server actions needs explicit review."""
    script = tmp_path / "action.py"
    script.write_text(
        """
result = eval(record.expression)
value = safe_eval(record.domain)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-loose-python-eval-exec" in rule_ids
    assert "odoo-loose-python-safe-eval" in rule_ids


def test_server_action_detects_aliased_safe_eval(tmp_path: Path) -> None:
    """Imported safe_eval aliases should still be treated as dynamic evaluation."""
    script = tmp_path / "action.py"
    script.write_text(
        """
from odoo.tools.safe_eval import safe_eval as run_eval

value = run_eval(record.domain)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-safe-eval" for f in findings)


def test_server_action_detects_sudo_write_and_manual_commit(tmp_path: Path) -> None:
    """Privileged mutation and manual transactions are review leads."""
    script = tmp_path / "action.py"
    script.write_text(
        """
records.sudo().write({'state': 'done'})
env.cr.commit()
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-loose-python-sudo-write" in rule_ids
    assert "odoo-loose-python-manual-transaction" in rule_ids


def test_server_action_detects_superuser_write(tmp_path: Path) -> None:
    """with_user(SUPERUSER_ID) mutations should be treated as privileged writes."""
    script = tmp_path / "action.py"
    script.write_text(
        """
from odoo import SUPERUSER_ID

records.with_user(SUPERUSER_ID).write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-sudo-write" for f in findings)


def test_server_action_detects_aliased_import_superuser_write(tmp_path: Path) -> None:
    """with_user imported SUPERUSER_ID aliases should be treated as privileged writes."""
    script = tmp_path / "action.py"
    script.write_text(
        """
from odoo import SUPERUSER_ID as ROOT_UID

records.with_user(ROOT_UID).write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-sudo-write" for f in findings)


def test_server_action_detects_constant_backed_superuser_write(tmp_path: Path) -> None:
    """with_user constants should be treated as privileged writes."""
    script = tmp_path / "action.py"
    script.write_text(
        """
ROOT_UID = 1

elevated = records.with_user(ROOT_UID)
elevated.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-sudo-write" for f in findings)


def test_server_action_detects_recursive_constant_superuser_write(tmp_path: Path) -> None:
    """Recursive with_user constants should be treated as privileged writes."""
    script = tmp_path / "action.py"
    script.write_text(
        """
from odoo import SUPERUSER_ID

ROOT_UID = SUPERUSER_ID
ADMIN_UID = ROOT_UID

records.with_user(ADMIN_UID).write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-sudo-write" for f in findings)


def test_server_action_detects_class_constant_superuser_write(tmp_path: Path) -> None:
    """Class-scoped with_user constants should be treated as privileged writes."""
    script = tmp_path / "action.py"
    script.write_text(
        """
class ActionHelper:
    ROOT_UID = 1
    ADMIN_UID = ROOT_UID

    def run(self, records):
        elevated = records.with_user(ADMIN_UID)
        elevated.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-sudo-write" for f in findings)


def test_server_action_detects_keyword_superuser_write(tmp_path: Path) -> None:
    """Keyword with_user(uid=SUPERUSER_ID) mutations are privileged writes."""
    script = tmp_path / "action.py"
    script.write_text(
        """
from odoo import SUPERUSER_ID

records.with_user(uid=SUPERUSER_ID).write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-sudo-write" for f in findings)


def test_server_action_detects_aliased_superuser_write(tmp_path: Path) -> None:
    """with_user(1) aliases should keep privileged mutation state."""
    script = tmp_path / "action.py"
    script.write_text(
        """
elevated = records.with_user(1)
elevated.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-sudo-write" for f in findings)


def test_server_action_detects_sudo_business_method_call(tmp_path: Path) -> None:
    """Workflow methods called through sudo should stand out from normal ORM reads."""
    script = tmp_path / "action.py"
    script.write_text(
        """
records.sudo().action_confirm()
records.sudo().mapped('name')
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()
    method_findings = [f for f in findings if f.rule_id == "odoo-loose-python-sudo-method-call"]

    assert len(method_findings) == 1
    assert method_findings[0].line == 2


def test_server_action_detects_aliased_superuser_business_method_call(tmp_path: Path) -> None:
    """with_user(SUPERUSER_ID) aliases should flag privileged workflow methods."""
    script = tmp_path / "action.py"
    script.write_text(
        """
from odoo import SUPERUSER_ID

elevated = pickings.with_user(SUPERUSER_ID)
elevated.button_validate()
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-sudo-method-call" for f in findings)


def test_server_action_detects_annotated_aliased_superuser_write(tmp_path: Path) -> None:
    """Annotated with_user(1) aliases should keep privileged mutation state."""
    script = tmp_path / "action.py"
    script.write_text(
        """
elevated: object = records.with_user(1)
elevated.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-sudo-write" for f in findings)


def test_server_action_detects_walrus_aliased_superuser_write(tmp_path: Path) -> None:
    """Assignment-expression with_user(1) aliases should keep privileged mutation state."""
    script = tmp_path / "action.py"
    script.write_text(
        """
if elevated := records.with_user(1):
    elevated.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-sudo-write" for f in findings)


def test_server_action_detects_env_ref_root_write(tmp_path: Path) -> None:
    """with_user(base.user_root) aliases should keep privileged mutation state."""
    script = tmp_path / "action.py"
    script.write_text(
        """
elevated = records.with_user(env.ref('base.user_root'))
elevated.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-sudo-write" for f in findings)


def test_server_action_reassigned_superuser_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned elevated aliases should not keep stale privileged-write state."""
    script = tmp_path / "action.py"
    script.write_text(
        """
elevated = records.with_user(1)
elevated = records
elevated.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert not any(f.rule_id == "odoo-loose-python-sudo-write" for f in findings)


def test_server_action_annotated_reassigned_superuser_alias_is_not_stale(tmp_path: Path) -> None:
    """Annotated elevated aliases should clear on normal-recordset rebinds."""
    script = tmp_path / "action.py"
    script.write_text(
        """
elevated: object = records.with_user(1)
elevated: object = records
elevated.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert not any(f.rule_id == "odoo-loose-python-sudo-write" for f in findings)


def test_server_action_detects_sensitive_model_mutation(tmp_path: Path) -> None:
    """Loose server action scripts mutating security-sensitive models should stand out."""
    script = tmp_path / "action.py"
    script.write_text(
        """
env['res.users'].write({'active': False})
env['ir.config_parameter'].set_param('auth.signup.allow_uninvited', 'False')
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()
    sensitive_mutations = [
        finding for finding in findings if finding.rule_id == "odoo-loose-python-sensitive-model-mutation"
    ]

    assert len(sensitive_mutations) == 2


def test_server_action_detects_constant_backed_sensitive_model_mutation(tmp_path: Path) -> None:
    """Sensitive model mutation should resolve env[...] constants."""
    script = tmp_path / "action.py"
    script.write_text(
        """
USERS_MODEL = 'res.users'
CONFIG_MODEL = 'ir.config_parameter'

env[USERS_MODEL].write({'active': False})
env[CONFIG_MODEL].set_param('auth.signup.allow_uninvited', 'False')
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()
    sensitive_mutations = [
        finding for finding in findings if finding.rule_id == "odoo-loose-python-sensitive-model-mutation"
    ]

    assert len(sensitive_mutations) == 2


def test_server_action_detects_recursive_constant_sensitive_model_mutation(tmp_path: Path) -> None:
    """Sensitive model mutation should resolve recursive env[...] constants."""
    script = tmp_path / "action.py"
    script.write_text(
        """
USERS_MODEL = 'res.users'
TARGET_MODEL = USERS_MODEL
PARAMS_MODEL = 'ir.config_parameter'
CONFIG_MODEL = PARAMS_MODEL

env[TARGET_MODEL].write({'active': False})
env[CONFIG_MODEL].set_param('auth.signup.allow_uninvited', 'False')
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()
    sensitive_mutations = [
        finding for finding in findings if finding.rule_id == "odoo-loose-python-sensitive-model-mutation"
    ]

    assert len(sensitive_mutations) == 2


def test_server_action_detects_class_constant_sensitive_model_mutation(tmp_path: Path) -> None:
    """Sensitive model mutation should resolve class-scoped env[...] constants."""
    script = tmp_path / "action.py"
    script.write_text(
        """
class ActionHelper:
    USERS_MODEL = 'res.users'
    TARGET_MODEL = USERS_MODEL
    PARAMS_MODEL = 'ir.config_parameter'
    CONFIG_MODEL = PARAMS_MODEL

    def run(self, env):
        env[TARGET_MODEL].write({'active': False})
        env[CONFIG_MODEL].set_param('auth.signup.allow_uninvited', 'False')
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()
    sensitive_mutations = [
        finding for finding in findings if finding.rule_id == "odoo-loose-python-sensitive-model-mutation"
    ]

    assert len(sensitive_mutations) == 2


def test_server_action_detects_http_without_timeout(tmp_path: Path) -> None:
    """Outbound HTTP in loose Python should set explicit timeouts."""
    script = tmp_path / "action.py"
    script.write_text(
        """
import requests

requests.post(record.callback_url, json={'id': record.id})
requests.get(record.health_url, timeout=10)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()
    http_findings = [f for f in findings if f.rule_id == "odoo-loose-python-http-no-timeout"]

    assert len(http_findings) == 1
    assert http_findings[0].line == 4


def test_server_action_detects_aliased_requests_without_timeout(tmp_path: Path) -> None:
    """Aliased requests imports should still require explicit timeouts."""
    script = tmp_path / "action.py"
    script.write_text(
        """
import requests as rq

rq.post(record.callback_url, json={'id': record.id})
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-http-no-timeout" for f in findings)


def test_server_action_detects_imported_http_function_without_timeout(tmp_path: Path) -> None:
    """Imported HTTP function aliases should still require explicit timeouts."""
    script = tmp_path / "action.py"
    script.write_text(
        """
from requests import post as http_post

http_post(record.callback_url, json={'id': record.id})
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-http-no-timeout" for f in findings)


def test_server_action_detects_urllib_request_import_alias_without_timeout(tmp_path: Path) -> None:
    """from urllib import request aliases should still require explicit timeouts."""
    script = tmp_path / "action.py"
    script.write_text(
        """
from urllib import request as urlreq

urlreq.urlopen(record.callback_url)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-http-no-timeout" for f in findings)


def test_server_action_detects_httpx_client_without_timeout(tmp_path: Path) -> None:
    """httpx client calls should also require timeout review."""
    script = tmp_path / "action.py"
    script.write_text(
        """
import httpx

client = httpx.Client()
client.get(record.callback_url)
httpx.post(record.callback_url, timeout=10)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-http-no-timeout" for f in findings)


def test_server_action_detects_aliased_httpx_client_without_timeout(tmp_path: Path) -> None:
    """Aliased httpx client constructors should still require timeout review."""
    script = tmp_path / "action.py"
    script.write_text(
        """
import httpx as hx

client = hx.Client()
client.get(record.callback_url)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-http-no-timeout" for f in findings)


def test_server_action_detects_aiohttp_client_session_context_without_timeout(tmp_path: Path) -> None:
    """aiohttp ClientSession context aliases should still require timeout review."""
    script = tmp_path / "action.py"
    script.write_text(
        """
import aiohttp

async def sync():
    async with aiohttp.ClientSession() as client:
        await client.get(record.callback_url)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-http-no-timeout" for f in findings)


def test_server_action_detects_aiohttp_module_call_without_timeout(tmp_path: Path) -> None:
    """Direct aiohttp module calls should require explicit timeouts."""
    script = tmp_path / "action.py"
    script.write_text(
        """
import aiohttp as ah

async def sync():
    await ah.request("GET", record.callback_url)
    await ah.get(record.health_url, timeout=10)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()
    http_findings = [f for f in findings if f.rule_id == "odoo-loose-python-http-no-timeout"]

    assert len(http_findings) == 1
    assert http_findings[0].line == 5


def test_server_action_detects_head_without_timeout(tmp_path: Path) -> None:
    """Loose Python should treat HEAD calls as outbound HTTP."""
    script = tmp_path / "action.py"
    script.write_text(
        """
import requests

requests.head(record.callback_url)
requests.head(record.health_url, timeout=10)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()
    http_findings = [f for f in findings if f.rule_id == "odoo-loose-python-http-no-timeout"]

    assert len(http_findings) == 1
    assert http_findings[0].line == 4


def test_server_action_detects_http_timeout_none(tmp_path: Path) -> None:
    """Loose Python should treat timeout=None as no effective HTTP timeout."""
    script = tmp_path / "action.py"
    script.write_text(
        """
import requests

requests.post(record.callback_url, timeout=None)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-http-no-timeout" for f in findings)


def test_server_action_static_kwargs_timeout_is_not_reported(tmp_path: Path) -> None:
    """Static **kwargs dictionaries should satisfy loose Python HTTP timeout checks."""
    script = tmp_path / "action.py"
    script.write_text(
        """
import requests

HTTP_OPTIONS = {'timeout': 10}

requests.post(record.callback_url, **HTTP_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert not any(f.rule_id == "odoo-loose-python-http-no-timeout" for f in findings)


def test_server_action_detects_tls_verification_disabled(tmp_path: Path) -> None:
    """Loose Python outbound HTTP should not disable TLS verification."""
    script = tmp_path / "action.py"
    script.write_text(
        """
import requests

TLS_VERIFY = False
requests.post(record.callback_url, timeout=10, verify=TLS_VERIFY)
requests.get(record.health_url, timeout=10, verify=True)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()
    tls_findings = [f for f in findings if f.rule_id == "odoo-loose-python-tls-verify-disabled"]

    assert len(tls_findings) == 1
    assert tls_findings[0].line == 5


def test_server_action_static_kwargs_tls_verify_disabled(tmp_path: Path) -> None:
    """Loose Python should flag verify=False from static **kwargs."""
    script = tmp_path / "action.py"
    script.write_text(
        """
import requests

HTTP_OPTIONS = {'timeout': 10, 'verify': False}

requests.post(record.callback_url, **HTTP_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-tls-verify-disabled" for f in findings)


def test_server_action_tracks_starred_rest_http_client_alias(tmp_path: Path) -> None:
    """Starred-rest HTTP client aliases should still require timeouts."""
    script = tmp_path / "action.py"
    script.write_text(
        """
import httpx

marker, *items, tail = "x", httpx.Client(), object(), "end"
client = items[0]
client.get(record.callback_url)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-http-no-timeout" for f in findings)


def test_server_action_reassigned_http_client_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned HTTP client aliases should not keep no-timeout state."""
    script = tmp_path / "action.py"
    script.write_text(
        """
import httpx

client = httpx.Client()
client = object()
client.get(record.callback_url)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert not any(f.rule_id == "odoo-loose-python-http-no-timeout" for f in findings)


def test_server_action_detects_annotated_http_client_without_timeout(tmp_path: Path) -> None:
    """Annotated HTTP client aliases should still require timeout review."""
    script = tmp_path / "action.py"
    script.write_text(
        """
import httpx

client: object = httpx.Client()
client.get(record.callback_url)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-http-no-timeout" for f in findings)


def test_server_action_detects_walrus_http_client_without_timeout(tmp_path: Path) -> None:
    """Assignment-expression HTTP client aliases should still require timeout review."""
    script = tmp_path / "action.py"
    script.write_text(
        """
import httpx

if client := httpx.Client():
    client.get(record.callback_url)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert any(f.rule_id == "odoo-loose-python-http-no-timeout" for f in findings)


def test_server_action_annotated_reassigned_http_client_alias_is_not_stale(tmp_path: Path) -> None:
    """Annotated HTTP client aliases should clear on safe rebinds."""
    script = tmp_path / "action.py"
    script.write_text(
        """
import httpx

client: object = httpx.Client()
client: object = object()
client.get(record.callback_url)
""",
        encoding="utf-8",
    )

    findings = LoosePythonScanner(str(script), "server_action").scan_file()

    assert not any(f.rule_id == "odoo-loose-python-http-no-timeout" for f in findings)


def test_repository_scan_detects_xml_server_action_code(tmp_path: Path) -> None:
    """XML ir.actions.server code should receive the loose Python AST checks."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "server_actions.xml").write_text(
        """<odoo>
  <record id="action_cleanup" model="ir.actions.server">
    <field name="state">code</field>
    <field name="code"><![CDATA[
query = "DELETE FROM %s" % model_name
env.cr.execute(query)
env.cr.commit()
requests.post(record.callback_url)
    ]]></field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_loose_python(tmp_path)
    rule_ids = {f.rule_id for f in findings}
    contexts = {f.context for f in findings}

    assert "odoo-loose-python-sql-injection" in rule_ids
    assert "odoo-loose-python-manual-transaction" in rule_ids
    assert "odoo-loose-python-http-no-timeout" in rule_ids
    assert "server_action_xml" in contexts


def test_repository_scan_detects_csv_server_action_code(tmp_path: Path) -> None:
    """CSV ir.actions.server code should receive the loose Python AST checks."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir_actions_server.csv").write_text(
        "id,name,state,code\naction_eval,Eval,code,safe_eval(record.domain)\n",
        encoding="utf-8",
    )

    findings = scan_loose_python(tmp_path)

    assert any(f.rule_id == "odoo-loose-python-safe-eval" and f.context == "server_action_csv" for f in findings)


def test_repository_scan_ignores_non_code_xml_server_actions(tmp_path: Path) -> None:
    """Only state='code' XML server actions should be parsed as loose Python."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "server_actions.xml").write_text(
        """<odoo>
  <record id="action_email" model="ir.actions.server">
    <field name="state">email</field>
    <field name="code">eval(record.expression)</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_loose_python(tmp_path) == []


def test_repository_scan_ignores_non_code_csv_server_actions(tmp_path: Path) -> None:
    """Only state='code' CSV server actions should be parsed as loose Python."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.actions.server.csv").write_text(
        "id,name,state,code\naction_email,Email,email,eval(record.expression)\n",
        encoding="utf-8",
    )

    assert scan_loose_python(tmp_path) == []


def test_repository_scan_only_targets_loose_python_locations(tmp_path: Path) -> None:
    """Only docs/server_actions and scripts should be scanned by this analyzer."""
    server_actions = tmp_path / "docs" / "server_actions"
    scripts = tmp_path / "scripts"
    module = tmp_path / "module" / "models"
    for directory in (server_actions, scripts, module):
        directory.mkdir(parents=True)

    (server_actions / "action.py").write_text("eval(record.expression)", encoding="utf-8")
    (scripts / "maintenance.py").write_text("env.cr.rollback()", encoding="utf-8")
    (module / "model.py").write_text("eval(record.expression)", encoding="utf-8")

    findings = scan_loose_python(tmp_path)

    assert len(findings) == 2
    assert {f.context for f in findings} == {"server_action", "script"}
