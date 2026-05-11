"""Tests for outbound integration scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.integration_scanner import IntegrationScanner, scan_integrations


def test_http_call_without_timeout_is_reported(tmp_path: Path) -> None:
    """Outbound HTTP calls should be bounded by timeouts."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

def sync():
    return requests.post('https://api.example.test/sync', json={})
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-http-no-timeout" for f in findings)


def test_tls_verification_disabled_is_reported(tmp_path: Path) -> None:
    """verify=False should be visible in review output."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

def sync():
    return requests.get('https://api.example.test', timeout=10, verify=False)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tls-verify-disabled" for f in findings)


def test_tls_verification_disabled_constant_is_reported(tmp_path: Path) -> None:
    """verify constants should not hide disabled TLS verification."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

TLS_VERIFY = False

def sync():
    return requests.get('https://api.example.test', timeout=10, verify=TLS_VERIFY)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tls-verify-disabled" for f in findings)


def test_tls_verification_disabled_recursive_constant_is_reported(tmp_path: Path) -> None:
    """Recursive verify constants should not hide disabled TLS verification."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

TLS_VERIFY_BASE = False
TLS_VERIFY = TLS_VERIFY_BASE

def sync():
    return requests.get('https://api.example.test', timeout=10, verify=TLS_VERIFY)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tls-verify-disabled" for f in findings)


def test_tls_verification_disabled_class_constant_is_reported(tmp_path: Path) -> None:
    """Class-scoped verify constants should not hide disabled TLS verification."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

class SyncClient:
    TLS_VERIFY_BASE = False
    TLS_VERIFY = TLS_VERIFY_BASE

    def sync(self):
        return requests.get('https://api.example.test', timeout=10, verify=TLS_VERIFY)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tls-verify-disabled" for f in findings)


def test_tls_verification_disabled_local_constant_is_reported(tmp_path: Path) -> None:
    """Function-local verify constants should not hide disabled TLS verification."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

def sync():
    verify_tls = False
    return requests.get('https://api.example.test', timeout=10, verify=verify_tls)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tls-verify-disabled" for f in findings)


def test_literal_metadata_url_is_reported(tmp_path: Path) -> None:
    """Hardcoded metadata endpoints should be surfaced as integration SSRF leads."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

def sync():
    return requests.get('http://169.254.169.254/latest/meta-data/', timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-internal-url-ssrf" for f in findings)


def test_literal_internal_url_keyword_constant_is_reported(tmp_path: Path) -> None:
    """Constant-backed url= values should not hide internal integration targets."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

ODOO_ADMIN_URL = 'http://localhost:8069/web/database/list'

def sync():
    return requests.request('GET', url=ODOO_ADMIN_URL, timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-internal-url-ssrf" for f in findings)


def test_public_literal_url_is_not_internal_ssrf(tmp_path: Path) -> None:
    """Normal public integration endpoints should not be treated as internal URLs."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

def sync():
    return requests.get('https://api.example.test/sync', timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-integration-internal-url-ssrf" for f in findings)


def test_request_controlled_url_is_reported_as_ssrf(tmp_path: Path) -> None:
    """Controller/request-derived URLs should be flagged as SSRF review leads."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import requests
from odoo.http import request

def webhook(**kwargs):
    callback_url = request.params.get('callback_url')
    return requests.get(callback_url, timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-url-ssrf" for f in findings)


def test_request_alias_controlled_url_is_reported_as_ssrf(tmp_path: Path) -> None:
    """Aliased Odoo request imports should still taint outbound URLs."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import requests
from odoo.http import request as req

def webhook():
    params = req.get_http_params()
    return requests.get(params.get('callback_url'), timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-url-ssrf" for f in findings)


def test_aliased_requests_module_url_is_reported(tmp_path: Path) -> None:
    """Aliased requests imports should still be treated as outbound HTTP."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import requests as req

def webhook(**kwargs):
    callback_url = kwargs.get('callback_url')
    return req.get(callback_url)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-integration-http-no-timeout" in rule_ids
    assert "odoo-integration-tainted-url-ssrf" in rule_ids


def test_imported_http_function_url_is_reported(tmp_path: Path) -> None:
    """from requests import get should not hide HTTP sinks."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
from requests import get as http_get

def webhook(**kwargs):
    endpoint = kwargs.get('endpoint')
    return http_get(url=endpoint, timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-url-ssrf" for f in findings)


def test_urllib_urlopen_is_reported(tmp_path: Path) -> None:
    """urllib.request.urlopen should receive the same timeout and SSRF review."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
from urllib.request import urlopen

def webhook(**kwargs):
    return urlopen(kwargs.get('callback_url'))
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-integration-http-no-timeout" in rule_ids
    assert "odoo-integration-tainted-url-ssrf" in rule_ids


def test_aliased_urllib_module_urlopen_is_reported(tmp_path: Path) -> None:
    """Aliased urllib.request imports should still be outbound HTTP sinks."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import urllib.request as urlreq

def webhook(**kwargs):
    return urlreq.urlopen(kwargs.get('callback_url'), timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-integration-tainted-url-ssrf" in rule_ids
    assert "odoo-integration-http-no-timeout" not in rule_ids


def test_endpoint_argument_url_is_reported(tmp_path: Path) -> None:
    """Endpoint-like function arguments should still seed outbound URL taint."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import requests

def webhook(endpoint):
    return requests.get(endpoint, timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-url-ssrf" for f in findings)


def test_reassigned_url_alias_is_not_stale_for_http_call(tmp_path: Path) -> None:
    """Reusing a request URL alias for a static endpoint should clear taint."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import requests

def webhook(**kwargs):
    url = kwargs.get('url')
    url = 'https://api.example.test/sync'
    return requests.get(url, timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-integration-tainted-url-ssrf" for f in findings)


def test_session_client_http_call_is_reported(tmp_path: Path) -> None:
    """requests.Session/httpx.Client variables should be recognized as HTTP clients."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import httpx
import requests as req

def sync(**kwargs):
    session = req.Session()
    client = httpx.Client()
    session.post(kwargs.get('callback_url'))
    client.get(kwargs.get('endpoint'), timeout=5, verify=False)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-integration-http-no-timeout" in rule_ids
    assert "odoo-integration-tainted-url-ssrf" in rule_ids
    assert "odoo-integration-tls-verify-disabled" in rule_ids


def test_aiohttp_client_session_context_is_reported(tmp_path: Path) -> None:
    """aiohttp ClientSession context managers should be recognized as outbound HTTP clients."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import aiohttp

async def sync(**kwargs):
    async with aiohttp.ClientSession() as session:
        return await session.get(kwargs.get('webhook_url'))
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-integration-http-no-timeout" in rule_ids
    assert "odoo-integration-tainted-url-ssrf" in rule_ids


def test_reassigned_http_client_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned HTTP client aliases should not keep outbound-call state."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

def sync(**kwargs):
    client = requests.Session()
    client = object()
    return client.get(kwargs.get('endpoint'))
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-integration-http-no-timeout" for f in findings)
    assert not any(f.rule_id == "odoo-integration-tainted-url-ssrf" for f in findings)


def test_unpacked_and_comprehension_urls_are_reported(tmp_path: Path) -> None:
    """Request-derived values should remain tainted through common Python reshaping."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import requests

def webhook(**kwargs):
    _, callback_url = ('fixed', kwargs.get('callback_url'))
    endpoints = [callback_url for value in kwargs.get('urls')]
    return requests.post(endpoints[0], timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-url-ssrf" for f in findings)


def test_starred_unpacked_url_is_reported(tmp_path: Path) -> None:
    """Starred request URL aliases should remain tainted for outbound calls."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import requests

def webhook(**kwargs):
    *callback_url, marker = kwargs.get('callback_url'), 'x'
    return requests.post(callback_url, timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-url-ssrf" for f in findings)


def test_starred_rest_url_is_reported(tmp_path: Path) -> None:
    """Starred-rest request URL aliases should remain tainted when not first in the rest list."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import requests

def webhook(**kwargs):
    marker, *endpoints, tail = 'x', 'https://api.example.test/sync', kwargs.get('callback_url'), 'end'
    return requests.post(endpoints[1], timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-url-ssrf" for f in findings)


def test_loop_derived_url_is_reported(tmp_path: Path) -> None:
    """Loop variables from request-derived URL lists should stay tainted."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import requests

def webhook(**kwargs):
    for callback_url in kwargs.get('callback_urls'):
        return requests.post(callback_url, timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-url-ssrf" for f in findings)


def test_safe_loop_reassignment_clears_url_taint(tmp_path: Path) -> None:
    """Safe loop targets should clear stale URL taint before outbound calls."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import requests

def webhook(**kwargs):
    callback_url = kwargs.get('callback_url')
    for callback_url in ['https://api.example.test/sync']:
        return requests.post(callback_url, timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-integration-tainted-url-ssrf" for f in findings)


def test_comprehension_filter_derived_url_is_reported(tmp_path: Path) -> None:
    """Tainted comprehension filters should preserve URL alias taint."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import requests

def webhook(**kwargs):
    endpoints = [url for url in ['https://api.example.test/sync'] if kwargs.get('callback_url')]
    return requests.post(endpoints[0], timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-url-ssrf" for f in findings)


def test_named_expression_derived_url_is_reported(tmp_path: Path) -> None:
    """Walrus-assigned request URLs should remain tainted for outbound calls."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import requests

def webhook(**kwargs):
    if callback_url := kwargs.get('callback_url'):
        return requests.post(callback_url, timeout=5)
    return None
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-url-ssrf" for f in findings)


def test_boolop_derived_url_is_reported(tmp_path: Path) -> None:
    """Boolean fallback URL expressions should remain tainted for outbound calls."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import requests

def webhook(**kwargs):
    callback_url = kwargs.get('callback_url') or 'https://api.example.test/sync'
    return requests.post(callback_url, timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-url-ssrf" for f in findings)


def test_tainted_authorization_header_is_reported(tmp_path: Path) -> None:
    """Request-derived outbound auth headers should be visible in review output."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

def sync(**kwargs):
    return requests.post(
        'https://api.example.test/sync',
        headers={'Authorization': 'Bearer %s' % kwargs.get('access_token')},
        timeout=5,
    )
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-auth-header" for f in findings)


def test_constant_authorization_header_name_is_reported(tmp_path: Path) -> None:
    """Constant-backed sensitive header names should still expose tainted credentials."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

AUTH_HEADER_BASE = 'Authorization'
AUTH_HEADER = AUTH_HEADER_BASE

def sync(**kwargs):
    return requests.post(
        'https://api.example.test/sync',
        headers={AUTH_HEADER: 'Bearer %s' % kwargs.get('access_token')},
        timeout=5,
    )
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-auth-header" for f in findings)


def test_class_constant_authorization_header_name_is_reported(tmp_path: Path) -> None:
    """Class-scoped sensitive header names should still expose tainted credentials."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

class SyncClient:
    AUTH_HEADER_BASE = 'Authorization'
    AUTH_HEADER = AUTH_HEADER_BASE

    def sync(self, **kwargs):
        return requests.post(
            'https://api.example.test/sync',
            headers={AUTH_HEADER: 'Bearer %s' % kwargs.get('access_token')},
            timeout=5,
        )
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-auth-header" for f in findings)


def test_local_authorization_header_name_is_reported(tmp_path: Path) -> None:
    """Function-local sensitive header names should still expose tainted credentials."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

def sync(**kwargs):
    header_name = 'Authorization'
    headers = {header_name: 'Bearer %s' % kwargs.get('access_token')}
    return requests.post('https://api.example.test/sync', headers=headers, timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-auth-header" for f in findings)


def test_request_alias_authorization_header_is_reported(tmp_path: Path) -> None:
    """Aliased request params should taint outbound auth headers."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests
from odoo.http import request as req

def sync():
    return requests.post(
        'https://api.example.test/sync',
        headers={'Authorization': 'Bearer %s' % req.params.get('access_token')},
        timeout=5,
    )
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-auth-header" for f in findings)


def test_tainted_api_key_header_alias_is_reported(tmp_path: Path) -> None:
    """Header dictionaries should keep auth-header taint when passed later."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

def sync(**kwargs):
    outbound_headers = {'X-Api-Key': kwargs.get('api_key')}
    return requests.post('https://api.example.test/sync', headers=outbound_headers, timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-auth-header" for f in findings)


def test_starred_tainted_api_key_header_alias_is_reported(tmp_path: Path) -> None:
    """Starred header aliases should keep outbound auth-header taint."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

def sync(**kwargs):
    *outbound_headers, marker = {'X-Api-Key': kwargs.get('api_key')}, 'x'
    return requests.post('https://api.example.test/sync', headers=outbound_headers, timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-auth-header" for f in findings)


def test_starred_rest_tainted_api_key_header_alias_is_reported(tmp_path: Path) -> None:
    """Starred-rest header aliases should keep sensitive outbound header taint."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

def sync(**kwargs):
    marker, *headers, tail = 'x', {'Accept': 'application/json'}, {'X-Api-Key': kwargs.get('api_key')}, {}
    return requests.post('https://api.example.test/sync', headers=headers[1], timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-auth-header" for f in findings)


def test_tainted_http_auth_parameter_is_reported(tmp_path: Path) -> None:
    """HTTP auth= credentials should not be request-controlled."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

def sync(**kwargs):
    return requests.get('https://api.example.test/user', auth=(kwargs.get('user'), kwargs.get('password')), timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-tainted-http-auth" for f in findings)


def test_static_server_side_auth_header_is_ignored(tmp_path: Path) -> None:
    """Server-owned integration credentials should not look attacker supplied."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

def sync(env):
    token = env['ir.config_parameter'].sudo().get_param('integration.token')
    headers = {'Authorization': 'Bearer %s' % token}
    return requests.post('https://api.example.test/sync', headers=headers, timeout=5)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert not any(
        f.rule_id in {"odoo-integration-tainted-auth-header", "odoo-integration-tainted-http-auth"} for f in findings
    )


def test_shell_true_with_tainted_command_is_high_severity(tmp_path: Path) -> None:
    """shell=True should be escalated when command text is request-controlled."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import subprocess

def run(**kwargs):
    cmd = kwargs.get('cmd')
    return subprocess.run(cmd, shell=True)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-subprocess-shell-true" and f.severity == "high" for f in findings)


def test_shell_true_constant_with_tainted_command_is_high_severity(tmp_path: Path) -> None:
    """shell constants should not hide shell=True subprocess review findings."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import subprocess

USE_SHELL = True

def run(**kwargs):
    cmd = kwargs.get('cmd')
    return subprocess.run(cmd, shell=USE_SHELL)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-subprocess-shell-true" and f.severity == "high" for f in findings)


def test_shell_true_recursive_constant_with_tainted_command_is_high_severity(tmp_path: Path) -> None:
    """Recursive shell constants should not hide shell=True subprocess review findings."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import subprocess

USE_SHELL_BASE = True
USE_SHELL = USE_SHELL_BASE

def run(**kwargs):
    cmd = kwargs.get('cmd')
    return subprocess.run(cmd, shell=USE_SHELL)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-subprocess-shell-true" and f.severity == "high" for f in findings)


def test_shell_true_class_constant_with_tainted_command_is_high_severity(tmp_path: Path) -> None:
    """Class-scoped shell constants should not hide shell=True subprocess review findings."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import subprocess

class Runner:
    USE_SHELL_BASE = True
    USE_SHELL = USE_SHELL_BASE

    def run(self, **kwargs):
        cmd = kwargs.get('cmd')
        return subprocess.run(cmd, shell=USE_SHELL)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-subprocess-shell-true" and f.severity == "high" for f in findings)


def test_shell_true_walrus_constant_with_tainted_command_is_high_severity(tmp_path: Path) -> None:
    """Walrus shell constants should not hide shell=True subprocess review findings."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import subprocess

def run(**kwargs):
    cmd = kwargs.get('cmd')
    if use_shell := True:
        return subprocess.run(cmd, shell=use_shell)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-subprocess-shell-true" and f.severity == "high" for f in findings)


def test_request_alias_tainted_command_is_reported(tmp_path: Path) -> None:
    """Aliased request params should taint process command arguments."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import subprocess
from odoo.http import request as req

def run():
    return subprocess.run(req.params.get('cmd'), shell=True)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-integration-subprocess-shell-true" in rule_ids
    assert "odoo-integration-tainted-command-args" in rule_ids


def test_starred_tainted_command_is_reported(tmp_path: Path) -> None:
    """Starred command aliases should remain tainted for process calls."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import subprocess

def run(**kwargs):
    *cmd, marker = kwargs.get('cmd'), 'x'
    return subprocess.run(cmd, shell=True)
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-integration-subprocess-shell-true" in rule_ids
    assert "odoo-integration-tainted-command-args" in rule_ids


def test_starred_rest_http_client_alias_is_reported(tmp_path: Path) -> None:
    """Starred-rest HTTP client aliases should still be recognized as outbound clients."""
    py = tmp_path / "integration.py"
    py.write_text(
        """
import requests

def sync(**kwargs):
    marker, *clients, tail = 'x', object(), requests.Session(), object()
    return clients[1].post(kwargs.get('callback_url'))
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-integration-http-no-timeout" in rule_ids
    assert "odoo-integration-tainted-url-ssrf" in rule_ids


def test_tainted_subprocess_args_and_missing_timeout_are_reported(tmp_path: Path) -> None:
    """Request-controlled subprocess arguments should be visible even without shell=True."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import subprocess

def convert(**kwargs):
    return subprocess.run(['wkhtmltopdf', kwargs.get('url'), '/tmp/out.pdf'])
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-integration-tainted-command-args" in rule_ids
    assert "odoo-integration-process-no-timeout" in rule_ids
    assert "odoo-integration-report-command-review" in rule_ids


def test_os_system_command_execution_is_reported(tmp_path: Path) -> None:
    """os.system/os.popen are shell execution sinks."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import os

def run(**kwargs):
    return os.system(kwargs.get('cmd'))
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-integration-os-command-execution" and f.severity == "critical" for f in findings)


def test_aliased_command_sinks_are_reported(tmp_path: Path) -> None:
    """Aliased subprocess/os imports should not hide command sinks."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import os as operating
import subprocess as sp
from subprocess import run as process_run

def run(**kwargs):
    process_run(kwargs.get('cmd'), shell=True)
    sp.check_output(['wkhtmltopdf', kwargs.get('url')])
    return operating.system(kwargs.get('cmd'))
""",
        encoding="utf-8",
    )

    findings = IntegrationScanner(py).scan_file()
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-integration-subprocess-shell-true" in rule_ids
    assert "odoo-integration-tainted-command-args" in rule_ids
    assert "odoo-integration-process-no-timeout" in rule_ids
    assert "odoo-integration-os-command-execution" in rule_ids


def test_repository_scan_skips_tests(tmp_path: Path) -> None:
    """Repository scan should include addon code but skip test fixtures."""
    addon = tmp_path / "addon"
    tests = tmp_path / "tests"
    addon.mkdir()
    tests.mkdir()
    (addon / "integration.py").write_text(
        "import requests\nrequests.get('https://api.example.test')\n",
        encoding="utf-8",
    )
    (tests / "test_integration.py").write_text(
        "import requests\nrequests.get('https://api.example.test')\n",
        encoding="utf-8",
    )

    findings = scan_integrations(tmp_path)

    assert len([f for f in findings if f.rule_id == "odoo-integration-http-no-timeout"]) == 1
