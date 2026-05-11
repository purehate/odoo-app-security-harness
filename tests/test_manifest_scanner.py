"""Tests for Odoo manifest/package scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.manifest_scanner import scan_manifests


def _write_manifest(module: Path, content: str) -> None:
    module.mkdir(parents=True, exist_ok=True)
    (module / "__manifest__.py").write_text(content, encoding="utf-8")


def test_installable_module_with_models_missing_acl_data(tmp_path: Path) -> None:
    """Modules defining models should load ir.model.access.csv."""
    module = tmp_path / "missing_acl"
    _write_manifest(module, "{'name': 'Missing ACL', 'installable': True, 'data': []}")
    models = module / "models"
    models.mkdir()
    (models / "thing.py").write_text(
        "from odoo import models\nclass Thing(models.Model):\n    _name='x.thing'\n", encoding="utf-8"
    )

    findings = scan_manifests(tmp_path)

    assert any(f.rule_id == "odoo-manifest-missing-acl-data" and f.severity == "high" for f in findings)


def test_demo_files_loaded_as_production_data(tmp_path: Path) -> None:
    """Demo-looking files in data are installed in production databases."""
    module = tmp_path / "demo_in_data"
    _write_manifest(
        module,
        "{'name': 'Demo In Data', 'license': 'LGPL-3', 'data': ['security/ir.model.access.csv', 'demo/users.xml']}",
    )

    findings = scan_manifests(tmp_path)

    assert any(f.rule_id == "odoo-manifest-demo-in-data" for f in findings)


def test_application_demo_data_is_review_signal(tmp_path: Path) -> None:
    """Application modules shipping demo data deserve review."""
    module = tmp_path / "app_demo"
    _write_manifest(
        module,
        "{'name': 'App Demo', 'license': 'LGPL-3', 'application': True, 'demo': ['demo/demo.xml']}",
    )

    findings = scan_manifests(tmp_path)

    assert any(f.rule_id == "odoo-manifest-application-demo-data" for f in findings)


def test_missing_license_for_installable_module(tmp_path: Path) -> None:
    """Installable modules should explicitly state license metadata."""
    module = tmp_path / "no_license"
    _write_manifest(module, "{'name': 'No License', 'installable': True}")

    findings = scan_manifests(tmp_path)

    assert any(f.rule_id == "odoo-manifest-missing-license" for f in findings)


def test_unexpected_license_identifier_is_reported(tmp_path: Path) -> None:
    """Unexpected license strings should be visible in packaging review."""
    module = tmp_path / "odd_license"
    _write_manifest(module, "{'name': 'Odd License', 'license': 'Commercial'}")

    findings = scan_manifests(tmp_path)

    assert any(f.rule_id == "odoo-manifest-unexpected-license" for f in findings)


def test_auto_install_module_loading_security_data_is_reported(tmp_path: Path) -> None:
    """Implicitly installed modules that alter security data should be review-visible."""
    module = tmp_path / "auto_security"
    _write_manifest(
        module,
        """{
    'name': 'Auto Security',
    'license': 'LGPL-3',
    'auto_install': True,
    'depends': ['sale'],
    'data': ['security/groups.xml', 'security/ir.model.access.csv'],
}""",
    )

    findings = scan_manifests(tmp_path)
    rule_ids = {f.rule_id for f in findings}

    assert "odoo-manifest-auto-install-security-data" in rule_ids
    assert "odoo-manifest-auto-install-without-depends" not in rule_ids


def test_auto_install_dependency_list_loading_security_data_is_reported(tmp_path: Path) -> None:
    """Odoo auto_install dependency lists should be treated as implicit installs."""
    module = tmp_path / "auto_security_list"
    _write_manifest(
        module,
        """{
    'name': 'Auto Security List',
    'license': 'LGPL-3',
    'auto_install': ['sale'],
    'depends': ['sale'],
    'data': ['security/groups.xml'],
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(f.rule_id == "odoo-manifest-auto-install-security-data" for f in findings)


def test_auto_install_without_dependencies_is_reported(tmp_path: Path) -> None:
    """auto_install=True without dependencies can activate unexpectedly."""
    module = tmp_path / "auto_no_depends"
    _write_manifest(module, "{'name': 'Auto No Depends', 'license': 'LGPL-3', 'auto_install': True}")

    findings = scan_manifests(tmp_path)

    assert any(f.rule_id == "odoo-manifest-auto-install-without-depends" for f in findings)


def test_remote_assets_are_reported(tmp_path: Path) -> None:
    """Remote frontend assets in manifests are supply-chain and CSP review leads."""
    module = tmp_path / "remote_assets"
    _write_manifest(
        module,
        """{
    'name': 'Remote Assets',
    'license': 'LGPL-3',
    'assets': {
        'web.assets_backend': [
            'https://cdn.example.com/widget.js',
            ('include', '//cdn.example.com/theme.css'),
        ],
    },
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(f.rule_id == "odoo-manifest-remote-assets" and f.severity == "high" for f in findings)


def test_legacy_remote_qweb_assets_are_reported(tmp_path: Path) -> None:
    """Legacy qweb manifest entries can also pull remote templates."""
    module = tmp_path / "remote_qweb"
    _write_manifest(
        module,
        "{'name': 'Remote QWeb', 'license': 'LGPL-3', 'qweb': ['http://cdn.example.com/template.xml']}",
    )

    findings = scan_manifests(tmp_path)

    assert any(f.rule_id == "odoo-manifest-remote-assets" for f in findings)


def test_insecure_remote_assets_are_reported(tmp_path: Path) -> None:
    """Cleartext manifest assets should be a distinct transport-security lead."""
    module = tmp_path / "insecure_remote_assets"
    _write_manifest(
        module,
        """{
    'name': 'Insecure Remote Assets',
    'license': 'LGPL-3',
    'assets': {
        'web.assets_backend': [
            'http://cdn.example.com/widget.js',
            'https://cdn.example.com/theme.css',
        ],
    },
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(
        f.rule_id == "odoo-manifest-insecure-remote-asset"
        and f.severity == "medium"
        and "http://cdn.example.com/widget.js" in f.message
        and "https://cdn.example.com/theme.css" not in f.message
        for f in findings
    )


def test_protocol_relative_remote_assets_are_reported(tmp_path: Path) -> None:
    """Scheme-relative manifest assets should be a distinct transport posture lead."""
    module = tmp_path / "protocol_relative_assets"
    _write_manifest(
        module,
        """{
    'name': 'Protocol Relative Assets',
    'license': 'LGPL-3',
    'assets': {
        'web.assets_backend': [
            '//cdn.example.com/widget.js',
            'https://cdn.example.com/theme.css',
        ],
    },
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(
        f.rule_id == "odoo-manifest-protocol-relative-remote-asset"
        and f.severity == "medium"
        and "//cdn.example.com/widget.js" in f.message
        and "https://cdn.example.com/theme.css" not in f.message
        for f in findings
    )


def test_risky_python_dependencies_are_reported_with_common_spellings(tmp_path: Path) -> None:
    """Security-sensitive Python dependency declarations should survive package spelling variants."""
    module = tmp_path / "risky_deps"
    _write_manifest(
        module,
        """{
    'name': 'Risky Deps',
    'license': 'LGPL-3',
    'external_dependencies': {
        'python': ['PyYAML', 'requests[security]', 'ldap3', 'openai', 'safe-package'],
    },
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(
        f.rule_id == "odoo-manifest-risky-python-dependency"
        and "PyYAML" in f.message
        and "requests[security]" in f.message
        and "ldap3" in f.message
        and "openai" in f.message
        and "safe-package" not in f.message
        for f in findings
    )


def test_modern_integration_python_dependencies_are_reported(tmp_path: Path) -> None:
    """HTTP, cloud storage, and messaging dependencies should be review-visible."""
    module = tmp_path / "modern_integration_deps"
    _write_manifest(
        module,
        """{
    'name': 'Modern Integration Deps',
    'license': 'LGPL-3',
    'external_dependencies': {
        'python': ['httpx[http2]', 'urllib3', 'google-cloud-storage', 'azure_storage_blob', 'stripe', 'safe-package'],
    },
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(
        f.rule_id == "odoo-manifest-risky-python-dependency"
        and "httpx[http2]" in f.message
        and "urllib3" in f.message
        and "google-cloud-storage" in f.message
        and "azure_storage_blob" in f.message
        and "stripe" in f.message
        and "safe-package" not in f.message
        for f in findings
    )


def test_auth_crypto_and_xml_signature_dependencies_are_reported(tmp_path: Path) -> None:
    """Auth, crypto, and XML-signature dependencies are security-sensitive review leads."""
    module = tmp_path / "auth_crypto_xml_deps"
    _write_manifest(
        module,
        """{
    'name': 'Auth Crypto XML Deps',
    'license': 'LGPL-3',
    'external_dependencies': {
        'python': [
            'Authlib',
            'python-jose[cryptography]',
            'requests-oauthlib',
            'pycryptodomex>=3.20',
            'signxml',
            'xmlsec',
            'lxml',
            'safe-package',
        ],
    },
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(
        f.rule_id == "odoo-manifest-risky-python-dependency"
        and "Authlib" in f.message
        and "python-jose[cryptography]" in f.message
        and "requests-oauthlib" in f.message
        and "pycryptodomex>=3.20" in f.message
        and "signxml" in f.message
        and "xmlsec" in f.message
        and "lxml" in f.message
        and "safe-package" not in f.message
        for f in findings
    )


def test_versioned_python_dependencies_are_reported(tmp_path: Path) -> None:
    """Requirement-style manifest dependency spellings should still be matched."""
    module = tmp_path / "versioned_deps"
    _write_manifest(
        module,
        """{
    'name': 'Versioned Deps',
    'license': 'LGPL-3',
    'external_dependencies': {
        'python': ['requests>=2.31', 'cryptography==42.0.0', 'PyJWT~=2.8', 'safe-package>=1'],
    },
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(
        f.rule_id == "odoo-manifest-risky-python-dependency"
        and "requests>=2.31" in f.message
        and "cryptography==42.0.0" in f.message
        and "PyJWT~=2.8" in f.message
        and "safe-package>=1" not in f.message
        for f in findings
    )


def test_direct_python_dependency_references_are_reported(tmp_path: Path) -> None:
    """Direct URL, VCS, and local-file Python dependencies need provenance review."""
    module = tmp_path / "direct_deps"
    _write_manifest(
        module,
        """{
    'name': 'Direct Deps',
    'license': 'LGPL-3',
    'external_dependencies': {
        'python': [
            'git+https://github.com/example/private-addon-helper.git@main',
            'helper @ https://packages.example.com/helper-1.0.tar.gz',
            'file:///opt/vendor/custom.whl',
            'safe-package',
        ],
    },
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(
        f.rule_id == "odoo-manifest-direct-python-dependency"
        and "git+https://github.com/example/private-addon-helper.git@main" in f.message
        and "helper @ https://packages.example.com/helper-1.0.tar.gz" in f.message
        and "file:///opt/vendor/custom.whl" in f.message
        and "safe-package" not in f.message
        for f in findings
    )


def test_insecure_python_dependency_references_are_reported(tmp_path: Path) -> None:
    """Cleartext package sources can compromise install-time code."""
    module = tmp_path / "insecure_direct_deps"
    _write_manifest(
        module,
        """{
    'name': 'Insecure Direct Deps',
    'license': 'LGPL-3',
    'external_dependencies': {
        'python': [
            'git+http://git.example.com/private-addon-helper.git@main',
            'helper @ http://packages.example.com/helper-1.0.tar.gz',
            'https://packages.example.com/safe-1.0.tar.gz',
        ],
    },
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(
        f.rule_id == "odoo-manifest-insecure-python-dependency"
        and f.severity == "high"
        and "git+http://git.example.com/private-addon-helper.git@main" in f.message
        and "helper @ http://packages.example.com/helper-1.0.tar.gz" in f.message
        and "https://packages.example.com/safe-1.0.tar.gz" not in f.message
        for f in findings
    )


def test_floating_vcs_python_dependency_references_are_reported(tmp_path: Path) -> None:
    """VCS dependencies should not follow moving branches during installs."""
    module = tmp_path / "floating_vcs_deps"
    _write_manifest(
        module,
        """{
    'name': 'Floating VCS Deps',
    'license': 'LGPL-3',
    'external_dependencies': {
        'python': [
            'git+https://github.com/example/helper.git@main',
            'git+https://github.com/example/other-helper.git',
            'git+https://github.com/example/pinned-helper.git@6f1e2d3c4b5a697887766554433221100ffeeabc',
        ],
    },
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(
        f.rule_id == "odoo-manifest-floating-vcs-python-dependency"
        and f.severity == "medium"
        and "git+https://github.com/example/helper.git@main" in f.message
        and "git+https://github.com/example/other-helper.git" in f.message
        and "pinned-helper" not in f.message
        for f in findings
    )


def test_local_python_dependency_references_are_reported(tmp_path: Path) -> None:
    """Local package paths make installs depend on unreviewed host filesystem state."""
    module = tmp_path / "local_python_deps"
    _write_manifest(
        module,
        """{
    'name': 'Local Python Deps',
    'license': 'LGPL-3',
    'external_dependencies': {
        'python': [
            './vendor/helper.whl',
            'helper @ ../shared/helper',
            '/opt/vendor/private_helper.whl',
            'safe-package',
        ],
    },
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(
        f.rule_id == "odoo-manifest-local-python-dependency"
        and f.severity == "medium"
        and "./vendor/helper.whl" in f.message
        and "helper @ ../shared/helper" in f.message
        and "/opt/vendor/private_helper.whl" in f.message
        and "safe-package" not in f.message
        for f in findings
    )


def test_risky_binary_dependencies_are_reported(tmp_path: Path) -> None:
    """Security-sensitive binary dependency declarations should be visible in manifest review."""
    module = tmp_path / "risky_bin_deps"
    _write_manifest(
        module,
        """{
    'name': 'Risky Bin Deps',
    'license': 'LGPL-3',
    'external_dependencies': {
        'bin': ['/usr/bin/wkhtmltopdf', 'curl', 'safe-tool'],
    },
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(
        f.rule_id == "odoo-manifest-risky-bin-dependency"
        and "/usr/bin/wkhtmltopdf" in f.message
        and "curl" in f.message
        and "safe-tool" not in f.message
        for f in findings
    )


def test_cloud_and_container_binary_dependencies_are_reported(tmp_path: Path) -> None:
    """Cloud and container CLIs in manifests should be review-visible."""
    module = tmp_path / "cloud_bin_deps"
    _write_manifest(
        module,
        """{
    'name': 'Cloud Bin Deps',
    'license': 'LGPL-3',
    'external_dependencies': {
        'bin': ['/usr/local/bin/aws', 'gcloud', 'kubectl', 'docker', 'safe-tool'],
    },
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(
        f.rule_id == "odoo-manifest-risky-bin-dependency"
        and "/usr/local/bin/aws" in f.message
        and "gcloud" in f.message
        and "kubectl" in f.message
        and "docker" in f.message
        and "safe-tool" not in f.message
        for f in findings
    )


def test_local_binary_dependency_references_are_reported(tmp_path: Path) -> None:
    """Binary dependency declarations should not rely on host-local executable paths."""
    module = tmp_path / "local_bin_deps"
    _write_manifest(
        module,
        """{
    'name': 'Local Bin Deps',
    'license': 'LGPL-3',
    'external_dependencies': {
        'bin': ['./bin/custom-tool', '../tools/helper', '/opt/vendor/private-tool', 'safe-tool'],
    },
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(
        f.rule_id == "odoo-manifest-local-bin-dependency"
        and f.severity == "medium"
        and "./bin/custom-tool" in f.message
        and "../tools/helper" in f.message
        and "/opt/vendor/private-tool" in f.message
        and "safe-tool" not in f.message
        for f in findings
    )


def test_lifecycle_hooks_are_reported(tmp_path: Path) -> None:
    """Install/uninstall hooks deserve explicit privileged-code review."""
    module = tmp_path / "hooks"
    _write_manifest(
        module,
        """{
    'name': 'Hooks',
    'license': 'LGPL-3',
    'post_init_hook': 'post_init',
    'uninstall_hook': 'uninstall_cleanup',
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(f.rule_id == "odoo-manifest-lifecycle-hook" and f.severity == "medium" for f in findings)


def test_post_load_lifecycle_hook_is_reported(tmp_path: Path) -> None:
    """post_load hooks run module lifecycle code and deserve review."""
    module = tmp_path / "post_load"
    _write_manifest(
        module,
        """{
    'name': 'Post Load',
    'license': 'LGPL-3',
    'post_load': 'patch_registry',
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(f.rule_id == "odoo-manifest-lifecycle-hook" and "post_load" in f.message for f in findings)


def test_suspicious_data_paths_are_reported(tmp_path: Path) -> None:
    """Manifest data/demo paths should not escape the module tree."""
    module = tmp_path / "suspicious_paths"
    _write_manifest(
        module,
        """{
    'name': 'Suspicious Paths',
    'license': 'LGPL-3',
    'data': ['../shared/security.xml'],
    'demo': ['/tmp/demo.xml'],
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(f.rule_id == "odoo-manifest-suspicious-data-path" and f.severity == "high" for f in findings)


def test_suspicious_asset_and_qweb_paths_are_reported(tmp_path: Path) -> None:
    """Asset and legacy qweb manifest paths should not escape the module tree."""
    module = tmp_path / "suspicious_asset_paths"
    _write_manifest(
        module,
        """{
    'name': 'Suspicious Asset Paths',
    'license': 'LGPL-3',
    'assets': {
        'web.assets_backend': [
            ('include', '../shared/private.js'),
            '/opt/odoo/debug.css',
            'https://cdn.example.com/safe.js',
        ],
    },
    'qweb': ['../../shared/template.xml'],
}""",
    )

    findings = scan_manifests(tmp_path)

    assert any(
        f.rule_id == "odoo-manifest-suspicious-data-path"
        and "../shared/private.js" in f.message
        and "/opt/odoo/debug.css" in f.message
        and "../../shared/template.xml" in f.message
        and "https://cdn.example.com/safe.js" not in f.message
        for f in findings
    )


def test_malformed_manifest_is_reported(tmp_path: Path) -> None:
    """Non-literal manifests should be surfaced for manual review."""
    module = tmp_path / "bad_manifest"
    _write_manifest(module, "not valid python {")

    findings = scan_manifests(tmp_path)

    assert any(f.rule_id == "odoo-manifest-parse-error" for f in findings)


def test_clean_manifest_has_no_findings(tmp_path: Path) -> None:
    """A basic clean manifest with ACL data should pass this scanner."""
    module = tmp_path / "clean"
    _write_manifest(
        module,
        "{'name': 'Clean', 'license': 'LGPL-3', 'data': ['security/ir.model.access.csv'], 'installable': True}",
    )
    models = module / "models"
    models.mkdir()
    (models / "thing.py").write_text(
        "from odoo import models\nclass Thing(models.Model):\n    _name='x.thing'\n", encoding="utf-8"
    )

    assert scan_manifests(tmp_path) == []
