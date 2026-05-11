"""Tests for unsafe deserialization/parser scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.serialization_scanner import SerializationScanner, scan_serialization


def test_tainted_pickle_loads_is_critical(tmp_path: Path) -> None:
    """pickle.loads on request-derived data is code execution risk."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import pickle

def import_payload(**kwargs):
    payload = kwargs.get('payload')
    return pickle.loads(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings)


def test_request_alias_pickle_loads_is_critical(tmp_path: Path) -> None:
    """Aliased Odoo request imports should still taint unsafe deserialization."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import pickle
from odoo.http import request as req

def import_payload():
    payload = req.params.get('payload')
    return pickle.loads(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings)


def test_imported_odoo_http_request_pickle_loads_is_critical(tmp_path: Path) -> None:
    """Direct odoo.http request access should still taint unsafe deserialization."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import pickle
import odoo.http as odoo_http

def import_payload():
    payload = odoo_http.request.params.get('payload')
    return pickle.loads(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings)


def test_imported_odoo_request_pickle_loads_is_critical(tmp_path: Path) -> None:
    """Direct odoo request access should still taint unsafe deserialization."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import pickle
import odoo as od

def import_payload():
    payload = od.http.request.params.get('payload')
    return pickle.loads(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings)


def test_reassigned_tainted_payload_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a payload alias for safe data should clear request-derived taint."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import pickle

def import_payload(**kwargs):
    raw = kwargs.get('payload')
    raw = b'cached-payload'
    return pickle.loads(raw)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "high" for f in findings)
    assert not any(
        f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings
    )


def test_reassigned_payload_name_is_not_permanently_tainted(tmp_path: Path) -> None:
    """Payload-like local names should not stay tainted after safe reassignment."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import pickle

def import_payload(**kwargs):
    payload = kwargs.get('payload')
    payload = b'cached-payload'
    return pickle.loads(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "high" for f in findings)
    assert not any(
        f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings
    )


def test_unsafe_yaml_load_is_reported(tmp_path: Path) -> None:
    """yaml.load without SafeLoader should be visible."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import yaml

def import_config(payload):
    return yaml.load(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-yaml-load" for f in findings)


def test_yaml_safe_loader_is_not_reported(tmp_path: Path) -> None:
    """SafeLoader should suppress the unsafe yaml.load finding."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import yaml

def import_config(payload):
    return yaml.load(payload, Loader=yaml.SafeLoader)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-serialization-unsafe-yaml-load" for f in findings)


def test_yaml_safe_loader_constant_is_not_reported(tmp_path: Path) -> None:
    """SafeLoader module constants should suppress unsafe yaml.load findings."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import yaml

SAFE_LOADER = yaml.SafeLoader

def import_config(payload):
    return yaml.load(payload, Loader=SAFE_LOADER)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-serialization-unsafe-yaml-load" for f in findings)


def test_yaml_safe_loader_recursive_unpack_constant_is_not_reported(tmp_path: Path) -> None:
    """Recursive static **options should preserve SafeLoader handling."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import yaml

LOADER = yaml.SafeLoader
YAML_OPTIONS = {'Loader': LOADER}

def import_config(payload):
    return yaml.load(payload, **YAML_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-serialization-unsafe-yaml-load" for f in findings)


def test_yaml_safe_loader_nested_unpack_constant_is_not_reported(tmp_path: Path) -> None:
    """Nested static **options should preserve SafeLoader handling."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import yaml

BASE_OPTIONS = {'Loader': yaml.SafeLoader}
YAML_OPTIONS = {**BASE_OPTIONS}

def import_config(payload):
    return yaml.load(payload, **YAML_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-serialization-unsafe-yaml-load" for f in findings)


def test_yaml_safe_loader_dict_union_unpack_constant_is_not_reported(tmp_path: Path) -> None:
    """Dict-union static **options should preserve SafeLoader handling."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import yaml

BASE_OPTIONS = {'Loader': yaml.SafeLoader}
YAML_OPTIONS = BASE_OPTIONS | {'version': None}

def import_config(payload):
    return yaml.load(payload, **YAML_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-serialization-unsafe-yaml-load" for f in findings)


def test_yaml_safe_loader_updated_unpack_constant_is_not_reported(tmp_path: Path) -> None:
    """Updated static **options should preserve SafeLoader handling."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import yaml

YAML_OPTIONS = {}
YAML_OPTIONS.update({'Loader': yaml.SafeLoader})

def import_config(payload):
    return yaml.load(payload, **YAML_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-serialization-unsafe-yaml-load" for f in findings)


def test_yaml_safe_loader_class_constant_is_not_reported(tmp_path: Path) -> None:
    """Class-level static **options should preserve SafeLoader handling."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import yaml

class Importer:
    LOADER = yaml.SafeLoader
    YAML_OPTIONS = {'Loader': LOADER}

    def import_config(self, payload):
        return yaml.load(payload, **YAML_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-serialization-unsafe-yaml-load" for f in findings)


def test_yaml_safe_loader_local_constant_is_not_reported(tmp_path: Path) -> None:
    """Function-local static **options should preserve SafeLoader handling."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import yaml

def import_config(payload):
    loader = yaml.SafeLoader
    yaml_options = {'Loader': loader}
    return yaml.load(payload, **yaml_options)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-serialization-unsafe-yaml-load" for f in findings)


def test_yaml_load_all_without_safe_loader_is_reported(tmp_path: Path) -> None:
    """yaml.load_all has the same unsafe constructor behavior as yaml.load."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import yaml

def import_config(payload):
    return list(yaml.load_all(payload))
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-yaml-load" and f.sink == "yaml.load_all" for f in findings)


def test_imported_yaml_load_all_alias_is_reported(tmp_path: Path) -> None:
    """from-yaml aliases for load_all should not hide unsafe YAML loading."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
from yaml import load_all as decode_all

def import_config(payload):
    return list(decode_all(payload))
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-yaml-load" and f.sink == "yaml.load_all" for f in findings)


def test_yaml_load_all_safe_loader_is_not_reported(tmp_path: Path) -> None:
    """SafeLoader should suppress yaml.load_all findings too."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import yaml

def import_config(payload):
    return list(yaml.load_all(payload, Loader=yaml.SafeLoader))
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-serialization-unsafe-yaml-load" for f in findings)


def test_yaml_unsafe_load_is_reported(tmp_path: Path) -> None:
    """yaml.unsafe_load should be flagged even when not spelled as yaml.load."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import yaml

def import_config(**kwargs):
    payload = kwargs.get('payload')
    return yaml.unsafe_load(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-yaml-load" and f.severity == "critical" for f in findings)


def test_imported_yaml_full_load_alias_is_reported(tmp_path: Path) -> None:
    """from-yaml aliases for full_load should remain visible."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
from yaml import full_load as decode_yaml

def import_config(payload):
    return decode_yaml(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-yaml-full-load" and f.sink == "yaml.full_load" for f in findings)


def test_jsonpickle_decode_is_reported(tmp_path: Path) -> None:
    """jsonpickle can instantiate attacker-controlled objects."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import jsonpickle

def import_payload(payload):
    return jsonpickle.decode(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" for f in findings)


def test_cloudpickle_loads_is_reported(tmp_path: Path) -> None:
    """cloudpickle.loads is pickle-compatible and unsafe on uploaded data."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import cloudpickle

def import_payload(**kwargs):
    payload = kwargs.get('payload')
    return cloudpickle.loads(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-serialization-unsafe-deserialization"
        and f.severity == "critical"
        and f.sink == "cloudpickle.loads"
        for f in findings
    )


def test_imported_cloudpickle_load_alias_is_reported(tmp_path: Path) -> None:
    """from-cloudpickle aliases should not hide unsafe deserialization."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
from cloudpickle import load as load_payload

def import_payload(file):
    return load_payload(file)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-serialization-unsafe-deserialization"
        and f.severity == "critical"
        and f.sink == "cloudpickle.load"
        for f in findings
    )


def test_torch_load_on_tainted_attachment_is_reported(tmp_path: Path) -> None:
    """torch.load is pickle-backed and unsafe for uploaded model files."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import torch

def import_model(attachment):
    return torch.load(attachment.datas)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" and f.sink == "torch.load"
        for f in findings
    )


def test_pandas_read_pickle_alias_is_reported(tmp_path: Path) -> None:
    """pandas.read_pickle should be treated as pickle deserialization."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
from pandas import read_pickle as load_frame

def import_frame(path):
    return load_frame(path)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-serialization-unsafe-deserialization" and f.sink == "pandas.read_pickle" for f in findings
    )


def test_numpy_load_allow_pickle_is_reported(tmp_path: Path) -> None:
    """numpy object-array pickle loading should be visible to reviewers."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import numpy as np

def import_array(**kwargs):
    payload = kwargs.get('attachment')
    return np.load(payload, allow_pickle=True)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" and f.sink == "numpy.load"
        for f in findings
    )


def test_numpy_load_constant_allow_pickle_is_reported(tmp_path: Path) -> None:
    """allow_pickle constants should still expose unsafe numpy object loading."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import numpy as np

ALLOW_PICKLE = True

def import_array(**kwargs):
    payload = kwargs.get('attachment')
    return np.load(payload, allow_pickle=ALLOW_PICKLE)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" and f.sink == "numpy.load"
        for f in findings
    )


def test_numpy_load_unpack_allow_pickle_constant_is_reported(tmp_path: Path) -> None:
    """Static **options should not hide unsafe numpy object loading."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import numpy as np

ALLOW = True
LOAD_OPTIONS = {'allow_pickle': ALLOW}

def import_array(**kwargs):
    payload = kwargs.get('attachment')
    return np.load(payload, **LOAD_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" and f.sink == "numpy.load"
        for f in findings
    )


def test_numpy_load_dict_union_allow_pickle_constant_is_reported(tmp_path: Path) -> None:
    """Dict-union static **options should not hide unsafe numpy object loading."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import numpy as np

BASE_OPTIONS = {'allow_pickle': True}
LOAD_OPTIONS = BASE_OPTIONS | {'mmap_mode': None}

def import_array(**kwargs):
    payload = kwargs.get('attachment')
    return np.load(payload, **LOAD_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" and f.sink == "numpy.load"
        for f in findings
    )


def test_numpy_load_updated_allow_pickle_constant_is_reported(tmp_path: Path) -> None:
    """Updated static **options should not hide unsafe numpy object loading."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import numpy as np

LOAD_OPTIONS = {}
LOAD_OPTIONS.update({'allow_pickle': True})

def import_array(**kwargs):
    payload = kwargs.get('attachment')
    return np.load(payload, **LOAD_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-serialization-unsafe-deserialization"
        and f.severity == "critical"
        and f.sink == "numpy.load"
        for f in findings
    )


def test_numpy_load_class_constant_allow_pickle_is_reported(tmp_path: Path) -> None:
    """Class-level static **options should not hide unsafe numpy object loading."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import numpy as np

class Importer:
    ALLOW = True
    LOAD_OPTIONS = {'allow_pickle': ALLOW}

    def import_array(self, **kwargs):
        payload = kwargs.get('attachment')
        return np.load(payload, **LOAD_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" and f.sink == "numpy.load"
        for f in findings
    )


def test_numpy_load_local_constant_allow_pickle_is_reported(tmp_path: Path) -> None:
    """Function-local static **options should not hide unsafe numpy object loading."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import numpy as np

def import_array(**kwargs):
    allow = True
    load_options = {'allow_pickle': allow}
    payload = kwargs.get('attachment')
    return np.load(payload, **load_options)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" and f.sink == "numpy.load"
        for f in findings
    )


def test_shelve_open_is_reported(tmp_path: Path) -> None:
    """shelve.open can read pickle-backed databases from attacker-chosen paths."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import shelve

def import_cache(**kwargs):
    filename = kwargs.get('file')
    return shelve.open(filename)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-serialization-unsafe-deserialization"
        and f.severity == "critical"
        and f.sink == "shelve.open"
        for f in findings
    )


def test_aliased_pickle_module_tainted_loads_is_critical(tmp_path: Path) -> None:
    """Aliased unsafe deserialization modules should still be recognized."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import pickle as serializer

def import_payload(**kwargs):
    payload = kwargs.get('payload')
    return serializer.loads(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings)


def test_imported_pickle_loads_alias_is_reported(tmp_path: Path) -> None:
    """from pickle import loads aliases should not hide unsafe deserialization."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
from pickle import loads as decode_payload

def import_payload(payload):
    return decode_payload(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" for f in findings)


def test_ast_literal_eval_on_request_payload_is_reported(tmp_path: Path) -> None:
    """literal_eval on request-derived data should be visible for parser hardening."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import ast

def import_filter(**kwargs):
    payload = kwargs.get('domain')
    return ast.literal_eval(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-serialization-literal-eval-tainted" and f.sink == "ast.literal_eval" for f in findings
    )


def test_imported_literal_eval_alias_is_reported(tmp_path: Path) -> None:
    """from-ast aliases for literal_eval should still flag tainted parsing."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
from ast import literal_eval as parse_literal

def import_filter(payload):
    return parse_literal(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-serialization-literal-eval-tainted" and f.sink == "ast.literal_eval" for f in findings
    )


def test_json_loads_without_size_guard_is_reported(tmp_path: Path) -> None:
    """Request JSON parsed manually should have a visible byte-size guard."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import json
from odoo.http import request

def import_payload():
    body = request.httprequest.data
    return json.loads(body)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-json-load-no-size-check" and f.sink == "json.loads" for f in findings)


def test_request_alias_json_loads_without_size_guard_is_reported(tmp_path: Path) -> None:
    """Aliased request body access should taint unbounded JSON parsing."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import json
from odoo.http import request as req

def import_payload():
    body = req.httprequest.data
    return json.loads(body)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-json-load-no-size-check" and f.sink == "json.loads" for f in findings)


def test_imported_json_loads_alias_without_size_guard_is_reported(tmp_path: Path) -> None:
    """from-json aliases should not hide unbounded request parsing."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
from json import loads as decode_json

def import_payload(body):
    return decode_json(body)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-json-load-no-size-check" and f.sink == "json.loads" for f in findings)


def test_json_loads_with_size_guard_is_not_reported(tmp_path: Path) -> None:
    """A visible byte-size guard should suppress the JSON parser size finding."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import json

def import_payload(body):
    if len(body or b'') > 2_000_000:
        raise ValueError('payload too large')
    return json.loads(body)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert not any(f.rule_id == "odoo-serialization-json-load-no-size-check" for f in findings)


def test_unpacked_and_comprehension_payloads_are_reported(tmp_path: Path) -> None:
    """Request-derived payloads should stay tainted through common reshaping."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import pickle

def import_payload(**kwargs):
    _, payload = ('fixed', kwargs.get('payload'))
    payloads = [payload for value in kwargs.get('items')]
    return pickle.loads(payloads[0])
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings)


def test_starred_unpacked_payload_is_reported(tmp_path: Path) -> None:
    """Starred request-derived payload aliases should stay tainted for deserialization."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import pickle

def import_payload(**kwargs):
    _, *payloads = ('fixed', kwargs.get('payload'))
    payload = payloads[0]
    return pickle.loads(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings)


def test_loop_derived_payload_is_reported_as_critical(tmp_path: Path) -> None:
    """Loop variables from request-derived payloads should stay tainted."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import pickle

def import_payload(**kwargs):
    for payload in kwargs.get('payloads'):
        return pickle.loads(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings)


def test_safe_loop_reassignment_clears_payload_taint(tmp_path: Path) -> None:
    """Safe loop targets should clear stale payload taint before deserialization."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import pickle

def import_payload(**kwargs):
    payload = kwargs.get('payload')
    for payload in [b'cached-payload']:
        return pickle.loads(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "high" for f in findings)
    assert not any(
        f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings
    )


def test_comprehension_filter_derived_payload_is_reported(tmp_path: Path) -> None:
    """Tainted comprehension filters should keep payload aliases tainted."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import pickle

def import_payload(**kwargs):
    payloads = [b'cached-payload' for value in [1] if kwargs.get('payload')]
    return pickle.loads(payloads[0])
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings)


def test_named_expression_derived_payload_is_reported(tmp_path: Path) -> None:
    """Walrus-bound serialized payloads should remain tainted after the condition."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import pickle

def import_payload(**kwargs):
    if payload := kwargs.get('payload'):
        return pickle.loads(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings)


def test_boolop_derived_payload_is_reported(tmp_path: Path) -> None:
    """Boolean fallback serialized payloads should not clear request taint."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import pickle

def import_payload(**kwargs):
    payload = kwargs.get('payload') or b'cached-payload'
    return pickle.loads(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings)


def test_route_path_payload_is_tainted_for_deserialization(tmp_path: Path) -> None:
    """Odoo route path parameters are request-controlled parser input."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import pickle
from odoo import http

class ImportController(http.Controller):
    @http.route('/public/import/<string:serialized_blob>', auth='public', csrf=False)
    def import_blob(self, serialized_blob):
        return pickle.loads(serialized_blob)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings)


def test_aliased_imported_route_path_payload_is_tainted_for_deserialization(tmp_path: Path) -> None:
    """Aliased imported Odoo route decorators should still taint route arguments."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import pickle
from odoo import http
from odoo.http import route as web_route

class ImportController(http.Controller):
    @web_route('/public/import/<string:serialized_blob>', auth='public', csrf=False)
    def import_blob(self, serialized_blob):
        return pickle.loads(serialized_blob)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings)


def test_aliased_http_module_route_path_payload_is_tainted_for_deserialization(tmp_path: Path) -> None:
    """Aliased odoo.http route decorators should still taint route arguments."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import pickle
from odoo import http as odoo_http

class ImportController(odoo_http.Controller):
    @odoo_http.route('/public/import/<string:serialized_blob>', auth='public', csrf=False)
    def import_blob(self, serialized_blob):
        return pickle.loads(serialized_blob)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings)


def test_imported_odoo_http_module_route_path_payload_is_tainted_for_deserialization(tmp_path: Path) -> None:
    """Direct odoo.http route decorators should still taint route arguments."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import pickle
import odoo.http as odoo_http

class ImportController(odoo_http.Controller):
    @odoo_http.route('/public/import/<string:serialized_blob>', auth='public', csrf=False)
    def import_blob(self, serialized_blob):
        return pickle.loads(serialized_blob)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings)


def test_imported_odoo_module_route_path_payload_is_tainted_for_deserialization(tmp_path: Path) -> None:
    """Direct odoo module route decorators should still taint route arguments."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import pickle
import odoo as od

class ImportController(od.http.Controller):
    @od.http.route('/public/import/<string:serialized_blob>', auth='public', csrf=False)
    def import_blob(self, serialized_blob):
        return pickle.loads(serialized_blob)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical" for f in findings)


def test_non_odoo_route_decorator_does_not_taint_deserialization_path_parameter(tmp_path: Path) -> None:
    """Local route decorators should not make arbitrary path parameters tainted."""
    py = tmp_path / "controller.py"
    py.write_text(
        """
import pickle
from odoo import http

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class ImportController(http.Controller):
    @router.route('/public/import/<string:serialized_blob>', auth='public', csrf=False)
    def import_blob(self, serialized_blob):
        return pickle.loads(serialized_blob)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert not any(
        f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "critical"
        for f in findings
    )
    assert any(f.rule_id == "odoo-serialization-unsafe-deserialization" and f.severity == "high" for f in findings)


def test_tainted_xml_fromstring_is_reported(tmp_path: Path) -> None:
    """Request/attachment-derived XML parsing deserves parser hardening review."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import xml.etree.ElementTree as ET

def import_xml(**kwargs):
    payload = kwargs.get('xml')
    return ET.fromstring(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-xml-fromstring-tainted" for f in findings)


def test_aliased_elementtree_fromstring_is_reported(tmp_path: Path) -> None:
    """Aliased ElementTree imports should still flag tainted XML parsing."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import xml.etree.ElementTree as XML

def import_xml(**kwargs):
    payload = kwargs.get('xml')
    return XML.fromstring(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-xml-fromstring-tainted" for f in findings)


def test_dotted_elementtree_import_xml_constructor_is_reported(tmp_path: Path) -> None:
    """Dotted ElementTree imports and XML() should still flag tainted XML parsing."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import xml.etree.ElementTree

def import_xml(payload):
    return xml.etree.ElementTree.XML(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-serialization-xml-fromstring-tainted"
        and f.sink == "xml.etree.ElementTree.XML"
        for f in findings
    )


def test_lxml_tainted_fromstring_and_xml_are_reported(tmp_path: Path) -> None:
    """lxml XML constructors should get the same tainted parser-hardening review."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
from lxml import etree
from lxml.etree import XML as parse_xml

def import_xml(payload):
    doc = etree.fromstring(payload)
    return parse_xml(payload), doc
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-serialization-xml-fromstring-tainted"
        and f.sink == "lxml.etree.fromstring"
        for f in findings
    )
    assert any(
        f.rule_id == "odoo-serialization-xml-fromstring-tainted"
        and f.sink == "lxml.etree.XML"
        for f in findings
    )


def test_minidom_and_sax_tainted_parse_string_are_reported(tmp_path: Path) -> None:
    """stdlib XML parseString helpers should be visible for entity/size review."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
import xml.dom.minidom as minidom
from xml.sax import parseString as sax_parse

def import_xml(payload):
    minidom.parseString(payload)
    return sax_parse(payload)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(
        f.rule_id == "odoo-serialization-xml-fromstring-tainted"
        and f.sink == "xml.dom.minidom.parseString"
        for f in findings
    )
    assert any(
        f.rule_id == "odoo-serialization-xml-fromstring-tainted"
        and f.sink == "xml.sax.parseString"
        for f in findings
    )


def test_unsafe_lxml_parser_options_are_reported(tmp_path: Path) -> None:
    """lxml parser options that enable DTD/entity behavior should be visible."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
from lxml import etree

def import_xml(payload):
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
    return etree.fromstring(payload, parser=parser)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-xml-parser" for f in findings)


def test_lxml_parser_constant_unsafe_options_are_reported(tmp_path: Path) -> None:
    """lxml parser constants should not hide unsafe entity/network options."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
from lxml import etree

RESOLVE_ENTITIES = True
NO_NETWORK = False

def import_xml(payload):
    parser = etree.XMLParser(resolve_entities=RESOLVE_ENTITIES, no_network=NO_NETWORK)
    return etree.fromstring(payload, parser=parser)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-xml-parser" for f in findings)


def test_lxml_parser_unpack_recursive_unsafe_options_are_reported(tmp_path: Path) -> None:
    """Static **parser options should not hide unsafe XML parser flags."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
from lxml import etree

ENABLE_ENTITIES = True
PARSER_OPTIONS = {'resolve_entities': ENABLE_ENTITIES}

def import_xml(payload):
    parser = etree.XMLParser(**PARSER_OPTIONS)
    return etree.fromstring(payload, parser=parser)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-xml-parser" for f in findings)


def test_lxml_parser_dict_union_unsafe_options_are_reported(tmp_path: Path) -> None:
    """Dict-union static **parser options should not hide unsafe XML parser flags."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
from lxml import etree

BASE_OPTIONS = {'resolve_entities': True}
PARSER_OPTIONS = BASE_OPTIONS | {'load_dtd': True}

def import_xml(payload):
    parser = etree.XMLParser(**PARSER_OPTIONS)
    return etree.fromstring(payload, parser=parser)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-xml-parser" for f in findings)


def test_lxml_parser_updated_unsafe_options_are_reported(tmp_path: Path) -> None:
    """Updated static **parser options should not hide unsafe XML parser flags."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
from lxml import etree

PARSER_OPTIONS = {'no_network': True}
PARSER_OPTIONS.update({'resolve_entities': True, 'no_network': False})

def import_xml(payload):
    parser = etree.XMLParser(**PARSER_OPTIONS)
    return etree.fromstring(payload, parser=parser)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-xml-parser" for f in findings)


def test_lxml_parser_class_constant_unsafe_options_are_reported(tmp_path: Path) -> None:
    """Class-level static **parser options should not hide unsafe XML parser flags."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
from lxml import etree

class Importer:
    RESOLVE = True
    LOAD_DTD = RESOLVE
    NO_NETWORK = False
    XML_OPTIONS = {'resolve_entities': RESOLVE, 'load_dtd': LOAD_DTD, 'no_network': NO_NETWORK}

    def import_xml(self, payload):
        parser = etree.XMLParser(**XML_OPTIONS)
        return etree.fromstring(payload, parser=parser)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-xml-parser" for f in findings)


def test_lxml_parser_local_constant_unsafe_options_are_reported(tmp_path: Path) -> None:
    """Function-local static **parser options should not hide unsafe XML parser flags."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
from lxml import etree

def import_xml(payload):
    resolve = True
    no_network = False
    parser_options = {'resolve_entities': resolve, 'no_network': no_network}
    parser = etree.XMLParser(**parser_options)
    return etree.fromstring(payload, parser=parser)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-xml-parser" for f in findings)


def test_imported_lxml_xmlparser_alias_is_reported(tmp_path: Path) -> None:
    """Imported XMLParser aliases should preserve unsafe option detection."""
    py = tmp_path / "importer.py"
    py.write_text(
        """
from lxml.etree import XMLParser as Parser

def parser():
    return Parser(resolve_entities=True)
""",
        encoding="utf-8",
    )

    findings = SerializationScanner(py).scan_file()

    assert any(f.rule_id == "odoo-serialization-unsafe-xml-parser" for f in findings)


def test_repository_scan_finds_serialization(tmp_path: Path) -> None:
    """Repository scanner should include addon Python files and skip tests."""
    module = tmp_path / "module"
    tests = tmp_path / "tests"
    module.mkdir()
    tests.mkdir()
    (module / "importer.py").write_text("import pickle\npickle.loads(payload)\n", encoding="utf-8")
    (tests / "test_importer.py").write_text("import pickle\npickle.loads(payload)\n", encoding="utf-8")

    findings = scan_serialization(tmp_path)

    assert len([f for f in findings if f.rule_id == "odoo-serialization-unsafe-deserialization"]) == 1
