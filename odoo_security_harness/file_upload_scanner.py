"""Scanner for risky Odoo file upload and filesystem handling."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class FileUploadFinding:
    """Represents a file upload/filesystem finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    sink: str = ""


TAINTED_ARG_NAMES = {"file", "files", "filename", "upload", "attachment", "data", "kwargs", "kw", "post"}
FILE_WRITE_METHODS = {"write_text", "write_bytes"}
SHUTIL_WRITE_SINKS = {"shutil.copy", "shutil.copyfile", "shutil.move"}
ARCHIVE_OPEN_SINKS = {"tarfile.open", "zipfile.ZipFile"}
ARCHIVE_EXTRACT_METHODS = {"extract", "extractall"}
SECURE_FILENAME_SINKS = {"werkzeug.utils.secure_filename", "secure_filename"}
UNSAFE_TEMPFILE_SINKS = {"tempfile.mktemp", "mktemp"}
ATTACHMENT_CREATE_VALUE_KEYS = {
    "access_token",
    "datas",
    "mimetype",
    "name",
    "public",
    "raw",
    "res_id",
    "res_model",
}


def scan_file_uploads(repo_path: Path) -> list[FileUploadFinding]:
    """Scan Python files for risky file upload/filesystem behavior."""
    findings: list[FileUploadFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(FileUploadScanner(path).scan_file())
    return findings


class FileUploadScanner(ast.NodeVisitor):
    """AST scanner for one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[FileUploadFinding] = []
        self.tainted_names: set[str] = set()
        self.decoded_uploads: set[str] = set()
        self.attachment_names: set[str] = set()
        self.attachment_value_names: dict[str, ast.Dict] = {}
        self.tainted_archive_names: set[str] = set()
        self.secure_filename_names: set[str] = set()
        self.module_aliases: dict[str, str] = {}
        self.function_aliases: dict[str, str] = {}
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}
        self.odoo_module_names: set[str] = {"odoo"}
        self.route_names: set[str] = set()
        self.constants: dict[str, ast.AST] = {}
        self.local_constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []

    def scan_file(self) -> list[FileUploadFinding]:
        """Scan the file."""
        try:
            content = self.path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content)
        except SyntaxError:
            return []
        except Exception:
            return []

        self.constants = _module_constants(tree)
        self.visit(tree)
        return self.findings

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        previous_tainted = set(self.tainted_names)
        previous_decoded = set(self.decoded_uploads)
        previous_attachments = set(self.attachment_names)
        previous_attachment_values = dict(self.attachment_value_names)
        previous_archives = set(self.tainted_archive_names)
        previous_secure_filenames = set(self.secure_filename_names)
        previous_local_constants = self.local_constants
        self.local_constants = {}
        is_route = _function_is_http_route(
            node,
            self.route_names,
            self.http_module_names,
            self.odoo_module_names,
        )
        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.arg in TAINTED_ARG_NAMES or (is_route and arg.arg not in {"self", "cls"}):
                self.tainted_names.add(arg.arg)
        if node.args.vararg:
            self.tainted_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self.tainted_names.add(node.args.kwarg.arg)

        self.generic_visit(node)
        self.tainted_names = previous_tainted
        self.decoded_uploads = previous_decoded
        self.attachment_names = previous_attachments
        self.attachment_value_names = previous_attachment_values
        self.tainted_archive_names = previous_archives
        self.secure_filename_names = previous_secure_filenames
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            local_name = alias.asname or alias.name.split(".", 1)[0]
            if alias.name in {"base64", "shutil", "tarfile", "zipfile"}:
                self.module_aliases[local_name] = alias.name
            elif alias.name in {"tempfile", "werkzeug.utils"}:
                self.module_aliases[local_name] = alias.name
            elif alias.name == "odoo":
                self.odoo_module_names.add(alias.asname or alias.name)
            elif alias.name == "odoo.http" and alias.asname:
                self.http_module_names.add(alias.asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module in {"base64", "shutil", "tarfile", "zipfile", "tempfile", "werkzeug.utils"}:
            for alias in node.names:
                self.function_aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        if node.module == "odoo":
            for alias in node.names:
                if alias.name == "http":
                    self.http_module_names.add(alias.asname or alias.name)
        elif node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
                elif alias.name == "route":
                    self.route_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
        is_attachment = _attachment_model_in_expr(node.value, self.attachment_names, self._effective_constants())
        is_decoded_upload = self._is_base64_decode(node.value) and _call_has_tainted_input(
            node.value, self._expr_is_tainted
        )
        is_tainted_archive = self._is_tainted_archive_open(node.value)
        is_secure_filename = self._expr_uses_secure_filename(node.value)
        for target in node.targets:
            self._mark_tainted_target(target, node.value)
            self._mark_decoded_upload_target(target, is_decoded_upload)
            self._mark_attachment_target(target, is_attachment)
            self._mark_attachment_value_target(target, node.value)
            self._mark_attachment_value_item_target(target, node.value)
            self._mark_archive_target_from_value(target, node.value, is_tainted_archive)
            self._mark_secure_filename_target(target, is_secure_filename)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
            self._mark_tainted_target(node.target, node.value)
            self._mark_decoded_upload_target(
                node.target,
                self._is_base64_decode(node.value) and _call_has_tainted_input(node.value, self._expr_is_tainted),
            )
            self._mark_attachment_target(
                node.target, _attachment_model_in_expr(node.value, self.attachment_names, self._effective_constants())
            )
            self._mark_attachment_value_target(node.target, node.value)
            self._mark_archive_target_from_value(node.target, node.value, self._is_tainted_archive_open(node.value))
            self._mark_secure_filename_target(node.target, self._expr_uses_secure_filename(node.value))
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        if self._expr_is_tainted(node.iter):
            self._mark_name_target(node.target, self.tainted_names)
        else:
            self._discard_name_target(node.target, self.tainted_names)
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit_For(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_local_constant_target(node.target, node.value)
        is_attachment = _attachment_model_in_expr(node.value, self.attachment_names, self._effective_constants())
        is_decoded_upload = self._is_base64_decode(node.value) and _call_has_tainted_input(
            node.value, self._expr_is_tainted
        )
        is_tainted_archive = self._is_tainted_archive_open(node.value)
        is_secure_filename = self._expr_uses_secure_filename(node.value)
        self._mark_tainted_target(node.target, node.value)
        self._mark_decoded_upload_target(node.target, is_decoded_upload)
        self._mark_attachment_target(node.target, is_attachment)
        self._mark_attachment_value_target(node.target, node.value)
        self._mark_archive_target_from_value(node.target, node.value, is_tainted_archive)
        self._mark_secure_filename_target(node.target, is_secure_filename)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        sink = self._canonical_call_name(node.func)
        self._mark_attachment_value_update_call(node)
        if sink == "open":
            self._scan_open(node)
        elif sink in SHUTIL_WRITE_SINKS:
            self._scan_shutil_write(node, sink)
        elif _is_path_write(node):
            self._scan_path_write(node, sink)
        elif _is_attachment_create(node, self.attachment_names, self._effective_constants()):
            self._scan_attachment_create(node)
        elif self._is_archive_extract(node, sink):
            self._scan_archive_extract(node, sink)
        elif sink in UNSAFE_TEMPFILE_SINKS and _call_has_tainted_input(node, self._expr_is_tainted):
            self._scan_unsafe_tempfile(node, sink)
        elif self._is_base64_decode(node) and _call_has_tainted_input(node, self._expr_is_tainted):
            self._add(
                "odoo-file-upload-base64-decode",
                "Request-derived base64 upload is decoded",
                "medium",
                node.lineno,
                "Request-derived base64 data is decoded; verify size limits, MIME validation, and storage destination",
                "base64.b64decode",
            )
        self.generic_visit(node)

    def _scan_open(self, node: ast.Call) -> None:
        if not node.args:
            return
        mode = _open_mode(node, self._effective_constants())
        if not any(flag in mode for flag in ("w", "a", "x", "+")):
            return
        if self._expr_is_tainted(node.args[0]):
            self._add(
                "odoo-file-upload-tainted-path-write",
                "Request-controlled path is opened for write",
                "high",
                node.lineno,
                "open() writes to a request-controlled path; validate basename, extension, destination, and traversal handling",
                "open",
            )
        if self._expr_uses_secure_filename(node.args[0]):
            self._scan_secure_filename_path_write(node, "open")

    def _scan_shutil_write(self, node: ast.Call, sink: str) -> None:
        if len(node.args) >= 2 and self._expr_is_tainted(node.args[1]):
            self._add(
                "odoo-file-upload-tainted-path-write",
                "Request-controlled path receives file copy/move",
                "high",
                node.lineno,
                f"{sink} writes to a request-controlled destination; validate basename, extension, destination, and traversal handling",
                sink,
            )
        if len(node.args) >= 2 and self._expr_uses_secure_filename(node.args[1]):
            self._scan_secure_filename_path_write(node, sink)

    def _scan_path_write(self, node: ast.Call, sink: str) -> None:
        if isinstance(node.func, ast.Attribute) and self._expr_is_tainted(node.func.value):
            self._add(
                "odoo-file-upload-tainted-path-write",
                "Request-controlled Path object is written",
                "high",
                node.lineno,
                "Path write uses a request-controlled path; validate basename, extension, destination, and traversal handling",
                sink,
            )
        if isinstance(node.func, ast.Attribute) and self._expr_uses_secure_filename(node.func.value):
            self._scan_secure_filename_path_write(node, sink)

    def _scan_attachment_create(self, node: ast.Call) -> None:
        values = self._attachment_create_values(node)
        if values is None:
            return
        dict_values = {
            key.value: value
            for key, value in zip(values.keys, values.values)
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        if "datas" in dict_values and self._expr_is_tainted(dict_values["datas"]):
            self._add(
                "odoo-file-upload-attachment-from-request",
                "Attachment is created from request-derived upload data",
                "medium",
                node.lineno,
                "ir.attachment is created from request-derived data; verify size, MIME, ACLs, res_model/res_id binding, and public flag",
                "ir.attachment.create",
            )
        public_value = dict_values.get("public")
        if public_value and _is_true_constant(public_value, self._effective_constants()):
            self._add(
                "odoo-file-upload-public-attachment-create",
                "Uploaded attachment is created public",
                "high",
                node.lineno,
                "ir.attachment.create sets public=True; verify uploaded content is intentionally world-readable",
                "ir.attachment.create",
            )

    def _scan_archive_extract(self, node: ast.Call, sink: str) -> None:
        archive_is_tainted = isinstance(node.func, ast.Attribute) and self._is_tainted_archive(node.func.value)
        target_is_tainted = _call_has_tainted_input(node, self._expr_is_tainted)
        severity = "critical" if archive_is_tainted or target_is_tainted else "high"
        self._add(
            "odoo-file-upload-archive-extraction",
            "Archive extraction requires traversal review",
            severity,
            node.lineno,
            "Archive extract/extractall can write files outside the intended directory through crafted member names; validate every member path before extraction",
            sink,
        )

    def _scan_secure_filename_path_write(self, node: ast.Call, sink: str) -> None:
        self._add(
            "odoo-file-upload-secure-filename-only",
            "Upload path write relies on secure_filename only",
            "medium",
            node.lineno,
            "secure_filename() normalizes a basename but does not enforce destination, extension, content type, uniqueness, or overwrite handling",
            sink,
        )

    def _scan_unsafe_tempfile(self, node: ast.Call, sink: str) -> None:
        self._add(
            "odoo-file-upload-unsafe-tempfile",
            "Upload flow uses tempfile.mktemp",
            "high",
            node.lineno,
            "tempfile.mktemp() creates predictable race-prone paths; use mkstemp(), NamedTemporaryFile(), or TemporaryDirectory() with controlled permissions",
            sink,
        )

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_request_derived(node):
            return True
        if isinstance(node, ast.Starred):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Name):
            return (
                node.id in self.tainted_names
                or node.id in self.decoded_uploads
                or node.id in self.tainted_archive_names
                or node.id in self.secure_filename_names
            )
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted(node.value) or self._expr_is_tainted(node.slice)
        if isinstance(node, ast.Attribute):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Call):
            return (
                self._is_request_derived(node)
                or self._expr_is_tainted(node.func)
                or any(self._expr_is_tainted(arg) for arg in node.args)
                or any(keyword.value is not None and self._expr_is_tainted(keyword.value) for keyword in node.keywords)
            )
        if isinstance(node, ast.JoinedStr):
            return any(self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.BinOp):
            return self._expr_is_tainted(node.left) or self._expr_is_tainted(node.right)
        if isinstance(node, ast.BoolOp):
            return any(self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.Compare):
            return self._expr_is_tainted(node.left) or any(
                self._expr_is_tainted(comparator) for comparator in node.comparators
            )
        if isinstance(node, ast.IfExp):
            return (
                self._expr_is_tainted(node.test)
                or self._expr_is_tainted(node.body)
                or self._expr_is_tainted(node.orelse)
            )
        if isinstance(node, ast.Dict):
            return any(value is not None and self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._expr_is_tainted(element) for element in node.elts)
        if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp):
            return self._expr_is_tainted(node.elt) or any(
                self._expr_is_tainted(generator.iter)
                or any(self._expr_is_tainted(condition) for condition in generator.ifs)
                for generator in node.generators
            )
        if isinstance(node, ast.DictComp):
            return (
                self._expr_is_tainted(node.key)
                or self._expr_is_tainted(node.value)
                or any(
                    self._expr_is_tainted(generator.iter)
                    or any(self._expr_is_tainted(condition) for condition in generator.ifs)
                    for generator in node.generators
                )
            )
        if isinstance(node, ast.NamedExpr):
            return self._expr_is_tainted(node.value)
        return False

    def _mark_tainted_target(self, target: ast.AST, value: ast.AST) -> None:
        is_tainted = self._is_request_derived(value) or self._expr_is_tainted(value)
        if isinstance(target, ast.Name):
            if is_tainted:
                self.tainted_names.add(target.id)
            else:
                self.tainted_names.discard(target.id)
            return

        if isinstance(target, ast.Starred):
            self._mark_tainted_target(target.value, value)
            return

        if isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List):
                for target_element, value_element in _unpack_target_value_pairs(target, value):
                    self._mark_tainted_target(target_element, value_element)
            elif is_tainted:
                for target_element in target.elts:
                    self._mark_name_target(target_element, self.tainted_names)
            else:
                self._discard_name_target(target, self.tainted_names)

    def _mark_name_target(self, target: ast.AST, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Starred):
            self._mark_name_target(target.value, names)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._mark_name_target(element, names)

    def _discard_name_target(self, target: ast.AST, names: set[str]) -> None:
        if isinstance(target, ast.Name):
            names.discard(target.id)
        elif isinstance(target, ast.Starred):
            self._discard_name_target(target.value, names)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_name_target(element, names)

    def _mark_local_constant_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_local_constant_target(target_element, value_element)
            return

        if isinstance(target, ast.Name):
            if _is_static_literal(value):
                self.local_constants[target.id] = value
            else:
                self.local_constants.pop(target.id, None)
            return

        if isinstance(target, ast.Starred):
            self._mark_local_constant_target(target.value, value)
            return

        if isinstance(target, ast.Tuple | ast.List):
            self._discard_local_constant_target(target)

    def _discard_local_constant_target(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.local_constants.pop(target.id, None)
        elif isinstance(target, ast.Starred):
            self._discard_local_constant_target(target.value)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_local_constant_target(element)

    def _effective_constants(self) -> dict[str, ast.AST]:
        constants = self.constants
        if self.class_constants_stack:
            constants = dict(constants)
            for class_constants in self.class_constants_stack:
                constants.update(class_constants)
        if self.local_constants:
            constants = {**constants, **self.local_constants}
        return constants

    def _mark_decoded_upload_target(self, target: ast.AST, is_decoded_upload: bool) -> None:
        if is_decoded_upload:
            self._mark_name_target(target, self.decoded_uploads)
        else:
            self._discard_name_target(target, self.decoded_uploads)

    def _mark_attachment_target(self, target: ast.AST, is_attachment: bool) -> None:
        if isinstance(target, ast.Name):
            if is_attachment:
                self.attachment_names.add(target.id)
            else:
                self.attachment_names.discard(target.id)
        elif isinstance(target, ast.Starred):
            self._mark_attachment_target(target.value, is_attachment)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._mark_attachment_target(element, is_attachment)

    def _mark_attachment_value_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_attachment_value_target(target_element, value_element)
            return
        if isinstance(target, ast.Starred):
            self._mark_attachment_value_target(target.value, value)
            return
        if isinstance(target, ast.Name):
            if isinstance(value, ast.Dict) and _dict_mentions_attachment_create_values(value):
                self.attachment_value_names[target.id] = value
            elif isinstance(value, ast.Name) and value.id in self.attachment_value_names:
                self.attachment_value_names[target.id] = self.attachment_value_names[value.id]
            else:
                self.attachment_value_names.pop(target.id, None)

    def _mark_attachment_value_item_target(self, target: ast.AST, value: ast.AST) -> None:
        if not isinstance(target, ast.Subscript) or not isinstance(target.value, ast.Name):
            return
        name = target.value.id
        values = self.attachment_value_names.get(name)
        if values is None:
            return
        key = _literal_string(target.slice, self._effective_constants())
        if key:
            self.attachment_value_names[name] = _dict_with_field(values, key, value)

    def _mark_attachment_value_update_call(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "update":
            return
        if not isinstance(node.func.value, ast.Name):
            return
        name = node.func.value.id
        values = self.attachment_value_names.get(name)
        if values is None:
            return
        update_values = node.args[0] if node.args else None
        if not isinstance(update_values, ast.Dict):
            return
        merged = values
        for key, value in zip(update_values.keys, update_values.values, strict=False):
            literal_key = _literal_string(key, self._effective_constants()) if key is not None else ""
            if literal_key:
                merged = _dict_with_field(merged, literal_key, value)
        self.attachment_value_names[name] = merged

    def _attachment_create_values(self, node: ast.Call) -> ast.Dict | None:
        values = node.args[0] if node.args else None
        if values is None:
            for keyword in node.keywords:
                if keyword.arg in {"vals", "values"}:
                    values = keyword.value
                    break
        if isinstance(values, ast.Name) and values.id in self.attachment_value_names:
            values = self.attachment_value_names[values.id]
        return values if isinstance(values, ast.Dict) else None

    def _mark_archive_target(self, target: ast.AST, is_tainted_archive: bool) -> None:
        if isinstance(target, ast.Name):
            if is_tainted_archive:
                self.tainted_archive_names.add(target.id)
            else:
                self.tainted_archive_names.discard(target.id)
        elif isinstance(target, ast.Starred):
            self._mark_archive_target(target.value, is_tainted_archive)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._mark_archive_target(element, is_tainted_archive)

    def _mark_archive_target_from_value(
        self, target: ast.AST, value: ast.AST, is_tainted_archive: bool | None = None
    ) -> None:
        if isinstance(target, ast.Starred):
            self._mark_archive_target_from_value(target.value, value, is_tainted_archive)
            return

        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            for target_element, value_element in _unpack_target_value_pairs(target, value):
                self._mark_archive_target_from_value(target_element, value_element)
            return

        if is_tainted_archive is None:
            is_tainted_archive = self._is_tainted_archive(value)
        self._mark_archive_target(target, is_tainted_archive)

    def _mark_secure_filename_target(self, target: ast.AST, is_secure_filename: bool) -> None:
        if isinstance(target, ast.Name):
            if is_secure_filename:
                self.secure_filename_names.add(target.id)
            else:
                self.secure_filename_names.discard(target.id)
        elif isinstance(target, ast.Starred):
            self._mark_secure_filename_target(target.value, is_secure_filename)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._mark_secure_filename_target(element, is_secure_filename)

    def _is_base64_decode(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Call) and self._canonical_call_name(node.func) in {"base64.b64decode", "b64decode"}

    def _is_tainted_archive_open(self, node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Call)
            and self._canonical_call_name(node.func) in ARCHIVE_OPEN_SINKS
            and _call_has_tainted_input(node, self._expr_is_tainted)
        )

    def _is_tainted_archive(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Starred):
            return self._is_tainted_archive(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.tainted_archive_names
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._is_tainted_archive(element) for element in node.elts)
        if isinstance(node, ast.Call):
            return self._is_tainted_archive_open(node)
        if isinstance(node, ast.Subscript):
            return self._is_tainted_archive(node.value) or self._is_tainted_archive(node.slice)
        return False

    def _is_archive_extract(self, node: ast.Call, sink: str) -> bool:
        if not isinstance(node.func, ast.Attribute) or node.func.attr not in ARCHIVE_EXTRACT_METHODS:
            return False
        if sink in {
            "tarfile.TarFile.extract",
            "tarfile.TarFile.extractall",
            "zipfile.ZipFile.extract",
            "zipfile.ZipFile.extractall",
        }:
            return True
        if self._is_tainted_archive(node.func.value):
            return True
        if (
            isinstance(node.func.value, ast.Call)
            and self._canonical_call_name(node.func.value.func) in ARCHIVE_OPEN_SINKS
        ):
            return True
        return _call_name(node.func.value) in {"tarfile.open", "zipfile.ZipFile"}

    def _is_secure_filename_from_upload(self, node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Call)
            and self._canonical_call_name(node.func) in SECURE_FILENAME_SINKS
            and _call_has_tainted_input(node, self._expr_is_tainted)
        )

    def _expr_uses_secure_filename(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Starred):
            return self._expr_uses_secure_filename(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.secure_filename_names
        if isinstance(node, ast.Call):
            return (
                self._is_secure_filename_from_upload(node)
                or any(self._expr_uses_secure_filename(arg) for arg in node.args)
                or any(
                    keyword.value is not None and self._expr_uses_secure_filename(keyword.value)
                    for keyword in node.keywords
                )
            )
        if isinstance(node, ast.Attribute):
            return self._expr_uses_secure_filename(node.value)
        if isinstance(node, ast.Subscript):
            return self._expr_uses_secure_filename(node.value) or self._expr_uses_secure_filename(node.slice)
        if isinstance(node, ast.JoinedStr):
            return any(self._expr_uses_secure_filename(value) for value in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._expr_uses_secure_filename(node.value)
        if isinstance(node, ast.BinOp):
            return self._expr_uses_secure_filename(node.left) or self._expr_uses_secure_filename(node.right)
        if isinstance(node, ast.BoolOp):
            return any(self._expr_uses_secure_filename(value) for value in node.values)
        if isinstance(node, ast.IfExp):
            return (
                self._expr_uses_secure_filename(node.test)
                or self._expr_uses_secure_filename(node.body)
                or self._expr_uses_secure_filename(node.orelse)
            )
        if isinstance(node, ast.Dict):
            return any(value is not None and self._expr_uses_secure_filename(value) for value in node.values)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._expr_uses_secure_filename(element) for element in node.elts)
        return False

    def _canonical_call_name(self, node: ast.AST) -> str:
        sink = _call_name(node)
        if sink in self.function_aliases:
            return self.function_aliases[sink]
        parts = sink.split(".")
        if parts and parts[0] in self.module_aliases:
            return ".".join([self.module_aliases[parts[0]], *parts[1:]])
        return sink

    def _is_request_derived(self, node: ast.AST) -> bool:
        return _is_request_derived(
            node,
            self.request_names,
            self.http_module_names,
            self.odoo_module_names,
        )

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, sink: str) -> None:
        self.findings.append(
            FileUploadFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                sink=sink,
            )
        )


def _is_request_derived(
    node: ast.AST,
    request_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    request_names = request_names or {"request"}
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    if _is_request_expr(node, request_names, http_module_names, odoo_module_names):
        return True
    if isinstance(node, ast.Attribute):
        if node.attr in {"params", "jsonrequest", "httprequest"} and _is_request_expr(
            node.value,
            request_names,
            http_module_names,
            odoo_module_names,
        ):
            return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"get_http_params", "get_json_data"} and _is_request_expr(
            node.func.value,
            request_names,
            http_module_names,
            odoo_module_names,
        ):
            return True
    text = _safe_unparse(node)
    return any(
        marker in text
        for marker in (
            "request.params",
            "request.httprequest",
            "request.get_http_params",
            "request.get_json_data",
            "request.jsonrequest",
            "kwargs.get",
            "kw.get",
            "post.get",
        )
    )


def _is_request_expr(
    node: ast.AST,
    request_names: set[str],
    http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in request_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "request"
        and _is_http_module_expr(node.value, http_module_names, odoo_module_names)
    )


def _function_is_http_route(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    route_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    return any(
        _is_http_route(decorator, route_names, http_module_names, odoo_module_names)
        for decorator in node.decorator_list
    )


def _is_http_route(
    node: ast.AST,
    route_names: set[str] | None = None,
    http_module_names: set[str] | None = None,
    odoo_module_names: set[str] | None = None,
) -> bool:
    route_names = route_names or set()
    http_module_names = http_module_names or {"http"}
    odoo_module_names = odoo_module_names or {"odoo"}
    target = node.func if isinstance(node, ast.Call) else node
    return (
        isinstance(target, ast.Attribute)
        and target.attr == "route"
        and _is_http_module_expr(target.value, http_module_names, odoo_module_names)
    ) or (isinstance(target, ast.Name) and target.id in route_names)


def _is_http_module_expr(
    node: ast.AST,
    http_module_names: set[str],
    odoo_module_names: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in http_module_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "http"
        and isinstance(node.value, ast.Name)
        and node.value.id in odoo_module_names
    )


def _call_has_tainted_input(node: ast.Call, is_tainted: Any) -> bool:
    return any(is_tainted(arg) for arg in node.args) or any(
        keyword.value is not None and is_tainted(keyword.value) for keyword in node.keywords
    )


def _is_path_write(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Attribute) and node.func.attr in FILE_WRITE_METHODS


def _is_attachment_create(
    node: ast.Call,
    attachment_names: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "create"
        and _attachment_model_in_expr(node.func.value, attachment_names, constants)
    )


def _dict_mentions_attachment_create_values(node: ast.Dict) -> bool:
    for key in node.keys:
        if isinstance(key, ast.Constant) and key.value in ATTACHMENT_CREATE_VALUE_KEYS:
            return True
    return False


def _dict_with_field(values: ast.Dict, key: str, value: ast.AST) -> ast.Dict:
    keys = list(values.keys)
    values_list = list(values.values)
    for index, existing_key in enumerate(keys):
        if isinstance(existing_key, ast.Constant) and existing_key.value == key:
            values_list[index] = value
            return ast.Dict(keys=keys, values=values_list)
    keys.append(ast.Constant(value=key))
    values_list.append(value)
    return ast.Dict(keys=keys, values=values_list)


def _attachment_model_in_expr(
    node: ast.AST,
    attachment_names: set[str],
    constants: dict[str, ast.AST] | None = None,
) -> bool:
    constants = constants or {}
    resolved = _resolve_constant(node, constants)
    if resolved is not node:
        return _attachment_model_in_expr(resolved, attachment_names, constants)
    if "ir.attachment" in _safe_unparse(node):
        return True
    if any(_literal_string(child, constants) == "ir.attachment" for child in ast.walk(node)):
        return True
    if isinstance(node, ast.Starred):
        return _attachment_model_in_expr(node.value, attachment_names, constants)
    if isinstance(node, ast.Name):
        return node.id in attachment_names
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_attachment_model_in_expr(element, attachment_names, constants) for element in node.elts)
    if isinstance(node, ast.Attribute):
        return _attachment_model_in_expr(node.value, attachment_names, constants)
    if isinstance(node, ast.Call):
        return _attachment_model_in_expr(node.func, attachment_names, constants)
    if isinstance(node, ast.Subscript):
        return _attachment_model_in_expr(node.value, attachment_names, constants)
    return False


def _open_mode(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> str:
    if len(node.args) > 1:
        mode = _literal_string(node.args[1], constants)
        if mode:
            return mode
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode = _literal_string(keyword.value, constants)
            if mode:
                return mode
    return "r"


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
    return ""


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _module_constants(tree: ast.Module) -> dict[str, ast.AST]:
    return _static_constants_from_body(tree.body)


def _static_constants_from_body(statements: list[ast.stmt]) -> dict[str, ast.AST]:
    constants: dict[str, ast.AST] = {}
    for statement in statements:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name) and _is_static_literal(statement.value):
                    constants[target.id] = statement.value
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.value is not None
            and _is_static_literal(statement.value)
        ):
            constants[statement.target.id] = statement.value
    return constants


def _resolve_constant(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> ast.AST:
    return _resolve_constant_seen(node, constants or {}, set())


def _resolve_constant_seen(node: ast.AST, constants: dict[str, ast.AST], seen: set[str]) -> ast.AST:
    if isinstance(node, ast.Name):
        if node.id in seen:
            return node
        value = constants.get(node.id)
        if value is None:
            return node
        return _resolve_constant_seen(value, constants, {*seen, node.id})
    return node


def _is_static_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return True
    return isinstance(node, ast.Constant) and isinstance(node.value, str | bool | int | float | type(None))


def _literal_string(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> str:
    value = _resolve_constant(node, constants)
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return ""


def _is_true_constant(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    value = _resolve_constant(node, constants)
    return isinstance(value, ast.Constant) and value.value is True


def _unpack_target_value_pairs(
    target: ast.Tuple | ast.List,
    value: ast.Tuple | ast.List,
) -> list[tuple[ast.AST, ast.AST]]:
    starred_index = next(
        (index for index, element in enumerate(target.elts) if isinstance(element, ast.Starred)),
        None,
    )
    if starred_index is None:
        return list(zip(target.elts, value.elts, strict=False))

    before = list(zip(target.elts[:starred_index], value.elts[:starred_index], strict=False))
    trailing_target_count = len(target.elts) - starred_index - 1
    after_values_start = max(len(value.elts) - trailing_target_count, starred_index)
    rest_value = ast.List(elts=value.elts[starred_index:after_values_start], ctx=ast.Load())
    after = list(zip(target.elts[starred_index + 1 :], value.elts[after_values_start:], strict=False))
    return [*before, (target.elts[starred_index], rest_value), *after]


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[FileUploadFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
        }
        for f in findings
    ]
