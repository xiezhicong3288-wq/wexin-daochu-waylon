#!/usr/bin/env python3
"""Restricted local adapter for the locked Moect 1.2.8 source.

The adapter uses core.data.Archive/core.exporting, never Service or the GUI.
Its Python audit guard blocks networking, subprocesses and writes outside this
run. This is defense in depth for the reviewed source, not an OS sandbox for
arbitrary native code. Windows capture is implemented but requires real-device
acceptance; account ownership is not authenticated by a supplied wxid.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import importlib
import importlib.metadata
import importlib.util
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import sqlite3
import stat
import struct
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
import xml.etree.ElementTree as ET

COMMIT = "88dffc7d0d06632f8061b0a19aa82b38337d7ee5"
LOCK = Path(__file__).resolve().parent.parent / "references" / "upstream-lock.json"
TZ = timezone(timedelta(hours=8))
SQLITE_HEADER = b"SQLite format 3\0"
DEPENDENCIES = {"psutil": ("psutil", "7.2.2"), "Cryptodome": ("pycryptodomex", "3.24.1"),
                "zstandard": ("zstandard", "0.25.0"), "PIL": ("Pillow", "12.0.0")}
if sys.platform == "win32":
    # Windows does not provide the IANA rules used by ZoneInfo.
    DEPENDENCIES["tzdata"] = ("tzdata", "2026.6")
sys.dont_write_bytecode = True


def load_support(name):
    spec = importlib.util.spec_from_file_location("moect_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


source_audit = load_support("source_audit")
wal_guard = load_support("wal_guard")

MESSAGES = {
    "arguments_invalid": "The explicit command or scope is invalid.",
    "path_invalid": "Use an absolute local path without links or reparse points.",
    "output_exists": "The output directory must not already exist.",
    "path_overlap": "Input, upstream and output directories must be separate.",
    "upstream_untrusted": "The upstream source does not match the approved lock.",
    "dependency_missing": "A required local dependency is missing.",
    "dependency_mismatch": "The local dependencies do not match the approved versions.",
    "snapshot_invalid": "A complete decrypted SQLite snapshot is required.",
    "source_manifest_invalid": "The fixed source manifest is invalid.",
    "source_manifest_mismatch": "The observed files differ from the fixed source manifest; inspect the local receipt.",
    "source_scope_invalid": "The independent source scope is invalid.",
    "source_schema_unsupported": "A selected source table cannot be independently accounted for.",
    "source_locator_unsupported": "A physical source-row locator is unavailable.",
    "source_query_failed": "The independent source query failed; inspect the local receipt.",
    "source_reconciliation_failed": "Saved records do not reconcile with the independent source reference.",
    "wal_invalid_or_unsupported": "A database log is invalid or its stored-byte format is unsupported; inspect the local receipt.",
    "rollback_journal_unsupported": "A nonempty rollback journal requires a supported acquisition method.",
    "orphan_database_log": "A database log has no corresponding database in the frozen inventory.",
    "source_changed": "The source changed during this run; the result is incomplete.",
    "session_missing": "A requested session was not found; no broader scope was substituted.",
    "decode_failed": "A message could not be decoded without losing bytes.",
    "message_build_failed": "A source row could not be interpreted; its local source position is recorded.",
    "network_disabled": "Networking is disabled in this adapter process.",
    "subprocess_disabled": "Child processes are disabled in this adapter process.",
    "write_outside_run": "A write outside the new run directory was blocked.",
    "import_disabled": "A desktop, online or unapproved memory-reading entry was blocked.",
    "cancelled": "The run was cancelled; incomplete results are marked as such.",
    "capture_approval_required": "Live memory reading requires the explicit approval flag.",
    "windows_required": "Live capture requires the authorized Windows computer.",
    "process_not_bound": "The selected process could not be bound to the specified account directory.",
    "process_changed": "The selected process changed; capture was stopped.",
    "capture_timeout": "The bounded memory-read deadline was reached.",
    "keys_incomplete": "Not all selected databases have verified in-memory keys.",
    "capture_incomplete": "The captured databases did not all pass validation.",
    "private_directory_failed": "A private output directory could not be created.",
    "operation_failed": "The operation failed; sensitive exception details were suppressed.",
}


class BridgeError(RuntimeError):
    def __init__(self, code, details=None):
        self.code = code
        self.details = details or {}
        super().__init__(MESSAGES.get(code, MESSAGES["operation_failed"]))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def is_link(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & 0x400
    )


def checked_path(value, *, exists=True, directory=True):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or str(path).startswith(("\\\\", "//")):
        raise BridgeError("path_invalid")
    # Reject NTFS alternate data streams, device paths and drive-relative paths.
    if os.name == "nt" and any(":" in part for part in path.parts[1:]):
        raise BridgeError("path_invalid")
    for component in reversed((path, *path.parents)):
        if component.exists() or component.is_symlink():
            if is_link(component):
                raise BridgeError("path_invalid")
    if exists and (not path.exists() or (directory and not path.is_dir()) or
                   (not directory and not path.is_file())):
        raise BridgeError("path_invalid")
    return path.absolute()


def checked_tree(root):
    checked_path(root)
    for parent, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            path = Path(parent) / name
            if is_link(path):
                raise BridgeError("path_invalid")
            if name in files and not path.is_file():
                raise BridgeError("path_invalid")


def separate(*paths):
    for index, a in enumerate(paths):
        for b in paths[index + 1:]:
            if a == b or a.is_relative_to(b) or b.is_relative_to(a):
                raise BridgeError("path_overlap")


def verify_upstream(root, lock_path=LOCK):
    root = checked_path(root)
    try:
        manifest = json.loads(Path(lock_path).read_text(encoding="utf-8"))
        files = manifest["files"]
        if (manifest["schema_version"] != 1 or manifest["commit"] != COMMIT or
                manifest["ref"] != "v1.2.8" or
                manifest["repository"] != "https://github.com/mofan6/Moect" or not files):
            raise ValueError()
        for name, expected in files.items():
            rel = PurePosixPath(name)
            if rel.is_absolute() or ".." in rel.parts or "\\" in name or ":" in name:
                raise ValueError()
            file = checked_path(root / name, directory=False)
            if not re.fullmatch(r"[0-9a-f]{64}", expected) or sha256(file) != expected:
                raise ValueError()
        checked_tree(root)
        for file in root.rglob("*"):
            # This is the prepared source subset, not an arbitrary checkout.
            # Root-level modules can otherwise impersonate installed dependencies.
            if file.is_file() and file.suffix.lower() in (".py", ".pyc", ".pyo", ".pyd", ".so", ".dll"):
                if file.relative_to(root).as_posix() not in files:
                    raise ValueError()
        required = {"core/data.py", "core/exporting.py", "core/resources.py", "wx4/reader.py", "wx4/key.py"}
        if not required.issubset(files):
            raise ValueError()
    except (OSError, ValueError, KeyError, TypeError):
        raise BridgeError("upstream_untrusted") from None
    return manifest


class Guard:
    """One permanent audit hook in a short-lived, dedicated CLI process."""
    def __init__(self, write_root=None):
        self.root = write_root
        self.allow_key = False
        self.cancelled = False

    def write(self, value, dir_fd=None):
        if isinstance(value, int):
            return
        try:
            value = os.fsdecode(value)
            if not os.path.isabs(value) and isinstance(dir_fd, int) and dir_fd >= 0 and sys.platform == "linux":
                value = str(Path(os.readlink("/proc/self/fd/" + str(dir_fd))) / value)
            path = checked_path(value, exists=False)
        except (TypeError, ValueError, OSError):
            raise BridgeError("write_outside_run") from None
        if self.root is None or not path.is_relative_to(self.root):
            raise BridgeError("write_outside_run")

    def audit(self, event, args):
        if event.startswith("socket."):
            raise BridgeError("network_disabled")
        if event in ("subprocess.Popen", "os.system", "os.posix_spawn", "os.exec", "os.fork", "os.forkpty", "pty.spawn"):
            raise BridgeError("subprocess_disabled")
        if event == "import":
            name = args[0]
            if name in ("core.service", "core.online", "core.online_protocol", "wx4.cli", "wx4.gui") or (
                    name == "wx4.key" and not self.allow_key):
                raise BridgeError("import_disabled")
        if event == "open":
            mode, flags = args[1], args[2]
            if ((isinstance(mode, str) and any(ch in mode for ch in "wax+")) or
                    (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))):
                self.write(args[0])
        if event in ("os.remove", "os.rmdir"):
            self.write(args[0], args[1] if len(args) > 1 else None)
        if event in ("os.mkdir", "os.chmod"):
            self.write(args[0], args[2] if len(args) > 2 else None)
        if event == "os.utime":
            self.write(args[0], args[3] if len(args) > 3 else None)
        if event == "os.rename":
            self.write(args[0], args[2] if len(args) > 2 else None)
            self.write(args[1], args[3] if len(args) > 3 else None)
        if event in ("os.symlink", "os.link"):
            raise BridgeError("write_outside_run")

    def check(self):
        if self.cancelled:
            raise BridgeError("cancelled")


def private_mkdir(path):
    if path.exists():
        raise BridgeError("output_exists")
    if os.name != "nt":
        path.mkdir(mode=0o700)
        return
    # Supply the protected DACL at creation, before writing any sensitive bytes.
    import ctypes
    from ctypes import wintypes as wt
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    token = wt.HANDLE(); needed = wt.DWORD(); sid_text = wt.LPWSTR(); descriptor = ctypes.c_void_p()
    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("length", wt.DWORD), ("descriptor", ctypes.c_void_p), ("inherit", wt.BOOL)]
    kernel.GetCurrentProcess.restype = wt.HANDLE
    adv.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    adv.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD)]
    adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.LPWSTR)]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wt.LPCWSTR, wt.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    kernel.CreateDirectoryW.argtypes = [wt.LPCWSTR, ctypes.POINTER(SecurityAttributes)]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [wt.HANDLE]
    try:
        if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            raise OSError()
        adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        info = ctypes.create_string_buffer(needed.value)
        if not adv.GetTokenInformation(token, 1, info, needed, ctypes.byref(needed)):
            raise OSError()
        sid = ctypes.cast(info, ctypes.POINTER(ctypes.c_void_p))[0]
        if not adv.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise OSError()
        sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + sid_text.value + ")"
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise OSError()
        attrs = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        if not kernel.CreateDirectoryW(str(path), ctypes.byref(attrs)):
            raise OSError()
    except OSError:
        raise BridgeError("private_directory_failed") from None
    finally:
        if token: kernel.CloseHandle(token)
        if sid_text: kernel.LocalFree(ctypes.cast(sid_text, ctypes.c_void_p))
        if descriptor: kernel.LocalFree(descriptor)


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with open(temporary, "x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    os.replace(temporary, path)


def db_manifest(root):
    checked_tree(root)
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name.endswith((".db", ".db-wal", ".db-shm", ".db-journal")):
            result[path.relative_to(root).as_posix()] = sha256(path)
    if not any(Path(name).name == "session.db" for name in result) or not any(
            re.fullmatch(r"message_\d+\.db", Path(name).name) for name in result):
        raise BridgeError("snapshot_invalid")
    return result


def copy_snapshot(source, destination, check, *, validate=True, expected=None, receipt=None):
    started = datetime.now(timezone.utc).isoformat()
    checked_tree(source)
    before = source_audit.inventory(source)
    binding = source_audit.bind_inventory(before, expected)
    states = {name: {"size": (source / name).stat().st_size, "mtime_ns": (source / name).stat().st_mtime_ns,
                     "sha256": digest} for name, digest in before.items()}
    destination.mkdir(mode=0o700)
    for name, expected in before.items():
        check()
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
        if sha256(target) != expected:
            raise BridgeError("source_changed")
    after = source_audit.inventory(source)
    if after != before or any((source / name).stat().st_mtime_ns != state["mtime_ns"] for name, state in states.items()):
        raise BridgeError("source_changed")
    if receipt is not None:
        receipt.update(started_at=started, ended_at=datetime.now(timezone.utc).isoformat(), files=states,
                       binding=binding, source_unchanged_during_copy=True,
                       copy_sha256_verified=True, cross_database_time_consistency_proven=False)
    if validate: validate_snapshot(destination)
    return before


def validate_database_files(root, *, encrypted=False, check=lambda: None):
    files = db_manifest(root)
    report = {"files": {}, "cross_database_time_consistency_proven": False,
              "database_log_pair_basis": "same_relative_path_in_frozen_acquisition_inventory",
              "cryptographic_database_log_pair_identity_proven": False}
    for name in files:
        for suffix in ("-wal", "-shm", "-journal"):
            if name.endswith(suffix) and name[:-len(suffix)] not in files:
                raise BridgeError("orphan_database_log", {"file": name})
        if name.endswith(".db-journal") and (root / name).stat().st_size:
            raise BridgeError("rollback_journal_unsupported", {"file": name})
    for name in files:
        if not name.endswith(".db"): continue
        check()
        path = root / name
        with open(path, "rb") as stream: header = stream.read(100)
        if encrypted:
            page_size = 4096
            if path.stat().st_size < page_size or path.stat().st_size % page_size:
                raise BridgeError("snapshot_invalid")
        else:
            if len(header) != 100 or header[:16] != SQLITE_HEADER: raise BridgeError("snapshot_invalid")
            page_size = int.from_bytes(header[16:18], "big")
            if page_size == 1: page_size = 65536
            if page_size < 512 or page_size > 65536 or page_size & (page_size - 1) or path.stat().st_size % page_size:
                raise BridgeError("snapshot_invalid")
        item = {"page_size": page_size, "database_sha256": files[name], "wal_status": "absent_in_frozen_inventory"}
        report["files"][name] = item
        if name + "-wal" in files:
            try:
                item["wal"] = wal_guard.validate_wal(root / (name + "-wal"), expected_page_size=page_size,
                    expected_sha256=files[name + "-wal"], check=check)
                item["wal_status"] = item["wal"]["status"]
            except wal_guard.WalValidationError as error:
                item["wal"] = error.report
                error.database_report = report
                raise
    return report


def validate_snapshot(root):
    validation = validate_database_files(root)
    files = db_manifest(root)
    try:
        for name in files:
            if not name.endswith(".db"):
                continue
            path = root / name
            with open(path, "rb") as stream:
                if stream.read(16) != SQLITE_HEADER:
                    raise BridgeError("snapshot_invalid")
            with contextlib.closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as con:
                con.execute("PRAGMA query_only=ON")
                if con.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                    raise BridgeError("snapshot_invalid")
    except sqlite3.Error:
        raise BridgeError("snapshot_invalid") from None
    validation["sqlite_structure_check"] = "quick_check_ok_not_record_completeness_proof"
    return validation


def epoch_text(value):
    try:
        return datetime.fromtimestamp(int(value), TZ).strftime("%Y-%m-%d %H:%M:%S") if value else ""
    except (ValueError, TypeError, OverflowError, OSError):
        return ""


def add_export_metadata(path, fmt, fields):
    """Add an explicit account scope without loading a large message array."""
    temporary = path.with_name(path.name + ".bridge-tmp")
    with open(path, "r", encoding="utf-8") as original, open(temporary, "x", encoding="utf-8") as updated:
        if fmt == "json":
            head = original.read(131072)
            prefix = '{"metadata":'
            if not head.startswith(prefix): raise BridgeError("operation_failed")
            metadata, stop = json.JSONDecoder().raw_decode(head, len(prefix))
            metadata.update(fields)
            updated.write(prefix + json.dumps(metadata, ensure_ascii=False) + head[stop:])
        elif fmt == "jsonl":
            first = original.readline(131072)
            record = json.loads(first); record["metadata"].update(fields)
            updated.write(json.dumps(record, ensure_ascii=False) + "\n")
        else:
            found = False
            for line in original:
                if line.startswith("const manifest="):
                    metadata = json.loads(line[len("const manifest="):].strip().removesuffix(";"))
                    metadata.update(fields)
                    line = "const manifest=" + json.dumps(metadata, ensure_ascii=False).replace("<", "\\u003c") + ";\n"
                    found = True
                updated.write(line)
            if not found: raise BridgeError("operation_failed")
        shutil.copyfileobj(original, updated)
    os.replace(temporary, path)


def saved_export_records(output, results):
    """Read actual saved payloads; build callbacks cannot prove a write happened."""
    for result in results:
        path = checked_path(output / result["path"], directory=False)
        if not path.is_relative_to(output): raise BridgeError("path_invalid")
        fmt = result["format"]
        if fmt == "json":
            with open(path, encoding="utf-8") as stream: document = json.load(stream)
            messages = document["messages"]
            if document.get("count") != len(messages): raise BridgeError("source_reconciliation_failed")
            batches = [(path, messages, "$.messages")]
        elif fmt == "jsonl":
            batches = []
            with open(path, encoding="utf-8") as stream:
                if set(json.loads(next(stream))) != {"metadata"}: raise BridgeError("source_reconciliation_failed")
                for number, line in enumerate(stream, 2):
                    if not line.strip(): raise BridgeError("source_reconciliation_failed")
                    batches.append((path, [json.loads(line)], "line:" + str(number)))
        else:
            with open(path, encoding="utf-8") as stream:
                line = next((line for line in stream if line.startswith("const manifest=")), None)
            if line is None: raise BridgeError("source_reconciliation_failed")
            meta = json.loads(line[len("const manifest="):].strip().removesuffix(";"))
            batches = []
            for chunk in meta["chunks"]:
                if not re.fullmatch(r"c\d{6}\.js", chunk["file"]): raise BridgeError("source_reconciliation_failed")
                file = checked_path(path.parent / chunk["file"], directory=False)
                text = file.read_text(encoding="utf-8")
                if not text.startswith("window.__wxChunk="): raise BridgeError("source_reconciliation_failed")
                messages = json.loads(text[len("window.__wxChunk="):].removesuffix(";"))
                if len(messages) != chunk["count"]: raise BridgeError("source_reconciliation_failed")
                batches.append((file, messages, "$"))
            if sum(len(batch) for _, batch, _ in batches) != meta["count"]: raise BridgeError("source_reconciliation_failed")
        count = 0
        for file, messages, location in batches:
            if not isinstance(messages, list): raise BridgeError("source_reconciliation_failed")
            for index, message in enumerate(messages):
                if not isinstance(message, dict): raise BridgeError("source_reconciliation_failed")
                count += 1
                yield dict(message, export_location={"file": file.relative_to(output).as_posix(),
                    "location": location if fmt == "jsonl" else location + "[" + str(index) + "]"})
        if count != result["count"]: raise BridgeError("source_reconciliation_failed")


def reconcile_saved(output, report, reference, *, failure=None):
    records = list(saved_export_records(output, report["results"]))
    reference["exports"] = [{"path": entry["path"], "sha256": sha256(output / entry["path"]),
                             "format": entry["format"], "count": entry["count"]} for entry in report["results"]]
    atomic_json(output / "source-reference.json", reference)
    rejected = []
    if failure:
        retained = {(m["bridge_source"]["database"], m["bridge_source"]["table"],
                     json.dumps({k: v for k, v in m["bridge_source"].items() if k in ("source_rowid", "source_pk")}, sort_keys=True))
                    for m in records if isinstance(m.get("bridge_source"), dict)}
        for row in reference["rows"]:
            key = (row["database"], row["table"], json.dumps({k: v for k, v in row.items() if k in ("source_rowid", "source_pk")}, sort_keys=True))
            if key not in retained:
                rejected.append({"bridge_source": {k: v for k, v in row.items() if k not in ("raw_fields", "session", "projection_occurrence")},
                    "reason": "run_stopped_without_confirmed_saved_record", "failure_code": failure})
    audit = source_audit.reconcile(reference, records, rejected)
    warnings = []
    stack = [(record, record.get("export_location")) for record in records]
    while stack:
        message, location = stack.pop()
        if not isinstance(message, dict): continue
        if (message.get("bridge_sender") or {}).get("status") == "conflict":
            warnings.append({"code": "sender_source_conflict", "location": location, "source": message.get("bridge_source")})
        if (message.get("bridge_reference") or {}).get("status") == "ambiguous_source_match":
            warnings.append({"code": "quoted_source_ambiguous", "location": location})
        if isinstance(message.get("quote"), dict): stack.append((message["quote"], {"parent": location, "relation": "quote"}))
        for index, child in enumerate((message.get("forward") or {}).get("messages", [])):
            stack.append((child, {"parent": location, "relation": "forward", "index": index}))
    audit["interpretation_warnings"] = warnings
    audit["run_failure_code"] = failure
    atomic_json(output / "source-audit.json", audit)
    report["source_audit"] = {"file": "source-audit.json", "passed": audit["passed"], "counts": audit["counts"],
        "semantic_checks_complete": audit.get("semantic_checks_complete", False),
        "interpretation_warning_count": len(warnings),
        "scope": "selected_rows_within_fixed_supplied_inventory_not_all_history"}
    return audit


def correct_forward_times(record):
    for index, child in enumerate(record.get("messages", [])):
        raw = child.get("_resource_source", "")
        stamp = text_time = original_id = data_id = ""
        try:
            item = ET.fromstring(raw)
            stamp = item.findtext("srcMsgCreateTime") or item.findtext("createtime") or ""
            text_time = item.findtext("sourcetime") or ""
            original_id = item.findtext("fromnewmsgid") or ""
            data_id = item.attrib.get("dataid", "")
        except ET.ParseError:
            pass
        timestamp = 0
        try:
            timestamp = int(stamp)
            if not 0 < timestamp < 253402300800: timestamp = 0
        except (ValueError, TypeError):
            pass
        child["create_time"] = timestamp
        child["time_str"] = epoch_text(timestamp) if timestamp else text_time
        child["bridge_time_status"] = "source_epoch" if timestamp else "source_text_unzoned" if text_time else "unknown"
        child["bridge_forward_index"] = index
        child["bridge_original_timestamp"] = stamp
        child["bridge_id_basis"] = "embedded_original_id" if original_id else "forward_item_id" if data_id else "parser_position"
        child["bridge_original_id"] = original_id or None
        child["bridge_original_time_text"] = text_time
        if child.get("forward"):
            correct_forward_times(child["forward"])
    return record


def sqlite_value(value):
    return {"bytes_base64": base64.b64encode(bytes(value)).decode("ascii")} if isinstance(value, (bytes, bytearray)) else value


def source_projection(con, table):
    """Carry a physical locator from the actual SELECT, not a guessed message ID."""
    q = lambda name: '"' + name.replace('"', '""') + '"'
    columns = con.execute("PRAGMA table_info(" + q(table) + ")").fetchall()
    names = {r[1].casefold() for r in columns}
    without_rowid = any(r[1] == table and r[4] for r in con.execute("PRAGMA table_list"))
    if without_rowid:
        primary = [r[1] for r in sorted(columns, key=lambda r: r[5]) if r[5]]
        if not primary: raise BridgeError("source_locator_unsupported")
        return ''.join(',' + q(name) + ' AS ' + q('__bridge_pk_' + name) for name in primary)
    alias = next((name for name in ('_rowid_', 'rowid', 'oid') if name not in names), None)
    if alias is None: raise BridgeError("source_locator_unsupported")
    return ',' + q(alias) + ' AS "__bridge_rowid"'


def exact_content(row, reader):
    decoded = {}
    raw_fields = {}
    rules = {}
    for field in ("message_content", "compress_content"):
        value = row[field]
        raw_fields[field] = sqlite_value(value)
        try:
            if value is None:
                decoded[field], rules[field] = "", "null"
            elif isinstance(value, str):
                decoded[field], rules[field] = value, "text"
            elif isinstance(value, (bytes, bytearray)):
                blob = bytes(value)
                rule = "utf8"
                if blob.startswith(reader.ZSTD_MAGIC):
                    if reader._ZSTD is None: raise ValueError()
                    blob = reader._ZSTD.decompress(blob, max_output_size=4 * 1024 * 1024)
                    rule = "zstd_utf8"
                decoded[field], rules[field] = blob.decode("utf-8", "strict"), rule
            else:
                raise ValueError()
        except Exception:
            raise BridgeError("decode_failed") from None
    preferred = next((f for f in ("message_content", "compress_content")
                      if rules[f] == "zstd_utf8" and decoded[f]), None)
    if preferred is None:
        preferred = next((f for f in ("compress_content", "message_content") if decoded[f].strip()), None)
    if preferred is None:
        preferred = next((f for f in ("message_content", "compress_content") if decoded[f]), "message_content")
    return {"raw_decoded": decoded[preferred], "source_field": preferred,
            "decode_rule": rules[preferred], "raw_fields": raw_fields,
            "selection_rule": "nonempty_zstd_then_nonblank_compressed_then_message_preserve_whitespace_only"}


def sender_evidence(data, row, names, session, content):
    mapped = names.get(row["real_sender_id"], "")
    prefix = ""
    body = content
    if session.endswith("@chatroom") and "\n" in content[:256]:
        head, rest = content.split("\n", 1)
        head = head.rstrip("\r")
        candidate = head[:-1] if head.endswith(":") else ""
        if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]{1,190}", candidate):
            known = (candidate == mapped or candidate in data.contacts or candidate in names.values()
                     or candidate in data.room_members.get(session, ()))
            recognizable = not mapped and (candidate.startswith("wxid_") or candidate.endswith("@openim"))
            if known or recognizable:
                prefix = candidate
                if not mapped or mapped == prefix: body = rest
    status = "conflict" if mapped and prefix and mapped != prefix else "mapped" if mapped else "prefix_only" if prefix else "unknown"
    selected = "" if status == "conflict" else mapped or prefix
    contact = data.contacts.get(selected) or {}
    return selected, body, {"status": status, "mapped_id": mapped or None, "prefix_id": prefix or None,
        "raw_real_sender_id": sqlite_value(row["real_sender_id"]),
        "selection_rule": "unresolved_conflicting_indicators" if status == "conflict" else "name2id_then_recognized_prefix",
        "display_name_basis": "current_contact_snapshot", "historical_display_name_verified": False,
        "contact_fields": {k: contact.get(k) for k in ("username", "nick_name", "remark", "alias")}}


def load_core(upstream, output):
    if any(name == "core" or name.startswith("core.") or name == "wx4" or name.startswith("wx4.") for name in sys.modules):
        raise BridgeError("upstream_untrusted")
    sys.dont_write_bytecode = True
    sys.path[:] = [entry for entry in sys.path if not Path(entry or os.getcwd()).resolve().is_relative_to(upstream)]
    try:
        # The pinned Cryptodome ctypes backend otherwise runs the external
        # `file` utility via platform.architecture(). Its libraries must match
        # the running interpreter's pointer width, which is already available.
        raw_api = importlib.import_module("Cryptodome.Util._raw_api")
        if hasattr(raw_api, "cached_architecture"):
            raw_api.cached_architecture[:] = (str(struct.calcsize("P") * 8) + "bit",
                                               "WindowsPE" if os.name == "nt" else "Mach-O" if sys.platform == "darwin" else "ELF")
        for package_name in ("wx4", "core"):
            package_dir = upstream / package_name
            spec = importlib.util.spec_from_file_location(package_name, package_dir / "__init__.py",
                submodule_search_locations=[str(package_dir)])
            package = importlib.util.module_from_spec(spec)
            sys.modules[package_name] = package
            spec.loader.exec_module(package)
        if os.name != "nt":
            # The locked media module has one unconditional Win32 DLL binding.
            # Keep its real offline algorithms; do not emulate memory-reading APIs.
            media_path = upstream / "wx4" / "media.py"
            source = media_path.read_text(encoding="utf-8")
            needle = "kernel32 = ctypes.windll.kernel32"
            if source.count(needle) != 1: raise BridgeError("upstream_untrusted")
            spec = importlib.util.spec_from_file_location("wx4.media", media_path)
            media = importlib.util.module_from_spec(spec)
            sys.modules["wx4.media"] = media
            exec(compile(source.replace(needle, "kernel32 = None"), str(media_path), "exec"), media.__dict__)
        data = importlib.import_module("core.data")
        exporting = importlib.import_module("core.exporting")
        reader = importlib.import_module("wx4.reader")
        resources = importlib.import_module("core.resources")
        codec = importlib.import_module("core.media_codec")
        avatars = importlib.import_module("core.avatars")
        stickers = importlib.import_module("core.sticker_cache")
        forward = importlib.import_module("wx4.forward")
    except ImportError:
        raise BridgeError("dependency_missing") from None

    # Add locators to the existing query without changing its filters or ordering.
    data_source = (upstream / "core/data.py").read_text(encoding="utf-8")
    needle = "            select = ','.join(f'\"{c}\"' if c in cols else f'NULL AS \"{c}\"' for c in FIELDS)"
    if data_source.count(needle) != 1: raise BridgeError("upstream_untrusted")
    data._bridge_projection = source_projection
    exec(compile(data_source.replace(needle, needle + "\n            select += _bridge_projection(con, table)"),
                 str(upstream / "core/data.py"), "exec"), data.__dict__)

    # These small runtime changes are recorded in run.json; upstream files stay intact.
    original_build = reader.Wx4Data._build_msg
    def source_for_row(self, row, session, shard):
        fields = dict(row)
        locator = {"source_rowid": fields["__bridge_rowid"]} if "__bridge_rowid" in fields else {}
        primary = [{"column": k[len("__bridge_pk_"):], "value": sqlite_value(v)} for k, v in fields.items() if k.startswith("__bridge_pk_")]
        if primary: locator = {"source_pk": primary}
        if not locator: return None
        source = self.msg_dbs[shard].execute("PRAGMA database_list").fetchone()[2]
        relative = Path(source).relative_to(Path(self.root)).as_posix()
        raw = {key: sqlite_value(fields.get(key)) for key in data.FIELDS}
        return {"database": relative, "database_sha256": self._bridge_hashes.get(relative),
            "table": self.msg_table_for(session), "local_id": row["local_id"], **locator,
            "row_sha256": hashlib.sha256(json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()}

    def build_message(self, row, names, session, shard):
        provenance = source_for_row(self, row, session, shard)
        try:
            content = exact_content(row, reader)
        except BridgeError as error:
            error.details.update(stage="message_decode", source=provenance,
                                 embedded_without_source_row=provenance is None)
            raise
        try:
            selected, body, sender = sender_evidence(self, row, names, session, content["raw_decoded"])
            msg = original_build(self, row, names, session, shard)
        except BridgeError as error:
            error.details.update(stage="message_build", source=provenance,
                                 embedded_without_source_row=provenance is None)
            raise
        except Exception as error:
            raise BridgeError("message_build_failed", {"stage": "message_build", "source": provenance,
                "embedded_without_source_row": provenance is None, "exception_type": type(error).__name__}) from None
        msg["server_id"] = str(row["server_id"]) if row["server_id"] is not None else ""
        msg["sender_wxid"] = selected
        msg["sender"] = self.name_of(selected) if selected else "未知发送者（来源冲突）" if sender["status"] == "conflict" else ("系统" if msg["type"] in (10000, 10002) else "未知发送者")
        msg["is_sender"] = bool(selected) and selected == self.wxid
        msg["bridge_sender"] = sender
        if msg["type"] == 1:
            msg["text"] = msg["content"] = body
            msg["_resource_source"] = body + "\n" + reader.reference_text(row["packed_info_data"])
            content["display_transform"] = "verified_group_prefix_removed" if body != content["raw_decoded"] else "none"
        else:
            content["display_transform"] = "upstream_structured_rendering"
        msg["bridge_content"] = content
        original_time = row["create_time"]
        valid_time = isinstance(original_time, (int, float)) and not isinstance(original_time, bool) and 0 < original_time < 253402300800
        msg["create_time"] = original_time if valid_time else 0
        msg["time_str"] = epoch_text(msg.get("create_time"))
        msg["bridge_original_timestamp"] = sqlite_value(original_time)
        msg["bridge_time_status"] = "source_epoch" if valid_time else "unknown"
        msg["bridge_time_rule"] = {"unit": "seconds", "display_timezone": "Asia/Shanghai", "basis": "sqlite_create_time_field", "verified_historical_event_time": False}
        if provenance: msg["bridge_source"] = provenance
        return msg
    reader.Wx4Data._build_msg = build_message

    def quote_with_provenance(self, msg, depth):
        quote = msg.get("_quote")
        if not quote: return None
        server = str(quote.get("server_id") or "")
        candidate_count = 0
        candidate = None
        table = self.data.msg_table_for(self.session)
        q = resources.quoted_identifier
        if server and server != "0":
            for shard, con in enumerate(self.data.msg_dbs):
                self.cancel()
                if table not in self.data.tables_of(con): continue
                cols = {r[1] for r in con.execute("PRAGMA table_info(" + q(table) + ")")}
                if "server_id" not in cols: continue
                where = " FROM " + q(table) + " WHERE CAST(server_id AS TEXT)=?"
                count = con.execute("SELECT COUNT(*)" + where, (server,)).fetchone()[0]
                candidate_count += count
                if count and candidate is None:
                    select = ','.join(q(c) if c in cols else 'NULL AS ' + q(c) for c in data.FIELDS)
                    row = con.execute("SELECT " + select + source_projection(con, table) + where + " LIMIT 1", (server,)).fetchone()
                    candidate = (row, shard)
        if candidate_count == 1:
            row, shard = candidate
            reference = self.data._build_msg(row, self.data._name2id(self.data.msg_dbs[shard]), self.session, shard)
            reference_status = "matched_source_row"
        else:
            original_time = quote.get("create_time")
            try:
                timestamp = int(original_time) if original_time else 0
                if not 0 < timestamp < 253402300800: timestamp = 0
            except (TypeError, ValueError): timestamp = 0
            row = {"local_id": 0, "server_id": server, "local_type": quote.get("type") or 1,
                "real_sender_id": 1, "create_time": timestamp, "message_content": quote.get("content") or quote.get("text", ""),
                "compress_content": None, "packed_info_data": None}
            reference = self.data._build_msg(row, {1: quote.get("sender_wxid", "")}, self.session, 0)
            reference["sender"] = quote.get("sender") or reference["sender"]
            reference["bridge_sender"]["display_name_basis"] = "embedded_reference_fields"
            reference["bridge_original_timestamp"] = original_time
            reference["bridge_time_rule"]["basis"] = "embedded_reference_time_field" if timestamp else "unknown"
            reference_status = "ambiguous_source_match" if candidate_count > 1 else "embedded_only"
        reference["bridge_reference"] = {"status": reference_status, "candidate_count": candidate_count,
            "id_basis": "embedded_server_id_not_unique" if candidate_count != 1 else "unique_match_within_frozen_session"}
        if not self.preferences["include_system_messages"] and resources.is_system_message(reference): return None
        reference = self.enrich(reference, depth=depth + 1)
        keep = ("server_id", "sender", "sender_wxid", "create_time", "time_str", "text", "kind", "extra", "avatar", "resources",
                "resource_status", "resource_notice", "forward", "quote", "type", "raw_type", "bridge_source", "bridge_sender",
                "bridge_content", "bridge_reference", "bridge_original_timestamp", "bridge_time_status", "bridge_time_rule")
        return {key: reference[key] for key in keep if key in reference}
    resources.ResourceStore._quote = quote_with_provenance

    original_forward = forward.build_forward
    def bounded_forward(*args, **kwargs):
        return correct_forward_times(original_forward(*args, **kwargs))
    forward.build_forward = resources.build_forward = bounded_forward

    original_keys = codec.ImageKeys
    class OfflineImageKeys(original_keys):
        def __init__(self, data, cancel, codec=None, progress=None):
            self.cancel = cancel; self.keys = []; self.xor = None; self.scanned = set()
            self.codec = codec; self.progress = progress or (lambda _: None)
            self.scan_remaining = 0; self.rendered = None; self.reason = ""; self.diagnostics = {}; self.xor_votes = {}
            self.account = Path(data.account_dir()); self.wxid = data.wxid; self.xor_search_keys = None
            self.path = output / ".work" / "disabled-key-cache.json"
        def _save(self):
            return None
    codec.ImageKeys = resources.ImageKeys = OfflineImageKeys
    stickers.discover_emoticon_key = lambda *args, **kwargs: None
    codec.find_dat_aes_key = lambda *args, **kwargs: None
    original_avatar_init = avatars.AvatarStore.__init__
    original_avatar_blob = avatars.AvatarStore.blob
    def avatar_init(self, data, cache=None):
        original_avatar_init(self, data, None)
    avatars.AvatarStore.__init__ = avatar_init
    avatars.AvatarStore.blob = lambda self, username, download=False: original_avatar_blob(self, username, False)
    def no_download(self, url, limit):
        self.download_outcomes[hashlib.sha256(url.encode()).hexdigest()] = {"status": "network_disabled"}
        return None
    resources.ResourceStore._download = no_download
    def no_transcode(*args, **kwargs):
        raise OSError("local_subprocess_conversion_disabled")
    codec.MediaCodec._run = no_transcode
    return data, exporting


def process_binding(args, *, initial=False):
    import psutil
    try:
        target = psutil.Process(args.pid)
        identity = (target.pid, target.create_time(), os.path.normcase(target.exe()), target.username().casefold())
        expected = (args.pid, args.process_start_time, os.path.normcase(str(args.process_exe)), psutil.Process().username().casefold())
        if identity != expected or target.name().casefold() != "weixin.exe":
            raise BridgeError("process_not_bound" if initial else "process_changed")
        if initial and sha256(args.process_exe) != args.process_sha256:
            raise BridgeError("process_not_bound")
        database_root = args.account_dir / "db_storage"
        matches = []
        for opened in target.open_files():
            try:
                path = checked_path(opened.path, directory=False)
                if path.is_relative_to(database_root) and path.name.endswith((".db", ".db-wal")):
                    matches.append(path)
            except (BridgeError, OSError):
                continue
        if not matches:
            raise BridgeError("process_not_bound")
    except (psutil.Error, OSError):
        raise BridgeError("process_not_bound" if initial else "process_changed") from None
    return target


def decrypt_frozen_snapshot(source, destination, keys, decrypt, check):
    """Validate and consume the same preserved input, never recopy the live DB."""
    hashes = db_manifest(source)
    if set(keys) != {name for name in hashes if name.endswith(".db")}:
        raise BridgeError("keys_incomplete")
    validation = validate_database_files(source, encrypted=True, check=check)
    destination.mkdir(mode=0o700)
    result = {"validation": validation, "files": []}
    for name in sorted(keys):
        check()
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            info = decrypt.decrypt_file(str(source / name), str(target), bytes.fromhex(keys[name]["enc_key"]), cancel=check)
        except decrypt.DecryptError:
            raise BridgeError("capture_incomplete", {"file": name, "stage": "decrypt_frozen_input"}) from None
        result["files"].append({"database": name, "pages": info["pages"], "wal_frames_applied": info["wal_frames"],
                                "database_first_page_key_verified": True, "all_page_hmac_verified": False})
    if db_manifest(source) != hashes: raise BridgeError("source_changed")
    result["decrypted_validation"] = validate_snapshot(destination)
    result["source_hashes"] = hashes
    result["decrypted_hashes"] = db_manifest(destination)
    return result


def capture_snapshot(args, destination, guard, report):
    guard.allow_key = True
    keys = {}
    extractor = None
    try:
        memory = importlib.import_module("wx4.key")
        decrypt = importlib.import_module("wx4.decrypt")
        deadline = time.monotonic() + args.scan_timeout
        last_check = [0.0]
        def check():
            guard.check()
            if time.monotonic() - last_check[0] >= 0.5:
                process_binding(args)
                last_check[0] = time.monotonic()
        def scan_check():
            check()
            if time.monotonic() > deadline: raise BridgeError("capture_timeout")
        storage = args.account_dir / "db_storage"
        checked_tree(storage)
        report["capture"] = {"started_at": datetime.now(timezone.utc).isoformat(),
            "scope_binding": "selected_pid_open_database_and_matching_first_page_hmac",
            "consistency": "sequential_copy_not_atomic_across_databases",
            "windows_acceptance": "not_yet_verified", "keys_saved": False}
        extractor = memory.KeyExtractor(str(storage), progress=lambda _: None, cancel=scan_check)
        extractor.collect()
        if not extractor.db_files:
            raise BridgeError("snapshot_invalid")
        process_binding(args, initial=True)
        stats = extractor.scan_process(args.pid)
        process_binding(args)
        if stats.get("error") or len(extractor.keys) != len(extractor.salt_index):
            raise BridgeError("keys_incomplete")
        keys = {Path(item["rel"]).as_posix(): {"enc_key": extractor.keys[item["salt"]]} for item in extractor.db_files}
        raw = destination.parent / "private-source"
        report["acquisition"] = {}
        expected = source_audit.load_manifest(args.source_manifest) if getattr(args, "source_manifest", None) else None
        hashes = copy_snapshot(storage, raw, check, validate=False, expected=expected, receipt=report["acquisition"])
        atomic_json(destination.parent / "source-manifest.json", {"schema_version": 1, "files": hashes,
                    "basis": report["acquisition"]["binding"]})
        report["capture"]["decryption"] = decrypt_frozen_snapshot(raw, destination, keys, decrypt, check)
        process_binding(args, initial=True)
        report["capture"]["ended_at"] = datetime.now(timezone.utc).isoformat()
        return hashes
    finally:
        keys.clear()
        if extractor is not None: extractor.keys.clear()
        guard.allow_key = False


def dependencies():
    result = {}
    for module, (distribution, expected) in DEPENDENCIES.items():
        present = importlib.util.find_spec(module) is not None
        try: version = importlib.metadata.version(distribution) if present else None
        except importlib.metadata.PackageNotFoundError: version = "unknown"
        result[module] = {"present": present, "version": version, "expected": expected, "matches": version == expected}
    return result


class Quiet(io.TextIOBase):
    def write(self, value): return len(value)
    def flush(self): pass


def execute(args):
    upstream = checked_path(args.upstream)
    manifest = verify_upstream(upstream)
    available = dependencies()
    if args.command == "doctor":
        return {"ok": all(item["matches"] for item in available.values()), "command": "doctor",
                "adapter_version": "0.2.1", "upstream_commit": COMMIT, "locked_files": len(manifest["files"]), "dependencies": available,
                "windows_capture": "implemented_requires_real_device_acceptance", "offline_export": "ready" if all(i["matches"] for i in available.values()) else "dependency_mismatch"}
    if not all(item["present"] for item in available.values()):
        raise BridgeError("dependency_missing")
    if not all(item["matches"] for item in available.values()):
        raise BridgeError("dependency_mismatch")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,190}", args.account_id):
        raise BridgeError("arguments_invalid")
    if not args.account_scope.strip() or len(args.account_scope) > 200 or any(ord(c) < 32 for c in args.account_scope):
        raise BridgeError("arguments_invalid")
    output = checked_path(args.output, exists=False)
    if output.exists(): raise BridgeError("output_exists")
    checked_path(output.parent)
    if getattr(args, "source_manifest", None):
        args.source_manifest = checked_path(args.source_manifest, directory=False)
    if args.command == "capture":
        if not args.live_read_approved: raise BridgeError("capture_approval_required")
        if os.name != "nt": raise BridgeError("windows_required")
        args.account_dir = checked_path(args.account_dir)
        args.process_exe = checked_path(args.process_exe, directory=False)
        if (args.pid <= 0 or not math.isfinite(args.process_start_time) or args.process_start_time <= 0 or
                args.process_exe.name.casefold() != "weixin.exe" or not re.fullmatch(r"[0-9a-f]{64}", args.process_sha256) or
                not 1 <= args.scan_timeout <= 60):
            raise BridgeError("arguments_invalid")
        checked_tree(args.account_dir)
        process_binding(args, initial=True)
        source = args.account_dir
    else:
        source = checked_path(args.source)
        checked_tree(source)
    separate(upstream, source, output)
    if args.command in ("export", "capture"):
        if not args.session or len(set(args.session)) != len(args.session) or any(not s or len(s) > 190 for s in args.session):
            raise BridgeError("arguments_invalid")
        if args.start is not None and args.end is not None and args.start > args.end:
            raise BridgeError("arguments_invalid")
    private_mkdir(output)
    guard = Guard(output)
    sys.addaudithook(guard.audit)
    sys.dont_write_bytecode = True
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: setattr(guard, "cancelled", True))
    work = output / ".work"; work.mkdir(mode=0o700)
    tempfile.tempdir = str(work)
    report = {"schema_version": 2, "adapter_version": "0.2.1", "status": "running", "command": args.command,
        "upstream_commit": COMMIT, "account_id": args.account_id, "account_id_kind": "wxid", "account_scope": args.account_scope,
        "scope_basis": "verified_process_binding" if args.command == "capture" else "user_selected", "identity_verified": False,
        "account_identity": "user_supplied_scope_not_independent_identity_proof", "started_at": datetime.now(timezone.utc).isoformat(),
        "policy": {"network": False, "subprocesses": False, "automatic_elevation": False, "media_memory_scan": False,
                   "key_cache": False, "strict_message_decode": True, "forward_missing_time": "unknown", "quote_missing_time": "unknown",
                   "display_timezone": "Asia/Shanghai", "raw_text_preserved": True, "sender_conflicts": "unresolved",
                   "source_accounting": "independent_sql_and_persisted_payload_readback", "wal": "validate_frozen_stored_bytes_before_consumption"},
        "non_windows_import_patch": "wx4.media: kernel32 = None" if os.name != "nt" else None,
        "crypto_architecture": "current_python_pointer_width_without_subprocess",
        "results": []}
    atomic_json(output / "run.json", report)
    archive = None
    reference = None
    try:
        with contextlib.redirect_stdout(Quiet()), contextlib.redirect_stderr(Quiet()):
            data, exporter = load_core(upstream, output)
            snapshot = output / "private-snapshot"
            if args.command == "capture":
                hashes = capture_snapshot(args, snapshot, guard, report)
            else:
                expected = source_audit.load_manifest(args.source_manifest) if getattr(args, "source_manifest", None) else None
                report["acquisition"] = {}
                raw = output / "private-source"
                hashes = copy_snapshot(source, raw, guard.check, validate=False, expected=expected, receipt=report["acquisition"])
                atomic_json(output / "source-manifest.json", {"schema_version": 1, "files": hashes,
                            "basis": report["acquisition"]["binding"]})
                report["processing_copy"] = {}
                copy_snapshot(raw, snapshot, guard.check, validate=False, expected=hashes, receipt=report["processing_copy"])
                report["database_validation"] = validate_snapshot(snapshot)
            report["source_database_hashes"] = hashes
            report["snapshot_consistency"] = "preserved_input_bytes_and_separate_processing_copy_not_shared_time_proof"
            processing_hashes = db_manifest(snapshot)
            report["processing_database_hashes"] = processing_hashes
            if args.command != "sessions":
                reference = source_audit.enumerate_source(snapshot, args.session, args.start, args.end,
                                                          source_hashes=processing_hashes)
                reference["scope"].update(account_id=args.account_id, account_scope=args.account_scope,
                                           account_identity_verified=False)
                atomic_json(output / "source-reference.json", reference)
            archive = data.Archive({"root": str(snapshot), "wxid": args.account_id,
                                    "account_dir": str(source), "storage_root": str(work)})
            archive.data._bridge_hashes = processing_hashes
            sessions = archive.sessions()
            if args.command == "sessions":
                listing = [{"session_id": s["username"], "display_name": s["display"], "is_group": s["is_group"], "category": s.get("category")} for s in sessions]
                atomic_json(output / "sessions.json", {"account_id": args.account_id, "account_scope": args.account_scope, "sessions": listing})
                report["session_count"] = len(listing)
            else:
                by_id = {s["username"]: s for s in sessions}
                if any(s not in by_id for s in args.session): raise BridgeError("session_missing")
                destination = output / "exports"; destination.mkdir()
                options = {"format": args.format, "kind": "all", "include_system_messages": True,
                           "include_avatars": False, "quick_export": not args.local_media}
                if args.start is not None: options["start"] = args.start
                if args.end is not None: options["end"] = args.end
                for uid in args.session:
                    guard.check()
                    result = exporter.export_session(archive, by_id[uid], options, destination,
                        upstream / "ui", lambda _: guard.check(), guard.check, status=lambda _: None)
                    add_export_metadata(Path(result["path"]), args.format,
                        {key: report[key] for key in ("account_id", "account_id_kind", "account_scope", "scope_basis", "identity_verified", "upstream_commit")})
                    result["path"] = Path(result["path"]).relative_to(output).as_posix()
                    report["results"].append(result)
                    atomic_json(output / "run.json", report)
            guard.check()
            if reference is not None:
                audit = reconcile_saved(output, report, reference)
                if not audit["passed"]: raise BridgeError("source_reconciliation_failed", {"audit_file": "source-audit.json"})
            if args.command != "capture" and db_manifest(source) != hashes:
                raise BridgeError("source_changed")
            if db_manifest(output / "private-source") != hashes:
                raise BridgeError("source_changed")
            verify_upstream(upstream)
        partial = reference is not None and (not audit.get("semantic_checks_complete", False) or bool(audit["interpretation_warnings"]))
        report["status"] = "partial" if partial else "completed"
        report["exit_code"] = 1 if partial else 0
        return {"ok": True, "status": report["status"], "exit_code": report["exit_code"], "command": args.command,
                "session_count": report.get("session_count", len(report["results"])),
                "message_count": sum(r["count"] for r in report["results"]), "run_manifest": "run.json",
                "source_audit": report.get("source_audit")}
    except BaseException as error:
        code = error.code if isinstance(error, (BridgeError, source_audit.SourceAuditError)) else "wal_invalid_or_unsupported" if isinstance(error, wal_guard.WalValidationError) else "cancelled" if isinstance(error, KeyboardInterrupt) else "operation_failed"
        if isinstance(error, wal_guard.WalValidationError):
            report["database_validation"] = getattr(error, "database_report", {"wal": error.report})
        if getattr(error, "details", None): report["error_details"] = error.details
        if reference is not None and code != "source_reconciliation_failed":
            try:
                reconcile_saved(output, report, reference, failure=code)
            except Exception:
                report["source_audit_failure"] = "unable_to_read_saved_payloads_after_failure"
        report.update(status="cancelled" if code == "cancelled" else "failed", error_code=code, incomplete=True)
        raise BridgeError(code) from None
    finally:
        if archive is not None: archive.close()
        # Only run-owned temporary files are removed; incomplete exports remain marked.
        if work.exists(): shutil.rmtree(work)
        report["ended_at"] = datetime.now(timezone.utc).isoformat()
        atomic_json(output / "run.json", report)


class Parser(argparse.ArgumentParser):
    def error(self, message): raise BridgeError("arguments_invalid")


def parser():
    p = Parser(description=__doc__)
    p.add_argument("--upstream", required=True, help="Absolute path to the approved source tree")
    commands = p.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor")
    for name in ("sessions", "export", "capture"):
        s = commands.add_parser(name)
        s.add_argument("--account-id", required=True)
        s.add_argument("--account-scope", required=True, help="User's account label; never an identity attestation")
        s.add_argument("--output", required=True, help="New private local output directory")
        s.add_argument("--source-manifest", help="Absolute path to a fixed prior file inventory; omitted means observed inputs only")
        if name != "capture": s.add_argument("--source", required=True, help="Frozen decrypted SQLite snapshot directory")
        if name in ("export", "capture"):
            s.add_argument("--session", action="append", required=True)
            s.add_argument("--format", choices=("json", "jsonl", "html"), default="json")
            s.add_argument("--start", type=int, help="Inclusive Unix seconds")
            s.add_argument("--end", type=int, help="Inclusive Unix seconds")
            s.add_argument("--local-media", action="store_true", help="Copy locally available media; do not retrieve keys or use the network")
        if name == "capture":
            s.add_argument("--account-dir", required=True)
            s.add_argument("--pid", required=True, type=int)
            s.add_argument("--process-exe", required=True)
            s.add_argument("--process-sha256", required=True)
            s.add_argument("--process-start-time", required=True, type=float)
            s.add_argument("--scan-timeout", type=int, default=30)
            s.add_argument("--live-read-approved", action="store_true")
    return p


def main(argv=None):
    try:
        result = execute(parser().parse_args(argv))
        print(json.dumps(result, ensure_ascii=False))
        return result.get("exit_code", 0 if result["ok"] else 2)
    except (BridgeError, KeyboardInterrupt) as error:
        code = error.code if isinstance(error, BridgeError) else "cancelled"
    except Exception:
        code = "operation_failed"
    print(json.dumps({"ok": False, "code": code, "message": MESSAGES.get(code, MESSAGES["operation_failed"])}, ensure_ascii=False))
    return 130 if code == "cancelled" else 2


if __name__ == "__main__":
    raise SystemExit(main())
