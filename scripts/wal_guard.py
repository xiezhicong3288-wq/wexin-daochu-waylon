"""Read-only validation of one frozen SQLite WAL's stored-byte checksum chain.

This proves only the observed file's framing, checksums and commit boundary.
It does not authenticate encrypted pages, bind a WAL cryptographically to a DB,
prove acquisition completeness, or establish a shared time across databases.
An encrypted writer with a different checksum domain is unsupported here; never
fall back to trusting its commit markers. Keep the original WAL unchanged.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import struct


WAL_VERSION = 3007000
WAL_MAGIC = {0x377F0682: "<", 0x377F0683: ">"}
HEADER_BYTES = 32
FRAME_HEADER_BYTES = 24
MAX_PAGE = 0xFFFFFFFE


class WalValidationError(RuntimeError):
    """A safe error code plus a JSON-safe, content-free partial report."""

    def __init__(self, code, report):
        self.code = code
        self.report = dict(report, status="invalid_or_unsupported", error_code=code)
        super().__init__(code)


def _checksum(data, byte_order, state=(0, 0)):
    s0, s1 = state
    for a, b in struct.iter_unpack(byte_order + "II", data):
        s0 = (s0 + a + s1) & 0xFFFFFFFF
        s1 = (s1 + b + s0) & 0xFFFFFFFF
    return s0, s1


def _file_state(value, *, cross_api=False):
    ctime = value.st_ctime_ns
    if cross_api and os.name == "nt":
        # Windows lstat and fstat can report creation and change time respectively.
        ctime = getattr(value, "st_birthtime_ns", ctime)
    return (value.st_dev, value.st_ino, value.st_size,
            value.st_mtime_ns, ctime)


def validate_wal(path, *, expected_page_size=None, expected_size=None,
                 expected_sha256=None, check=None):
    """Validate a present frozen WAL without changing it.

    ``expected_size``/``expected_sha256`` bind a prior inventory when available.
    They are necessary to detect removal of a whole valid final transaction:
    a self-consistent shorter WAL cannot disclose bytes already missing from it.
    No-WAL absence must be checked against the caller's acquisition inventory.

    A zero-byte WAL is a valid empty file. A valid 32-byte header with no frames
    is also accepted, with no observed page-checksum domain. Full valid frames
    after the last commit are counted as an unapplied transaction tail. Partial
    frames, mismatching generation salts and any bad checksum fail closed; this
    deliberately does not guess whether invalid trailing bytes are harmless.
    """
    report = {
        "schema": "moect-wal-validation-v1",
        "status": "checking", "file_size": None, "sha256": None,
        "header_valid": False, "page_size": None, "format_version": None,
        "checksum_domain": "not_observed", "valid_frames": 0,
        "complete_frames": 0, "trailing_bytes": 0,
        "committed_transactions": 0, "last_committed_frame": 0,
        "committed_prefix_bytes": 0, "committed_database_pages": None,
        "uncommitted_tail_frames": 0,
        "acquisition_completeness_proven": False,
        "database_pair_identity_proven": False,
        "encrypted_page_authentication_proven": False,
        "cross_database_time_consistency_proven": False,
    }

    def fail(code, **extra):
        report.update(extra)
        raise WalValidationError(code, report)

    if expected_page_size is not None and (type(expected_page_size) is not int
            or expected_page_size < 512 or expected_page_size > 65536
            or expected_page_size & (expected_page_size - 1)):
        fail("wal_expected_page_size_invalid")
    if expected_size is not None and (type(expected_size) is not int or expected_size < 0):
        fail("wal_expected_size_invalid")
    if expected_sha256 is not None and (not isinstance(expected_sha256, str)
            or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256)):
        fail("wal_expected_hash_invalid")

    path = Path(path)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or getattr(before, "st_file_attributes", 0) & 0x400:
            fail("wal_file_not_regular")
        report["file_size"] = before.st_size
        if expected_size is not None and before.st_size != expected_size:
            fail("wal_inventory_size_mismatch")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if _file_state(before, cross_api=True) != _file_state(opened, cross_api=True):
                fail("wal_changed_during_validation")
            digest = hashlib.sha256()
            header = stream.read(HEADER_BYTES)
            digest.update(header)
            if check:
                check()
            if before.st_size == 0:
                report["status"] = "valid_empty"
            elif len(header) != HEADER_BYTES:
                fail("wal_header_truncated", trailing_bytes=len(header))
            else:
                magic, version, page_size, _, salt0, salt1, h0, h1 = struct.unpack(">8I", header)
                if magic not in WAL_MAGIC:
                    fail("wal_magic_unsupported")
                if version != WAL_VERSION:
                    fail("wal_version_unsupported", format_version=version)
                if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
                    fail("wal_page_size_unsupported", page_size=page_size)
                if expected_page_size is not None and page_size != expected_page_size:
                    fail("wal_page_size_mismatch", page_size=page_size)
                report.update(format_version=version, page_size=page_size)
                byte_order = WAL_MAGIC[magic]
                state = _checksum(header[:24], byte_order)
                if state != (h0, h1):
                    fail("wal_header_checksum_mismatch")
                report["header_valid"] = True
                frame_size = FRAME_HEADER_BYTES + page_size
                report["complete_frames"], report["trailing_bytes"] = divmod(
                    before.st_size - HEADER_BYTES, frame_size)
                report["committed_prefix_bytes"] = HEADER_BYTES
                for index in range(1, report["complete_frames"] + 1):
                    if check:
                        check()
                    frame = stream.read(FRAME_HEADER_BYTES)
                    payload = stream.read(page_size)
                    digest.update(frame); digest.update(payload)
                    if len(frame) != FRAME_HEADER_BYTES or len(payload) != page_size:
                        fail("wal_changed_during_validation", frame_index=index)
                    page_number, commit_pages, f0, f1, c0, c1 = struct.unpack(">6I", frame)
                    if page_number == 0 or page_number > MAX_PAGE or commit_pages > MAX_PAGE:
                        fail("wal_frame_page_invalid", frame_index=index)
                    if (f0, f1) != (salt0, salt1):
                        fail("wal_generation_mismatch", frame_index=index)
                    state = _checksum(payload, byte_order, _checksum(frame[:8], byte_order, state))
                    if state != (c0, c1):
                        # A different encrypted writer domain and corrupt bytes are
                        # indistinguishable here; neither may be accepted silently.
                        fail("wal_frame_checksum_unsupported_or_invalid", frame_index=index)
                    report["valid_frames"] = index
                    if commit_pages:
                        report["committed_transactions"] += 1
                        report["last_committed_frame"] = index
                        report["committed_database_pages"] = commit_pages
                        report["committed_prefix_bytes"] = HEADER_BYTES + index * frame_size
                remainder = stream.read(report["trailing_bytes"] + 1)
                digest.update(remainder)
                if len(remainder) != report["trailing_bytes"]:
                    fail("wal_changed_during_validation")
                if report["trailing_bytes"]:
                    fail("wal_frame_truncated")
                report["uncommitted_tail_frames"] = (report["valid_frames"]
                                                       - report["last_committed_frame"])
                if report["valid_frames"]:
                    report["checksum_domain"] = "observed_stored_payload_bytes"
                report["status"] = ("valid_with_uncommitted_tail" if report["uncommitted_tail_frames"]
                                    else "valid")
            if _file_state(opened) != _file_state(os.fstat(stream.fileno())):
                fail("wal_changed_during_validation")
            report["sha256"] = digest.hexdigest()
        if _file_state(before) != _file_state(path.lstat()):
            fail("wal_changed_during_validation")
        if expected_sha256 is not None and report["sha256"] != expected_sha256.lower():
            fail("wal_inventory_hash_mismatch")
        return report
    except FileNotFoundError:
        fail("wal_file_missing")
    except OSError:
        fail("wal_io_error")
