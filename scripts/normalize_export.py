#!/usr/bin/env python3
"""Normalize explicit Moect exports into a local, neutral, traceable archive.

Only Python's standard library is used. No network or legal classification.
Source files and explicitly referenced local attachments are copied, never edited.
JSON is bounded at 256 MiB; use JSONL for larger exports. JSONL lines are bounded
at 16 MiB. Nested expansion is bounded, with omissions reported, not hidden.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import math
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat
import sys
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MAX_JSON_BYTES = 256 * 1024 * 1024
MAX_LINE_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 32
MAX_NESTED_PER_MESSAGE = 10000
BEIJING = timezone(timedelta(hours=8))
SCRIPT_VERSION = "0.2.1"


class NormalizeError(ValueError):
    """A safe error code: never include source text or exception payloads."""


def _inside(path, directory):
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def _no_links(path):
    """Reject existing symlink components, including Windows directory links."""
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise NormalizeError("path_metadata_unavailable") from None
        # Path.is_junction was added in 3.12. Moect supports Python 3.11, so
        # reject all Windows reparse points by their native file attributes.
        reparse = getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if stat.S_ISLNK(info.st_mode) or reparse:
            raise NormalizeError("linked_path_rejected")


def _regular(path):
    _no_links(path)
    if not stat.S_ISREG(path.stat().st_mode):
        raise NormalizeError("input_is_not_regular_file")


def _sha256(path):
    _regular(path)
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_hash(source, destination):
    _regular(source)
    before = source.stat()
    digest = hashlib.sha256()
    size = 0
    with source.open("rb") as src, destination.open("xb") as dst:
        opened = os.fstat(src.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise NormalizeError("source_changed_during_open")
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            dst.write(chunk)
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(src.fileno())
    if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise NormalizeError("source_changed_during_copy")
    return digest.hexdigest(), size


def _strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise NormalizeError("duplicate_json_key")
            result[key] = value
        return result

    def nonfinite(_):
        raise NormalizeError("nonfinite_json_number")

    result = json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)
    pending = [result]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError:
                raise NormalizeError("invalid_unicode_value") from None
        elif isinstance(value, float) and not math.isfinite(value):
            raise NormalizeError("nonfinite_json_number")
    return result


def _write_json(writer, value):
    writer.write(json.dumps(value, ensure_ascii=False, allow_nan=False) + "\n")


def _cell(value):
    value = str(value)
    # Excel may ignore whitespace before a formula marker.
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value


def _identifier(value):
    if isinstance(value, str):
        return value or None
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return None


def _time_consistency(raw, display, zone_name, basis, valid):
    """Compare declared fields only; never infer a zone or authenticate a time."""
    result = {"status": "not_checked", "basis": "declared_export_fields_only",
              "declared_timezone": zone_name if isinstance(zone_name, str) else None}
    if not valid:
        result["reason"] = "unknown_or_unsupported_epoch"
    elif basis not in ("upstream_create_time_seconds", "bridge_reports_source_epoch"):
        result["reason"] = "unknown_or_fallback_time_origin"
    elif not isinstance(zone_name, str) or not zone_name or zone_name == "unknown":
        result["reason"] = "timezone_unknown"
    elif not isinstance(display, str) or not display:
        result["reason"] = "display_time_missing"
    else:
        try:
            zone = timezone.utc if zone_name in ("UTC", "Etc/UTC") else ZoneInfo(zone_name)
        except (ZoneInfoNotFoundError, ValueError, OSError):
            result["reason"] = "timezone_unsupported_or_rules_unavailable"
            return result
        try:
            declared = datetime.strptime(display, "%Y-%m-%d %H:%M:%S")
            expected = datetime.fromtimestamp(raw, timezone.utc).astimezone(zone)
            # Upstream time_str has second precision. Compare at that precision,
            # preserving fractional epoch values and the display string unchanged.
            expected = expected.replace(tzinfo=None, microsecond=0)
        except (ValueError, OverflowError, OSError):
            result["reason"] = "display_time_unparseable_or_epoch_unsupported"
            return result
        result["status"] = "match" if declared == expected else "mismatch"
    return result


def _time_info(message, metadata, nested):
    raw = message.get("create_time")
    numeric = ((isinstance(raw, int) and not isinstance(raw, bool))
               or (isinstance(raw, float) and math.isfinite(raw)))
    valid = numeric and 0 < raw < 253402300800
    utc = beijing = None
    if valid:
        try:
            moment = datetime.fromtimestamp(raw, timezone.utc)
            utc = moment.isoformat()
            beijing = moment.astimezone(BEIJING).isoformat()
        except (ValueError, OverflowError, OSError):
            valid = False
    supplied = message.get("provenance")
    supplied = supplied if isinstance(supplied, dict) else {}
    declared = supplied.get("time_basis", message.get("time_basis"))
    if not valid:
        basis = "unknown_or_unsupported_timestamp"
    elif nested:
        # Moect may synthesize nested timestamps. The cleaned export cannot prove
        # whether a number was native, parsed from text, or copied from its parent.
        basis = "unknown_nested_time_origin"
    else:
        basis = "upstream_create_time_seconds"
    if isinstance(declared, str) and "fallback" in declared.casefold():
        basis = "input_reports_fallback"
    bridge_status = message.get("bridge_time_status")
    if bridge_status == "source_epoch" and valid:
        basis = "bridge_reports_source_epoch"
    elif bridge_status == "source_text_unzoned":
        basis = "source_text_timezone_unknown"
    elif bridge_status == "unknown":
        basis = "bridge_reports_unknown_time"
    return {
        "raw_create_time": raw,
        "raw_time_str": message.get("time_str"),
        "source_display_timezone": metadata.get("time_zone") or "unknown",
        "basis": basis,
        "input_declared_basis": declared,
        "input_bridge_time_status": bridge_status,
        "bridge_original_time_text": message.get("bridge_original_time_text"),
        "utc_from_exported_value": utc,
        "beijing_from_exported_value": beijing,
        "display_consistency": _time_consistency(raw, message.get("time_str"),
                                                  metadata.get("time_zone"), basis, valid),
        "verified_original_event_time": False,
    }


def _metadata(document, jsonl=False):
    """Recognize the two Moect schemas; do not guess other exporters."""
    if not isinstance(document, dict):
        raise NormalizeError("unsupported_export_shape")
    if "metadata" in document:
        if jsonl and set(document) != {"metadata"}:
            raise NormalizeError("invalid_jsonl_metadata_header")
        meta = document["metadata"]
        if not isinstance(meta, dict) or meta.get("application") != "Moect":
            raise NormalizeError("unrecognized_gui_exporter")
        if not isinstance(meta.get("session"), str) or not meta["session"]:
            raise NormalizeError("missing_conversation_id")
        if not isinstance(meta.get("name"), str):
            raise NormalizeError("missing_conversation_display")
        if not jsonl and not isinstance(document.get("messages"), list):
            raise NormalizeError("messages_not_array")
        return "moect-gui-jsonl" if jsonl else "moect-gui-json", dict(meta)
    if jsonl:
        raise NormalizeError("jsonl_metadata_header_required")
    required = ("session", "display", "wxid", "exported_at", "count", "messages")
    if not all(key in document for key in required):
        raise NormalizeError("unrecognized_legacy_export")
    if not all(isinstance(document[key], str) for key in required[:4]):
        raise NormalizeError("invalid_legacy_metadata")
    if not document["session"] or not isinstance(document["messages"], list):
        raise NormalizeError("invalid_legacy_export")
    return "moect-legacy-json", {
        "application": "Moect", "session": document["session"],
        "name": document["display"], "exported_account_id": document["wxid"],
        "exported_at": document["exported_at"], "time_zone": "unknown",
        "schema_identification": "legacy_shape_not_proof_of_exporter_identity",
    }


def _account_claims(metadata, scope):
    declared_scope = metadata.get("account_scope")
    if scope is not None and declared_scope is not None and declared_scope != scope:
        raise NormalizeError("declared_account_scope_conflict")
    owner = metadata.get("exported_account_id")
    owner = owner if isinstance(owner, str) and owner else None
    bridge_owner = metadata.get("account_id")
    if bridge_owner is not None:
        if not isinstance(bridge_owner, str) or not bridge_owner:
            raise NormalizeError("invalid_exported_account_id")
        if metadata.get("account_id_kind") != "wxid":
            raise NormalizeError("unsupported_account_id_kind")
        if owner and owner != bridge_owner:
            raise NormalizeError("exported_account_id_conflict")
        owner = bridge_owner
    return owner, declared_scope


def _jsonl_header(stream):
    header = stream.readline(MAX_LINE_BYTES + 1)
    if len(header) > MAX_LINE_BYTES:
        raise NormalizeError("jsonl_header_size_limit")
    try:
        document = _strict_json(header.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise NormalizeError("invalid_jsonl_header") from None
    return _metadata(document, jsonl=True)


def _jsonl_records(stream):
    number = 1
    while line := stream.readline(MAX_LINE_BYTES + 1):
        number += 1
        location = "line:%d" % number
        if len(line) > MAX_LINE_BYTES:
            while line and not line.endswith(b"\n"):
                line = stream.readline(MAX_LINE_BYTES + 1)
            yield location, None, "jsonl_record_size_limit"
        elif line.strip():
            try:
                message = _strict_json(line.decode("utf-8"))
            except (UnicodeError, ValueError, RecursionError):
                yield location, None, "invalid_jsonl_record"
            else:
                yield location, message, None


def _valid_scope(scope):
    return (isinstance(scope, str) and scope.strip() and len(scope) <= 256
            and not any(ord(c) < 32 for c in scope))


class _Archive:
    def __init__(self, output, account, writers):
        self.output, self.account = output, account
        self.messages, self.attachments, self.issues, self.html = writers
        self.counts = dict(input_files=0, valid_input_files=0, top_level_seen=0,
                           top_level_messages=0, nested_messages=0, rejected_records=0,
                           top_level_rejected=0, nested_rejected=0, nested_omitted=0,
                           attachment_references=0, copied_attachments=0,
                           issues=0, warnings=0, errors=0)
        self.groups, self.seen_ids, self.copied, self.sources = {}, set(), {}, []
        self.sequence = 0
        self.known_owner = None
        self.account_conflict = False

    def register_account(self, source, metadata):
        try:
            owner, _ = _account_claims(metadata, self.account)
        except NormalizeError as exc:
            if str(exc) in ("declared_account_scope_conflict", "exported_account_id_conflict"):
                self.account_conflict = True
            raise
        source["exported_account_id"] = owner
        source["account_binding"] = ("caller_scope_and_exported_owner_unverified" if owner
                                     else "caller_declared_scope_only")
        source["input_scope_basis"] = metadata.get("scope_basis", "unknown")
        if owner:
            if self.known_owner is not None and self.known_owner != owner:
                self.account_conflict = True
                raise NormalizeError("exported_account_id_conflict")
            self.known_owner = owner

    def issue(self, code, source=None, location=None, severity="warning"):
        self.counts["issues"] += 1
        if severity in ("warning", "error"):
            self.counts["warnings" if severity == "warning" else "errors"] += 1
        _write_json(self.issues, {"code": code, "severity": severity,
                                "input_id": (source or {}).get("input_id"),
                                "source_location": location})

    def attachment(self, value, source, location, record_id):
        self.counts["attachment_references"] += 1
        item = {"record_id": record_id, "source_location": location,
                "input_id": source["input_id"], "reported": value,
                "verification": "unavailable", "copied_path": None, "sha256": None}
        if not isinstance(value, dict):
            self.issue("invalid_attachment_record", source, location)
            _write_json(self.attachments, item)
            return item
        raw = value.get("path")
        try:
            if not isinstance(raw, str) or not raw or "\x00" in raw:
                raise NormalizeError("invalid_attachment_path")
            normalized = raw.replace("\\", "/")
            relative = PurePosixPath(normalized)
            if (relative.is_absolute() or PureWindowsPath(raw).drive
                    or ":" in normalized or ".." in relative.parts
                    or normalized.startswith("//")):
                raise NormalizeError("attachment_path_escape")
            candidate = source["_root"].joinpath(*relative.parts)
            _no_links(candidate)
            resolved = candidate.resolve()
            if not _inside(resolved, source["_root"]) or _inside(resolved, self.output):
                raise NormalizeError("attachment_path_escape")
            if not candidate.exists():
                item["verification"] = "missing"
                self.issue("attachment_missing", source, location)
            else:
                _regular(candidate)
                key = str(resolved)
                if key not in self.copied:
                    suffix = candidate.suffix.lower()
                    if not suffix or len(suffix) > 12 or not suffix[1:].isalnum():
                        suffix = ".bin"
                    destination = self.output / "attachments" / (
                        "%06d%s" % (len(self.copied) + 1, suffix))
                    digest, size = _copy_hash(candidate, destination)
                    if _sha256(candidate) != digest:
                        raise NormalizeError("attachment_changed_during_processing")
                    self.copied[key] = dict(copied_path=destination.relative_to(self.output).as_posix(),
                                            sha256=digest, size=size)
                    self.counts["copied_attachments"] += 1
                item.update(self.copied[key], verification="bytes_copied_and_hashed")
                if value.get("status") not in (None, "available"):
                    self.issue("attachment_reported_incomplete", source, location)
        except NormalizeError as exc:
            item["verification"] = "rejected"
            item["reason"] = str(exc)
            self.issue(str(exc), source, location)
        except OSError:
            item["verification"] = "read_failed"
            self.issue("attachment_read_failed", source, location)
        _write_json(self.attachments, item)
        return item

    def record(self, message, source, metadata, location, relation="top_level",
               parent=None, root=None, depth=0, budget=None):
        if not isinstance(message, dict) or set(message) == {"metadata"}:
            self.counts["rejected_records"] += 1
            self.counts["top_level_rejected" if relation == "top_level" else "nested_rejected"] += 1
            self.issue("invalid_message_record", source, location, "error")
            return
        if depth > MAX_DEPTH or (budget is not None and budget[0] <= 0):
            self.counts["nested_omitted"] += 1
            self.issue("nested_expansion_limit", source, location)
            return
        if budget is None:
            budget = [MAX_NESTED_PER_MESSAGE]
        elif relation != "top_level":
            budget[0] -= 1
        nested = relation != "top_level"
        self.counts["nested_messages" if nested else "top_level_messages"] += 1
        self.sequence += 1
        record_id = "record-%09d" % self.sequence
        root = root or record_id
        sid = _identifier(message.get("sender_wxid"))
        native_id = _identifier(message.get("server_id"))
        session = metadata["session"]
        group = self.groups.setdefault(session, {
            "session": session, "names": set(), "top": 0, "nested": 0,
            "senders": set(), "unknown_senders": 0})
        group["names"].add(metadata["name"])
        group["nested" if nested else "top"] += 1
        if sid:
            group["senders"].add(sid)
        else:
            group["unknown_senders"] += 1
        if not nested and native_id:
            key = (session, native_id)
            if key in self.seen_ids:
                self.issue("duplicate_exported_server_id_retained", source, location, "note")
            self.seen_ids.add(key)
        text = message.get("text")
        if not isinstance(text, str):
            self.issue("text_unavailable_or_nonstring", source, location)
            text = None
        if message.get("session") not in (None, session):
            self.issue("message_session_mismatch", source, location)
        sender_evidence = message.get("bridge_sender")
        if isinstance(sender_evidence, dict) and sender_evidence.get("status") == "conflict":
            self.issue("sender_source_conflict", source, location)
        reference_evidence = message.get("bridge_reference")
        if isinstance(reference_evidence, dict) and reference_evidence.get("status") == "ambiguous_source_match":
            self.issue("quoted_source_ambiguous", source, location)
        resources = message.get("resources", [])
        if not isinstance(resources, list):
            self.issue("resources_not_array", source, location)
            resources = []
        attachment_rows = [self.attachment(value, source, location + ".resources[%d]" % n, record_id)
                           for n, value in enumerate(resources)]
        if message.get("resource_status") not in (None, "available"):
            self.issue("message_resources_incomplete_or_skipped", source, location)
        row = {
            "record_id": record_id, "record_kind": relation, "parent_record_id": parent,
            "root_record_id": root, "account_scope": self.account,
            "exported_account_id": source.get("exported_account_id"),
            "account_binding": source.get("account_binding"),
            "input_scope_basis": source.get("input_scope_basis"),
            "conversation_id": session, "conversation_display_name": metadata["name"],
            "sender_display_name": message.get("sender"), "sender_id": sid,
            "sender_group_basis": "account_and_exported_sender_id" if sid else "unresolved_no_name_merge",
            "server_id": native_id, "local_id": _identifier(message.get("local_id")),
            "shard": message.get("shard"),
            "id_basis": "unknown_nested_identifier_origin" if nested else "upstream_server_id_not_authenticated",
            "kind": message.get("kind"), "source_type": message.get("type"),
            "raw_type": message.get("raw_type"), "content": text,
            "time": _time_info(message, metadata, nested),
            "source": {"input_id": source["input_id"], "file_sha256": source["sha256"],
                       "location": location, "original_copy": source["original_copy"],
                       "upstream_row_provenance": message.get("bridge_source")},
            "source_fields": {k: v for k, v in message.items() if k not in ("quote", "forward")},
            "forward_metadata": ({k: v for k, v in message["forward"].items() if k != "messages"}
                                 if isinstance(message.get("forward"), dict) else None),
        }
        if row["time"]["display_consistency"]["status"] == "mismatch":
            self.issue("exported_time_fields_mismatch", source, location)
        _write_json(self.messages, row)
        esc = lambda value: html.escape(str(value if value is not None else "未知"), quote=True)
        self.html.write('<article class="%s"><h3>%s · %s</h3><p>%s · %s · %s</p><pre>%s</pre>' % (
            "nested" if nested else "message", esc(metadata["name"]), esc(message.get("sender")),
            esc(record_id), esc(row["time"]["beijing_from_exported_value"]),
            esc(row["time"]["basis"]), esc(text)))
        message_status = message.get("resource_status")
        if message_status not in (None, "available"):
            self.html.write('<p>媒体状态：%s · 详见 issues.jsonl</p>' % esc(message_status))
        for attachment in attachment_rows:
            reported = attachment.get("reported")
            upstream = reported.get("status") if isinstance(reported, dict) else None
            note = "" if upstream in (None, "available") else " · 上游状态：%s" % esc(upstream)
            if attachment["copied_path"]:
                self.html.write('<p><a download href="%s">本地附件</a> · %s%s</p>' % (
                    esc(attachment["copied_path"]), esc(attachment.get("sha256")), note))
            else:
                self.html.write('<p>附件状态：%s%s</p>' % (
                    esc(attachment["verification"]), note))
        self.html.write("</article>\n")
        quote = message.get("quote")
        if quote is not None:
            self.record(quote, source, metadata, location + ".quote", "quote", record_id,
                        root, depth + 1, budget)
        forward = message.get("forward")
        if forward is not None:
            if not isinstance(forward, dict):
                self.issue("forward_not_object", source, location)
            else:
                if forward.get("truncated") or forward.get("notice"):
                    self.issue("forward_incomplete_or_has_notice", source, location)
                children = forward.get("messages", [])
                if not isinstance(children, list):
                    self.issue("forward_messages_not_array", source, location)
                else:
                    for index, child in enumerate(children):
                        if budget[0] <= 0:
                            self.counts["nested_omitted"] += len(children) - index
                            self.issue("nested_expansion_limit", source, location)
                            break
                        self.record(child, source, metadata,
                                    location + ".forward.messages[%d]" % index,
                                    "forward", record_id, root, depth + 1, budget)

    def process(self, path, number):
        self.counts["input_files"] += 1
        source = {"input_id": "input-%04d" % number, "original_filename": path.name,
                  "original_copy": "originals/%04d%s" % (number, path.suffix.lower()),
                  "original_copy_status": "not_copied",
                  "status": "failed", "_root": path.parent.resolve()}
        self.sources.append(source)
        before_issues = self.counts["warnings"] + self.counts["errors"]
        copy = self.output / source["original_copy"]
        try:
            if path.suffix.lower() == ".json" and path.stat().st_size > MAX_JSON_BYTES:
                raise NormalizeError("json_size_limit_use_jsonl")
            source["sha256"], source["size"] = _copy_hash(path, copy)
            source["original_copy_status"] = "copied_and_hashed"
            if path.suffix.lower() == ".jsonl":
                self.process_jsonl(copy, source)
            else:
                if source["size"] > MAX_JSON_BYTES:
                    raise NormalizeError("json_size_limit_use_jsonl")
                try:
                    document = _strict_json(copy.read_text(encoding="utf-8-sig"))
                except (UnicodeError, json.JSONDecodeError, RecursionError):
                    raise NormalizeError("invalid_json") from None
                shape, metadata = _metadata(document)
                source.update(schema=shape, metadata=metadata)
                self.register_account(source, metadata)
                self.counts["valid_input_files"] += 1
                for index, message in enumerate(document["messages"]):
                    self.counts["top_level_seen"] += 1
                    self.record(message, source, metadata, "$.messages[%d]" % index)
                declared = document.get("count")
                if declared is not None and (isinstance(declared, bool)
                                             or declared != len(document["messages"])):
                    self.issue("declared_count_mismatch", source)
            source["post_read_sha256"] = _sha256(path)
            if source["post_read_sha256"] != source["sha256"]:
                self.issue("input_changed_during_processing", source, severity="error")
            source["status"] = ("partial" if self.counts["warnings"] + self.counts["errors"]
                                > before_issues else "success")
        except NormalizeError as exc:
            self.issue(str(exc), source, severity="error")
        except (OSError, UnicodeError, ValueError, OverflowError, RecursionError):
            self.issue("input_processing_failed", source, severity="error")

    def process_jsonl(self, copy, source):
        with copy.open("rb") as stream:
            shape, metadata = _jsonl_header(stream)
            source.update(schema=shape, metadata=metadata)
            self.register_account(source, metadata)
            self.counts["valid_input_files"] += 1
            for location, message, error in _jsonl_records(stream):
                self.counts["top_level_seen"] += 1
                if error:
                    self.counts["rejected_records"] += 1
                    self.counts["top_level_rejected"] += 1
                    self.issue(error, source, location, "error")
                else:
                    self.record(message, source, metadata, location)


def normalize(inputs, account_scope, out):
    """Return status/exit_code/counts/manifest; unsafe preflight raises NormalizeError.

    Success means the selected exports were processed, not that their authenticity,
    completeness or account ownership was verified. Missing resources are partial.
    """
    if isinstance(inputs, (str, os.PathLike)):
        inputs = [inputs]
    if not inputs:
        raise NormalizeError("input_required")
    if not _valid_scope(account_scope):
        raise NormalizeError("invalid_account_scope")
    output = Path(out).expanduser().absolute()
    _no_links(output)
    if os.path.lexists(output):
        raise NormalizeError("output_already_exists")
    if not output.parent.is_dir():
        raise NormalizeError("output_parent_must_exist")
    output = output.parent.resolve() / output.name
    paths = []
    for value in inputs:
        path = Path(value).expanduser().absolute()
        try:
            _regular(path)
        except OSError:
            raise NormalizeError("input_unavailable") from None
        path = path.resolve()
        if path.suffix.lower() not in (".json", ".jsonl"):
            raise NormalizeError("unsupported_input_extension")
        if _inside(path, output):
            raise NormalizeError("input_output_overlap")
        if path in paths:
            raise NormalizeError("duplicate_input_path")
        paths.append(path)
    try:
        output.mkdir()
        (output / "originals").mkdir()
        (output / "attachments").mkdir()
        with ((output / "messages.jsonl").open("x", encoding="utf-8") as messages,
              (output / "attachment_index.jsonl").open("x", encoding="utf-8") as attachments,
              (output / "issues.jsonl").open("x", encoding="utf-8") as issues,
              (output / "archive.html").open("x", encoding="utf-8") as page):
            page.write('<!doctype html><html lang="zh-CN"><meta charset="utf-8">'
                       '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
                       'style-src \'unsafe-inline\'; img-src \'none\'; base-uri \'none\'; form-action \'none\'">'
                       '<title>微信中立归档</title><style>body{max-width:960px;margin:2rem auto;'
                       'font:16px system-ui;padding:1rem}article{border:1px solid #ddd;'
                       'padding:1rem;margin:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}'
                       '.nested{margin-left:2rem;background:#f7f7f7}p{overflow-wrap:anywhere}</style>'
                       '<h1>微信中立归档</h1><p>仅整理所提供的导出件；未验证原始来源、身份或历史完整性。'
                       '转发及引用时间可能来自上游回退；其时间依据单独标注。</p>\n')
            archive = _Archive(output, account_scope, (messages, attachments, issues, page))
            for number, path in enumerate(paths, 1):
                archive.process(path, number)
            page_status, _ = _outcome(archive)
            page.write("<footer><h2>处理状态：%s</h2><p>顶层消息 %d 条；嵌套记录 %d 条。"
                       "partial 或 failed 表示存在缺项或冲突，请先查看 manifest.json 与 issues.jsonl。"
                       "</p></footer></html>\n" % (page_status, archive.counts["top_level_messages"],
                                                  archive.counts["nested_messages"]))
        with (output / "conversation_index.csv").open("x", encoding="utf-8-sig", newline="") as target:
            writer = csv.writer(target)
            writer.writerow(["账号范围", "会话ID", "显示名（可能为备注）", "顶层消息数", "嵌套记录数",
                             "稳定发言人标识数", "发言人标识未知记录数"])
            for session, group in sorted(archive.groups.items()):
                writer.writerow([_cell(x) for x in (account_scope, session,
                    " / ".join(sorted(group["names"])), group["top"], group["nested"],
                    len(group["senders"]), group["unknown_senders"])])
        counts = archive.counts
        status, code = _outcome(archive)
        manifest = {
            "schema": "moect-neutral-archive/1", "normalizer_version": SCRIPT_VERSION,
            "status": status, "exit_code": code, "completed": True,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "account_scope": account_scope, "counts": counts,
            "account_scope_verified": False,
            "known_exported_account_id": archive.known_owner,
            "conflicting_exported_account_ids": archive.account_conflict,
            "sources": [{k: v for k, v in source.items() if not k.startswith("_")}
                        for source in archive.sources],
            "scope": "Selected export bytes and explicitly referenced local attachments only; no authenticity or completeness certification.",
            "limitations": ["Unknown nested identifier/time origins remain unknown.",
                            "A caller-provided account scope does not verify account ownership; conflicting exported owners fail the entire run.",
                            "Display names may be remarks and are not verified identities.",
                            "Only resources[].path attachments are copied; absent media references cannot be recovered.",
                            "No OCR, transcription, legal classification, network access or automatic account discovery."],
            "files": ["messages.jsonl", "conversation_index.csv", "attachment_index.jsonl",
                      "issues.jsonl", "archive.html", "originals/", "attachments/"],
        }
        with (output / "manifest.json").open("x", encoding="utf-8") as target:
            json.dump(manifest, target, ensure_ascii=False, indent=2, allow_nan=False)
        return {"status": status, "exit_code": code, "counts": counts,
                "manifest": str(output / "manifest.json")}
    except (OSError, UnicodeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, NormalizeError):
            raise
        raise NormalizeError("output_processing_failed_partial_directory_retained") from None


def _outcome(archive):
    counts = archive.counts
    if archive.account_conflict or not counts["valid_input_files"] or (counts["top_level_seen"] and not counts["top_level_messages"]):
        return "failed", 2
    if counts["errors"] or counts["warnings"]:
        return "partial", 1
    return "success", 0


INSPECTION_HINTS = {
    "wechat-native-backup": "verify_origin_and_use_wechat_restore_on_authorized_device",
    "wechat-personal-copy": "retain_as_personal_information_material",
    "moect-non-session": "retain_separately_and_select_session_json_or_jsonl",
    "sqlite-container": "verify_provenance_and_supported_snapshot_before_any_export",
    "unknown": "verify_origin_or_export_session_json_or_jsonl",
}

INSPECTION_ISSUE_HINTS = {
    "duplicate_exported_server_id_retained": "use_source_positions_for_repeated_message_ids",
    "json_size_limit_use_jsonl": "export_same_scope_as_jsonl",
    "declared_account_scope_conflict": "check_selected_scope_against_original_export",
    "exported_account_id_conflict": "separate_conflicting_account_sources",
    "linked_path_rejected": "select_original_path_without_links",
    "input_changed_during_inspection": "repeat_inspection_after_export_is_stable",
}


def _inspect_export(stream, extension, size, item, scope):
    issues = set()
    seen_ids = set()
    repeated_ids = 0
    if extension == ".jsonl":
        kind, metadata = _jsonl_header(stream)
        records = _jsonl_records(stream)
    else:
        if size > MAX_JSON_BYTES:
            raise NormalizeError("json_size_limit_use_jsonl")
        data = stream.read(size + 1)
        if len(data) != size:
            raise NormalizeError("input_changed_during_inspection")
        try:
            document = _strict_json(data.decode("utf-8-sig"))
        except (UnicodeError, ValueError, RecursionError) as exc:
            if isinstance(exc, NormalizeError):
                raise
            raise NormalizeError("invalid_json") from None
        if (isinstance(document, dict) and document.get("application") == "Moect"
                and document.get("category") in ("favorites", "stickers", "moments")
                and isinstance(document.get("items"), list)):
            item["format"] = "moect-non-session"
            item["category"] = document["category"]
            return None, None
        kind, metadata = _metadata(document)
        messages = document["messages"]
        declared = document.get("count")
        if type(declared) is not int or declared != len(messages):
            issues.add("declared_count_mismatch")
        records = ((None, message, None) for message in messages)
    item.update(format=kind, message_count=0, problem_record_count=0)
    owner, declared_scope = _account_claims(metadata, scope)
    if declared_scope is not None and not _valid_scope(declared_scope):
        raise NormalizeError("invalid_declared_account_scope")
    if "exported_account_id" in metadata and not isinstance(metadata["exported_account_id"], str):
        raise NormalizeError("invalid_exported_account_id")
    item["account_claim_present"] = owner is not None
    item["filters_present"] = bool(metadata.get("filters"))
    if "filters" in metadata and not isinstance(metadata["filters"], dict):
        issues.add("invalid_export_filters")
    if "demo" in metadata and not isinstance(metadata["demo"], bool):
        issues.add("invalid_demo_flag")
    for _, message, error in records:
        item["message_count"] += 1
        if error is None:
            if not isinstance(message, dict) or not isinstance(message.get("text"), str):
                error = "invalid_message_record"
            elif message.get("session") not in (None, metadata["session"]):
                error = "message_session_mismatch"
        if error:
            item["problem_record_count"] += 1
            issues.add(error)
        else:
            server_id = _identifier(message.get("server_id"))
            if server_id:
                repeated_ids += int(server_id in seen_ids)
                seen_ids.add(server_id)
    item["issues"] = sorted(issues)
    item["repeated_server_id_records"] = repeated_ids
    item["demo"] = metadata.get("demo") is True
    return owner, declared_scope


def _inspect_source(path, info, item, scope, declared_kind):
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise NormalizeError("input_is_not_regular_file")
    if declared_kind:
        item.update(format=declared_kind, basis="caller_declared_origin")
        return None, None
    if stat.S_ISDIR(info.st_mode):
        if (path.name.casefold() == "chatpackage"
                or all(os.path.lexists(path / name) for name in ("ChatPackage", "Index"))):
            item.update(format="wechat-native-backup", basis="directory_marker_only")
        return None, None
    extension = path.suffix.lower()
    if extension not in (".json", ".jsonl", ".dat", ".enc", ".db"):
        return None, None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
            raise NormalizeError("input_changed_during_inspection")
        prefix = stream.read(16)
        if prefix.startswith(b"RMFH"):
            item.update(format="wechat-native-backup", basis="header_marker_only")
        elif prefix == b"SQLite format 3\x00":
            item.update(format="sqlite-container", basis="header_marker_only")
        elif extension in (".json", ".jsonl"):
            stream.seek(0)
            claims = _inspect_export(stream, extension, opened.st_size, item, scope)
            after = os.fstat(stream.fileno())
            current = path.stat()
            if ((opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
                    or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
                raise NormalizeError("input_changed_during_inspection")
            item["basis"] = "export_structure_only"
            return claims
    return None, None


def inspect_inputs(inputs, scope=None, declared_kind=None):
    if scope is not None and not _valid_scope(scope):
        raise NormalizeError("invalid_account_scope")
    if declared_kind and len(inputs) != 1:
        raise NormalizeError("source_kind_requires_single_input")
    items, owners, declared_scopes, paths = [], set(), set(), set()
    for index, raw_path in enumerate(inputs, 1):
        item = {"input_index": index, "format": "unknown", "basis": "unproven",
                "issues": [], "status": "blocked"}
        items.append(item)
        try:
            path = Path(raw_path).expanduser().absolute()
            _no_links(path)
            info = path.stat()
            resolved = path.resolve()
            if resolved in paths:
                raise NormalizeError("duplicate_input_path")
            paths.add(resolved)
            owner, declared_scope = _inspect_source(path, info, item, scope, declared_kind)
            if owner is not None:
                owners.add(owner)
            if declared_scope is not None:
                declared_scopes.add(declared_scope)
            if "message_count" in item and not item["issues"]:
                if scope is None or item["demo"]:
                    item["issues"].append("demo_export" if item["demo"] else "account_scope_unchecked")
                if item["repeated_server_id_records"]:
                    item["issues"].append("duplicate_exported_server_id_retained")
                item["status"] = "review" if item["issues"] else "ready"
        except NormalizeError as exc:
            item["issues"].append(str(exc))
        except (OSError, ValueError, RuntimeError):
            item["issues"].append("input_unavailable")
        if item["format"] == "unknown" and not item["issues"]:
            item["issues"].append("unrecognized_input")
        hint = next((INSPECTION_ISSUE_HINTS[code] for code in item["issues"]
                     if code in INSPECTION_ISSUE_HINTS), None)
        item["next_step"] = hint or INSPECTION_HINTS.get(item["format"], {
            "ready": "confirm_authorized_scope_and_normalize",
            "review": "review_declared_scope_and_demo_status",
            "blocked": "review_source_structure_or_export_again",
        }[item["status"]])
    issues = []
    blocked = any(item["status"] == "blocked" for item in items)
    if len(owners) > 1 or len(declared_scopes) > 1:
        issues.append("mixed_account_claims")
        blocked = True
    elif len(items) > 1 and any(item.get("account_claim_present") is False for item in items):
        issues.append("batch_account_unconfirmed")
    status = "blocked" if blocked else (
        "review" if issues or any(item["status"] == "review" for item in items) else "ready")
    return {"schema": "moect-input-inspection/1", "status": status,
            "exit_code": {"ready": 0, "review": 1, "blocked": 2}[status],
            "input_count": len(items), "account_scope_verified": False,
            "issues": issues, "inputs": items}


def main(argv=None):
    parser = argparse.ArgumentParser(description="本机整理 Moect JSON/JSONL 导出，不联网、不改原件")
    parser.add_argument("--input", action="append", required=True)
    parser.add_argument("--account-scope")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--out", help="整理到全新目录")
    mode.add_argument("--inspect", action="store_true", help="只读预检，不生成归档")
    parser.add_argument("--source-kind", choices=("wechat-native-backup", "wechat-personal-copy"),
                        help="只在预检登记已知来源，限单个输入")
    args = parser.parse_args(argv)
    if not args.inspect and (args.account_scope is None or args.source_kind):
        parser.error("--out requires --account-scope; --source-kind is only for --inspect")
    try:
        if args.inspect:
            result = inspect_inputs(args.input, args.account_scope, args.source_kind)
        else:
            result = normalize(args.input, args.account_scope, args.out)
    except (NormalizeError, TypeError) as exc:
        error = str(exc) if isinstance(exc, NormalizeError) else "invalid_arguments"
        result = {"status": "failed", "exit_code": 2, "error_code": error}
        if args.inspect:
            result.update(schema="moect-input-inspection/1", status="blocked",
                          input_count=len(args.input), account_scope_verified=False,
                          issues=[], inputs=[])
    print(json.dumps(result, ensure_ascii=False))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
