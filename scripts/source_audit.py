#!/usr/bin/env python3
"""Independent source-row accounting for the supported SQLite message schema.

No Moect or bridge imports are used to enumerate the reference. SQL reads must
target a run-owned processing copy: SQLite read-only WAL readers may maintain
SHM files. Preserve original acquisition bytes separately before calling this
module. This proves accounting within the supplied inventory and scope, not
unknown pre-acquisition history or real-world account identity.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import sys


FIELDS = ("local_id", "server_id", "local_type", "sort_seq", "real_sender_id",
          "create_time", "message_content", "compress_content", "packed_info_data")
REQUIRED = {"local_id", "create_time", "message_content"}


class SourceAuditError(RuntimeError):
    def __init__(self, code, details=None):
        self.code = code
        self.details = details or {}
        super().__init__(code)


def _hash(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_path(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or str(path).startswith(("//", "\\\\")):
        raise SourceAuditError("source_manifest_invalid")
    for part in reversed((path, *path.parents)):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise SourceAuditError("source_manifest_invalid")
    return path


def _relative_name(value):
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise SourceAuditError("source_manifest_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value or value == ".":
        raise SourceAuditError("source_manifest_invalid")
    return value


def _files(value):
    if not isinstance(value, dict) or not value:
        raise SourceAuditError("source_manifest_invalid")
    result = {}
    for name, digest in value.items():
        _relative_name(name)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise SourceAuditError("source_manifest_invalid")
        result[name] = digest
    return result


def inventory(root):
    """Return all database and associated-log byte hashes; never follow links."""
    root = _safe_path(root)
    if not root.is_dir():
        raise SourceAuditError("source_manifest_invalid")
    result = {}
    try:
        for parent, dirs, files in os.walk(root, followlinks=False):
            for name in dirs + files:
                path = Path(parent) / name
                _safe_path(path)
                if name in files and name.endswith((".db", ".db-wal", ".db-shm", ".db-journal")):
                    if not path.is_file():
                        raise SourceAuditError("source_manifest_invalid")
                    result[path.relative_to(root).as_posix()] = _hash(path)
    except OSError:
        raise SourceAuditError("source_manifest_invalid") from None
    if not any(name.endswith(".db") for name in result):
        raise SourceAuditError("source_manifest_invalid")
    return dict(sorted(result.items()))


def load_manifest(path):
    """Read the documented wrapper or the prior audit's plain hash-map shape."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SourceAuditError("source_manifest_invalid")
            result[key] = value
        return result
    try:
        with open(_safe_path(path), encoding="utf-8") as stream:
            document = json.load(stream, object_pairs_hook=unique_object)
        if isinstance(document, dict) and "schema_version" in document:
            if type(document["schema_version"]) is not int or document["schema_version"] != 1:
                raise SourceAuditError("source_manifest_invalid")
            document = document.get("files")
        return _files(document)
    except (OSError, ValueError, TypeError):
        raise SourceAuditError("source_manifest_invalid") from None


def bind_inventory(observed, expected=None):
    """Fail if a predeclared inventory differs; label observation-only limits."""
    observed = _files(observed)
    if expected is None:
        return {"status": "observed_only", "basis": "current_input_inventory_only",
                "file_count": len(observed), "predeclared_inventory_verified": False}
    expected = _files(expected)
    differences = {"missing": sorted(expected.keys() - observed.keys()),
                   "extra": sorted(observed.keys() - expected.keys()),
                   "changed": sorted(name for name in expected.keys() & observed.keys()
                                     if expected[name] != observed[name])}
    if any(differences.values()):
        raise SourceAuditError("source_manifest_mismatch", differences)
    return {"status": "matched", "basis": "predeclared_inventory",
            "file_count": len(observed), "predeclared_inventory_verified": True,
            "limit": "Matches only the supplied manifest; its historical completeness is not authenticated."}


def _json_value(value):
    if isinstance(value, bytes):
        return {"bytes_base64": base64.b64encode(value).decode("ascii")}
    return value


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _quote(name):
    return '"' + name.replace('"', '""') + '"'


def _restore(value):
    if isinstance(value, dict) and set(value) == {"bytes_base64"}:
        return base64.b64decode(value["bytes_base64"], validate=True)
    return value


def _decoded_reference(raw):
    """Apply the declared field-selection/codec contract, never Moect code."""
    decoded, rules = {}, {}
    try:
        for field in ("message_content", "compress_content"):
            value = _restore(raw[field])
            if value is None:
                decoded[field], rules[field] = "", "null"
            elif isinstance(value, str):
                decoded[field], rules[field] = value, "text"
            elif isinstance(value, bytes):
                rule = "utf8"
                if value.startswith(b"\x28\xb5\x2f\xfd"):
                    import zstandard
                    value = zstandard.ZstdDecompressor().decompress(value, max_output_size=4 * 1024 * 1024)
                    rule = "zstd_utf8"
                decoded[field], rules[field] = value.decode("utf-8", "strict"), rule
            else:
                return {"status": "unverified", "reason": "unsupported_content_storage_type"}
        selected = next((f for f in ("message_content", "compress_content")
                         if rules[f] == "zstd_utf8" and decoded[f]), None)
        if selected is None:
            selected = next((f for f in ("compress_content", "message_content") if decoded[f].strip()), None)
        if selected is None:
            selected = next((f for f in ("message_content", "compress_content") if decoded[f]), "message_content")
        return {"status": "decoded", "raw_decoded": decoded[selected], "source_field": selected,
                "decode_rule": rules[selected]}
    except (ImportError, ValueError, UnicodeError):
        return {"status": "unverified", "reason": "independent_codec_unavailable_or_invalid"}
    except Exception:
        return {"status": "unverified", "reason": "independent_decode_failed"}


def _contact_ids(root, files):
    """Read only raw stable usernames needed to recognize a wire prefix."""
    result = set()
    for name in files:
        if not name.endswith(".db"):
            continue
        try:
            with contextlib.closing(sqlite3.connect((root / name).as_uri() + "?mode=ro", uri=True)) as con:
                con.execute("PRAGMA query_only=ON")
                tables = {r[0] for r in con.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
                for table in ("contact", "stranger"):
                    if table not in tables:
                        continue
                    columns = {r[1] for r in con.execute("PRAGMA table_info(" + _quote(table) + ")")}
                    fields = [f for f in ("username", "user_name") if f in columns]
                    if not fields:
                        continue
                    for row in con.execute("SELECT " + ",".join(_quote(f) for f in fields) + " FROM " + _quote(table)):
                        value = next((v for v in row if v), None)
                        if isinstance(value, bytes):
                            try: value = value.decode("utf-8", "strict")
                            except UnicodeError: continue
                        if isinstance(value, str) and value:
                            result.add(value)
        except sqlite3.Error:
            raise SourceAuditError("source_query_failed", {"database": name}) from None
    return result


def _sender_reference(row, names, contacts):
    mapped = names.get(_restore(row["raw_fields"]["real_sender_id"]))
    mapped = mapped if isinstance(mapped, str) and mapped else None
    text = row["text_reference"]
    if text["status"] != "decoded":
        return {"status": "unverified", "mapped_id": mapped, "reason": "content_decode_unverified"}
    body = text["raw_decoded"]
    prefix = None
    candidate = None
    if row["session"].endswith("@chatroom") and "\n" in body[:256]:
        head, rest = body.split("\n", 1)
        head = head.rstrip("\r")
        candidate = head[:-1] if head.endswith(":") else None
        if candidate and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]{1,190}", candidate):
            known = candidate == mapped or candidate in names.values() or candidate in contacts
            recognizable = not mapped and (candidate.startswith("wxid_") or candidate.endswith("@openim"))
            if known or recognizable:
                prefix = candidate
                if not mapped or mapped == prefix:
                    body = rest
    status = "conflict" if mapped and prefix and mapped != prefix else "mapped" if mapped else "prefix_only" if prefix else "unknown"
    return {"status": status, "mapped_id": mapped, "prefix_id": prefix,
            "selected_id": "" if status == "conflict" else mapped or prefix or "",
            "display_text": body, "display_transform": "none" if body == text["raw_decoded"] else "verified_group_prefix_removed"}


def _locator(source):
    if not isinstance(source, dict):
        return None
    if type(source.get("source_rowid")) is int:
        location = ("rowid", source["source_rowid"])
    elif isinstance(source.get("source_pk"), list) and source["source_pk"]:
        pk = source["source_pk"]
        if any(not isinstance(item, dict) or set(item) != {"column", "value"} or
               not isinstance(item["column"], str) or not item["column"] for item in pk):
            return None
        location = ("pk", _canonical(pk))
    else:
        return None
    if not isinstance(source.get("database"), str) or not isinstance(source.get("table"), str):
        return None
    return source["database"], source["table"], *location


def enumerate_source(root, sessions, start=None, end=None, *, source_hashes=None):
    """Enumerate selected tables with physical locators independently of Moect.

    ``source_hashes`` may bind a processing copy to separately preserved raw
    evidence. The caller must retain that derivation receipt; actual queried
    database hashes are recorded independently in this reference.
    """
    root = _safe_path(root)
    if (not sessions or any(not isinstance(s, str) or not s for s in sessions) or
            len(set(sessions)) != len(sessions) or
            any(v is not None and type(v) is not int for v in (start, end)) or
            (start is not None and end is not None and start > end)):
        raise SourceAuditError("source_scope_invalid")
    processing = inventory(root)
    evidence = _files(source_hashes) if source_hashes is not None else processing
    selected = {"Msg_" + (s[10:] if re.fullmatch(r"local-msg:[0-9a-f]{32}", s)
                           else hashlib.md5(s.encode("utf-8")).hexdigest()): s for s in sessions}
    if len(selected) != len(sessions):
        raise SourceAuditError("source_scope_invalid")
    result = {"schema_version": 1,
              "scope": {"sessions": list(sessions), "start_inclusive": start, "end_inclusive": end},
              "reference_method": "independent sqlite3 mode=ro/query_only; all supplied DBs; no Moect imports",
              "processing_database_hashes": {n: h for n, h in processing.items() if n.endswith(".db")},
              "hash_basis": "separately_preserved_evidence" if source_hashes is not None else "queried_database_bytes",
              "rows": [], "time_excluded_rows": [], "tables": [],
              "limit": "Selected sessions in the supplied inventory only; no proof of unknown historical absence."}
    occurrence = Counter()
    contacts = _contact_ids(root, processing)
    for name in sorted(n for n in processing if n.endswith(".db")):
        if name not in evidence:
            raise SourceAuditError("source_manifest_mismatch", {"missing_evidence_hash": [name]})
        try:
            with contextlib.closing(sqlite3.connect((root / name).as_uri() + "?mode=ro", uri=True)) as con:
                con.row_factory = sqlite3.Row
                con.execute("PRAGMA query_only=ON")
                tables = {r["name"] for r in con.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
                try:
                    names_map = {r[0]: r[1] for r in con.execute("SELECT rowid,user_name FROM Name2Id")} if "Name2Id" in tables else {}
                except sqlite3.Error:
                    names_map = {}
                for table, session in selected.items():
                    if table not in tables:
                        continue
                    columns = con.execute("PRAGMA table_info(" + _quote(table) + ")").fetchall()
                    names = {r["name"] for r in columns}
                    if not REQUIRED <= names:
                        raise SourceAuditError("source_schema_unsupported", {
                            "database": name, "table": table, "missing_columns": sorted(REQUIRED - names),
                            "row_count": con.execute("SELECT count(*) FROM " + _quote(table)).fetchone()[0]})
                    meta = con.execute("PRAGMA table_list(" + _quote(table) + ")").fetchone()
                    if meta is None:
                        raise SourceAuditError("source_locator_unsupported", {"database": name, "table": table})
                    without_rowid = bool(meta["wr"])
                    pk = [r["name"] for r in sorted(columns, key=lambda r: r["pk"]) if r["pk"]]
                    aliases = [a for a in ("_rowid_", "rowid", "oid") if a.casefold() not in {n.casefold() for n in names}]
                    if (without_rowid and not pk) or (not without_rowid and not aliases):
                        raise SourceAuditError("source_locator_unsupported", {"database": name, "table": table})
                    location_select = ([f'{_quote(c)} AS "__audit_pk_{i}"' for i, c in enumerate(pk)] if without_rowid
                                       else [f'{aliases[0]} AS "__audit_rowid"'])
                    fields = [_quote(f) if f in names else 'NULL AS ' + _quote(f) for f in FIELDS]
                    order = ",".join(_quote(c) for c in pk) if without_rowid else aliases[0]
                    # Ask SQLite to apply the declared inclusive filter, preserving
                    # SQL NULL and column-affinity behavior instead of guessing it.
                    inside = " AND ".join((["create_time >= ?"] if start is not None else []) +
                                          (["create_time <= ?"] if end is not None else [])) or "1"
                    values = [v for v in (start, end) if v is not None]
                    query = "SELECT " + ",".join(location_select + fields +
                        ["CASE WHEN " + inside + " THEN 1 ELSE 0 END AS __audit_in_scope"]) + " FROM " + _quote(table) + " ORDER BY " + order
                    count = included = 0
                    for row in con.execute(query, values):
                        count += 1
                        raw = {f: _json_value(row[f]) for f in FIELDS}
                        projected_hash = hashlib.sha256(_canonical(raw).encode("utf-8")).hexdigest()
                        record = {"database": name, "database_sha256": evidence[name], "table": table,
                                  "session": session, "local_id": _json_value(row["local_id"]),
                                  "row_sha256": projected_hash, "raw_fields": raw}
                        record["text_reference"] = _decoded_reference(raw)
                        record["sender_reference"] = _sender_reference(record, names_map, contacts)
                        if without_rowid:
                            record["source_pk"] = [{"column": c, "value": _json_value(row[f"__audit_pk_{i}"])} for i, c in enumerate(pk)]
                        else:
                            record["source_rowid"] = row["__audit_rowid"]
                        signature = (name, table, projected_hash)
                        occurrence[signature] += 1
                        record["projection_occurrence"] = occurrence[signature]
                        if row["__audit_in_scope"]:
                            included += 1
                            result["rows"].append(record)
                        else:
                            record["exclusion_reason"] = "timestamp_null_not_comparable" if row["create_time"] is None else "outside_inclusive_time_window"
                            result["time_excluded_rows"].append(record)
                    result["tables"].append({"database": name, "table": table, "session": session,
                                             "rows": count, "included": included, "time_excluded": count - included,
                                             "locator_kind": "primary_key" if without_rowid else "rowid"})
        except sqlite3.Error:
            raise SourceAuditError("source_query_failed", {"database": name}) from None
    after = inventory(root)
    stable_files = lambda files: {n: h for n, h in files.items() if not n.endswith(".db-shm")}
    if stable_files(after) != stable_files(processing):
        raise SourceAuditError("source_changed")
    return result


def _embedded_counts(message):
    quotes = forwards = 0
    stack = [message]
    while stack:
        current = stack.pop()
        if not isinstance(current, dict):
            continue
        quote = current.get("quote")
        if isinstance(quote, dict) and quote:
            quotes += 1
            stack.append(quote)
        forward = current.get("forward")
        children = forward.get("messages", []) if isinstance(forward, dict) else []
        if isinstance(children, list):
            forwards += len(children)
            stack.extend(children)
    return quotes, forwards


def _persisted_field_checks(message, row):
    raw = row["raw_fields"]
    content = message.get("bridge_content")
    sender = message.get("bridge_sender")
    content = content if isinstance(content, dict) else {}
    sender = sender if isinstance(sender, dict) else {}
    original_id = _restore(raw["server_id"])
    expected = {"server_id": str(original_id) if original_id is not None else "",
                "raw_type": raw["local_type"], "bridge_original_timestamp": raw["create_time"]}
    mismatches = [name for name, value in expected.items() if name not in message or _canonical(message[name]) != _canonical(value)]
    for field in ("message_content", "compress_content"):
        stored = content.get("raw_fields")
        if not isinstance(stored, dict) or field not in stored or _canonical(stored[field]) != _canonical(raw[field]):
            mismatches.append("bridge_content.raw_fields." + field)
    if "raw_real_sender_id" not in sender or _canonical(sender["raw_real_sender_id"]) != _canonical(raw["real_sender_id"]):
        mismatches.append("bridge_sender.raw_real_sender_id")
    timestamp = _restore(raw["create_time"])
    valid_time = isinstance(timestamp, (int, float)) and not isinstance(timestamp, bool) and 0 < timestamp < 253402300800
    try:
        display_time = datetime.fromtimestamp(int(timestamp), timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S") if valid_time else ""
    except (ValueError, OverflowError, OSError):
        display_time = ""
    for field, value in {"create_time": timestamp if valid_time else 0, "time_str": display_time,
                         "bridge_time_status": "source_epoch" if valid_time else "unknown"}.items():
        if field not in message or _canonical(message[field]) != _canonical(value):
            mismatches.append(field)
    time_rule = message.get("bridge_time_rule")
    if not isinstance(time_rule, dict) or time_rule.get("unit") != "seconds" or time_rule.get("display_timezone") != "Asia/Shanghai":
        mismatches.append("bridge_time_rule")
    reference = row["text_reference"]
    unverified = []
    if reference["status"] == "decoded":
        for field in ("raw_decoded", "source_field", "decode_rule"):
            if content.get(field) != reference[field]:
                mismatches.append("bridge_content." + field)
    else:
        unverified.append(reference["reason"])
    sender_ref = row["sender_reference"]
    if sender_ref["status"] != "unverified":
        for field in ("status", "mapped_id", "prefix_id"):
            if field not in sender or sender[field] != sender_ref[field]:
                mismatches.append("bridge_sender." + field)
        if message.get("sender_wxid") != sender_ref["selected_id"]:
            mismatches.append("sender_wxid")
    else:
        unverified.append(sender_ref["reason"])
    # Only the ordinary text contract is compared as presentation text. Complex
    # type rendering is intentionally bounded to exact original-field retention.
    local_type = _restore(raw["local_type"])
    try: ordinary_text = int(local_type) == 1 or (int(local_type) > 65535 and (int(local_type) & 0xFFFFFFFF) == 1)
    except (TypeError, ValueError, OverflowError): ordinary_text = False
    if ordinary_text and sender_ref["status"] != "unverified":
        for field in ("text", "content"):
            if (field == "text" or field in message) and message.get(field) != sender_ref["display_text"]:
                mismatches.append(field)
        if message.get("type") != 1:
            mismatches.append("type")
        if content.get("display_transform") != sender_ref["display_transform"]:
            mismatches.append("bridge_content.display_transform")
    return mismatches, sorted(set(unverified))


def reconcile(reference, exported_messages, rejected=()):
    """Match persisted top-level records/rejects; nested records never fill gaps."""
    rows = reference["rows"]
    expected = {_locator(row): row for row in rows}
    if None in expected or len(expected) != len(rows):
        raise SourceAuditError("source_locator_unsupported")
    seen = Counter()
    issues, ledger, semantic_unverified = [], [], []
    quote_count = forward_count = top_count = rejected_count = 0
    for rejection, records in ((False, exported_messages), (True, rejected)):
        for position, message in enumerate(records, 1):
            if not isinstance(message, dict):
                issues.append({"code": "invalid_output_record", "record_index": position, "rejected": rejection})
                continue
            top_count += not rejection
            rejected_count += rejection
            source = message.get("bridge_source")
            locator = _locator(source)
            location = {"record_index": position, "rejected": rejection}
            if message.get("export_location") is not None:
                location["export_location"] = message["export_location"]
            if not rejection:
                quotes, forwards = _embedded_counts(message)
                quote_count += quotes
                forward_count += forwards
            if locator is None:
                issues.append({"code": "physical_locator_missing", **location})
                continue
            seen[locator] += 1
            row = expected.get(locator)
            if row is None:
                issues.append({"code": "unexpected_source_row", "bridge_source": source, **location})
                continue
            mismatches = [key for key in ("database_sha256", "local_id", "row_sha256")
                          if _canonical(source.get(key)) != _canonical(row.get(key))]
            if not rejection and message.get("session") != row["session"]:
                mismatches.append("session")
            if not rejection:
                field_mismatches, unverified = _persisted_field_checks(message, row)
                mismatches.extend(field_mismatches)
                if unverified:
                    semantic_unverified.append({"source": row, "reasons": unverified, **location})
            if rejection and (not isinstance(message.get("reason"), str) or not message["reason"].strip()):
                mismatches.append("rejection_reason")
            status = "rejected" if rejection else "retained"
            if mismatches:
                status = "mismatch"
                issues.append({"code": "source_fields_mismatch", "fields": mismatches,
                               "bridge_source": source, **location})
            ledger.append({"status": status, "source": row, "output": location,
                           **({"reason": message.get("reason")} if rejection else {})})
    for locator, row in expected.items():
        if not seen[locator]:
            issues.append({"code": "missing_source_row", "source": row})
            ledger.append({"status": "missing", "source": row})
        elif seen[locator] > 1:
            issues.append({"code": "source_row_repeated_in_output", "source": row, "occurrences": seen[locator]})
    return {"schema_version": 1, "passed": not issues,
            "counts": {"source_in_scope": len(rows), "source_time_excluded": len(reference["time_excluded_rows"]),
                       "exported_top_level": top_count, "rejected_top_level": rejected_count,
                       "embedded_quotes": quote_count, "embedded_forward_items": forward_count},
            "ledger": ledger, "time_excluded_rows": reference["time_excluded_rows"], "issues": issues,
            "semantic_checks_complete": not semantic_unverified,
            "semantic_unverified": semantic_unverified,
            "semantic_check_scope": "exact raw fields, IDs, source timestamp/display rule, source sender indicators and ordinary text; complex display rendering not validated",
            "embedded_count_basis": "structured embedded items in the supplied persisted records; never top-level source rows",
            "completeness_limit": reference["limit"]}


def _normalized_identifier(value):
    if isinstance(value, str):
        return value or None
    if type(value) is int:
        return str(value)
    return None


def _normalized_time_reference(fields, metadata, nested):
    """Derive organizer time labels from the fixed export, not its output labels."""
    raw = fields.get("create_time")
    valid = isinstance(raw, (int, float)) and not isinstance(raw, bool) and 0 < raw < 253402300800
    instant = None
    if valid:
        try:
            instant = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=raw)
        except (ValueError, OverflowError):
            valid = False
    provenance = fields.get("provenance")
    provenance = provenance if isinstance(provenance, dict) else {}
    declared = provenance.get("time_basis", fields.get("time_basis"))
    basis = "unknown_or_unsupported_timestamp" if not valid else "unknown_nested_time_origin" if nested else "upstream_create_time_seconds"
    if isinstance(declared, str) and "fallback" in declared.casefold(): basis = "input_reports_fallback"
    status = fields.get("bridge_time_status")
    if status == "source_epoch" and valid: basis = "bridge_reports_source_epoch"
    elif status == "source_text_unzoned": basis = "source_text_timezone_unknown"
    elif status == "unknown": basis = "bridge_reports_unknown_time"
    zone_name, display = metadata.get("time_zone"), fields.get("time_str")
    check = {"status": "not_checked", "basis": "declared_export_fields_only",
             "declared_timezone": zone_name if isinstance(zone_name, str) else None}
    if not valid: check["reason"] = "unknown_or_unsupported_epoch"
    elif basis not in ("upstream_create_time_seconds", "bridge_reports_source_epoch"):
        check["reason"] = "unknown_or_fallback_time_origin"
    elif not isinstance(zone_name, str) or not zone_name or zone_name == "unknown": check["reason"] = "timezone_unknown"
    elif not isinstance(display, str) or not display: check["reason"] = "display_time_missing"
    else:
        try:
            zone = timezone.utc if zone_name in ("UTC", "Etc/UTC") else ZoneInfo(zone_name)
        except (ZoneInfoNotFoundError, ValueError, OSError):
            check["reason"] = "timezone_unsupported_or_rules_unavailable"
        else:
            try:
                actual = datetime.strptime(display, "%Y-%m-%d %H:%M:%S")
                expected = instant.astimezone(zone).replace(tzinfo=None, microsecond=0)
                check["status"] = "match" if actual == expected else "mismatch"
            except (ValueError, OverflowError, OSError):
                check["reason"] = "display_time_unparseable_or_epoch_unsupported"
    return {"raw_create_time": raw, "raw_time_str": display,
        "source_display_timezone": zone_name or "unknown", "basis": basis,
        "input_declared_basis": declared, "input_bridge_time_status": status,
        "bridge_original_time_text": fields.get("bridge_original_time_text"),
        "utc_from_exported_value": instant.isoformat() if valid else None,
        "beijing_from_exported_value": instant.astimezone(timezone(timedelta(hours=8))).isoformat() if valid else None,
        "display_consistency": check, "verified_original_event_time": False}


def _export_nodes(document, export_format):
    """Enumerate actual saved payload nodes independently of the organizer."""
    if export_format == "json":
        if not isinstance(document, dict) or not isinstance(document.get("messages"), list):
            raise SourceAuditError("export_payload_invalid")
        metadata = document.get("metadata")
        initial = [(f"$.messages[{i}]", row) for i, row in enumerate(document["messages"])]
        declared = document.get("count")
    else:
        if not document or not isinstance(document[0], dict) or set(document[0]) != {"metadata"}:
            raise SourceAuditError("export_payload_invalid")
        metadata = document[0]["metadata"]
        initial = [(f"line:{i}", row) for i, row in document[1:]]
        declared = metadata.get("count") if isinstance(metadata, dict) else None
    if not isinstance(metadata, dict) or metadata.get("application") != "Moect" or not isinstance(metadata.get("session"), str):
        raise SourceAuditError("export_payload_invalid")
    if declared is not None and (type(declared) is not int or declared != len(initial)):
        raise SourceAuditError("export_payload_count_mismatch")
    nodes = {}
    stack = [(location, row, "top_level", None, location) for location, row in initial]
    while stack:
        location, row, kind, parent, root = stack.pop()
        if not isinstance(row, dict) or set(row) == {"metadata"}:
            raise SourceAuditError("export_payload_node_invalid")
        forward = row.get("forward")
        if forward is not None and not isinstance(forward, dict):
            raise SourceAuditError("export_payload_forward_invalid")
        nodes[location] = {"record_kind": kind, "parent_location": parent, "root_location": root,
                           "conversation_id": metadata["session"],
                           "conversation_display_name": metadata.get("name"),
                           "sender_display_name": row.get("sender"),
                           "kind": row.get("kind"), "shard": row.get("shard"),
                           "id_basis": "upstream_server_id_not_authenticated" if kind == "top_level" else "unknown_nested_identifier_origin",
                           "sender_group_basis": "account_and_exported_sender_id" if _normalized_identifier(row.get("sender_wxid")) else "unresolved_no_name_merge",
                           "account_binding": "caller_scope_and_exported_owner_unverified" if metadata.get("account_id") or metadata.get("exported_account_id") else "caller_declared_scope_only",
                           "input_scope_basis": metadata.get("scope_basis", "unknown"),
                           "time": _normalized_time_reference(row, metadata, kind != "top_level"),
                           "source_fields": {key: value for key, value in row.items() if key not in ("quote", "forward")},
                           "forward_metadata": {key: value for key, value in forward.items() if key != "messages"} if isinstance(forward, dict) else None}
        if row.get("quote") is not None:
            stack.append((location + ".quote", row["quote"], "quote", location, root))
        if isinstance(forward, dict):
            children = forward.get("messages", [])
            if not isinstance(children, list):
                raise SourceAuditError("export_payload_forward_invalid")
            stack.extend((f"{location}.forward.messages[{i}]", child, "forward", location, root)
                         for i, child in enumerate(children))
    return nodes, len(initial)


def verify_normalized_exports(reference, records, archive_root):
    """Bind every final node and relationship to unchanged saved export bytes."""
    exports = reference.get("exports")
    if not exports:
        return {"status": "unverified", "reason": "expected_exports_not_bound", "issues": []}
    if archive_root is None:
        return {"status": "unverified", "reason": "normalized_archive_root_required", "issues": []}
    issues, expected, copies, nodes = [], {}, {}, {}
    try:
        root = _safe_path(archive_root)
        originals = _safe_path(root / "originals")
        for item in exports:
            if not isinstance(item, dict) or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))):
                raise SourceAuditError("expected_exports_invalid")
            _relative_name(item.get("path"))
            digest = item["sha256"]
            if digest in expected:
                raise SourceAuditError("expected_exports_duplicate")
            if item.get("format") == "html":
                return {"status": "unsupported", "reason": "html_not_supported_as_normalizer_input", "issues": []}
            if item.get("format") not in ("json", "jsonl") or type(item.get("count")) is not int or item["count"] < 0:
                raise SourceAuditError("expected_exports_invalid")
            expected[digest] = item
        for path in originals.rglob("*"):
            _safe_path(path)
            if path.is_file():
                raw = path.read_bytes()
                digest = hashlib.sha256(raw).hexdigest()
                if digest not in expected:
                    issues.append({"code": "unexpected_original_export_copy", "original_copy": path.relative_to(root).as_posix()})
                    continue
                if digest in copies:
                    issues.append({"code": "duplicate_original_export_copy", "export_sha256": digest})
                    continue
                copies[digest] = path.relative_to(root).as_posix()
                item = expected[digest]
                text = raw.decode("utf-8-sig")
                if item["format"] == "json":
                    document = json.loads(text)
                else:
                    lines = text.splitlines()
                    document = [json.loads(lines[0])] + [(i, json.loads(line)) for i, line in enumerate(lines[1:], 2) if line.strip()] if lines else []
                found, top_count = _export_nodes(document, item["format"])
                if top_count != item["count"]:
                    issues.append({"code": "expected_export_count_mismatch", "export_sha256": digest})
                nodes.update({(digest, location): node for location, node in found.items()})
                if _hash(path) != digest:
                    raise SourceAuditError("source_changed")
        for digest in expected.keys() - copies.keys():
            issues.append({"code": "original_export_copy_missing_or_changed", "export_sha256": digest})
        matched = {}
        for line, record in enumerate(records, 1):
            if not isinstance(record, dict):
                continue  # The outer normalized-row check records the malformed row.
            source = record.get("source")
            source = source if isinstance(source, dict) else {}
            digest, location = source.get("file_sha256"), source.get("location")
            info = {"normalized_line": line, "record_id": record.get("record_id")}
            key = (digest, location) if isinstance(digest, str) and isinstance(location, str) else None
            node = nodes.get(key)
            if node is None:
                issues.append({"code": "unexpected_normalized_node", **info})
                continue
            if key in matched:
                issues.append({"code": "normalized_source_node_repeated", **info})
                continue
            matched[key] = (record, info)
            mismatches = [field for field in ("record_kind", "conversation_id", "conversation_display_name", "sender_display_name",
                          "kind", "shard", "id_basis", "sender_group_basis", "account_binding", "input_scope_basis", "time",
                          "source_fields", "forward_metadata")
                          if field not in record or _canonical(record[field]) != _canonical(node[field])]
            if source.get("original_copy") != copies[digest]:
                mismatches.append("source.original_copy")
            if mismatches:
                issues.append({"code": "normalized_export_payload_mismatch", "fields": mismatches, **info})
        for key in nodes.keys() - matched.keys():
            issues.append({"code": "normalized_source_node_missing", "export_sha256": key[0], "source_location": key[1]})
        for key, (record, info) in matched.items():
            node = nodes[key]
            parent = matched.get((key[0], node["parent_location"])) if node["parent_location"] is not None else None
            root_node = matched.get((key[0], node["root_location"]))
            parent_id = parent[0].get("record_id") if parent else None
            root_id = root_node[0].get("record_id") if root_node else None
            if record.get("parent_record_id") != parent_id or record.get("root_record_id") != root_id:
                issues.append({"code": "normalized_export_relationship_mismatch", **info})
        return {"status": "passed" if not issues else "failed", "issues": issues,
                "expected_export_files": len(expected), "verified_export_files": len(copies),
                "expected_nodes": len(nodes), "matched_nodes": len(matched),
                "limit": "Organizer fidelity to saved export bytes; not independent validation of complex Moect rendering."}
    except SourceAuditError as error:
        code = error.code
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        code = "export_payload_verification_failed"
    return {"status": "failed", "issues": issues + [{"code": code}]}


def reconcile_normalized(reference, records, archive_root=None):
    """Close the final hop using persisted normalizer rows and raw SQL reference."""
    records = list(records)
    top, issues, links = [], [], []
    record_ids, root_ids = set(), set()
    counts = Counter()
    for line, record in enumerate(records, 1):
        if not isinstance(record, dict):
            issues.append({"code": "normalized_record_invalid", "normalized_line": line})
            continue
        kind, record_id = record.get("record_kind"), record.get("record_id")
        location = {"normalized_line": line, "record_id": record_id}
        if kind not in ("top_level", "quote", "forward"):
            issues.append({"code": "normalized_record_kind_invalid", **location})
            continue
        counts[kind] += 1
        if not isinstance(record_id, str) or not record_id or record_id in record_ids:
            issues.append({"code": "normalized_record_id_missing_or_repeated", **location})
        else:
            record_ids.add(record_id)
        if kind == "top_level":
            root_ids.add(record_id)
        links.append((location, kind, record.get("parent_record_id"), record.get("root_record_id")))
        fields = record.get("source_fields")
        if not isinstance(fields, dict):
            issues.append({"code": "normalized_source_fields_missing", **location})
            continue
        expected = {"content": fields.get("text") if isinstance(fields.get("text"), str) else None,
                    "sender_id": _normalized_identifier(fields.get("sender_wxid")),
                    "server_id": _normalized_identifier(fields.get("server_id")),
                    "local_id": _normalized_identifier(fields.get("local_id")),
                    "raw_type": fields.get("raw_type"), "source_type": fields.get("type")}
        if kind == "top_level":
            expected["conversation_id"] = fields.get("session")
            top.append({**fields, "export_location": location})
        for scope_field, normalized_field in (("account_id", "exported_account_id"), ("account_scope", "account_scope")):
            if scope_field in reference["scope"]:
                expected[normalized_field] = reference["scope"][scope_field]
        mismatches = [name for name, value in expected.items() if name not in record or _canonical(record[name]) != _canonical(value)]
        source = record.get("source")
        if not isinstance(source, dict) or source.get("upstream_row_provenance") != fields.get("bridge_source"):
            mismatches.append("source.upstream_row_provenance")
        time_info = record.get("time")
        time_info = time_info if isinstance(time_info, dict) else {}
        for field, value in {"raw_create_time": fields.get("create_time"), "raw_time_str": fields.get("time_str"),
                             "input_bridge_time_status": fields.get("bridge_time_status"),
                             "verified_original_event_time": False}.items():
            if field not in time_info or _canonical(time_info[field]) != _canonical(value):
                mismatches.append("time." + field)
        stamp = fields.get("create_time")
        utc = beijing = None
        if isinstance(stamp, (int, float)) and not isinstance(stamp, bool) and 0 < stamp < 253402300800:
            try:
                instant = datetime.fromtimestamp(stamp, timezone.utc)
                utc = instant.isoformat()
                beijing = instant.astimezone(timezone(timedelta(hours=8))).isoformat()
            except (ValueError, OverflowError, OSError):
                pass
        for field, value in (("utc_from_exported_value", utc), ("beijing_from_exported_value", beijing)):
            if field not in time_info or time_info[field] != value:
                mismatches.append("time." + field)
        if mismatches:
            issues.append({"code": "normalized_fields_mismatch", "fields": mismatches, **location})
    for location, kind, parent, root in links:
        if ((kind == "top_level" and (parent is not None or root != location["record_id"])) or
                (kind != "top_level" and (parent not in record_ids or root not in root_ids or parent == location["record_id"]))):
            issues.append({"code": "normalized_relation_invalid", **location})
    result = reconcile(reference, top)
    result["issues"].extend(issues)
    result["passed"] = not result["issues"]
    result["stage"] = "source_to_normalized_records"
    result["counts"].update(normalized_top_level=counts["top_level"], embedded_quotes=counts["quote"],
                            embedded_forward_items=counts["forward"])
    result["embedded_count_basis"] = "final record_kind; counts are separate from top-level source accounting"
    closure = verify_normalized_exports(reference, records, archive_root)
    result["export_payload_closure"] = closure
    result["issues"].extend(closure["issues"])
    result["passed"] = not result["issues"]
    result["three_hop_verified"] = result["passed"] and result["semantic_checks_complete"] and closure["status"] == "passed"
    return result


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise SourceAuditError("arguments_invalid")


def main(argv=None):
    parser = _Parser(description="Reconcile final local normalized records with the independent source reference.")
    parser.add_argument("--reference", required=True, help="Absolute source-reference.json path")
    parser.add_argument("--normalized", required=True, help="Absolute final messages.jsonl path")
    parser.add_argument("--out", required=True, help="New report file inside an existing private local directory")
    try:
        args = parser.parse_args(argv)
        reference_path, normalized_path = _safe_path(args.reference), _safe_path(args.normalized)
        output = Path(args.out)
        if not output.is_absolute() or ".." in output.parts or str(output).startswith(("//", "\\\\")):
            raise SourceAuditError("source_manifest_invalid")
        _safe_path(output.parent)
        if output.exists() or output.is_symlink():
            raise SourceAuditError("output_exists")
        before = {"source_reference_sha256": _hash(reference_path), "normalized_messages_sha256": _hash(normalized_path)}
        with open(reference_path, encoding="utf-8") as stream:
            reference = json.load(stream)
        def rows():
            with open(normalized_path, encoding="utf-8") as stream:
                for line in stream:
                    # Blank lines are invalid records, preserving actual line positions.
                    yield json.loads(line)
        result = reconcile_normalized(reference, rows(), normalized_path.parent)
        if before != {"source_reference_sha256": _hash(reference_path), "normalized_messages_sha256": _hash(normalized_path)}:
            raise SourceAuditError("source_changed")
        result["input_hashes"] = before
        result["status"] = "failed" if not result["passed"] else "passed" if result["three_hop_verified"] else "partial"
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        print(json.dumps({"ok": result["status"] == "passed", "status": result["status"], "counts": result["counts"]}))
        return 0 if result["status"] == "passed" else 1 if result["status"] == "partial" else 2
    except SourceAuditError as error:
        code = error.code
    except Exception:
        code = "source_audit_failed"
    print(json.dumps({"ok": False, "code": code}))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
