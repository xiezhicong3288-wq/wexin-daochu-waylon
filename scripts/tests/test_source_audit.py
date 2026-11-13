"""Independent physical-row accounting tests using hand-built SQLite inputs."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
from contextlib import closing
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "source_audit.py"
spec = importlib.util.spec_from_file_location("source_audit", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
SESSION = "wxid_synthetic_peer"
TABLE = "Msg_" + hashlib.md5(SESSION.encode()).hexdigest()


class SourceAudit(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def database(self, name="message_0.db", rows=None, *, without_rowid=False, body_name="message_content", session=SESSION,
                 local_type=None, sender_id=None):
        rows = rows if rows is not None else [(1, 99, 100, "literal"), (1, 99, 101, "literal")]
        with closing(sqlite3.connect(self.source / name)) as con, con:
            table = "Msg_" + hashlib.md5(session.encode()).hexdigest()
            prefix = "slot TEXT, " if without_rowid else ""
            suffix = ", PRIMARY KEY(slot, local_id)) WITHOUT ROWID" if without_rowid else ")"
            con.execute(f'CREATE TABLE "{table}" ({prefix}local_id INTEGER, server_id INTEGER, create_time INTEGER, "{body_name}" TEXT{suffix}')
            for index, (local, server, stamp, body) in enumerate(rows, 1):
                values = [local, server, stamp, body]
                if without_rowid:
                    values.insert(0, f"slot-{index}")
                con.execute(f'INSERT INTO "{table}" VALUES (' + ",".join("?" for _ in values) + ")", values)
            for field, value in (("local_type", local_type), ("real_sender_id", sender_id)):
                if value is not None:
                    con.execute(f'ALTER TABLE "{table}" ADD COLUMN "{field}" INTEGER')
                    con.execute(f'UPDATE "{table}" SET "{field}"=?', (value,))

    def messages(self, name="message_0.db", rows=None, *, without_rowid=False, session=SESSION,
                 local_type=None, sender_id=None, sender_expectation=None, decoded_body=None):
        # Expected output provenance is built from fixture literals, not from
        # enumerate_source(), a Moect reader, or the implementation's hashing helper.
        rows = rows if rows is not None else [(1, 99, 100, "literal"), (1, 99, 101, "literal")]
        result = []
        for index, (local, server, stamp, body) in enumerate(rows, 1):
            stored_body = {"bytes_base64": base64.b64encode(body).decode()} if isinstance(body, bytes) else body
            raw = {"local_id": local, "server_id": server, "local_type": local_type,
                   "sort_seq": None, "real_sender_id": sender_id, "create_time": stamp,
                   "message_content": stored_body, "compress_content": None, "packed_info_data": None}
            raw_hash = hashlib.sha256(json.dumps(raw, ensure_ascii=False, sort_keys=True,
                                                separators=(",", ":")).encode()).hexdigest()
            source = {"database": name, "database_sha256": hashlib.sha256((self.source/name).read_bytes()).hexdigest(),
                      "table": "Msg_" + (session[10:] if session.startswith("local-msg:") else hashlib.md5(session.encode()).hexdigest()),
                      "local_id": local, "row_sha256": raw_hash}
            if without_rowid:
                source["source_pk"] = [{"column": "slot", "value": f"slot-{index}"},
                                       {"column": "local_id", "value": local}]
            else:
                source["source_rowid"] = index
            text = body if decoded_body is None else decoded_body
            sender = {"status": "unknown", "mapped_id": None, "prefix_id": None, "raw_real_sender_id": sender_id}
            sender.update(sender_expectation or {})
            selected = "" if sender["status"] == "conflict" else sender["mapped_id"] or sender["prefix_id"] or ""
            display = text.split("\n", 1)[1] if sender["prefix_id"] and sender["status"] != "conflict" else text
            result.append({"session": session, "bridge_source": source,
                "server_id": str(server) if server is not None else "", "raw_type": local_type,
                "type": 1 if local_type == 1 else 0, "text": display, "content": display,
                "bridge_original_timestamp": stamp, "create_time": stamp or 0,
                "time_str": datetime.fromtimestamp(stamp, timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S") if stamp else "",
                "bridge_time_status": "source_epoch" if stamp else "unknown",
                "bridge_time_rule": {"unit": "seconds", "display_timezone": "Asia/Shanghai"},
                "bridge_sender": sender, "sender_wxid": selected,
                "bridge_content": {"raw_fields": {"message_content": stored_body, "compress_content": None},
                    "raw_decoded": text, "source_field": "message_content", "decode_rule": "utf8" if isinstance(body, bytes) else "text",
                    "display_transform": "verified_group_prefix_removed" if display != text else "none"}})
        return result

    def test_observed_manifest_does_not_claim_prior_inventory_verification(self):
        self.database()
        observed = audit.inventory(self.source)
        receipt = audit.bind_inventory(observed)
        self.assertEqual(receipt["basis"], "current_input_inventory_only")
        self.assertFalse(receipt["predeclared_inventory_verified"])

    def test_known_missing_shard_is_rejected_before_row_accounting(self):
        self.database()
        self.database("message_1.db")
        expected = audit.inventory(self.source)
        (self.source / "message_1.db").unlink()
        with self.assertRaises(audit.SourceAuditError) as caught:
            audit.bind_inventory(audit.inventory(self.source), expected)
        self.assertEqual(caught.exception.code, "source_manifest_mismatch")
        self.assertEqual(caught.exception.details["missing"], ["message_1.db"])

    def test_changed_and_extra_file_differences_are_separate(self):
        self.database()
        expected = audit.inventory(self.source)
        with closing(sqlite3.connect(self.source / "message_0.db")) as con, con:
            con.execute(f'UPDATE "{TABLE}" SET message_content="changed" WHERE rowid=1')
        self.database("unexpected.db")
        with self.assertRaises(audit.SourceAuditError) as caught:
            audit.bind_inventory(audit.inventory(self.source), expected)
        self.assertEqual(caught.exception.details["changed"], ["message_0.db"])
        self.assertEqual(caught.exception.details["extra"], ["unexpected.db"])

    def test_manifest_supports_prior_plain_shape_and_explicit_schema(self):
        self.database()
        expected = audit.inventory(self.source)
        for index, payload in enumerate((expected, {"schema_version": 1, "files": expected})):
            file = self.root / f"manifest-{index}.json"
            file.write_text(json.dumps(payload))
            self.assertEqual(audit.load_manifest(file), expected)
            self.assertTrue(audit.bind_inventory(expected, audit.load_manifest(file))["predeclared_inventory_verified"])
        for name in ("../message.db", "/message.db", "a\\message.db", "C:message.db", "a//message.db"):
            with self.subTest(name=name), self.assertRaises(audit.SourceAuditError):
                audit.bind_inventory({name: "0" * 64})
        file = self.root / "duplicate.json"
        file.write_text('{"message_0.db":"' + '0' * 64 + '","message_0.db":"' + '1' * 64 + '"}')
        with self.assertRaises(audit.SourceAuditError):
            audit.load_manifest(file)

    def test_duplicate_ids_and_identical_values_need_distinct_physical_rows(self):
        rows = [(1, 99, 100, "same"), (1, 99, 100, "same")]
        self.database(rows=rows)
        reference = audit.enumerate_source(self.source, [SESSION])
        self.assertEqual([r["source_rowid"] for r in reference["rows"]], [1, 2])
        self.assertEqual([r["projection_occurrence"] for r in reference["rows"]], [1, 2])
        messages = self.messages(rows=rows)
        self.assertTrue(audit.reconcile(reference, messages)["passed"])
        changed = [messages[0], messages[0]]
        result = audit.reconcile(reference, changed)
        self.assertFalse(result["passed"])
        self.assertEqual({i["code"] for i in result["issues"]}, {"missing_source_row", "source_row_repeated_in_output"})

    def test_equal_total_cannot_hide_missing_and_extra_source_rows(self):
        self.database()
        reference = audit.enumerate_source(self.source, [SESSION])
        messages = self.messages()
        messages[1]["bridge_source"]["source_rowid"] = 999
        result = audit.reconcile(reference, messages)
        self.assertEqual(result["counts"]["source_in_scope"], result["counts"]["exported_top_level"])
        self.assertFalse(result["passed"])
        self.assertEqual({i["code"] for i in result["issues"]}, {"missing_source_row", "unexpected_source_row"})

    def test_projection_hash_without_physical_locator_cannot_pass(self):
        self.database()
        reference = audit.enumerate_source(self.source, [SESSION])
        messages = self.messages()
        for message in messages:
            del message["bridge_source"]["source_rowid"]
        result = audit.reconcile(reference, messages)
        self.assertFalse(result["passed"])
        self.assertIn("physical_locator_missing", [i["code"] for i in result["issues"]])

    def test_inclusive_time_window_retains_repeated_id_and_explains_exclusions(self):
        rows = [(1, 99, 99, "a"), (2, 99, 100, "b"), (3, 99, 101, "c"),
                (4, 99, 101, "c"), (5, 99, 102, "d")]
        self.database(rows=rows)
        reference = audit.enumerate_source(self.source, [SESSION], 100, 101)
        self.assertEqual([r["source_rowid"] for r in reference["rows"]], [2, 3, 4])
        self.assertEqual([r["source_rowid"] for r in reference["time_excluded_rows"]], [1, 5])
        result = audit.reconcile(reference, self.messages(rows=rows)[1:4])
        self.assertTrue(result["passed"])
        self.assertEqual(result["counts"]["source_time_excluded"], 2)

    def test_nullable_time_exclusion_is_not_invented_as_known_time(self):
        self.database(rows=[(1, 99, None, "unknown")])
        reference = audit.enumerate_source(self.source, [SESSION], start=100)
        self.assertEqual(reference["rows"], [])
        self.assertEqual(reference["time_excluded_rows"][0]["exclusion_reason"], "timestamp_null_not_comparable")

    def test_independent_discovery_finds_selected_table_in_other_named_database(self):
        self.database("renamed-source.db")
        reference = audit.enumerate_source(self.source, [SESSION])
        self.assertEqual(len(reference["rows"]), 2)
        self.assertFalse(audit.reconcile(reference, [])["passed"])

    def test_without_rowid_uses_ordered_declared_primary_key(self):
        self.database(without_rowid=True)
        reference = audit.enumerate_source(self.source, [SESSION])
        self.assertNotIn("source_rowid", reference["rows"][0])
        self.assertEqual(reference["rows"][0]["source_pk"], [{"column": "slot", "value": "slot-1"},
                                                          {"column": "local_id", "value": 1}])
        self.assertTrue(audit.reconcile(reference, self.messages(without_rowid=True))["passed"])

    def test_optional_absent_columns_are_explicit_null_and_required_missing_fails(self):
        self.database()
        reference = audit.enumerate_source(self.source, [SESSION])
        self.assertIsNone(reference["rows"][0]["raw_fields"]["compress_content"])
        self.database("message_1.db", body_name="unsupported_body")
        with self.assertRaises(audit.SourceAuditError) as caught:
            audit.enumerate_source(self.source, [SESSION])
        self.assertEqual(caught.exception.code, "source_schema_unsupported")
        self.assertEqual(caught.exception.details["row_count"], 2)

    def test_rejected_row_needs_locator_and_reason_and_is_not_retained(self):
        self.database()
        reference = audit.enumerate_source(self.source, [SESSION])
        messages = self.messages()
        rejection = {"bridge_source": messages[1]["bridge_source"], "reason": "decode_failed"}
        result = audit.reconcile(reference, messages[:1], [rejection])
        self.assertTrue(result["passed"])
        self.assertEqual((result["counts"]["exported_top_level"], result["counts"]["rejected_top_level"]), (1, 1))
        rejection["reason"] = ""
        self.assertFalse(audit.reconcile(reference, messages[:1], [rejection])["passed"])

    def test_embedded_counts_cannot_replace_missing_top_level_and_order_is_irrelevant(self):
        self.database()
        reference = audit.enumerate_source(self.source, [SESSION])
        messages = self.messages()
        self.assertTrue(audit.reconcile(reference, list(reversed(messages)))["passed"])
        messages[0]["sender"] = "display-name-can-change"
        messages[0]["quote"] = dict(messages[1])
        messages[0]["forward"] = {"messages": [{"text": "child", "quote": {"text": "nested quote"}}]}
        result = audit.reconcile(reference, messages[:1])
        self.assertFalse(result["passed"])
        self.assertEqual(result["counts"]["embedded_quotes"], 2)
        self.assertEqual(result["counts"]["embedded_forward_items"], 1)
        self.assertEqual(result["counts"]["exported_top_level"], 1)
        self.assertTrue(audit.reconcile(reference, messages)["passed"])

    def test_provenance_field_corruption_is_detected(self):
        self.database()
        reference = audit.enumerate_source(self.source, [SESSION])
        messages = self.messages()
        messages[0]["bridge_source"]["row_sha256"] = "0" * 64
        messages[1]["session"] = "wrong-session"
        result = audit.reconcile(reference, messages)
        self.assertFalse(result["passed"])
        self.assertEqual({field for issue in result["issues"] for field in issue.get("fields", [])},
                         {"row_sha256", "session"})

    def test_sql_read_does_not_change_source_bytes(self):
        self.database()
        before = audit.inventory(self.source)
        audit.enumerate_source(self.source, [SESSION])
        self.assertEqual(before, audit.inventory(self.source))

    def test_local_msg_alias_points_to_raw_hash_table(self):
        self.database(local_type=1)
        alias = "local-msg:" + TABLE[4:]
        reference = audit.enumerate_source(self.source, [alias])
        self.assertEqual(len(reference["rows"]), 2)
        self.assertEqual(reference["rows"][0]["table"], TABLE)
        self.assertTrue(audit.reconcile(reference, self.messages(session=alias, local_type=1))["passed"])

    def test_saved_field_mutations_fail_even_when_source_locator_and_hash_match(self):
        rows = [(1, 0, 100, " \tLiteral\r\n😀\n ")]
        self.database(rows=rows, local_type=1)
        reference = audit.enumerate_source(self.source, [SESSION])
        original = self.messages(rows=rows, local_type=1)
        self.assertTrue(audit.reconcile(reference, original)["passed"])
        changes = [(["server_id"], ""), (["raw_type"], 3), (["bridge_original_timestamp"], 999),
                   (["create_time"], 999), (["time_str"], "invented"), (["text"], "Literal"),
                   (["content"], "Literal"), (["bridge_content", "raw_fields", "message_content"], "changed"),
                   (["bridge_content", "raw_fields", "compress_content"], "changed"),
                   (["bridge_sender", "raw_real_sender_id"], 42), (["bridge_content", "raw_decoded"], "changed"),
                   (["bridge_content", "display_transform"], "unrecorded"), (["sender_wxid"], "invented")]
        for path, value in changes:
            with self.subTest(field=".".join(path)):
                messages = json.loads(json.dumps(original))
                target = messages[0]
                for component in path[:-1]:
                    target = target[component]
                target[path[-1]] = value
                result = audit.reconcile(reference, messages)
                self.assertFalse(result["passed"])
                self.assertTrue(any(".".join(path) in issue.get("fields", []) for issue in result["issues"]))

    def test_group_prefix_is_grounded_in_independent_name2id_rows(self):
        session = "synthetic@chatroom"
        rows = [(1, 99, 100, "wxid_B:\n exact body ")]
        self.database(rows=rows, local_type=1, sender_id=1, session=session)
        with closing(sqlite3.connect(self.source / "message_0.db")) as con, con:
            con.execute("CREATE TABLE Name2Id(user_name TEXT)")
            con.executemany("INSERT INTO Name2Id VALUES (?)", [("wxid_A",), ("wxid_B",)])
        reference = audit.enumerate_source(self.source, [session])
        messages = self.messages(rows=rows, local_type=1, sender_id=1, session=session,
            sender_expectation={"status": "conflict", "mapped_id": "wxid_A", "prefix_id": "wxid_B"})
        self.assertTrue(audit.reconcile(reference, messages)["passed"])
        self.assertEqual(reference["rows"][0]["sender_reference"]["display_text"], rows[0][3])
        messages[0]["text"] = " exact body "
        self.assertFalse(audit.reconcile(reference, messages)["passed"])

    def test_unavailable_interpretation_is_explicit_without_hiding_row_accounting(self):
        rows = [(1, 99, 100, b"\xffinvalid")]
        self.database(rows=rows, local_type=1)
        reference = audit.enumerate_source(self.source, [SESSION])
        result = audit.reconcile(reference, self.messages(rows=rows, local_type=1, decoded_body=""))
        self.assertTrue(result["passed"])
        self.assertFalse(result["semantic_checks_complete"])
        self.assertEqual(len(result["semantic_unverified"]), 1)

    def normalized_fixture(self, *, nested=False, export_format="json"):
        self.database(local_type=1)
        messages = self.messages(local_type=1)
        for message in messages:
            del message["content"]  # Actual Moect clean() omits this redundant key.
        if nested:
            messages[0]["quote"] = {"text": "quoted original", "type": 1, "sender_wxid": "quote-author"}
            messages[1]["forward"] = {"title": "forwarded", "count": 1, "messages": [
                {"text": "forward child", "type": 1, "quote": {"text": "nested original", "type": 1}}]}
        export = self.root / ("export." + export_format)
        metadata = {"application": "Moect", "session": SESSION, "name": "synthetic", "time_zone": "Asia/Shanghai",
                    "account_id": "owner", "account_id_kind": "wxid", "account_scope": "synthetic-scope"}
        text = (json.dumps({"metadata": metadata, "messages": messages}) if export_format == "json" else
                json.dumps({"metadata": metadata}) + "\n\n" + "\n".join(json.dumps(row) for row in messages) + "\n")
        export.write_text(text, encoding="utf-8")
        normalized = self.root / "normalized"
        run = subprocess.run([sys.executable, "-B", str(SCRIPT.with_name("normalize_export.py")), "--input", str(export),
            "--account-scope", "synthetic-scope", "--out", str(normalized)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, (run.stdout, run.stderr))
        reference = audit.enumerate_source(self.source, [SESSION])
        reference["scope"].update(account_id="owner", account_scope="synthetic-scope")
        reference["exports"] = [{"path": "exports/" + export.name, "sha256": hashlib.sha256(export.read_bytes()).hexdigest(),
                                  "format": export_format, "count": len(messages)}]
        records = [json.loads(line) for line in (normalized / "messages.jsonl").read_text().splitlines()]
        return reference, records, normalized / "messages.jsonl"

    def test_final_hop_uses_actual_normalizer_and_detects_mutated_visible_fields(self):
        reference, records, normalized_path = self.normalized_fixture()
        self.assertTrue(audit.reconcile_normalized(reference, records, normalized_path.parent)["three_hop_verified"])
        mutations = [(["content"], "POST-NORMALIZATION-CHANGE"), (["sender_id"], "other"),
                     (["conversation_id"], "other-chat"), (["server_id"], "999"),
                     (["time", "raw_create_time"], 999), (["time", "beijing_from_exported_value"], "invented"),
                     (["account_scope"], "wrong-account-scope")]
        for path, value in mutations:
            with self.subTest(field=".".join(path)):
                changed = json.loads(json.dumps(records))
                target = changed[0]
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                result = audit.reconcile_normalized(reference, changed, normalized_path.parent)
                self.assertFalse(result["passed"])
                self.assertTrue(any(".".join(path) in item.get("fields", []) for item in result["issues"]))

    def test_final_hop_detects_omission_duplication_and_preserves_nested_counts(self):
        reference, records, path = self.normalized_fixture(nested=True)
        result = audit.reconcile_normalized(reference, records, path.parent)
        self.assertTrue(result["three_hop_verified"])
        self.assertEqual(result["counts"]["source_in_scope"], 2)
        self.assertEqual(result["counts"]["normalized_top_level"], 2)
        self.assertEqual(result["counts"]["embedded_quotes"], 2)
        self.assertEqual(result["counts"]["embedded_forward_items"], 1)
        self.assertFalse(audit.reconcile_normalized(reference, records[:1], path.parent)["passed"])
        self.assertFalse(audit.reconcile_normalized(reference, [records[0], records[0]], path.parent)["passed"])

    def test_final_hop_rejects_missing_invented_or_mutated_nested_nodes(self):
        reference, records, path = self.normalized_fixture(nested=True)
        nested_index = next(i for i, row in enumerate(records) if row["record_kind"] == "quote")
        omitted = records[:nested_index] + records[nested_index + 1:]
        result = audit.reconcile_normalized(reference, omitted, path.parent)
        self.assertFalse(result["three_hop_verified"])
        self.assertIn("normalized_source_node_missing", [issue["code"] for issue in result["issues"]])
        invented = json.loads(json.dumps(records[nested_index]))
        invented["record_id"] = "invented-node"
        invented["source"]["location"] += ".quote"
        result = audit.reconcile_normalized(reference, records + [invented], path.parent)
        self.assertIn("unexpected_normalized_node", [issue["code"] for issue in result["issues"]])
        mutated = json.loads(json.dumps(records))
        mutated[nested_index]["content"] = mutated[nested_index]["source_fields"]["text"] = "changed together"
        result = audit.reconcile_normalized(reference, mutated, path.parent)
        self.assertIn("normalized_export_payload_mismatch", [issue["code"] for issue in result["issues"]])

    def test_final_hop_rejects_wrong_root_and_cycles_even_with_existing_parents(self):
        reference, records, path = self.normalized_fixture(nested=True)
        roots = [row["record_id"] for row in records if row["record_kind"] == "top_level"]
        nested_indices = [i for i, row in enumerate(records) if row["record_kind"] != "top_level"]
        wrong_root = json.loads(json.dumps(records))
        wrong_root[nested_indices[0]]["root_record_id"] = roots[1]
        result = audit.reconcile_normalized(reference, wrong_root, path.parent)
        self.assertIn("normalized_export_relationship_mismatch", [issue["code"] for issue in result["issues"]])
        cycle = json.loads(json.dumps(records))
        a, b = nested_indices[:2]
        cycle[a]["parent_record_id"], cycle[b]["parent_record_id"] = cycle[b]["record_id"], cycle[a]["record_id"]
        result = audit.reconcile_normalized(reference, cycle, path.parent)
        self.assertIn("normalized_export_relationship_mismatch", [issue["code"] for issue in result["issues"]])

    def test_final_hop_jsonl_node_locations_and_export_hash_binding(self):
        reference, records, path = self.normalized_fixture(nested=True, export_format="jsonl")
        self.assertTrue(audit.reconcile_normalized(reference, records, path.parent)["three_hop_verified"])
        changed = json.loads(json.dumps(reference))
        changed["exports"][0]["sha256"] = "0" * 64
        result = audit.reconcile_normalized(changed, records, path.parent)
        self.assertFalse(result["passed"])
        self.assertIn("original_export_copy_missing_or_changed", [issue["code"] for issue in result["issues"]])
        copy = next((path.parent / "originals").iterdir())
        copy.with_name("duplicate.jsonl").write_bytes(copy.read_bytes())
        result = audit.reconcile_normalized(reference, records, path.parent)
        self.assertIn("duplicate_original_export_copy", [issue["code"] for issue in result["issues"]])

    def test_final_hop_cli_writes_report_preserves_inputs_and_refuses_overwrite(self):
        reference, _, normalized = self.normalized_fixture()
        reference_path = self.root / "reference.json"
        reference_path.write_text(json.dumps(reference))
        output = self.root / "report.json"
        before = [hashlib.sha256(path.read_bytes()).hexdigest() for path in (reference_path, normalized)]
        command = [sys.executable, "-B", str(SCRIPT), "--reference", str(reference_path),
                   "--normalized", str(normalized), "--out", str(output)]
        run = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, (run.stdout, run.stderr))
        result = json.loads(output.read_text())
        self.assertEqual(result["status"], "passed")
        self.assertEqual([result["input_hashes"][key] for key in ("source_reference_sha256", "normalized_messages_sha256")], before)
        self.assertNotIn(SESSION, run.stdout + run.stderr)
        saved = output.read_bytes()
        again = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(again.returncode, 2)
        self.assertEqual(json.loads(again.stdout)["code"], "output_exists")
        self.assertEqual(saved, output.read_bytes())
        self.assertEqual(before, [hashlib.sha256(path.read_bytes()).hexdigest() for path in (reference_path, normalized)])
        unbound = self.root / "unbound-reference.json"
        del reference["exports"]
        unbound.write_text(json.dumps(reference))
        command[command.index("--reference") + 1] = str(unbound)
        command[command.index("--out") + 1] = str(self.root / "partial-report.json")
        partial = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(partial.returncode, 1, (partial.stdout, partial.stderr))
        self.assertEqual(json.loads(partial.stdout)["status"], "partial")


if __name__ == "__main__":
    unittest.main()
