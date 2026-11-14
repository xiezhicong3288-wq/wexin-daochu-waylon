"""Synthetic, offline acceptance tests. Never read a real WeChat account."""
import contextlib
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "normalize_export", Path(__file__).resolve().parents[1] / "normalize_export.py")
normalizer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(normalizer)


def message(**changes):
    value = dict(server_id="90071992547409931234", local_id=7, shard=0,
                 create_time=1767225600, time_str="2026-01-01 08:00:00",
                 sender="合成昵称", sender_wxid="synthetic_sender", session="synthetic_chat",
                 kind="text", type=1, text="合成原话\n保留换行  ", resources=[])
    value.update(changes)
    return value


def document(messages=None, session="synthetic_chat", name="合成会话"):
    return {"metadata": {"application": "Moect", "version": "1.2.8", "session": session,
                         "name": name, "time_zone": "Asia/Shanghai", "demo": True},
            "messages": messages if messages is not None else [message()],
            "count": len(messages) if messages is not None else 1}


class NormalizeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.inputs = self.base / "inputs"
        self.inputs.mkdir()
        self.out = self.base / "out"

    def tearDown(self):
        self.temp.cleanup()

    def write(self, value, name="source.json"):
        path = self.inputs / name
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
        return path

    def rows(self, name="messages.jsonl"):
        return [json.loads(line) for line in (self.out / name).read_text(encoding="utf-8").splitlines()]

    def run_export(self, paths):
        return normalizer.normalize(paths, "synthetic-account", self.out)

    def test_gui_preserves_original_bytes_text_and_source_locations(self):
        path = self.write(document())
        before = path.read_bytes()
        result = self.run_export([path])
        self.assertEqual(result["status"], "success")
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual((self.out / "originals/0001.json").read_bytes(), before)
        row = self.rows()[0]
        self.assertEqual(row["content"], message()["text"])
        self.assertEqual(row["source"]["location"], "$.messages[0]")
        self.assertEqual(row["source"]["file_sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(row["time"]["beijing_from_exported_value"], "2026-01-01T08:00:00+08:00")

    def test_jsonl_metadata_is_not_message_and_physical_lines_are_retained(self):
        path = self.inputs / "source.jsonl"
        header = {"metadata": document()["metadata"]}
        path.write_text(json.dumps(header) + "\n\n" + json.dumps(message()) + "\n", encoding="utf-8")
        result = self.run_export([path])
        self.assertEqual(result["counts"]["top_level_seen"], 1)
        self.assertEqual(self.rows()[0]["source"]["location"], "line:3")

    def test_legacy_schema_keeps_account_and_unknown_display_timezone(self):
        legacy = dict(session="synthetic_chat", display="合成会话", wxid="synthetic_owner",
                      exported_at="2026-01-01T12:00:00", count=1, messages=[message()])
        result = self.run_export([self.write(legacy)])
        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        self.assertEqual(manifest["sources"][0]["metadata"]["exported_account_id"], "synthetic_owner")
        self.assertEqual(self.rows()[0]["time"]["source_display_timezone"], "unknown")
        self.assertEqual(self.rows()[0]["exported_account_id"], "synthetic_owner")

    def test_conflicting_known_owners_fail_entire_run_and_do_not_merge_messages(self):
        one = dict(session="synthetic_chat", display="合成会话", wxid="synthetic_owner_A",
                   exported_at="2026-01-01T12:00:00", count=1, messages=[message()])
        two = dict(one, wxid="synthetic_owner_B")
        result = self.run_export([self.write(one, "ownerA.json"), self.write(two, "ownerB.json")])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["counts"]["top_level_messages"], 1)
        self.assertEqual(self.rows()[0]["exported_account_id"], "synthetic_owner_A")
        self.assertIn("exported_account_id_conflict", [row["code"] for row in self.rows("issues.jsonl")])
        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        self.assertTrue(manifest["conflicting_exported_account_ids"])

    def test_gui_scope_is_explicitly_caller_declared_and_unverified(self):
        result = self.run_export([self.write(document())])
        self.assertEqual(self.rows()[0]["account_binding"], "caller_declared_scope_only")
        self.assertIsNone(self.rows()[0]["exported_account_id"])
        manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        self.assertFalse(manifest["account_scope_verified"])

    def test_bridge_account_identity_and_scope_are_preserved(self):
        doc = document()
        doc["metadata"].update(account_id="synthetic_owner", account_id_kind="wxid",
                               account_scope="synthetic-account", scope_basis="user_selected",
                               identity_verified=False)
        result = self.run_export([self.write(doc)])
        self.assertEqual(result["status"], "success")
        self.assertEqual(self.rows()[0]["exported_account_id"], "synthetic_owner")
        self.assertEqual(self.rows()[0]["input_scope_basis"], "user_selected")

    def test_bridge_owner_conflicts_fail_without_cross_owner_merge(self):
        one, two = document(), document()
        for doc, owner in ((one, "owner_A"), (two, "owner_B")):
            doc["metadata"].update(account_id=owner, account_id_kind="wxid",
                                   account_scope="synthetic-account")
        result = self.run_export([self.write(one, "a.json"), self.write(two, "b.json")])
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["counts"]["top_level_messages"], 1)
        self.assertIn("处理状态：failed", (self.out / "archive.html").read_text(encoding="utf-8"))

    def test_cli_label_cannot_override_declared_input_scope(self):
        doc = document()
        doc["metadata"].update(account_id="owner_A", account_id_kind="wxid",
                               account_scope="different-declared-scope")
        result = self.run_export([self.write(doc)])
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["counts"]["top_level_messages"], 0)
        self.assertIn("declared_account_scope_conflict", [r["code"] for r in self.rows("issues.jsonl")])

    def test_bridge_nested_time_flags_and_provenance_remain_explicit(self):
        child = message(bridge_time_status="source_epoch",
                        bridge_source={"table": "Msg_synthetic", "row_sha256": "synthetic-only"})
        raw = message(forward={"messages": [child]})
        self.run_export([self.write(document([raw]))])
        nested = self.rows()[1]
        self.assertEqual(nested["time"]["basis"], "bridge_reports_source_epoch")
        self.assertFalse(nested["time"]["verified_original_event_time"])
        self.assertEqual(nested["source"]["upstream_row_provenance"], child["bridge_source"])

    def test_duplicate_and_large_ids_are_retained_without_rounding(self):
        huge = 9007199254740993123456789
        records = [message(server_id=huge), message(server_id=huge)]
        result = self.run_export([self.write(document(records))])
        self.assertEqual(result["counts"]["top_level_messages"], 2)
        self.assertEqual([row["server_id"] for row in self.rows()], [str(huge)] * 2)
        self.assertEqual(self.rows()[0]["source_fields"]["server_id"], huge)
        self.assertIn("duplicate_exported_server_id_retained", [r["code"] for r in self.rows("issues.jsonl")])

    def test_unknown_type_is_preserved(self):
        raw = message(kind="future_type", type=99887, raw_type=99887, text="未知类型仍保留")
        self.run_export([self.write(document([raw]))])
        self.assertEqual(self.rows()[0]["kind"], "future_type")
        self.assertEqual(self.rows()[0]["source_type"], 99887)
        self.assertEqual(self.rows()[0]["content"], raw["text"])

    def test_nested_relationships_do_not_inflate_top_level_count(self):
        raw = message(kind="chatrecord", quote=message(server_id="quote"),
                      forward={"messages": [message(server_id="0")], "count": 1})
        result = self.run_export([self.write(document([raw]))])
        rows = self.rows()
        self.assertEqual(result["counts"]["top_level_messages"], 1)
        self.assertEqual(result["counts"]["nested_messages"], 2)
        self.assertEqual([r["record_kind"] for r in rows], ["top_level", "quote", "forward"])
        self.assertEqual(rows[1]["parent_record_id"], rows[0]["record_id"])
        self.assertEqual(rows[2]["root_record_id"], rows[0]["record_id"])
        self.assertEqual(rows[2]["id_basis"], "unknown_nested_identifier_origin")
        self.assertEqual(rows[2]["time"]["basis"], "unknown_nested_time_origin")

    def test_names_do_not_merge_different_conversations_or_senders(self):
        one = self.write(document([message(sender_wxid="person_1"),
                                  message(sender_wxid="person_2", server_id="2")]), "one.json")
        two = self.write(document([message(sender_wxid="person_1", server_id="3")],
                                  name="改名后的会话"), "two.json")
        three = self.write(document([message(session="other_chat")], session="other_chat"), "three.json")
        self.run_export([one, two, three])
        with (self.out / "conversation_index.csv").open(encoding="utf-8-sig", newline="") as target:
            groups = {row["会话ID"]: row for row in csv.DictReader(target)}
        self.assertEqual(len(groups), 2)
        self.assertEqual(groups["synthetic_chat"]["稳定发言人标识数"], "2")
        self.assertIn("改名后的会话", groups["synthetic_chat"]["显示名（可能为备注）"])

    def test_attachment_copy_is_limited_to_referenced_bytes(self):
        (self.inputs / "media").mkdir()
        payload = self.inputs / "media/sample.bin"
        payload.write_bytes(b"synthetic attachment\x00\xff")
        (self.inputs / "unreferenced-secret.bin").write_bytes(b"do not copy")
        raw = message(resources=[dict(path="media/sample.bin", status="available", kind="file")])
        result = self.run_export([self.write(document([raw]))])
        attachment = self.rows("attachment_index.jsonl")[0]
        self.assertEqual(result["status"], "success")
        self.assertEqual((self.out / attachment["copied_path"]).read_bytes(), payload.read_bytes())
        self.assertEqual(attachment["sha256"], hashlib.sha256(payload.read_bytes()).hexdigest())
        self.assertEqual(len(list((self.out / "attachments").iterdir())), 1)
        self.assertFalse((self.out / "unreferenced-secret.bin").exists())

    def test_external_and_parent_attachment_paths_are_rejected(self):
        bad = ["../outside.bin", "/etc/passwd", "C:\\secret.txt", "\\\\host\\file", "file.txt:stream",
               "https://example.com/secret", "..\\secret.txt"]
        raw = message(resources=[dict(path=value, status="available") for value in bad])
        result = self.run_export([self.write(document([raw]))])
        self.assertEqual(result["status"], "partial")
        self.assertTrue(all(row["verification"] == "rejected" for row in self.rows("attachment_index.jsonl")))
        self.assertEqual(result["counts"]["copied_attachments"], 0)

    def test_missing_encrypted_and_skipped_resources_are_distinct(self):
        raw = message(resource_status="skipped", resources=[dict(path="missing.dat", status="encrypted")])
        result = self.run_export([self.write(document([raw]))])
        attachment = self.rows("attachment_index.jsonl")[0]
        self.assertEqual(result["status"], "partial")
        self.assertEqual(attachment["reported"]["status"], "encrypted")
        self.assertEqual(attachment["verification"], "missing")
        self.assertEqual(self.rows()[0]["source_fields"]["resource_status"], "skipped")

    def test_html_discloses_upstream_resource_status_even_when_bytes_copied(self):
        (self.inputs / "media").mkdir()
        encrypted = self.inputs / "media/encrypted.dat"
        encrypted.write_bytes(b"synthetic encrypted bytes")
        available = self.inputs / "media/available.wav"
        available.write_bytes(b"synthetic available bytes")
        messages = [
            message(resource_status="encrypted",
                    resources=[dict(path="media/encrypted.dat", status="encrypted", kind="image")]),
            message(server_id="90071992547409931235", local_id=8,
                    resources=[dict(path="media/available.wav", status="available", kind="voice")]),
            message(server_id="90071992547409931236", local_id=9, resource_status="missing"),
            message(server_id="90071992547409931237", local_id=10,
                    resource_status='<script>alert("x")</script>'),
        ]
        result = self.run_export([self.write(document(messages))])
        rendered = (self.out / "archive.html").read_text(encoding="utf-8")
        self.assertEqual(result["status"], "partial")
        self.assertIn("上游状态：encrypted", rendered)
        self.assertIn("媒体状态：missing", rendered)
        self.assertEqual(rendered.count("上游状态："), 1)
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertEqual(result["counts"]["copied_attachments"], 2)
        self.assertTrue(all(row["verification"] == "bytes_copied_and_hashed"
                            for row in self.rows("attachment_index.jsonl")))

    def test_symlink_input_and_attachment_are_rejected(self):
        target = self.write(document())
        link = self.inputs / "linked.json"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(normalizer.NormalizeError):
            self.run_export([link])
        self.assertFalse(self.out.exists())
        outside = self.base / "outside.bin"
        outside.write_bytes(b"synthetic external")
        (self.inputs / "escape.bin").symlink_to(outside)
        self.run_export([self.write(document([message(resources=[dict(path="escape.bin")])]), "second.json")])
        self.assertEqual(self.rows("attachment_index.jsonl")[0]["reason"], "linked_path_rejected")

    def test_existing_output_and_linked_output_parent_are_not_overwritten(self):
        path = self.write(document())
        self.out.mkdir()
        sentinel = self.out / "keep.txt"
        sentinel.write_text("keep", encoding="utf-8")
        with self.assertRaises(normalizer.NormalizeError):
            self.run_export([path])
        self.assertEqual(sentinel.read_text(), "keep")
        linked = self.base / "linked_parent"
        try:
            linked.symlink_to(self.out, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(normalizer.NormalizeError):
            normalizer.normalize([path], "synthetic", linked / "new")
        self.assertFalse((self.out / "new").exists())

    def test_windows_reparse_flag_is_rejected_without_is_junction(self):
        target = self.write(document())
        original = normalizer.Path.lstat
        def lstat_with_reparse(path):
            if path == target:
                return SimpleNamespace(st_mode=original(path).st_mode, st_file_attributes=0x400)
            return original(path)
        with mock.patch.object(normalizer.Path, "lstat", lstat_with_reparse):
            with self.assertRaisesRegex(normalizer.NormalizeError, "linked_path_rejected"):
                self.run_export([target])
        self.assertFalse(self.out.exists())

    def test_millisecond_and_missing_times_are_not_silently_converted(self):
        records = [message(create_time=1767225600000), message(create_time=None, server_id="2"),
                   message(server_id="3", provenance={"time_basis": "parent_fallback"}),
                   message(server_id="4", create_time=10 ** 1000)]
        self.run_export([self.write(document(records))])
        rows = self.rows()
        self.assertIsNone(rows[0]["time"]["beijing_from_exported_value"])
        self.assertEqual(rows[0]["time"]["raw_create_time"], 1767225600000)
        self.assertEqual(rows[1]["time"]["basis"], "unknown_or_unsupported_timestamp")
        self.assertEqual(rows[2]["time"]["basis"], "input_reports_fallback")
        self.assertEqual(rows[3]["time"]["basis"], "unknown_or_unsupported_timestamp")

    def test_explicit_shanghai_time_mismatch_is_partial_without_repair(self):
        raw = message(create_time=1767225601, time_str="2026-01-01 08:00:00")
        source = self.write(document([raw]))
        before = source.read_bytes()
        result = self.run_export([source])
        self.assertEqual(result["status"], "partial")
        row = self.rows()[0]
        self.assertEqual(row["time"]["display_consistency"]["status"], "mismatch")
        self.assertEqual(row["source_fields"]["create_time"], raw["create_time"])
        self.assertEqual(row["source_fields"]["time_str"], raw["time_str"])
        self.assertEqual(source.read_bytes(), before)
        self.assertEqual([r["code"] for r in self.rows("issues.jsonl")], ["exported_time_fields_mismatch"])

    def test_explicit_shanghai_matching_time_has_no_issue(self):
        result = self.run_export([self.write(document())])
        self.assertEqual(result["status"], "success")
        self.assertEqual(self.rows()[0]["time"]["display_consistency"]["status"], "match")
        self.assertEqual(self.rows("issues.jsonl"), [])

    def test_absent_timezone_does_not_infer_shanghai_or_raise_mismatch(self):
        doc = document([message(create_time=1767225601, time_str="2026-01-01 08:00:00")])
        del doc["metadata"]["time_zone"]
        result = self.run_export([self.write(doc)])
        self.assertEqual(result["status"], "success")
        consistency = self.rows()[0]["time"]["display_consistency"]
        self.assertEqual(consistency["status"], "not_checked")
        self.assertEqual(consistency["reason"], "timezone_unknown")
        self.assertEqual(self.rows("issues.jsonl"), [])

    def test_nested_unknown_time_origin_is_not_overclaimed(self):
        child = message(create_time=1767225601, time_str="2026-01-01 08:00:00")
        raw = message(forward={"messages": [child]})
        result = self.run_export([self.write(document([raw]))])
        self.assertEqual(result["status"], "success")
        nested = self.rows()[1]
        self.assertEqual(nested["time"]["display_consistency"]["status"], "not_checked")
        self.assertEqual(nested["time"]["display_consistency"]["reason"], "unknown_or_fallback_time_origin")
        self.assertFalse(nested["time"]["verified_original_event_time"])

    def test_unavailable_timezone_rules_leave_consistency_unknown(self):
        doc = document([message(create_time=1767225601, time_str="2026-01-01 08:00:00")])
        with mock.patch.object(normalizer, "ZoneInfo", side_effect=normalizer.ZoneInfoNotFoundError):
            result = self.run_export([self.write(doc)])
        self.assertEqual(result["status"], "success")
        consistency = self.rows()[0]["time"]["display_consistency"]
        self.assertEqual(consistency["status"], "not_checked")
        self.assertEqual(consistency["reason"], "timezone_unsupported_or_rules_unavailable")
        self.assertEqual(self.rows("issues.jsonl"), [])

    def test_html_and_csv_treat_commands_as_data(self):
        payload = '<script>alert("secret")</script><img src="https://bad.test/a">\n$(touch nope)'
        path = self.write(document([message(text=payload, sender="<b>sender</b>")], name=" =HYPERLINK(\"x\")"))
        self.run_export([path])
        rendered = (self.out / "archive.html").read_text(encoding="utf-8")
        self.assertNotIn("<script>", rendered)
        self.assertNotIn('<img src="https://', rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("Content-Security-Policy", rendered)
        self.assertEqual(self.rows()[0]["content"], payload)
        with (self.out / "conversation_index.csv").open(encoding="utf-8-sig", newline="") as target:
            row = next(csv.DictReader(target))
        self.assertTrue(row["显示名（可能为备注）"].startswith("'"))
        self.assertFalse((self.base / "nope").exists())

    def test_partial_valid_and_invalid_inputs_do_not_leak_body_into_errors(self):
        good = self.write(document(), "good.json")
        bad = self.inputs / "bad.json"
        bad.write_text('{"TOP_SECRET_BODY": broken}', encoding="utf-8")
        result = self.run_export([good, bad])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["counts"]["top_level_messages"], 1)
        self.assertNotIn("TOP_SECRET_BODY", (self.out / "issues.jsonl").read_text())
        self.assertNotIn("TOP_SECRET_BODY", Path(result["manifest"]).read_text())

    def test_bad_jsonl_records_are_counted_and_following_records_survive(self):
        path = self.inputs / "source.jsonl"
        path.write_text(json.dumps({"metadata": document()["metadata"]}) + "\n{bad}\n"
                        + json.dumps(message()) + "\n", encoding="utf-8")
        result = self.run_export([path])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["counts"]["top_level_seen"], 2)
        self.assertEqual(result["counts"]["top_level_rejected"], 1)
        self.assertEqual(self.rows()[0]["source"]["location"], "line:3")

    def test_repeated_jsonl_metadata_is_rejected_not_counted_as_message(self):
        path = self.inputs / "source.jsonl"
        header = json.dumps({"metadata": document()["metadata"]})
        path.write_text(header + "\n" + header + "\n" + json.dumps(message()) + "\n", encoding="utf-8")
        result = self.run_export([path])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["counts"]["top_level_messages"], 1)
        self.assertEqual(result["counts"]["top_level_rejected"], 1)

    def test_nonfinite_values_duplicate_keys_and_lone_surrogates_fail_safely(self):
        cases = ['{"metadata":1,"metadata":2}', '{"value":1e400}', '{"text":"\\ud800"}']
        for number, raw in enumerate(cases):
            with self.subTest(number=number):
                source = self.inputs / ("bad%d.json" % number)
                source.write_text(raw, encoding="utf-8")
                result = normalizer.normalize([source], "synthetic", self.base / ("badout%d" % number))
                self.assertEqual(result["status"], "failed")

    def test_nested_expansion_limit_is_reported_and_original_kept(self):
        raw = message(forward={"messages": [message(server_id=str(n)) for n in range(3)]})
        source = self.write(document([raw]))
        with mock.patch.object(normalizer, "MAX_NESTED_PER_MESSAGE", 1):
            result = self.run_export([source])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["counts"]["nested_messages"], 1)
        self.assertEqual(result["counts"]["nested_omitted"], 2)
        self.assertEqual((self.out / "originals/0001.json").read_bytes(), source.read_bytes())

    def test_empty_export_success_and_bad_schema_failure(self):
        result = self.run_export([self.write(document([]))])
        self.assertEqual(result["status"], "success")
        bad = self.write({"messages": [message()]}, "not_moect.json")
        failed = normalizer.normalize([bad], "synthetic", self.base / "bad_schema")
        self.assertEqual(failed["status"], "failed")

    def test_json_size_limit_is_checked_before_copying(self):
        source = self.write(document())
        with mock.patch.object(normalizer, "MAX_JSON_BYTES", 16):
            result = self.run_export([source])
        self.assertEqual(result["status"], "failed")
        self.assertFalse((self.out / "originals/0001.json").exists())

    def test_cli_returns_machine_readable_result_and_safe_error(self):
        path = self.write(document())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = normalizer.main(["--input", str(path), "--account-scope", "synthetic", "--out", str(self.out)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "success")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = normalizer.main(["--input", str(path), "--account-scope", "synthetic", "--out", str(self.out)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["error_code"], "output_already_exists")


if __name__ == "__main__":
    unittest.main()
