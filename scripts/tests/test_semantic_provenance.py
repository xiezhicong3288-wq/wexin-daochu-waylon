"""Synthetic field/provenance checks against the real locked exporter.

Expected answers are fixture literals and independent SQLite rows. No Moect
parser is imported to calculate them. Set MOECT_TEST_UPSTREAM and run with the
prepared runtime; no Windows process or real chat is accessed.
"""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from contextlib import closing
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "moect_bridge.py"
NORMALIZER = ROOT / "scripts" / "normalize_export.py"
UPSTREAM = os.environ.get("MOECT_TEST_UPSTREAM")
OWNER = "wxid_semantic_owner"
ALPHA = "wxid_semantic_alpha"
BETA = "wxid_semantic_beta"
SCOPE = "synthetic-semantic-regression"


def hashes(directory):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(directory.glob("*.db"))}


def snapshot(directory, session, rows, *, names=None, reverse=False):
    """Rows declare source values directly; local_id is a frozen-copy row key."""
    directory.mkdir()
    display = {OWNER: "合成账号", ALPHA: "同名成员", BETA: "同名成员",
               session: "合成会话"}
    display.update(names or {})
    with closing(sqlite3.connect(directory / "session.db")) as con, con:
        con.execute("CREATE TABLE SessionTable(username TEXT,summary TEXT,last_timestamp INTEGER)")
        con.execute("INSERT INTO SessionTable VALUES (?, '', 1700001000)", (session,))
    with closing(sqlite3.connect(directory / "contact.db")) as con, con:
        con.execute("CREATE TABLE contact(id INTEGER,username TEXT,nick_name TEXT,remark TEXT,alias TEXT)")
        con.executemany("INSERT INTO contact VALUES (?, ?, ?, '', '')",
                        [(i, key, value) for i, (key, value) in enumerate(display.items(), 1)])
    table = "Msg_" + hashlib.md5(session.encode()).hexdigest()
    with closing(sqlite3.connect(directory / "message_0.db")) as con, con:
        con.execute("CREATE TABLE Name2Id(user_name TEXT)")
        con.executemany("INSERT INTO Name2Id VALUES (?)", [(OWNER,), (ALPHA,), (BETA,)])
        con.execute(f'CREATE TABLE "{table}" (local_id INTEGER PRIMARY KEY,server_id INTEGER,local_type INTEGER,sort_seq INTEGER,real_sender_id INTEGER,create_time INTEGER,message_content,compress_content,packed_info_data)')
        ordered = list(reversed(rows)) if reverse else rows
        con.executemany(f'INSERT INTO "{table}" VALUES (?,?,?,?,?,?,?,NULL,NULL)', ordered)
    return table


def independent_rows(directory, table):
    with closing(sqlite3.connect((directory / "message_0.db").as_uri() + "?mode=ro", uri=True)) as con, con:
        con.row_factory = sqlite3.Row
        return [dict(row) for row in con.execute(
            f'SELECT m.local_id,m.server_id,m.message_content,m.create_time,n.user_name AS sender '
            f'FROM "{table}" AS m LEFT JOIN Name2Id AS n ON n.rowid=m.real_sender_id ORDER BY m.local_id')]


def quoted_xml(server_id, content="被引用的合成原话", *, source_time=None):
    timestamp = "" if source_time is None else f"<createtime>{source_time}</createtime>"
    return ("<msg><appmsg><type>57</type><title>合成引用回复</title><refermsg>"
            f"<type>1</type><svrid>{server_id}</svrid><fromusr>{BETA}</fromusr>"
            f"<displayname>被引用的合成人员</displayname><content>{content}</content>"
            f"{timestamp}</refermsg></appmsg></msg>")


@unittest.skipUnless(UPSTREAM, "Set MOECT_TEST_UPSTREAM to run the real upstream exporter")
class SemanticProvenance(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="moect-semantic-check-")
        self.base = Path(self.temp.name)
        self.call_number = 0
        self.env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")

    def tearDown(self):
        self.temp.cleanup()

    def pipeline(self, source, session, *, bridge_codes=(0,), normalizer_codes=(0,)):
        self.call_number += 1
        out = self.base / f"export-{self.call_number}"
        before = hashes(source)
        command = [sys.executable, "-B", str(SCRIPT), "--upstream", UPSTREAM,
                   "export", "--source", str(source), "--account-id", OWNER,
                   "--account-scope", SCOPE, "--session", session,
                   "--format", "json", "--output", str(out)]
        completed = subprocess.run(command, env=self.env, capture_output=True, text=True, timeout=45)
        self.assertIn(completed.returncode, bridge_codes, completed.stdout + completed.stderr)
        self.assertEqual(before, hashes(source), "An input database changed")
        run = json.loads((out / "run.json").read_text())
        self.assertFalse(run["identity_verified"])
        document_path = out / run["results"][0]["path"]
        document = json.loads(document_path.read_text())
        normalized = self.base / f"normalized-{self.call_number}"
        invocation = subprocess.run([sys.executable, "-B", str(NORMALIZER),
                                    "--input", str(document_path), "--account-scope", SCOPE,
                                    "--out", str(normalized)], env=self.env,
                                   capture_output=True, text=True, timeout=45)
        self.assertIn(invocation.returncode, normalizer_codes, invocation.stdout + invocation.stderr)
        self.assertEqual(before, hashes(source))
        self.assertEqual(before, hashes(out / "private-snapshot"))
        self.assertEqual(document_path.read_bytes(), (normalized / "originals/0001.json").read_bytes())
        records = [json.loads(line) for line in (normalized / "messages.jsonl").read_text().splitlines()]
        issues = [json.loads(line) for line in (normalized / "issues.jsonl").read_text().splitlines()]
        return {"document": document, "records": records, "issues": issues, "run": run,
                "manifest": json.loads((normalized / "manifest.json").read_text())}

    def test_equivalent_text_storage_preserves_exact_literal_and_source_rows(self):
        import zstandard
        body = " \t第一行  \r\n第二行😀\n "
        whitespace_only = " \t\r\n "
        values = [body, body.encode("utf-8"), zstandard.ZstdCompressor().compress(body.encode("utf-8")),
                  whitespace_only]
        expected_text = [body] * 3 + [whitespace_only]
        session = "semantic_text_peer"
        source = self.base / "source"
        table = snapshot(source, session,
                         [(i, 9007199254741000 + i, 1, i, 2, 1700000000 + i, value)
                          for i, value in enumerate(values, 1)])
        reference = independent_rows(source, table)
        self.assertEqual(values, [r["message_content"] for r in reference])
        result = self.pipeline(source, session)
        messages = result["document"]["messages"]
        self.assertEqual(expected_text, [m["text"] for m in messages])
        self.assertEqual(expected_text, [m["content"] for m in result["records"]])
        self.assertEqual([str(r["server_id"]) for r in reference], [m["server_id"] for m in messages])
        self.assertEqual([r["sender"] for r in reference], [m["sender_wxid"] for m in messages])
        self.assertEqual([r["create_time"] for r in reference], [m["create_time"] for m in messages])
        self.assertEqual(expected_text, [m["bridge_content"]["raw_decoded"] for m in messages])
        self.assertEqual(["text", "utf8", "zstd_utf8", "text"], [m["bridge_content"]["decode_rule"] for m in messages])
        self.assertEqual(["message_content"] * 4, [m["bridge_content"]["source_field"] for m in messages])
        self.assertEqual(["none"] * 4, [m["bridge_content"]["display_transform"] for m in messages])
        self.assertEqual(body, messages[0]["bridge_content"]["raw_fields"]["message_content"])

    def test_conflicting_sender_indicators_are_preserved_and_unresolved(self):
        session = "semantic_sender_conflict@chatroom"
        source = self.base / "source"
        conflicting_body = BETA + ":\n来源故意矛盾的合成原话\n "
        table = snapshot(source, session, [
            (1, 9007199254741051, 1, 1, 2, 1700000101, ALPHA + ":\n甲的合成原话"),
            (2, 9007199254741052, 1, 2, 3, 1700000102, BETA + ":\n乙的合成原话"),
            (3, 9007199254741053, 1, 3, 2, 1700000103, conflicting_body)])
        reference = independent_rows(source, table)
        self.assertEqual(ALPHA, reference[2]["sender"])
        self.assertTrue(reference[2]["message_content"].startswith(BETA + ":\n"))
        result = self.pipeline(source, session, bridge_codes=(0, 1), normalizer_codes=(1,))
        messages = result["document"]["messages"]
        self.assertEqual([ALPHA, BETA], [m["sender_wxid"] for m in messages[:2]])
        self.assertEqual(messages[0]["sender"], messages[1]["sender"])
        conflict = messages[2]
        self.assertFalse(conflict["sender_wxid"])
        self.assertFalse(conflict["is_sender"])
        self.assertEqual(conflicting_body, conflict["text"])
        indicators = conflict["bridge_sender"]
        self.assertEqual("conflict", indicators["status"])
        self.assertEqual(ALPHA, indicators["mapped_id"])
        self.assertEqual(BETA, indicators["prefix_id"])
        self.assertEqual(2, indicators["raw_real_sender_id"])
        self.assertEqual("current_contact_snapshot", indicators["display_name_basis"])
        self.assertEqual(conflicting_body, conflict["bridge_content"]["raw_decoded"])
        normalized = [r for r in result["records"] if r["server_id"] == str(reference[2]["server_id"])][0]
        self.assertIsNone(normalized["sender_id"])
        self.assertEqual(indicators, normalized["source_fields"]["bridge_sender"])
        conflicts = [i for i in result["issues"] if "sender" in i["code"] and "conflict" in i["code"]]
        self.assertTrue(conflicts)
        self.assertTrue(all(i["input_id"] and i["source_location"] for i in conflicts))
        self.assertEqual("partial", result["manifest"]["status"])

    def test_quote_without_original_row_or_timestamp_stays_unknown(self):
        session = "semantic_quote_peer"
        source = self.base / "source"
        quote_id = 9007199254741999
        body = quoted_xml(quote_id)
        table = snapshot(source, session, [(1, 9007199254741100, 49, 1, 2, 1700000200, body)])
        reference = independent_rows(source, table)
        self.assertEqual([9007199254741100], [r["server_id"] for r in reference])
        self.assertNotIn("<createtime>", reference[0]["message_content"])
        result = self.pipeline(source, session)
        parent = result["document"]["messages"][0]
        quote = parent["quote"]
        self.assertEqual(str(quote_id), quote["server_id"])
        self.assertEqual("unknown", quote["bridge_time_status"])
        self.assertIn(quote.get("create_time"), (None, 0))
        self.assertFalse(quote.get("time_str"))
        self.assertFalse(quote.get("bridge_source"), "Embedded fallback must not pretend to be a database row")
        self.assertEqual("embedded_only", quote["bridge_reference"]["status"])
        self.assertEqual(0, quote["bridge_reference"]["candidate_count"])
        nested = [r for r in result["records"] if r["record_kind"] == "quote"]
        self.assertEqual(1, len(nested))
        self.assertEqual(result["records"][0]["record_id"], nested[0]["parent_record_id"])
        self.assertEqual("bridge_reports_unknown_time", nested[0]["time"]["basis"])
        self.assertFalse(nested[0]["time"]["verified_original_event_time"])

    def test_quote_resolved_to_source_row_preserves_its_time_and_locator(self):
        session = "semantic_quote_source_peer"
        source = self.base / "source"
        original_id = 9007199254741201
        original_body = " \t有原始行的合成原话\n "
        table = snapshot(source, session, [
            (1, original_id, 1, 1, 3, 1700000001, original_body),
            (2, 9007199254741202, 49, 2, 2, 1700000200, quoted_xml(original_id, "嵌入副本"))])
        reference = independent_rows(source, table)
        result = self.pipeline(source, session)
        parent = result["document"]["messages"][1]
        quote = parent["quote"]
        self.assertEqual(reference[0]["message_content"], quote["text"])
        self.assertEqual(reference[0]["create_time"], quote["create_time"])
        self.assertEqual("source_epoch", quote["bridge_time_status"])
        self.assertEqual(table, quote["bridge_source"]["table"])
        self.assertEqual(reference[0]["local_id"], quote["bridge_source"]["local_id"])
        self.assertEqual("matched_source_row", quote["bridge_reference"]["status"])
        self.assertEqual(1, quote["bridge_reference"]["candidate_count"])
        self.assertNotEqual(parent["create_time"], quote["create_time"])
        nested = [r for r in result["records"] if r["record_kind"] == "quote"]
        self.assertEqual("bridge_reports_source_epoch", nested[0]["time"]["basis"])
        self.assertFalse(nested[0]["time"]["verified_original_event_time"])

    def test_duplicate_reference_ids_do_not_authenticate_first_match(self):
        session = "semantic_ambiguous_quote_peer"
        source = self.base / "source"
        original_id = 9007199254741251
        table = snapshot(source, session, [
            (1, original_id, 1, 1, 2, 1700000001, "第一个同编号原始行"),
            (2, original_id, 1, 2, 3, 1700000002, "第二个同编号原始行"),
            (3, 9007199254741253, 49, 3, 2, 1700000200, quoted_xml(original_id, "仅有嵌入的引用正文"))])
        reference = independent_rows(source, table)
        self.assertEqual(2, sum(r["server_id"] == original_id for r in reference))
        result = self.pipeline(source, session, bridge_codes=(0, 1), normalizer_codes=(0, 1))
        self.assertEqual(3, len(result["document"]["messages"]))
        quote = result["document"]["messages"][2]["quote"]
        self.assertEqual("仅有嵌入的引用正文", quote["text"])
        self.assertEqual("ambiguous_source_match", quote["bridge_reference"]["status"])
        self.assertEqual(2, quote["bridge_reference"]["candidate_count"])
        self.assertFalse(quote.get("bridge_source"))
        self.assertEqual("unknown", quote["bridge_time_status"])
        self.assertIn(quote.get("create_time"), (None, 0))
        self.assertFalse(quote.get("time_str"))
        nested = [r for r in result["records"] if r["record_kind"] == "quote"]
        self.assertEqual(1, len(nested))
        self.assertFalse(nested[0]["time"]["verified_original_event_time"])

    def test_order_display_name_and_repeat_preserve_semantic_identity(self):
        session = "semantic_metamorphic@chatroom"
        rows = [(1, 9007199254741301, 1, 1, 2, 1700000001, ALPHA + ":\n合成甲\n"),
                (2, 9007199254741302, 1, 2, 3, 1700000002, BETA + ":\n合成乙\n")]
        original = self.base / "original"
        snapshot(original, session, rows)
        reference = self.pipeline(original, session)

        def semantic_projection(result):
            return sorted((r["conversation_id"], r["sender_id"], r["server_id"],
                           r["content"], r["time"]["raw_create_time"], r["record_kind"])
                          for r in result["records"])

        expected = semantic_projection(reference)
        self.assertEqual({ALPHA, BETA}, {r["sender_id"] for r in reference["records"]})
        self.assertEqual(1, len({r["sender_display_name"] for r in reference["records"]}))
        reordered = self.base / "reordered"
        snapshot(reordered, session, rows, reverse=True)
        renamed = self.base / "renamed"
        snapshot(renamed, session, rows, names={ALPHA: "新展示甲", BETA: "新展示乙", session: "新会话展示"})
        for label, path in [("input-row-order", reordered), ("display-names", renamed),
                            ("repeat-frozen-input", original)]:
            with self.subTest(variation=label):
                result = self.pipeline(path, session)
                self.assertEqual(expected, semantic_projection(result))
                if label == "display-names":
                    self.assertEqual({"新展示甲", "新展示乙"}, {r["sender_display_name"] for r in result["records"]})


if __name__ == "__main__":
    unittest.main(verbosity=2)
