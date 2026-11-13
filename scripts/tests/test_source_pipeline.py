"""Actual saved source -> Moect -> neutral archive closure on tiny fixtures."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
from contextlib import closing
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
UPSTREAM = os.environ.get("MOECT_TEST_UPSTREAM")
spec = importlib.util.spec_from_file_location("source_pipeline_bridge", SCRIPTS / "moect_bridge.py")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
FRIEND, GROUP = "fixture_friend", "fixture_group@chatroom"


def table(session):
    return "Msg_" + hashlib.md5(session.encode()).hexdigest()


def fixture(root):
    root.mkdir()
    with closing(sqlite3.connect(root / "session.db")) as con, con:
        con.execute("CREATE TABLE SessionTable(username TEXT PRIMARY KEY, summary TEXT, last_timestamp INTEGER)")
        con.executemany("INSERT INTO SessionTable VALUES (?, '', 1700000010)", [(FRIEND,), (GROUP,)])
    with closing(sqlite3.connect(root / "contact.db")) as con, con:
        con.execute("CREATE TABLE contact(id INTEGER, username TEXT, nick_name TEXT, remark TEXT, alias TEXT)")
        con.executemany("INSERT INTO contact VALUES (?, ?, ?, '', '')", [
            (1, "fixture_owner", "Owner"), (2, FRIEND, "Same name"), (3, "fixture_member", "Same name")])
    for shard, session in enumerate((FRIEND, GROUP)):
        with closing(sqlite3.connect(root / ("message_%d.db" % shard))) as con, con:
            con.execute("CREATE TABLE Name2Id(user_name TEXT)")
            con.executemany("INSERT INTO Name2Id VALUES (?)", [("fixture_owner",), (FRIEND,), ("fixture_member",)])
            con.execute('CREATE TABLE "' + table(session) + '"(local_id INTEGER,server_id INTEGER,local_type INTEGER,sort_seq INTEGER,real_sender_id INTEGER,create_time INTEGER,message_content,compress_content,packed_info_data)')
            rows = [(1, 9007199254740993, 1, 1, 2, 1700000000, " same literal \n", None, None),
                    (1, 9007199254740993, 1, 1, 2, 1700000000, " same literal \n", None, None),
                    (2, 0, 1, 2, 2, 1700000010, "last", None, None)] if session == FRIEND else [
                    (1, 9007199254741100, 1, 1, 2, 1700000005, FRIEND + ":\ngroup A", None, None),
                    (2, 9007199254741101, 1, 2, 3, 1700000015, "fixture_member:\ngroup B", None, None)]
            con.executemany('INSERT INTO "' + table(session) + '" VALUES (?,?,?,?,?,?,?,?,?)', rows)


def inventory(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


@unittest.skipUnless(UPSTREAM, "Requires the locked real upstream runtime")
class SourcePipeline(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "input"
        fixture(self.source)
        self.fixed = inventory(self.source)
        self.manifest = self.root / "prior.json"
        self.manifest.write_text(json.dumps({"schema_version": 1, "files": self.fixed}))

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *args):
        result = subprocess.run([sys.executable, "-B", *map(str, args)], capture_output=True, text=True, timeout=30)
        self.assertEqual("", result.stderr)
        return result, json.loads(result.stdout)

    def export(self, *, fixed=True, sessions=(FRIEND, GROUP), extra=(), name="export"):
        output = self.root / name
        args = [SCRIPTS / "moect_bridge.py", "--upstream", UPSTREAM, "export", "--source", self.source,
                "--account-id", "fixture_owner", "--account-scope", "synthetic-pilot", "--output", output]
        for session in sessions: args += ["--session", session]
        if fixed: args += ["--source-manifest", self.manifest]
        result, receipt = self.invoke(*args, *extra)
        return output, result, receipt

    def test_full_two_session_closure_and_changed_final_body(self):
        output, result, _ = self.export()
        self.assertEqual(0, result.returncode, result.stdout)
        run = json.loads((output / "run.json").read_text())
        audit = json.loads((output / "source-audit.json").read_text())
        self.assertTrue(audit["passed"])
        self.assertEqual(5, audit["counts"]["source_in_scope"])
        self.assertEqual(5, audit["counts"]["exported_top_level"])
        self.assertEqual(5, len(audit["ledger"]))
        self.assertTrue(run["acquisition"]["binding"]["predeclared_inventory_verified"])
        self.assertEqual(self.fixed, inventory(output / "private-source"))
        normal = self.root / "normalized"
        args = [SCRIPTS / "normalize_export.py", "--account-scope", "synthetic-pilot", "--out", normal]
        for entry in run["results"]: args += ["--input", output / entry["path"]]
        normalized, _ = self.invoke(*args)
        self.assertEqual(0, normalized.returncode, normalized.stdout)
        command = [SCRIPTS / "source_audit.py", "--reference", output / "source-reference.json", "--normalized", normal / "messages.jsonl"]
        checked, _ = self.invoke(*command, "--out", self.root / "final-check.json")
        self.assertEqual(0, checked.returncode, checked.stdout)
        self.assertTrue(json.loads((self.root / "final-check.json").read_text())["three_hop_verified"])
        records = [json.loads(line) for line in (normal / "messages.jsonl").read_text().splitlines()]
        self.assertEqual(5, len(records))
        self.assertEqual("0", next(r for r in records if r["local_id"] == "2" and r["conversation_id"] == FRIEND)["server_id"])
        records[0]["content"] = "post-export altered body"
        (normal / "messages.jsonl").write_text(''.join(json.dumps(r) + "\n" for r in records))
        changed, _ = self.invoke(*command, "--out", self.root / "changed-check.json")
        self.assertEqual(2, changed.returncode, changed.stdout)
        self.assertEqual(self.fixed, inventory(self.source))

    def test_known_missing_shard_fails_before_copy(self):
        (self.source / "message_1.db").unlink()
        output, result, receipt = self.export()
        self.assertEqual(2, result.returncode)
        self.assertEqual("source_manifest_mismatch", receipt["code"])
        run = json.loads((output / "run.json").read_text())
        self.assertEqual(["message_1.db"], run["error_details"]["missing"])
        self.assertFalse((output / "private-source").exists())

    def test_final_display_and_time_interpretation_mutations_are_detected(self):
        output, result, _ = self.export()
        self.assertEqual(0, result.returncode, result.stdout)
        run = json.loads((output / "run.json").read_text())
        normal = self.root / "normalized-labels"
        args = [SCRIPTS / "normalize_export.py", "--account-scope", "synthetic-pilot", "--out", normal]
        for entry in run["results"]: args += ["--input", output / entry["path"]]
        normalized, _ = self.invoke(*args)
        self.assertEqual(0, normalized.returncode, normalized.stdout)
        records_path = normal / "messages.jsonl"
        baseline = [json.loads(line) for line in records_path.read_text().splitlines()]
        command = [SCRIPTS / "source_audit.py", "--reference", output / "source-reference.json", "--normalized", records_path]
        checked, _ = self.invoke(*command, "--out", self.root / "unchanged-labels.json")
        self.assertEqual(0, checked.returncode, checked.stdout)
        mutations = [(("sender_display_name",), "invented sender"),
                     (("conversation_display_name",), "invented conversation"),
                     (("time", "basis"), "invented original event basis"),
                     (("time", "source_display_timezone"), "Pacific/Honolulu"),
                     (("time", "display_consistency"), {"status": "match", "basis": "invented"})]
        for number, (keys, value) in enumerate(mutations):
            with self.subTest(field=".".join(keys)):
                changed = copy.deepcopy(baseline)
                target = changed[0]
                for key in keys[:-1]: target = target[key]
                target[keys[-1]] = value
                records_path.write_text(''.join(json.dumps(row) + "\n" for row in changed))
                report_path = self.root / ("changed-label-%d.json" % number)
                failed, _ = self.invoke(*command, "--out", report_path)
                self.assertEqual(2, failed.returncode, failed.stdout)
                report = json.loads(report_path.read_text())
                self.assertFalse(report["three_hop_verified"])
                self.assertTrue(any(issue["code"] == "normalized_export_payload_mismatch"
                                    and keys[0] in issue["fields"] for issue in report["issues"]))
        self.assertEqual(self.fixed, inventory(self.source))

    def test_unbound_inventory_and_time_exclusions_are_explicit(self):
        output, result, _ = self.export(fixed=False, extra=("--start", "1700000005", "--end", "1700000010"))
        self.assertEqual(0, result.returncode, result.stdout)
        run = json.loads((output / "run.json").read_text())
        self.assertFalse(run["acquisition"]["binding"]["predeclared_inventory_verified"])
        audit = json.loads((output / "source-audit.json").read_text())
        self.assertEqual((2, 3), (audit["counts"]["source_in_scope"], audit["counts"]["source_time_excluded"]))
        self.assertEqual(3, len(audit["time_excluded_rows"]))

    def test_equal_count_saved_field_mutation_is_not_a_pass(self):
        output, result, _ = self.export()
        self.assertEqual(0, result.returncode, result.stdout)
        run = json.loads((output / "run.json").read_text())
        document_path = output / run["results"][0]["path"]
        document = json.loads(document_path.read_text())
        document["messages"][0]["text"] = "changed with same count and locator"
        document_path.write_text(json.dumps(document))
        reference = json.loads((output / "source-reference.json").read_text())
        audit = bridge.reconcile_saved(output, run, reference)
        self.assertFalse(audit["passed"])
        self.assertEqual(5, audit["counts"]["exported_top_level"])

    def test_decode_failure_accounts_for_unconfirmed_rows(self):
        with closing(sqlite3.connect(self.source / "message_0.db")) as con, con:
            con.execute('UPDATE "' + table(FRIEND) + '" SET message_content=? WHERE rowid=1', (sqlite3.Binary(b"\xffinvalid"),))
        output, result, receipt = self.export(fixed=False)
        self.assertEqual(2, result.returncode)
        self.assertEqual("decode_failed", receipt["code"])
        run = json.loads((output / "run.json").read_text())
        self.assertEqual("failed", run["status"])
        self.assertEqual(1, run["error_details"]["source"]["source_rowid"])
        audit = json.loads((output / "source-audit.json").read_text())
        self.assertEqual(5, audit["counts"]["rejected_top_level"])
        self.assertTrue(all(row["status"] == "rejected" and row["reason"] for row in audit["ledger"]))

    def test_non_decode_build_failure_has_the_exact_source_position(self):
        with closing(sqlite3.connect(self.source / "message_0.db")) as con, con:
            con.execute('UPDATE "' + table(FRIEND) + '" SET packed_info_data=? WHERE rowid=2', ("invalid packed field type",))
        before = inventory(self.source)
        output, result, receipt = self.export(fixed=False)
        self.assertEqual(2, result.returncode, result.stdout)
        self.assertEqual("message_build_failed", receipt["code"])
        run = json.loads((output / "run.json").read_text())
        detail = run["error_details"]
        self.assertEqual("message_build", detail["stage"])
        self.assertEqual(2, detail["source"]["source_rowid"])
        self.assertEqual(table(FRIEND), detail["source"]["table"])
        self.assertEqual("TypeError", detail["exception_type"])
        audit = json.loads((output / "source-audit.json").read_text())
        self.assertEqual(5, audit["counts"]["rejected_top_level"])
        self.assertTrue(all(row["status"] == "rejected" and row["reason"] for row in audit["ledger"]))
        self.assertEqual(before, inventory(self.source))

    def test_independent_discovery_exposes_unread_source_table(self):
        hidden = self.source / "other_source.db"
        (self.source / "message_1.db").rename(hidden)
        with closing(sqlite3.connect(hidden)) as con, con:
            con.execute('ALTER TABLE "' + table(GROUP) + '" RENAME TO "' + table(FRIEND) + '"')
        output, result, receipt = self.export(fixed=False, sessions=(FRIEND,))
        self.assertEqual(2, result.returncode, result.stdout)
        self.assertEqual("source_reconciliation_failed", receipt["code"])
        audit = json.loads((output / "source-audit.json").read_text())
        self.assertEqual((5, 3), (audit["counts"]["source_in_scope"], audit["counts"]["exported_top_level"]))
        self.assertEqual(2, sum(row["status"] == "missing" for row in audit["ledger"]))

    def test_clear_wal_is_read_from_processing_copy_without_mutating_preserved_input(self):
        writer = self.root / "writer"
        shutil.copytree(self.source, writer)
        with closing(sqlite3.connect(writer / "message_0.db")) as con, con:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA wal_autocheckpoint=0")
            con.execute('INSERT INTO "' + table(FRIEND) + '" VALUES (9,99,1,9,2,1700000020,\'WAL committed\',NULL,NULL)')
            con.commit()
            for suffix in ("", "-wal"):
                shutil.copyfile(writer / ("message_0.db" + suffix), self.source / ("message_0.db" + suffix))
        before = inventory(self.source)
        output, result, _ = self.export(fixed=False)
        self.assertEqual(0, result.returncode, result.stdout)
        run = json.loads((output / "run.json").read_text())
        self.assertEqual(6, run["source_audit"]["counts"]["source_in_scope"])
        self.assertEqual(before, inventory(self.source))
        self.assertEqual(before, inventory(output / "private-source"))
        self.assertEqual("observed_stored_payload_bytes", run["database_validation"]["files"]["message_0.db"]["wal"]["checksum_domain"])


if __name__ == "__main__":
    unittest.main()
