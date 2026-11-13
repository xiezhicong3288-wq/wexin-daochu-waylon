"""Synthetic tests. Set MOECT_TEST_UPSTREAM to the locked Moect source tree.

Real-core cases run the actual upstream exporter in a separate CLI process.
No test uses WeChat, real messages, real credentials, or a live memory reader.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
from contextlib import closing
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from types import SimpleNamespace

SCRIPT = Path(__file__).resolve().parents[1] / "moect_bridge.py"
spec = importlib.util.spec_from_file_location("moect_bridge", SCRIPT)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
UPSTREAM = os.environ.get("MOECT_TEST_UPSTREAM")


def fixture(root, *, invalid=False, many=0):
    root.mkdir()
    with closing(sqlite3.connect(root / "session.db")) as con, con:
        con.execute("CREATE TABLE SessionTable (username TEXT PRIMARY KEY, summary TEXT, last_timestamp INTEGER)")
        con.executemany("INSERT INTO SessionTable VALUES (?, '', 1700000000)", [("friend_a",), ("friend_b",)])
    with closing(sqlite3.connect(root / "contact.db")) as con, con:
        con.execute("CREATE TABLE contact (id INTEGER, username TEXT, nick_name TEXT, remark TEXT, alias TEXT)")
        con.executemany("INSERT INTO contact VALUES (?, ?, ?, '', '')", [
            (1, "wxid_owner", "合成账号"), (2, "friend_a", "同名联系人"), (3, "friend_b", "同名联系人")])
    with closing(sqlite3.connect(root / "message_0.db")) as con, con:
        con.execute("CREATE TABLE Name2Id (user_name TEXT)")
        con.executemany("INSERT INTO Name2Id VALUES (?)", [("wxid_owner",), ("friend_a",), ("friend_b",)])
        for session in ("friend_a", "friend_b"):
            table = "Msg_" + hashlib.md5(session.encode()).hexdigest()
            con.execute(f'CREATE TABLE "{table}" (local_id INTEGER PRIMARY KEY, server_id INTEGER, local_type INTEGER, sort_seq INTEGER, real_sender_id INTEGER, create_time INTEGER, message_content, compress_content, packed_info_data)')
            body = sqlite3.Binary(b"\xffbad utf8") if invalid else "合成原话：保留换行\n😀 <script>alert(1)</script>"
            con.execute(f'INSERT INTO "{table}" VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)',
                        (1, 9007199254740993, 1, 1, 2 if session == "friend_a" else 3, 1700000000, body))
            if session == "friend_a":
                con.execute(f'INSERT INTO "{table}" VALUES (2, 9007199254740994, 3, 2, 2, 1700000010, ?, NULL, NULL)',
                            ('<msg><img md5="0123456789abcdef0123456789abcdef"/></msg>',))
                forward = '<msg><appmsg><type>19</type><title>合成转发</title><recorditem><![CDATA[<recordinfo><datalist><dataitem datatype="1"><sourcename>合成发送者</sourcename><datadesc>没有原始时间</datadesc></dataitem></datalist></recordinfo>]]></recorditem></appmsg></msg>'
                con.execute(f'INSERT INTO "{table}" VALUES (3, 9007199254740995, 49, 3, 2, 1700000020, ?, NULL, NULL)', (forward,))
                if many:
                    con.executemany(f'INSERT INTO "{table}" VALUES (?, ?, 1, ?, 2, ?, ?, NULL, NULL)',
                        ((i, 9007199254740993 + i, i, 1700000000 + i, "Synthetic cancellation record " * 20) for i in range(4, many + 4)))


class Boundaries(unittest.TestCase):
    def test_reject_relative_parent_and_network_paths(self):
        for value in ("relative", "/tmp/../tmp", "//host/share", "\\\\host\\share"):
            with self.subTest(value=value), self.assertRaises(bridge.BridgeError):
                bridge.checked_path(value, exists=False)

    def test_reject_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / "real").mkdir()
            try: (root / "link").symlink_to(root / "real", target_is_directory=True)
            except OSError: self.skipTest("No symlink creation support")
            with self.assertRaises(bridge.BridgeError): bridge.checked_path(root / "link")

    def test_reject_simulated_windows_reparse(self):
        fake = mock.Mock(st_mode=0, st_file_attributes=0x400)
        with mock.patch.object(Path, "lstat", return_value=fake):
            self.assertTrue(bridge.is_link(Path("synthetic-reparse")))

    def test_overlap_rejected(self):
        with self.assertRaises(bridge.BridgeError):
            bridge.separate(Path("/input"), Path("/input/output"))

    def test_original_forward_time_is_not_inferred_from_parent(self):
        record = {"messages": [{"create_time": 1700000000, "time_str": "invented", "_resource_source": "<dataitem><datadesc>x</datadesc></dataitem>"}]}
        result = bridge.correct_forward_times(record)["messages"][0]
        self.assertEqual((result["create_time"], result["time_str"], result["bridge_time_status"]), (0, "", "unknown"))

    def test_unzoned_forward_text_remains_unzoned(self):
        result = bridge.correct_forward_times({"messages": [{"_resource_source": "<dataitem><sourcetime>2026-11-13 08:10:20</sourcetime></dataitem>"}]})["messages"][0]
        self.assertEqual(result["create_time"], 0)
        self.assertEqual(result["bridge_time_status"], "source_text_unzoned")
        self.assertEqual(result["time_str"], "2026-11-13 08:10:20")

    def test_forward_millisecond_like_value_is_not_silently_rescaled(self):
        result = bridge.correct_forward_times({"messages": [{"_resource_source": "<dataitem><srcMsgCreateTime>1700000000000</srcMsgCreateTime></dataitem>"}]})["messages"][0]
        self.assertEqual(result["create_time"], 0)
        self.assertEqual(result["bridge_time_status"], "unknown")
        self.assertEqual(result["bridge_original_timestamp"], "1700000000000")

    def test_network_subprocess_and_outside_writes_really_blocked(self):
        code = """import importlib.util,sys,socket,subprocess,pathlib
spec=importlib.util.spec_from_file_location('bridge',sys.argv[1]); b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
guard=b.Guard(pathlib.Path(sys.argv[2]));sys.addaudithook(guard.audit)
results=[]
for op in (lambda: socket.socket(), lambda: subprocess.Popen([sys.executable,'-c','pass']), lambda: pathlib.Path(sys.argv[3]).write_text('unexpected')):
 try: op();results.append('ALLOWED')
 except b.BridgeError as e: results.append(e.code)
print('|'.join(results))
"""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); allowed = root / "allowed"; allowed.mkdir(); blocked = root / "blocked.txt"
            result = subprocess.run([sys.executable, "-B", "-c", code, str(SCRIPT), str(allowed), str(blocked)], capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout.strip(), "network_disabled|subprocess_disabled|write_outside_run")
            self.assertFalse(blocked.exists())

    def test_exception_output_does_not_repeat_sensitive_arguments(self):
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--upstream", "/not-a-real-path", "export", "--unexpected", "SENSITIVE-SENTINEL"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("SENSITIVE-SENTINEL", result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_process_binding_uses_real_process_user_and_open_database(self):
        import psutil
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); account = root / "account"; db = account / "db_storage"; db.mkdir(parents=True)
            database = db / "session.db"; database.write_bytes(b"synthetic")
            exe = root / "Weixin.exe"; exe.write_bytes(b"synthetic-executable-not-run")
            target = mock.Mock(pid=123)
            target.create_time.return_value = 1000.25
            target.exe.return_value = str(exe)
            target.name.return_value = "Weixin.exe"
            target.username.return_value = "DOMAIN\\owner"
            target.open_files.return_value = [SimpleNamespace(path=str(database))]
            current = mock.Mock(); current.username.return_value = "DOMAIN\\owner"
            args = SimpleNamespace(pid=123, process_start_time=1000.25, process_exe=exe,
                process_sha256=bridge.sha256(exe), account_dir=account)
            def factory(pid=None): return current if pid is None else target
            with mock.patch.object(psutil, "Process", side_effect=factory), mock.patch.dict(os.environ, {"USERNAME": "spoofed"}):
                self.assertIs(bridge.process_binding(args, initial=True), target)
                target.username.return_value = "DOMAIN\\someone_else"
                with self.assertRaises(bridge.BridgeError): bridge.process_binding(args, initial=True)
                target.username.return_value = "DOMAIN\\owner"
                target.open_files.return_value = []
                with self.assertRaises(bridge.BridgeError): bridge.process_binding(args, initial=True)
                target.open_files.return_value = [SimpleNamespace(path=str(database))]
                target.create_time.return_value = 1001.25
                with self.assertRaises(bridge.BridgeError): bridge.process_binding(args)

    def test_source_copy_rejects_linked_databases(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); fixture(root / "source")
            (root / "external.db").write_bytes((root / "source/message_0.db").read_bytes())
            (root / "source/message_0.db").unlink()
            try: (root / "source/message_0.db").symlink_to(root / "external.db")
            except OSError: self.skipTest("No symlink creation support")
            with self.assertRaises(bridge.BridgeError):
                bridge.copy_snapshot(root / "source", root / "copy", lambda: None)
            self.assertFalse((root / "copy").exists())


@unittest.skipUnless(UPSTREAM, "Set MOECT_TEST_UPSTREAM to run the real upstream exporter")
class RealCore(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        fixture(self.source)
        self.before = bridge.db_manifest(self.source)

    def tearDown(self):
        self.temp.cleanup()

    def command(self, name="export", output="result", *, upstream=UPSTREAM, extra=()):
        args = [sys.executable, "-B", str(SCRIPT), "--upstream", str(upstream), name]
        if name != "doctor":
            args += ["--source", str(self.source), "--account-id", "wxid_owner", "--account-scope", "synthetic-owner", "--output", str(self.root / output)]
        if name == "export": args += ["--session", "friend_a"]
        return args + list(extra)

    def run_bridge(self, *args, **kwargs):
        completed = subprocess.run(self.command(*args, **kwargs), capture_output=True, text=True, timeout=45)
        self.assertEqual(completed.stderr, "")
        result = json.loads(completed.stdout)
        return completed, result

    def test_doctor_validates_source_and_real_dependencies(self):
        result, info = self.run_bridge("doctor")
        self.assertEqual(result.returncode, 0, info)
        self.assertEqual(info["upstream_commit"], bridge.COMMIT)

    def test_real_export_with_ctypes_crypto_backend_never_needs_a_subprocess(self):
        # A minimal installed runtime has no optional cffi. Exercise that real
        # Cryptodome backend even when the test runner happens to have cffi.
        code = """import importlib.util,sys
sys.modules['cffi']=None
spec=importlib.util.spec_from_file_location('bridge',sys.argv[1]); b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
raise SystemExit(b.main(sys.argv[2:]))
"""
        args = self.command()
        result = subprocess.run([sys.executable, "-B", "-c", code, str(SCRIPT), *args[3:]], capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        report = json.loads((self.root / "result/run.json").read_text())
        self.assertEqual(report["crypto_architecture"], "current_python_pointer_width_without_subprocess")
        self.assertEqual(report["status"], "completed")

    def test_real_json_preserves_text_ids_scope_provenance_and_missing_time(self):
        result, info = self.run_bridge()
        self.assertEqual(result.returncode, 0, info)
        report = json.loads((self.root / "result/run.json").read_text())
        payload = json.loads((self.root / "result" / report["results"][0]["path"]).read_text())
        self.assertEqual(payload["count"], 3)
        msg = payload["messages"][0]
        self.assertEqual(msg["server_id"], "9007199254740993")
        self.assertIn("😀 <script>alert(1)</script>", msg["text"])
        self.assertEqual(msg["time_str"], "2023-11-15 06:13:20")
        self.assertEqual(msg["bridge_source"]["database_sha256"], self.before["message_0.db"])
        self.assertEqual(payload["metadata"]["account_id_kind"], "wxid")
        self.assertEqual(payload["metadata"]["account_scope"], "synthetic-owner")
        self.assertFalse(payload["metadata"]["identity_verified"])
        forwarded = payload["messages"][2]["forward"]["messages"][0]
        self.assertEqual((forwarded["create_time"], forwarded["bridge_time_status"]), (0, "unknown"))
        self.assertEqual(bridge.db_manifest(self.source), self.before)
        self.assertFalse((self.root / "result/.work").exists())
        self.assertNotIn("同名联系人", result.stdout)
        self.assertNotIn("keys.json", str(list((self.root / "result").rglob("*"))))

    def test_real_html_and_jsonl(self):
        for fmt in ("html", "jsonl"):
            with self.subTest(fmt=fmt):
                result, info = self.run_bridge(output=fmt, extra=("--format", fmt))
                self.assertEqual(result.returncode, 0, info)
                report = json.loads((self.root / fmt / "run.json").read_text())
                text = (self.root / fmt / report["results"][0]["path"]).read_text()
                self.assertIn('"account_scope": "synthetic-owner"', text)
                if fmt == "html": self.assertNotIn("__MANIFEST__", text)

    def test_missing_local_media_is_reported_without_network_or_key_cache(self):
        result, info = self.run_bridge(extra=("--local-media",))
        self.assertEqual(result.returncode, 0, info)
        report = json.loads((self.root / "result/run.json").read_text())
        self.assertGreaterEqual(report["results"][0]["resource_summary"]["missing"], 1)
        self.assertFalse(any(p.name in ("image-keys.json", "keys.json", "emoticon-key.bin") for p in (self.root / "result").rglob("*")))

    def test_sessions_keep_equal_names_separate(self):
        result, info = self.run_bridge("sessions")
        self.assertEqual(result.returncode, 0, info)
        listing = json.loads((self.root / "result/sessions.json").read_text())["sessions"]
        self.assertEqual({row["session_id"] for row in listing}, {"friend_a", "friend_b"})
        self.assertEqual({row["display_name"] for row in listing}, {"同名联系人"})

    def test_existing_output_unchanged(self):
        out = self.root / "result"; out.mkdir(); (out / "keep").write_text("preserve")
        result, info = self.run_bridge()
        self.assertEqual((result.returncode, info["code"]), (2, "output_exists"))
        self.assertEqual((out / "keep").read_text(), "preserve")

    def test_live_capture_requires_approval_and_windows_without_creating_output(self):
        args = [sys.executable, "-B", str(SCRIPT), "--upstream", UPSTREAM, "capture",
            "--account-dir", str(self.source), "--account-id", "wxid_owner", "--account-scope", "synthetic-owner",
            "--output", str(self.root / "result"), "--session", "friend_a", "--pid", "123", "--process-exe", str(self.root / "Weixin.exe"),
            "--process-start-time", "1000.25", "--process-sha256", "0" * 64]
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(json.loads(result.stdout)["code"], "capture_approval_required")
        if os.name != "nt":
            result = subprocess.run(args + ["--live-read-approved"], capture_output=True, text=True)
            self.assertEqual(json.loads(result.stdout)["code"], "windows_required")
        self.assertFalse((self.root / "result").exists())

    def test_modified_source_and_unlocked_python_rejected(self):
        target = self.root / "upstream"; shutil.copytree(UPSTREAM, target)
        original = (target / "core/data.py").read_bytes()
        (target / "core/data.py").write_bytes(original + b"\n# tampered\n")
        result, info = self.run_bridge(upstream=target)
        self.assertEqual((result.returncode, info["code"]), (2, "upstream_untrusted"))
        (target / "core/data.py").write_bytes(original)
        (target / "core/unlisted.py").write_text("raise AssertionError('must not import')")
        result, info = self.run_bridge(upstream=target)
        self.assertEqual((result.returncode, info["code"]), (2, "upstream_untrusted"))
        self.assertFalse((self.root / "result").exists())

    def test_root_dependency_shadow_is_rejected_before_it_can_execute(self):
        target = self.root / "upstream"; shutil.copytree(UPSTREAM, target)
        canary = self.root / "injected-import-ran.txt"
        (target / "zstandard.py").write_text("from pathlib import Path\nPath(" + repr(str(canary)) + ").write_text('ran')\n")
        result, info = self.run_bridge("doctor", upstream=target)
        self.assertEqual((result.returncode, info["code"]), (2, "upstream_untrusted"))
        result, info = self.run_bridge(upstream=target)
        self.assertEqual((result.returncode, info["code"]), (2, "upstream_untrusted"))
        self.assertFalse(canary.exists())
        self.assertFalse((self.root / "result").exists())

    def test_invalid_utf8_fails_without_silent_replacement(self):
        shutil.rmtree(self.source); fixture(self.source, invalid=True)
        before = bridge.db_manifest(self.source)
        result, info = self.run_bridge()
        self.assertEqual((result.returncode, info["code"]), (2, "decode_failed"))
        report = json.loads((self.root / "result/run.json").read_text())
        self.assertEqual((report["status"], report["incomplete"]), ("failed", True))
        self.assertEqual(bridge.db_manifest(self.source), before)

    def test_unknown_session_fails_without_exporting_other_conversations(self):
        result, info = self.run_bridge(extra=("--session", "does_not_exist"))
        self.assertEqual((result.returncode, info["code"]), (2, "session_missing"))
        report = json.loads((self.root / "result/run.json").read_text())
        self.assertEqual(report["results"], [])

    @unittest.skipIf(os.name == "nt", "POSIX signal test; Windows cancellation needs device acceptance")
    def test_actual_cancel_keeps_original_and_marks_incomplete(self):
        shutil.rmtree(self.source); fixture(self.source, many=50000)
        before = bridge.db_manifest(self.source)
        process = subprocess.Popen(self.command(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline and not (self.root / "result/run.json").exists() and process.poll() is None:
                time.sleep(0.01)
            self.assertIsNone(process.poll(), "The synthetic run ended before cancellation could be tested")
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 130, (stdout, stderr))
            report = json.loads((self.root / "result/run.json").read_text())
            self.assertEqual(report["status"], "cancelled")
            self.assertEqual(bridge.db_manifest(self.source), before)
        finally:
            if process.poll() is None: process.kill(); process.wait()


if __name__ == "__main__":
    unittest.main()
