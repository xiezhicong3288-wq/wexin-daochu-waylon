"""Synthetic independent bridge checks; never accesses a real WeChat process."""
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
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'moect_bridge.py'
UPSTREAM = Path(os.environ["MOECT_TEST_UPSTREAM"]) if os.environ.get("MOECT_TEST_UPSTREAM") else None
spec = importlib.util.spec_from_file_location('independent_bridge_target', SCRIPT)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def fixture(root):
    root.mkdir()
    with closing(sqlite3.connect(root / 'session.db')) as con, con:
        con.execute('CREATE TABLE SessionTable(username TEXT, summary TEXT, last_timestamp INTEGER)')
        con.executemany('INSERT INTO SessionTable VALUES (?, ?, ?)',
                        [('peer_selected', '', 1700000000), ('peer_out_of_scope', '', 1700000000)])
    with closing(sqlite3.connect(root / 'contact.db')) as con, con:
        con.execute('CREATE TABLE contact(id INTEGER, username TEXT, nick_name TEXT, remark TEXT, alias TEXT)')
        con.executemany('INSERT INTO contact VALUES (?, ?, ?, ?, ?)',
                        [(1, 'wxid_owner', '合成账号', '', ''),
                         (2, 'peer_selected', '同名', '', ''),
                         (3, 'peer_out_of_scope', '同名', '', '')])
    with closing(sqlite3.connect(root / 'message_0.db')) as con, con:
        con.execute('CREATE TABLE Name2Id(user_name TEXT)')
        con.executemany('INSERT INTO Name2Id VALUES (?)',
                        [('wxid_owner',), ('peer_selected',), ('peer_out_of_scope',)])
        for peer, sender in [('peer_selected', 2), ('peer_out_of_scope', 3)]:
            table = 'Msg_' + hashlib.md5(peer.encode()).hexdigest()
            con.execute(f'CREATE TABLE "{table}"(local_id INTEGER,server_id INTEGER,local_type INTEGER,sort_seq INTEGER,real_sender_id INTEGER,create_time INTEGER,message_content,compress_content,packed_info_data)')
            con.execute(f'INSERT INTO "{table}" VALUES (1,9007199254740993,1,1,?,1700000000,?,NULL,NULL)',
                        (sender, 'SYNTHETIC_BODY_' + peer + '\n<script>not_executed()</script>'))


class IndependentBridgeChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='moect-bridge-audit-')
        self.base = Path(self.temp.name)
        self.source = self.base / 'snapshot'
        fixture(self.source)
        self.before = bridge.db_manifest(self.source)
        self.out = self.base / 'out'
        self.env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')

    def tearDown(self):
        self.temp.cleanup()

    def command(self, upstream=UPSTREAM, command='export', extra=()):
        argv = [sys.executable, '-B', str(SCRIPT), '--upstream', str(upstream or self.base / 'unavailable-upstream'), command]
        if command == 'export':
            argv += ['--source', str(self.source), '--account-id', 'wxid_owner',
                     '--account-scope', 'audit_declared_scope', '--output', str(self.out),
                     '--session', 'peer_selected']
        argv += list(extra)
        return subprocess.run(argv, env=self.env, capture_output=True, text=True, timeout=30)

    @unittest.skipUnless(UPSTREAM, "Set MOECT_TEST_UPSTREAM to run the real upstream exporter")
    def test_actual_core_selects_only_requested_conversation(self):
        result = self.command()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        run = json.loads((self.out / 'run.json').read_text())
        exported = json.loads((self.out / run['results'][0]['path']).read_text())
        self.assertEqual('peer_selected', exported['metadata']['session'])
        self.assertEqual(1, exported['count'])
        self.assertNotIn('peer_out_of_scope', json.dumps(exported))
        self.assertEqual('9007199254740993', exported['messages'][0]['server_id'])
        self.assertEqual(self.before, bridge.db_manifest(self.source))
        self.assertNotIn('SYNTHETIC_BODY', result.stdout + result.stderr)
        self.assertFalse(any(p.name in ('keys.json', 'image-keys.json') for p in self.out.rglob('*')))

    @unittest.skipUnless(UPSTREAM, "Set MOECT_TEST_UPSTREAM to run the real upstream exporter")
    def test_root_dependency_shadow_never_executes(self):
        up = self.base / 'altered-upstream'
        shutil.copytree(UPSTREAM, up)
        marker = self.out / 'injected-import-ran.txt'
        (up / 'zstandard.py').write_text(
            'from pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("CANARY")\n'
            'class ZstdDecompressor:\n    pass\n')
        result = self.command(upstream=up)
        self.assertFalse(marker.exists(), 'An unapproved root dependency shadow was executed')
        self.assertNotEqual(0, result.returncode)
        self.assertEqual('upstream_untrusted', json.loads(result.stdout)['code'])
        doctor = self.command(upstream=up, command='doctor')
        self.assertNotEqual(0, doctor.returncode)
        self.assertEqual('upstream_untrusted', json.loads(doctor.stdout)['code'])

    def test_forward_time_unit_is_not_guessed(self):
        raw_value = '1700000000000'
        record = {'messages': [{'_resource_source':
            '<dataitem><srcMsgCreateTime>' + raw_value + '</srcMsgCreateTime></dataitem>',
            'create_time': 1700000000, 'time_str': 'wrong inherited time',
            'forward': {'messages': [{'_resource_source': '<dataitem/>',
                                     'create_time': 1700000000}]}}]}
        corrected = bridge.correct_forward_times(record)['messages'][0]
        self.assertEqual(0, corrected['create_time'])
        self.assertEqual('unknown', corrected['bridge_time_status'])
        self.assertEqual(raw_value, corrected['bridge_original_timestamp'])
        self.assertEqual('', corrected['time_str'])
        self.assertEqual('parser_position', corrected['bridge_id_basis'])
        nested = corrected['forward']['messages'][0]
        self.assertEqual(0, nested['create_time'])
        self.assertEqual('unknown', nested['bridge_time_status'])

    def test_live_capture_requires_explicit_flag_before_any_output(self):
        args = ['--account-id', 'wxid_owner', '--account-scope', 'audit', '--output', str(self.out),
                '--account-dir', str(self.base / 'account'), '--pid', '1',
                '--process-exe', str(self.base / 'Weixin.exe'), '--process-sha256', 'a' * 64,
                '--process-start-time', '1', '--session', 'peer_selected']
        result = self.command(command='capture', extra=args)
        self.assertEqual('capture_approval_required', json.loads(result.stdout)['code'])
        self.assertFalse(self.out.exists())

    @unittest.skipIf(os.name == 'nt', 'This is the non-Windows fail-closed boundary')
    def test_live_capture_cannot_run_on_cloud_linux(self):
        args = ['--account-id', 'wxid_owner', '--account-scope', 'audit', '--output', str(self.out),
                '--account-dir', str(self.base / 'account'), '--pid', '1',
                '--process-exe', str(self.base / 'Weixin.exe'), '--process-sha256', 'a' * 64,
                '--process-start-time', '1', '--session', 'peer_selected', '--live-read-approved']
        result = self.command(command='capture', extra=args)
        self.assertEqual('windows_required', json.loads(result.stdout)['code'])
        self.assertFalse(self.out.exists())

    def test_frozen_snapshot_change_is_detected(self):
        changed = False
        def mutate_once():
            nonlocal changed
            if not changed:
                changed = True
                with closing(sqlite3.connect(self.source / 'session.db')) as con, con:
                    con.execute("UPDATE SessionTable SET summary='changed after manifest'")
        with self.assertRaises(bridge.BridgeError) as caught:
            bridge.copy_snapshot(self.source, self.base / 'copy', mutate_once)
        self.assertEqual('source_changed', caught.exception.code)

    def test_snapshot_link_is_rejected_before_copy(self):
        outside = self.base / 'outside.db'
        shutil.copyfile(self.source / 'message_0.db', outside)
        try:
            (self.source / 'linked.db').symlink_to(outside)
        except OSError as error:
            if getattr(error, 'winerror', None) != 1314:
                raise
            self.skipTest('Windows symlink creation privilege is unavailable (WinError 1314)')
        with self.assertRaises(bridge.BridgeError):
            bridge.copy_snapshot(self.source, self.base / 'copy', lambda: None)
        self.assertFalse((self.base / 'copy').exists())

    def test_process_binding_rejects_wrong_user_and_unbound_directory(self):
        import psutil
        exe = self.base / 'Weixin.exe'
        exe.write_bytes(b'SYNTHETIC_EXECUTABLE_NOT_RUN')
        account = self.base / 'account'
        storage = account / 'db_storage'
        storage.mkdir(parents=True)
        db = storage / 'session.db'; db.write_bytes(b'SYNTHETIC_OPEN_FILE')
        args = SimpleNamespace(pid=7, process_start_time=123.0, process_exe=exe,
                               process_sha256=bridge.sha256(exe), account_dir=account)
        target = mock.Mock(pid=7)
        target.create_time.return_value = 123.0
        target.exe.return_value = str(exe)
        target.name.return_value = 'Weixin.exe'
        target.username.return_value = 'other-user'
        target.open_files.return_value = [SimpleNamespace(path=str(db))]
        me = mock.Mock(); me.username.return_value = 'current-user'
        with mock.patch.object(psutil, 'Process', side_effect=lambda pid=None: me if pid is None else target):
            with self.assertRaises(bridge.BridgeError):
                bridge.process_binding(args, initial=True)
            target.username.return_value = 'current-user'
            target.open_files.return_value = []
            with self.assertRaises(bridge.BridgeError):
                bridge.process_binding(args, initial=True)
            target.open_files.return_value = [SimpleNamespace(path=str(db))]
            self.assertIs(target, bridge.process_binding(args, initial=True))
            target.create_time.return_value = 124.0
            with self.assertRaises(bridge.BridgeError):
                bridge.process_binding(args)


if __name__ == '__main__':
    unittest.main(verbosity=2)
