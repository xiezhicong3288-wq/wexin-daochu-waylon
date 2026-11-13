"""Frozen-input decryption with native SQLite transactions and synthetic AES.

Set MOECT_TEST_UPSTREAM to the pinned source directory. These fixtures are not
real WeChat writer samples and do not establish that writer's checksum domain.
"""
import ctypes
import ctypes.util
import hashlib
import hmac
import importlib
import importlib.util
import os
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "moect_bridge.py"
spec = importlib.util.spec_from_file_location("capture_test_bridge", SCRIPT)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
UPSTREAM = os.environ.get("MOECT_TEST_UPSTREAM")
PAGE = 4096
RESERVE = 80
SALT = bytes(range(16))
KEY = hashlib.sha256(b"PUBLIC SYNTHETIC CAPTURE TEST KEY").digest()


def native_transactions(path):
    library = ctypes.util.find_library("sqlite3")
    if not library:
        raise unittest.SkipTest("Native SQLite shared library required for reserved-page fixture")
    lib = ctypes.CDLL(library)
    lib.sqlite3_open.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    lib.sqlite3_open.restype = ctypes.c_int
    lib.sqlite3_exec.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    lib.sqlite3_exec.restype = ctypes.c_int
    lib.sqlite3_file_control.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
    lib.sqlite3_file_control.restype = ctypes.c_int
    lib.sqlite3_db_cacheflush.argtypes = [ctypes.c_void_p]
    lib.sqlite3_db_cacheflush.restype = ctypes.c_int
    lib.sqlite3_close.argtypes = [ctypes.c_void_p]
    lib.sqlite3_errmsg.argtypes = [ctypes.c_void_p]
    lib.sqlite3_errmsg.restype = ctypes.c_char_p
    con = ctypes.c_void_p()
    if lib.sqlite3_open(os.fsencode(path), ctypes.byref(con)):
        raise RuntimeError("Synthetic SQLite writer open failed")
    def execute(sql):
        if lib.sqlite3_exec(con, sql.encode(), None, None, None):
            raise RuntimeError(lib.sqlite3_errmsg(con).decode())
    try:
        execute("PRAGMA page_size=4096; PRAGMA journal_mode=DELETE;")
        reserve = ctypes.c_int(RESERVE)
        if lib.sqlite3_file_control(con, b"main", 38, ctypes.byref(reserve)):
            raise RuntimeError("Synthetic SQLite reserve-byte setting failed")
        execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, body TEXT NOT NULL);"
                "INSERT INTO messages VALUES(1,'BASE');"
                "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; PRAGMA wal_checkpoint(TRUNCATE);")
        baseline = path.read_bytes()
        execute("INSERT INTO messages VALUES(2,'COMMITTED_A'); INSERT INTO messages VALUES(3,'COMMITTED_B');")
        wal_path = Path(str(path) + "-wal")
        committed = wal_path.read_bytes()
        execute("BEGIN IMMEDIATE; UPDATE messages SET body='UNCOMMITTED' WHERE id=3;")
        if lib.sqlite3_db_cacheflush(con):
            raise RuntimeError("Synthetic SQLite cache flush failed")
        tail = wal_path.read_bytes()
        assert len(tail) > len(committed) and baseline[20] == RESERVE
        execute("ROLLBACK;")
        return baseline, committed, tail
    finally:
        lib.sqlite3_close(con)


def encrypt_page(plain, number):
    from Cryptodome.Cipher import AES
    iv = hashlib.sha256(b"fixture-iv" + struct.pack(">I", number) + plain).digest()[:16]
    start = 16 if number == 1 else 0
    body = AES.new(KEY, AES.MODE_CBC, iv).encrypt(plain[start:PAGE - RESERVE])
    mac_key = hashlib.pbkdf2_hmac("sha512", KEY, bytes(x ^ 0x3A for x in SALT), 2, dklen=32)
    mac = hmac.new(mac_key, body + iv + struct.pack("<I", number), hashlib.sha512).digest()
    return (SALT if number == 1 else b"") + body + iv + mac


def encode_wal(plain):
    """Synthetic stored-payload checksum domain, not a WeChat compatibility claim."""
    out = bytearray(plain[:32])
    order = "little" if int.from_bytes(out[:4], "big") == 0x377F0682 else "big"
    def checksum(data, state):
        a, b = state
        for offset in range(0, len(data), 8):
            a = (a + int.from_bytes(data[offset:offset + 4], order) + b) & 0xFFFFFFFF
            b = (b + int.from_bytes(data[offset + 4:offset + 8], order) + a) & 0xFFFFFFFF
        return a, b
    state = checksum(out[:24], (0, 0))
    out[24:32] = struct.pack(">II", *state)
    for offset in range(32, len(plain), PAGE + 24):
        frame = bytearray(plain[offset:offset + 24])
        payload = encrypt_page(plain[offset + 24:offset + 24 + PAGE], int.from_bytes(frame[:4], "big"))
        state = checksum(frame[:8] + payload, state)
        frame[16:24] = struct.pack(">II", *state)
        out.extend(frame + payload)
    return bytes(out)


@unittest.skipUnless(UPSTREAM, "Set MOECT_TEST_UPSTREAM for the real locked decryptor")
class FrozenCaptureValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        bridge.verify_upstream(Path(UPSTREAM))
        sys.path.insert(0, UPSTREAM)
        cls.decrypt = importlib.import_module("wx4.decrypt")
        assert Path(cls.decrypt.__file__).resolve() == (Path(UPSTREAM) / "wx4/decrypt.py").resolve()
        cls.fixture_dir = tempfile.TemporaryDirectory()
        cls.database, cls.committed, cls.tail = native_transactions(Path(cls.fixture_dir.name) / "fixture.db")
        cls.encrypted_db = b"".join(encrypt_page(cls.database[p:p + PAGE], p // PAGE + 1)
                                    for p in range(0, len(cls.database), PAGE))
        cls.encrypted_wal = encode_wal(cls.tail)

    @classmethod
    def tearDownClass(cls):
        cls.fixture_dir.cleanup()
        sys.path.remove(UPSTREAM)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.source = self.root / "private-source"; self.source.mkdir()
        for name in ("session.db", "message_0.db"):
            (self.source / name).write_bytes(self.encrypted_db)
        self.wal = self.source / "message_0.db-wal"
        self.wal.write_bytes(self.encrypted_wal)
        self.destination = self.root / "decrypted"
        self.keys = {name: {"enc_key": KEY.hex()} for name in ("session.db", "message_0.db")}

    def tearDown(self):
        self.directory.cleanup()

    def hashes(self):
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.source.iterdir()}

    def call(self):
        return bridge.decrypt_frozen_snapshot(self.source, self.destination, self.keys, self.decrypt, lambda: None)

    def rows(self, path):
        con = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        try:
            self.assertEqual(con.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
            return con.execute("SELECT id, body FROM messages ORDER BY id").fetchall()
        finally:
            con.close()

    def test_real_decryptor_preserves_commits_and_excludes_uncommitted_tail(self):
        reference = self.root / "reference"; reference.mkdir()
        db = reference / "message_0.db"; db.write_bytes(self.database)
        Path(str(db) + "-wal").write_bytes(self.tail)
        expected = self.rows(db)
        self.assertEqual(expected, [(1, "BASE"), (2, "COMMITTED_A"), (3, "COMMITTED_B")])
        before = self.hashes()
        result = self.call()
        self.assertEqual(self.rows(self.destination / "message_0.db"), expected)
        self.assertEqual(self.hashes(), before)
        wal = result["validation"]["files"]["message_0.db"]["wal"]
        self.assertEqual(wal["uncommitted_tail_frames"], 1)
        self.assertEqual(wal["committed_prefix_bytes"], len(self.committed))
        self.assertFalse(result["validation"]["cryptographic_database_log_pair_identity_proven"])
        self.assertTrue(all(x["database_first_page_key_verified"] for x in result["files"]))
        self.assertTrue(all(not x["all_page_hmac_verified"] for x in result["files"]))

    def test_invalid_wal_is_rejected_before_any_output_is_created(self):
        for kind, code in (("header", "wal_header_checksum_mismatch"),
                           ("commit", "wal_frame_checksum_unsupported_or_invalid"),
                           ("truncated", "wal_frame_truncated")):
            with self.subTest(kind=kind):
                changed = bytearray(self.encrypted_wal)
                if kind == "header": changed[24] ^= 1
                elif kind == "commit": struct.pack_into(">I", changed, len(changed) - PAGE - 20, 2)
                else: changed = changed[:-100]
                self.wal.write_bytes(changed)
                before = self.hashes()
                with self.assertRaises(bridge.wal_guard.WalValidationError) as error:
                    self.call()
                self.assertEqual(error.exception.code, code)
                self.assertFalse(self.destination.exists())
                self.assertEqual(self.hashes(), before)

    def test_bad_later_database_wal_prevents_decrypting_earlier_database(self):
        changed = bytearray(self.encrypted_wal); changed[24] ^= 1
        (self.source / "session.db-wal").write_bytes(changed)
        before = self.hashes()
        with self.assertRaises(bridge.wal_guard.WalValidationError): self.call()
        self.assertFalse(self.destination.exists())
        self.assertEqual(self.hashes(), before)

    def test_missing_key_and_partial_database_page_fail_before_decryption(self):
        self.keys.pop("session.db")
        with self.assertRaises(bridge.BridgeError) as error: self.call()
        self.assertEqual(error.exception.code, "keys_incomplete")
        self.assertFalse(self.destination.exists())
        self.keys["session.db"] = {"enc_key": KEY.hex()}
        (self.source / "message_0.db").write_bytes(self.encrypted_db[:-1])
        with self.assertRaises(bridge.BridgeError) as error: self.call()
        self.assertEqual(error.exception.code, "snapshot_invalid")
        self.assertFalse(self.destination.exists())

    def test_known_whole_page_loss_is_stopped_by_prior_inventory(self):
        original = bridge.source_audit.inventory(self.source)
        (self.source / "message_0.db").write_bytes(self.encrypted_db[:-PAGE])
        with self.assertRaises(bridge.source_audit.SourceAuditError) as error:
            bridge.copy_snapshot(self.source, self.destination, lambda: None, validate=False, expected=original)
        self.assertEqual(error.exception.code, "source_manifest_mismatch")
        self.assertIn("message_0.db", error.exception.details["changed"])
        self.assertFalse(self.destination.exists())

    def test_orphan_wal_and_nonempty_rollback_journal_are_not_ignored(self):
        orphan = self.source / "missing.db-wal"; orphan.write_bytes(self.encrypted_wal)
        with self.assertRaises(bridge.BridgeError) as error: self.call()
        self.assertEqual(error.exception.code, "orphan_database_log")
        self.assertFalse(self.destination.exists())
        orphan.unlink()
        (self.source / "message_0.db-journal").write_bytes(b"SYNTHETIC unresolved journal")
        with self.assertRaises(bridge.BridgeError) as error: self.call()
        self.assertEqual(error.exception.code, "rollback_journal_unsupported")
        self.assertFalse(self.destination.exists())

    def test_wrong_key_is_sanitized_by_actual_page_hmac_failure(self):
        self.keys["message_0.db"]["enc_key"] = bytes(32).hex()
        before = self.hashes()
        with self.assertRaises(bridge.BridgeError) as error: self.call()
        self.assertEqual(error.exception.code, "capture_incomplete")
        self.assertEqual(error.exception.details["stage"], "decrypt_frozen_input")
        self.assertEqual(self.hashes(), before)


if __name__ == "__main__":
    unittest.main()
