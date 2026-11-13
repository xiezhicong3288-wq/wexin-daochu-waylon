"""Read-only WAL checks against transactions written by native SQLite.

The fixture writer and SQL reference do not use the validator's checksum code.
Only synthetic records are created; no live WeChat files or keys are accessed.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "wal_guard.py"
spec = importlib.util.spec_from_file_location("wal_guard", SCRIPT)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
PAGE = 1024
FRAME = PAGE + 24


def make_fixture(root):
    """SQLite cache spilling writes genuine uncommitted WAL frames."""
    database = root / "writer.db"
    con = sqlite3.connect(database)
    try:
        con.execute("PRAGMA page_size=1024")
        con.execute("CREATE TABLE items(id INTEGER PRIMARY KEY, body TEXT)")
        con.commit()
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA wal_autocheckpoint=0")
        con.execute("PRAGMA cache_size=5")
        con.execute("PRAGMA cache_spill=ON")
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        baseline = database.read_bytes()
        wal = Path(str(database) + "-wal")
        con.execute("INSERT INTO items VALUES (1,'COMMITTED_ONE')"); con.commit()
        one = wal.read_bytes()
        con.execute("INSERT INTO items VALUES (2,'COMMITTED_TWO')"); con.commit()
        committed = wal.read_bytes()
        con.execute("BEGIN IMMEDIATE")
        con.execute("UPDATE items SET body=? WHERE id=2", ("UNCOMMITTED" * 20000,))
        tail = wal.read_bytes()
        assert len(tail) > len(committed) > len(one)
        con.rollback()
        return baseline, one, committed, tail
    finally:
        con.close()


class WalGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_dir = tempfile.TemporaryDirectory()
        cls.database, cls.one, cls.committed, cls.tail = make_fixture(Path(cls.fixture_dir.name))

    @classmethod
    def tearDownClass(cls):
        cls.fixture_dir.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.path = self.root / "fixture.db-wal"

    def tearDown(self):
        self.directory.cleanup()

    def write(self, data):
        self.path.write_bytes(data)
        return self.path

    def invalid(self, data, code, **kwargs):
        self.write(data)
        with self.assertRaises(guard.WalValidationError) as result:
            guard.validate_wal(self.path, **kwargs)
        self.assertEqual(result.exception.code, code)
        self.assertEqual(result.exception.report["status"], "invalid_or_unsupported")
        json.dumps(result.exception.report)
        return result.exception.report

    def oracle(self, wal):
        directory = self.root / "reference"
        directory.mkdir()
        database = directory / "fixture.db"
        database.write_bytes(self.database)
        Path(str(database) + "-wal").write_bytes(wal)
        con = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
        try:
            return con.execute("SELECT id, body FROM items ORDER BY id").fetchall()
        finally:
            con.close()

    def test_native_committed_chain_and_read_only_input(self):
        self.write(self.committed)
        before = self.path.stat()
        report = guard.validate_wal(self.path, expected_page_size=PAGE,
                    expected_size=len(self.committed),
                    expected_sha256=hashlib.sha256(self.committed).hexdigest())
        self.assertEqual(report["status"], "valid")
        self.assertEqual(report["committed_transactions"], 2)
        self.assertEqual(report["last_committed_frame"], (len(self.committed) - 32) // FRAME)
        self.assertEqual(report["committed_prefix_bytes"], len(self.committed))
        self.assertEqual(report["uncommitted_tail_frames"], 0)
        self.assertEqual(report["checksum_domain"], "observed_stored_payload_bytes")
        self.assertEqual(self.path.read_bytes(), self.committed)
        self.assertEqual(self.path.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertFalse(report["database_pair_identity_proven"])
        self.assertFalse(report["encrypted_page_authentication_proven"])
        self.assertEqual(self.oracle(self.committed), [(1, "COMMITTED_ONE"), (2, "COMMITTED_TWO")])

    def test_genuine_uncommitted_tail_is_accounted_but_not_committed(self):
        self.write(self.tail)
        report = guard.validate_wal(self.path)
        self.assertEqual(report["status"], "valid_with_uncommitted_tail")
        self.assertEqual(report["committed_prefix_bytes"], len(self.committed))
        self.assertGreater(report["uncommitted_tail_frames"], 0)
        self.assertEqual(report["valid_frames"], report["complete_frames"])
        self.assertEqual(self.oracle(self.tail), [(1, "COMMITTED_ONE"), (2, "COMMITTED_TWO")])

    def test_corrupt_header_checksum_rejected(self):
        damaged = bytearray(self.committed); damaged[24] ^= 1
        self.invalid(damaged, "wal_header_checksum_mismatch")

    def test_forged_uncommitted_commit_marker_rejected(self):
        damaged = bytearray(self.tail)
        offset = len(damaged) - FRAME
        self.assertEqual(struct.unpack_from(">I", damaged, offset + 4)[0], 0)
        struct.pack_into(">I", damaged, offset + 4, 2)
        report = self.invalid(damaged, "wal_frame_checksum_unsupported_or_invalid")
        self.assertEqual(report["frame_index"], (len(damaged) - 32) // FRAME)

    def test_partial_committed_transaction_is_not_complete(self):
        report = self.invalid(self.committed[:-100], "wal_frame_truncated")
        self.assertEqual(report["trailing_bytes"], FRAME - 100)

    def test_known_whole_transaction_removal_needs_inventory(self):
        self.write(self.one)
        report = guard.validate_wal(self.path)
        self.assertEqual(report["status"], "valid")
        self.assertFalse(report["acquisition_completeness_proven"])
        self.invalid(self.one, "wal_inventory_size_mismatch", expected_size=len(self.committed))
        self.invalid(self.one, "wal_inventory_hash_mismatch",
                     expected_sha256=hashlib.sha256(self.committed).hexdigest())

    def test_salt_mismatch_not_skipped(self):
        damaged = bytearray(self.committed); damaged[32 + 8] ^= 1
        report = self.invalid(damaged, "wal_generation_mismatch")
        self.assertEqual(report["frame_index"], 1)

    def test_page_size_version_and_magic_must_match_supported_format(self):
        self.invalid(self.committed, "wal_page_size_mismatch", expected_page_size=4096)
        damaged = bytearray(self.committed); struct.pack_into(">I", damaged, 4, 123)
        self.invalid(damaged, "wal_version_unsupported")
        damaged = bytearray(self.committed); struct.pack_into(">I", damaged, 8, 0)
        self.invalid(damaged, "wal_page_size_unsupported")
        damaged = bytearray(self.committed); damaged[0] ^= 1
        self.invalid(damaged, "wal_magic_unsupported")

    def test_different_or_corrupt_payload_domain_cannot_fall_back(self):
        damaged = bytearray(self.committed); damaged[32 + 24 + 100] ^= 1
        report = self.invalid(damaged, "wal_frame_checksum_unsupported_or_invalid")
        self.assertEqual(report["valid_frames"], 0)
        self.assertEqual(report["checksum_domain"], "not_observed")

    def test_empty_and_header_only_have_no_observed_payload_domain(self):
        for data, status in [(b"", "valid_empty"), (self.committed[:32], "valid")]:
            with self.subTest(bytes=len(data)):
                self.write(data); report = guard.validate_wal(self.path)
                self.assertEqual(report["status"], status)
                self.assertEqual(report["checksum_domain"], "not_observed")
                self.assertEqual(report["valid_frames"], 0)
                self.assertEqual(report["sha256"], hashlib.sha256(data).hexdigest())

    def test_partial_header_rejected(self):
        self.invalid(self.committed[:12], "wal_header_truncated")

    def test_change_during_validation_fails_and_cancellation_propagates(self):
        self.write(self.committed)
        def mutate():
            self.path.write_bytes(self.committed + b"x")
        with self.assertRaises(guard.WalValidationError) as result:
            guard.validate_wal(self.path, check=mutate)
        self.assertEqual(result.exception.code, "wal_changed_during_validation")
        class Cancelled(Exception): pass
        def cancel(): raise Cancelled()
        self.write(self.committed)
        with self.assertRaises(Cancelled):
            guard.validate_wal(self.path, check=cancel)

    def test_windows_stat_time_difference_and_real_changes(self):
        self.write(self.committed)
        actual = self.path.lstat()
        fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
        base = {field: getattr(actual, field) for field in fields}
        base.update(st_ctime_ns=100, st_birthtime_ns=100)
        cases = [("nt", None, None), ("posix", None, None),
                 ("nt", "ended", "st_ctime_ns"), ("nt", "after", "st_ctime_ns"),
                 ("nt", "after", "st_ino")]
        cases.extend(("nt", "opened", field) for field in
                     ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns"))
        for platform, changed_stage, changed_field in cases:
            with self.subTest(platform=platform, stage=changed_stage, field=changed_field):
                states = {stage: SimpleNamespace(**base) for stage in
                          ("before", "opened", "ended", "after")}
                states["opened"].st_ctime_ns = states["ended"].st_ctime_ns = 200
                if changed_stage:
                    value = getattr(states[changed_stage], changed_field)
                    setattr(states[changed_stage], changed_field, value + 1)
                fake_os = SimpleNamespace(name=platform, fstat=mock.Mock(
                    side_effect=[states["opened"], states["ended"]]))
                with mock.patch.object(guard, "os", fake_os), mock.patch.object(
                        Path, "lstat", side_effect=[states["before"], states["after"]]):
                    if platform == "nt" and changed_stage is None:
                        self.assertEqual(guard.validate_wal(self.path)["status"], "valid")
                    else:
                        with self.assertRaises(guard.WalValidationError) as result:
                            guard.validate_wal(self.path)
                        self.assertEqual(result.exception.code, "wal_changed_during_validation")

    def test_missing_and_directory_fail_safely(self):
        with self.assertRaises(guard.WalValidationError) as result:
            guard.validate_wal(self.path)
        self.assertEqual(result.exception.code, "wal_file_missing")
        with self.assertRaises(guard.WalValidationError) as result:
            guard.validate_wal(self.root)
        self.assertEqual(result.exception.code, "wal_file_not_regular")

    def test_link_fails_safely(self):
        try:
            self.path.symlink_to(self.root / "missing")
        except OSError as error:
            if getattr(error, "winerror", None) != 1314:
                raise
            self.skipTest("Windows symlink privilege unavailable (WinError 1314)")
        with self.assertRaises(guard.WalValidationError) as result:
            guard.validate_wal(self.path)
        self.assertEqual(result.exception.code, "wal_file_not_regular")


if __name__ == "__main__":
    unittest.main()
