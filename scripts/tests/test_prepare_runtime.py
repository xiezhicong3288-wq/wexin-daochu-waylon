import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

MODULE = Path(__file__).resolve().parents[1] / "prepare_runtime.py"
spec = importlib.util.spec_from_file_location("prepare_runtime", MODULE)
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.content = b"# synthetic source\nVALUE=1\n"
        self.lock = {"schema_version": 1, "repository": "https://github.com/mofan6/Moect",
                     "commit": setup.COMMIT,
                     "files": {"core/example.py": hashlib.sha256(self.content).hexdigest()}}

    def tearDown(self):
        self.tmp.cleanup()

    def archive(self, members=None):
        path = self.root / "source.zip"
        with zipfile.ZipFile(path, "w") as z:
            for name, content in (members or [(setup.SOURCE_PREFIX + "core/example.py", self.content)]):
                info = zipfile.ZipInfo(name)
                # Preserve deliberately unsafe names instead of Windows normalizing them.
                info.filename = name
                z.writestr(info, content)
        return path

    def test_verified_subset_and_original_unchanged(self):
        archive = self.archive([(setup.SOURCE_PREFIX + "core/example.py", self.content),
                                (setup.SOURCE_PREFIX + "unselected.py", b"raise RuntimeError()")])
        before = archive.read_bytes()
        output = self.root / "verified"
        result = setup.extract_verified(archive, output, self.lock)
        self.assertEqual(result["verified_file_count"], 1)
        self.assertEqual((output / "core/example.py").read_bytes(), self.content)
        self.assertFalse((output / "unselected.py").exists())
        self.assertEqual(archive.read_bytes(), before)

    def test_wrong_hash_writes_no_source(self):
        archive = self.archive([(setup.SOURCE_PREFIX + "core/example.py", b"changed")])
        output = self.root / "verified"
        with self.assertRaisesRegex(setup.SetupError, "hash_mismatch"):
            setup.extract_verified(archive, output, self.lock)
        self.assertFalse(output.exists())

    def test_traversal_and_absolute_paths(self):
        for name in ["../escape", "/absolute", setup.SOURCE_PREFIX + "../escape",
                     setup.SOURCE_PREFIX + "C:/evil", setup.SOURCE_PREFIX + "a\\b"]:
            with self.subTest(name=name):
                archive = self.archive([(name, b"x")])
                with zipfile.ZipFile(archive) as z:
                    self.assertEqual(z.infolist()[0].orig_filename, name)
                with self.assertRaisesRegex(setup.SetupError, "path_refused"):
                    setup.extract_verified(archive, self.root / "verified", self.lock)

    def test_windows_zip_name_normalization_does_not_hide_unsafe_original(self):
        name = setup.SOURCE_PREFIX + "core\\example.py"
        archive = self.archive([(name, self.content)])
        with patch.object(zipfile.os, "sep", "\\"):
            with zipfile.ZipFile(archive) as z:
                self.assertEqual(z.infolist()[0].orig_filename, name)
                self.assertEqual(z.infolist()[0].filename, setup.SOURCE_PREFIX + "core/example.py")
            with self.assertRaisesRegex(setup.SetupError, "path_refused"):
                setup.extract_verified(archive, self.root / "verified", self.lock)
        self.assertFalse((self.root / "verified").exists())

    def test_case_collision(self):
        archive = self.archive([(setup.SOURCE_PREFIX + "core/example.py", self.content),
                                (setup.SOURCE_PREFIX + "CORE/EXAMPLE.py", self.content)])
        with self.assertRaisesRegex(setup.SetupError, "duplicate_path"):
            setup.extract_verified(archive, self.root / "verified", self.lock)

    def test_symlink_zip_entry(self):
        archive = self.root / "linked.zip"
        with zipfile.ZipFile(archive, "w") as z:
            info = zipfile.ZipInfo(setup.SOURCE_PREFIX + "core/example.py")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, "../../outside")
        with self.assertRaisesRegex(setup.SetupError, "link_refused"):
            setup.extract_verified(archive, self.root / "verified", self.lock)

    def test_missing_file(self):
        archive = self.archive([(setup.SOURCE_PREFIX + "other", b"x")])
        with self.assertRaisesRegex(setup.SetupError, "missing_files"):
            setup.extract_verified(archive, self.root / "verified", self.lock)

    def test_existing_output_is_not_replaced(self):
        output = self.root / "existing"
        output.mkdir()
        marker = output / "keep.txt"
        marker.write_text("keep")
        with patch.object(setup, "read_lock", return_value=self.lock):
            with self.assertRaisesRegex(setup.SetupError, "already_exists"):
                setup.prepare(output, self.archive())
        self.assertEqual(marker.read_text(), "keep")

    def test_setup_does_not_run_program_or_install_dependencies(self):
        output = self.root / "runtime"
        with patch.object(setup, "read_lock", return_value=self.lock), \
                patch.object(setup.subprocess, "run") as run, \
                patch.object(setup, "download_source") as download:
            result = setup.prepare(output, self.archive())
        run.assert_not_called()
        download.assert_not_called()
        self.assertFalse(result["chat_data_accessed"])
        self.assertFalse(result["runtime_executed"])
        self.assertEqual(result["windows_acceptance"], "not_tested")
        self.assertEqual(json.loads((output / "setup-status.json").read_text())["status"], "prepared")

    def test_linked_output_parent_rejected(self):
        link = self.root / "link"
        try:
            link.symlink_to(self.root, target_is_directory=True)
        except OSError:
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(setup.SetupError, "linked_path"):
            setup.checked_path(link / "new")

    def test_failed_setup_keeps_checkpoint(self):
        archive = self.archive([(setup.SOURCE_PREFIX + "core/example.py", b"bad")])
        output = self.root / "failed"
        with patch.object(setup, "read_lock", return_value=self.lock):
            with self.assertRaises(setup.SetupError):
                setup.prepare(output, archive)
        status = json.loads((output / "setup-status.json").read_text())
        self.assertEqual(status["status"], "failed")
        self.assertFalse((output / "source").exists())


if __name__ == "__main__":
    unittest.main()
