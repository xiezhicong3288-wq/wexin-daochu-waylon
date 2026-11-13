#!/usr/bin/env python3
"""Prepare a pinned Moect source subset; never launch WeChat or read chats.

Network access and dependency installation are explicit setup operations.
The export bridge is a separate process with its own offline restrictions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

COMMIT = "88dffc7d0d06632f8061b0a19aa82b38337d7ee5"
SOURCE_URL = f"https://codeload.github.com/mofan6/Moect/zip/{COMMIT}"
SOURCE_PREFIX = f"Moect-{COMMIT}/"
SKILL_ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = SKILL_ROOT / "references" / "upstream-lock.json"
REQUIREMENTS = SKILL_ROOT / "references" / "requirements-runtime.txt"
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
MAX_ENTRIES = 5000
MAX_FILE = 16 * 1024 * 1024


class SetupError(Exception):
    """An error code safe to return without source data or credentials."""


def is_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        info = path.lstat()
        return bool(getattr(info, "st_file_attributes", 0) & 0x400)
    except FileNotFoundError:
        return False


def checked_path(value: str | Path) -> Path:
    path = Path(value).expanduser().absolute()
    for part in (path, *path.parents):
        if is_link(part):
            raise SetupError("linked_path_refused")
    return path.resolve()


def safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and not any(
        x in ("", ".", "..") or ":" in x or "\\" in x or "\x00" in x
        for x in name.rstrip("/").split("/")
    )


def read_lock(path: Path = LOCK_PATH) -> dict:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise SetupError("source_lock_unreadable") from None
    if (lock.get("schema_version") != 1 or lock.get("commit") != COMMIT
            or lock.get("repository") != "https://github.com/mofan6/Moect"
            or not isinstance(lock.get("files"), dict) or not lock["files"]):
        raise SetupError("source_lock_invalid")
    for name, digest in lock["files"].items():
        if not safe_member(name) or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise SetupError("source_lock_invalid")
    return lock


class SameHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if (target.scheme != "https" or target.hostname != "codeload.github.com"
                or target.username or target.password or target.port not in (None, 443)):
            raise SetupError("source_redirect_refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_source(path: Path) -> None:
    opener = urllib.request.build_opener(
        SameHostRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
    )
    request = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "moect-local-export-setup/0.1.0"})
    started = time.monotonic()
    try:
        with opener.open(request, timeout=20) as response, path.open("xb") as target:
            declared = response.headers.get("Content-Length")
            if declared and int(declared) > MAX_ARCHIVE:
                raise SetupError("source_archive_too_large")
            total = 0
            while True:
                if time.monotonic() - started > 120:
                    raise SetupError("source_download_timeout")
                block = response.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > MAX_ARCHIVE:
                    raise SetupError("source_archive_too_large")
                target.write(block)
    except SetupError:
        raise
    except (OSError, ValueError, urllib.error.URLError):
        raise SetupError("source_download_failed") from None


def extract_verified(archive: Path, destination: Path, lock: dict) -> dict:
    """Validate every selected byte before writing any executable source file."""
    if archive.stat().st_size > MAX_ARCHIVE:
        raise SetupError("source_archive_too_large")
    blobs = {}
    try:
        with zipfile.ZipFile(archive) as z:
            infos = z.infolist()
            if len(infos) > MAX_ENTRIES or sum(x.file_size for x in infos) > MAX_EXPANDED:
                raise SetupError("source_archive_limits")
            names = set()
            for info in infos:
                # On Windows ZipInfo normalizes backslashes in filename. Check
                # the original archive name before accepting that normalization.
                original_name = info.orig_filename
                if (not safe_member(original_name) or not original_name.startswith(SOURCE_PREFIX)
                        or original_name != info.filename
                        or not safe_member(info.filename) or not info.filename.startswith(SOURCE_PREFIX)):
                    raise SetupError("source_archive_path_refused")
                if stat.S_ISLNK(info.external_attr >> 16):
                    raise SetupError("source_archive_link_refused")
                folded = info.filename.casefold().rstrip("/")
                if folded in names:
                    raise SetupError("source_archive_duplicate_path")
                names.add(folded)
                relative = info.filename[len(SOURCE_PREFIX):]
                if relative not in lock["files"]:
                    continue
                if info.is_dir() or info.file_size > MAX_FILE:
                    raise SetupError("source_file_invalid")
                blob = z.read(info)
                if hashlib.sha256(blob).hexdigest() != lock["files"][relative]:
                    raise SetupError("source_file_hash_mismatch")
                blobs[relative] = blob
    except (zipfile.BadZipFile, RuntimeError, OSError):
        raise SetupError("source_archive_invalid") from None
    if set(blobs) != set(lock["files"]):
        raise SetupError("source_archive_missing_files")
    destination.mkdir(exist_ok=False)
    for name, blob in blobs.items():
        output = destination / name
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("xb") as f:
            f.write(blob)
    return {"verified_file_count": len(blobs), "source_commit": COMMIT}


def prepare(destination, archive=None, download=False, install_deps=False) -> dict:
    if sys.version_info < (3, 11):
        raise SetupError("python_3_11_or_later_required")
    if bool(archive) == bool(download):
        raise SetupError("choose_exactly_one_source_route")
    target = checked_path(destination)
    if target.exists():
        raise SetupError("destination_already_exists")
    if target == SKILL_ROOT or target.is_relative_to(SKILL_ROOT) or SKILL_ROOT.is_relative_to(target):
        raise SetupError("runtime_must_be_outside_skill")
    lock = read_lock()
    original = checked_path(archive) if archive else None
    if original and (not original.is_file() or original.is_relative_to(target)):
        raise SetupError("source_archive_invalid")
    if not target.parent.is_dir():
        raise SetupError("destination_parent_missing")
    target.mkdir(mode=0o700, exist_ok=False)
    status = {"schema_version": 1, "status": "preparing", "source_commit": COMMIT,
              "source_url": SOURCE_URL, "chat_data_accessed": False,
              "source_route": "download" if download else "provided_archive",
              "runtime_executed": False, "windows_acceptance": "not_tested"}
    status_path = target / "setup-status.json"
    def save():
        status_path.write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
    save()
    try:
        zip_path = original
        if download:
            zip_path = target / f"Moect-{COMMIT}.zip"
            download_source(zip_path)
        if zip_path.stat().st_size > MAX_ARCHIVE:
            raise SetupError("source_archive_too_large")
        status["archive_sha256"] = hashlib.sha256(zip_path.read_bytes()).hexdigest()
        status.update(extract_verified(zip_path, target / "source", lock))
        status["dependency_installation"] = "not_requested"
        if install_deps:
            venv = target / "venv"
            log_path = target / "dependency-install.log"
            with log_path.open("xb") as log:
                subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True,
                               stdout=log, stderr=subprocess.STDOUT, timeout=120)
                py = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
                subprocess.run([str(py), "-m", "pip", "install", "--disable-pip-version-check",
                                "--no-input", "--no-deps", "--only-binary=:all:",
                                "--index-url", "https://pypi.org/simple", "-r", str(REQUIREMENTS)],
                               check=True, stdout=log, stderr=subprocess.STDOUT, timeout=300)
            status["dependency_installation"] = "completed"
            status["python"] = str(py)
        status["status"] = "prepared"
        save()
        return status
    except (SetupError, OSError, subprocess.SubprocessError) as exc:
        status["status"] = "failed"
        status["error_code"] = str(exc) if isinstance(exc, SetupError) else "setup_operation_failed"
        save()
        raise SetupError(status["error_code"]) from None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--destination", required=True)
    route = p.add_mutually_exclusive_group(required=True)
    route.add_argument("--archive")
    route.add_argument("--download", action="store_true")
    p.add_argument("--install-deps", action="store_true")
    args = p.parse_args()
    try:
        result = prepare(args.destination, args.archive, args.download, args.install_deps)
        print(json.dumps({k: v for k, v in result.items() if k != "python"}, ensure_ascii=False))
        return 0
    except SetupError as exc:
        print(json.dumps({"status": "failed", "error_code": str(exc)}))
        return 2
    except Exception:
        print(json.dumps({"status": "failed", "error_code": "unexpected_setup_failure"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
