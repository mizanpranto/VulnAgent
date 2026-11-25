"""Hardened extraction of an uploaded zip.

Threats handled: zip-slip (``../`` and absolute paths), symlink entries, zip
bombs (declared and actual size, compression ratio, file count), encrypted
archives, and junk files. Only source files VulnAgent can analyze are
written to disk; nothing is ever executed.
"""

from __future__ import annotations

import posixpath
import stat
import zipfile
from pathlib import Path

from .deps import is_manifest
from .scanner import A01_EXTRA_EXTENSIONS, EXTENSIONS, SKIP_DIRS
from .a01.patterns import SENSITIVE_FILE_NAMES


class UnsafeArchive(ValueError):
    """The archive is invalid or exceeds a safety limit (message is user-presentable)."""


def safe_extract(zip_path, dest, max_files: int = 3000, max_total_bytes: int = 120 * 1024 * 1024,
                 max_file_bytes: int = 5 * 1024 * 1024, max_ratio: int = 200) -> dict:
    zip_path, dest = Path(zip_path), Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    if not zipfile.is_zipfile(zip_path):
        raise UnsafeArchive("That file is not a valid zip archive.")
    stats = {"extracted": 0, "skipped_other": 0, "skipped_symlinks": 0, "skipped_unsafe": 0, "total_bytes": 0}
    try:
        archive = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as error:
        raise UnsafeArchive("The zip archive is corrupt.") from error
    with archive:
        infos = archive.infolist()
        if len(infos) > max_files * 5:
            raise UnsafeArchive(f"The archive has too many entries ({len(infos)}).")
        declared = sum(i.file_size for i in infos if not i.is_dir())
        if declared > max_total_bytes * 20:
            raise UnsafeArchive("The archive expands to an unreasonable size.")
        for info in infos:
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                raise UnsafeArchive("Password-protected archives are not supported.")
            mode = info.external_attr >> 16
            if mode and stat.S_ISLNK(mode):
                stats["skipped_symlinks"] += 1
                continue
            name = info.filename.replace("\\", "/")
            parts = [p for p in posixpath.normpath(name).split("/") if p not in ("", ".")]
            if name.startswith("/") or (len(name) > 1 and name[1] == ":") or ".." in parts or not parts:
                stats["skipped_unsafe"] += 1
                continue
            listing_only = False
            if len(parts) >= 2 and parts[-2] == ".git" and parts[-1] == "HEAD" and not any(
                    p in SKIP_DIRS and p != ".git" or p.startswith("__MACOSX") for p in parts[:-2]):
                listing_only = True        # marker so the report can see a served .git directory (content not kept)
            elif any(p in SKIP_DIRS or p.startswith("__MACOSX") for p in parts[:-1]):
                stats["skipped_other"] += 1
                continue
            suffix = Path(parts[-1]).suffix.lower()
            if not listing_only and suffix not in EXTENSIONS | A01_EXTRA_EXTENSIONS and not is_manifest(parts[-1]):
                if SENSITIVE_FILE_NAMES.search(parts[-1]) and not parts[-1].startswith("._"):
                    listing_only = True    # keep only an EMPTY placeholder: the name is evidence, the content is never stored
                else:
                    stats["skipped_other"] += 1
                    continue
            if parts[-1].startswith("._"):
                stats["skipped_other"] += 1
                continue
            if listing_only:
                target = (root / Path(*parts)).resolve()
                if root in target.parents:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(b"")
                    stats["listing_only"] = stats.get("listing_only", 0) + 1
                continue
            if info.file_size > max_file_bytes:
                stats["skipped_other"] += 1
                continue
            if info.compress_size and info.file_size > 1_000_000 and info.file_size / info.compress_size > max_ratio:
                raise UnsafeArchive("The archive looks like a zip bomb (extreme compression ratio).")
            if stats["extracted"] >= max_files:
                raise UnsafeArchive(f"Too many source files (limit {max_files}).")
            target = (root / Path(*parts)).resolve()
            if root not in target.parents:
                stats["skipped_unsafe"] += 1
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with archive.open(info) as source, open(target, "wb") as out:
                while True:
                    chunk = source.read(64 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > max_file_bytes:
                        raise UnsafeArchive("A file in the archive is larger than its header claims.")
                    stats["total_bytes"] += len(chunk)
                    if stats["total_bytes"] > max_total_bytes:
                        raise UnsafeArchive("The extracted source exceeds the size limit.")
                    out.write(chunk)
            stats["extracted"] += 1
    if stats["extracted"] == 0:
        raise UnsafeArchive("No Python, JavaScript or TypeScript source files were found in the archive.")
    return stats
