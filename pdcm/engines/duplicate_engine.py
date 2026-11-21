from __future__ import annotations

from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import hashlib
import logging
import os
import stat

from ..services.path_policy import is_link_or_junction, validate_user_scan_root

CHUNK_SIZE = 1024 * 1024
SAMPLE_SIZE = 64 * 1024
_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DuplicateItem:
    path: str
    size: int
    sha256: str


def _file_signature(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


@contextmanager
def _open_verified(path: Path):
    before = path.lstat()
    if is_link_or_junction(path) or not stat.S_ISREG(before.st_mode):
        raise OSError("Not a regular file.")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        after = path.lstat()
        if (
            is_link_or_junction(path)
            or _file_identity(before) != _file_identity(opened)
            or _file_identity(opened) != _file_identity(after)
            or _file_signature(before) != _file_signature(after)
        ):
            raise OSError("File changed during scan.")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            yield stream
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _quick_fingerprint(path: Path, size: int) -> str:
    """Cheap candidate filter; complete SHA-256 remains the equality test."""
    digest = hashlib.sha256()
    digest.update(str(size).encode("ascii"))
    with _open_verified(path) as stream:
        digest.update(stream.read(SAMPLE_SIZE))
        if size > SAMPLE_SIZE:
            stream.seek(max(0, size - SAMPLE_SIZE))
            digest.update(stream.read(SAMPLE_SIZE))
        if os.fstat(stream.fileno()).st_size != size:
            raise OSError("File changed during scan.")
    return digest.hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with _open_verified(path) as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


class DuplicateEngine:
    """Read-only exact duplicate scanner."""

    def scan(self, folder: str | Path) -> list[list[DuplicateItem]]:
        root = validate_user_scan_root(folder)
        by_size: dict[int, list[Path]] = defaultdict(list)

        for current, dirs, names in os.walk(
            root,
            followlinks=False,
            onerror=lambda _error: _logger.warning(
                "Skipped an inaccessible directory during duplicate scan."
            ),
        ):
            dirs[:] = [
                name for name in dirs
                if not is_link_or_junction(Path(current) / name)
            ]
            for name in names:
                path = Path(current) / name
                try:
                    if is_link_or_junction(path):
                        continue
                    file_stat = path.lstat()
                    if not stat.S_ISREG(file_stat.st_mode):
                        continue
                    if file_stat.st_size > 0:
                        by_size[file_stat.st_size].append(path)
                except OSError:
                    _logger.warning("Skipped an inaccessible file during duplicate scan.")

        by_sample: dict[str, list[tuple[int, Path]]] = defaultdict(list)
        for size, paths in by_size.items():
            if len(paths) < 2:
                continue
            for path in paths:
                try:
                    before = path.lstat()
                    if before.st_size != size:
                        continue
                    fingerprint = _quick_fingerprint(path, size)
                    after = path.lstat()
                    if _file_signature(before) != _file_signature(after):
                        continue
                    by_sample[fingerprint].append((size, path))
                except OSError:
                    _logger.warning("Skipped a file changed or inaccessible during duplicate scan.")

        by_hash: dict[tuple[int, str], list[DuplicateItem]] = defaultdict(list)
        for candidates in by_sample.values():
            if len(candidates) < 2:
                continue
            for size, path in candidates:
                try:
                    before = path.lstat()
                    if before.st_size != size:
                        continue
                    digest = _sha256_file(path)
                    after = path.lstat()
                    if _file_signature(before) != _file_signature(after):
                        continue
                    by_hash[(size, digest)].append(DuplicateItem(str(path), size, digest))
                except OSError:
                    _logger.warning("Skipped a file changed or inaccessible during duplicate scan.")

        return [
            sorted(group, key=lambda item: (item.path.casefold(), item.path))
            for group in by_hash.values()
            if len(group) > 1
        ]
