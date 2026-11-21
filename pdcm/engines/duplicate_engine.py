from __future__ import annotations

from collections import defaultdict
from contextlib import ExitStack, contextmanager
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import ntpath
from pathlib import Path
import hashlib
import logging
import os
import stat
import sys
from threading import Event

from ..services.path_policy import is_link_or_junction, is_protected_path, validate_user_scan_root
from ..services.quarantine_store import (
    STORE_NAME,
    is_within_quarantine_store,
    reserved_quarantine_store,
)
from ..services.scan_control import raise_if_cancelled

CHUNK_SIZE = 1024 * 1024
SAMPLE_SIZE = 64 * 1024
_logger = logging.getLogger(__name__)

_FILE_READ_ATTRIBUTES = 0x0080
_FILE_LIST_DIRECTORY = 0x0001
_FILE_SHARE_READ = 0x0001
_FILE_SHARE_WRITE = 0x0002
_OPEN_EXISTING = 3
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_ATTRIBUTE_DIRECTORY = 0x0010
_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = [
        ("file_attributes", wintypes.DWORD),
        ("reparse_tag", wintypes.DWORD),
    ]


if os.name == "nt":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _create_file = _kernel32.CreateFileW
    _create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    _create_file.restype = wintypes.HANDLE
    _get_file_info = _kernel32.GetFileInformationByHandleEx
    _get_file_info.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    _get_file_info.restype = wintypes.BOOL
    _get_final_path = _kernel32.GetFinalPathNameByHandleW
    _get_final_path.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    _get_final_path.restype = wintypes.DWORD
    _close_handle = _kernel32.CloseHandle
    _close_handle.argtypes = (wintypes.HANDLE,)
    _close_handle.restype = wintypes.BOOL


@dataclass(frozen=True)
class DuplicateItem:
    path: str
    size: int
    sha256: str
    file_id: tuple[int, int] | None = None
    file_signature: tuple[int, int, int, int, int] | None = None


@dataclass(frozen=True)
class _FileCandidate:
    path: Path
    signature: tuple[int, int, int, int, int]


def _file_signature(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


@contextmanager
def _windows_open_handle(
    path: Path,
    access: int,
    share_mode: int,
    *,
    directory: bool,
    root_final_path: str | None = None,
):
    flags = _FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= _FILE_FLAG_BACKUP_SEMANTICS
    handle = _create_file(
        str(path),
        access,
        share_mode,
        None,
        _OPEN_EXISTING,
        flags,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        attributes = _FileAttributeTagInfo()
        if not _get_file_info(handle, 9, ctypes.byref(attributes), ctypes.sizeof(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
        if attributes.file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError("Reparse points are not scanned.")
        is_directory = bool(attributes.file_attributes & _FILE_ATTRIBUTE_DIRECTORY)
        if is_directory != directory:
            raise OSError("Filesystem entry changed during scan.")
        final_path = _windows_final_path(handle)
        if root_final_path and not _windows_path_is_within(final_path, root_final_path):
            raise OSError("Filesystem entry is outside the selected root.")
        yield handle, final_path
    finally:
        _close_handle(handle)


def _normalize_windows_path(path: str) -> str:
    if path.startswith("\\\\?\\UNC\\"):
        path = "\\\\" + path[8:]
    elif path.startswith("\\\\?\\"):
        path = path[4:]
    return ntpath.normcase(ntpath.normpath(path))


def _windows_path_is_within(path: str, root: str) -> bool:
    normalized_path = _normalize_windows_path(path)
    normalized_root = _normalize_windows_path(root)
    try:
        return ntpath.commonpath((normalized_path, normalized_root)) == normalized_root
    except ValueError:
        return False


def _path_is_within(path: Path, root: Path) -> bool:
    if os.name == "nt":
        return _windows_path_is_within(str(path), str(root))
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _windows_final_path(handle) -> str:
    buffer = ctypes.create_unicode_buffer(32768)
    length = _get_final_path(handle, buffer, len(buffer), 0)
    if not length:
        raise ctypes.WinError(ctypes.get_last_error())
    if length >= len(buffer):
        buffer = ctypes.create_unicode_buffer(length + 1)
        length = _get_final_path(handle, buffer, len(buffer), 0)
        if not length or length >= len(buffer):
            raise ctypes.WinError(ctypes.get_last_error())
    return buffer.value


@contextmanager
def _windows_root_guard(root: Path):
    if os.name != "nt":
        yield None
        return

    with ExitStack() as handles:
        current = Path(root.anchor)
        root_final_path = None
        for component in root.parts[1:]:
            current /= component
            _, root_final_path = handles.enter_context(
                _windows_open_handle(
                    current,
                    _FILE_READ_ATTRIBUTES,
                    _FILE_SHARE_READ | _FILE_SHARE_WRITE,
                    directory=True,
                )
            )
        if root_final_path is None:
            _, root_final_path = handles.enter_context(
                _windows_open_handle(
                    current,
                    _FILE_READ_ATTRIBUTES,
                    _FILE_SHARE_READ | _FILE_SHARE_WRITE,
                    directory=True,
                )
            )
        yield root_final_path


@contextmanager
def _windows_open_directory(path: Path, root_final_path: str):
    with _windows_open_handle(
        path,
        _FILE_LIST_DIRECTORY | _FILE_READ_ATTRIBUTES,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        directory=True,
        root_final_path=root_final_path,
    ):
        yield


@contextmanager
def _windows_open_file(path: Path, root_final_path: str | None):
    handle = _create_file(
        str(path),
        0x80000000,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        attributes = _FileAttributeTagInfo()
        if not _get_file_info(handle, 9, ctypes.byref(attributes), ctypes.sizeof(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
        if attributes.file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError("Reparse points are not scanned.")
        if attributes.file_attributes & _FILE_ATTRIBUTE_DIRECTORY:
            raise OSError("Filesystem entry changed during scan.")
        final_path = _windows_final_path(handle)
        if root_final_path and not _windows_path_is_within(final_path, root_final_path):
            raise OSError("Filesystem entry is outside the selected root.")
        import msvcrt

        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        handle = None
        try:
            stream = os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise
        with stream:
            yield stream
    finally:
        if handle is not None:
            _close_handle(handle)


@contextmanager
def _open_verified(
    path: Path,
    expected_signature: tuple[int, int, int, int, int] | None = None,
    root_final_path: str | None = None,
):
    before = path.lstat()
    if is_link_or_junction(path) or not stat.S_ISREG(before.st_mode):
        raise OSError("Not a regular file.")
    if expected_signature is not None and _file_signature(before) != expected_signature:
        raise OSError("File was replaced during scan.")

    if os.name == "nt":
        with _windows_open_file(path, root_final_path) as stream:
            opened = os.fstat(stream.fileno())
            after = path.lstat()
            if (
                is_link_or_junction(path)
                or _file_identity(before) != _file_identity(opened)
                or _file_identity(opened) != _file_identity(after)
                or _file_signature(before) != _file_signature(after)
                or (expected_signature is not None and _file_signature(after) != expected_signature)
            ):
                raise OSError("File changed during scan.")
            yield stream
    else:
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
                or (expected_signature is not None and _file_signature(after) != expected_signature)
            ):
                raise OSError("File changed during scan.")
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                yield stream
        finally:
            if descriptor >= 0:
                os.close(descriptor)


def _quick_fingerprint(
    path: Path,
    size: int,
    expected_signature: tuple[int, int, int, int, int] | None = None,
    root_final_path: str | None = None,
    cancellation_event: Event | None = None,
) -> str:
    """Cheap candidate filter; complete SHA-256 remains the equality test."""
    raise_if_cancelled(cancellation_event)
    digest = hashlib.sha256()
    digest.update(str(size).encode("ascii"))
    with _open_verified(path, expected_signature, root_final_path) as stream:
        digest.update(stream.read(SAMPLE_SIZE))
        if size > SAMPLE_SIZE:
            stream.seek(max(0, size - SAMPLE_SIZE))
            digest.update(stream.read(SAMPLE_SIZE))
        raise_if_cancelled(cancellation_event)
        if os.fstat(stream.fileno()).st_size != size:
            raise OSError("File changed during scan.")
    return digest.hexdigest()


def _sha256_file(
    path: Path,
    expected_signature: tuple[int, int, int, int, int] | None = None,
    root_final_path: str | None = None,
    cancellation_event: Event | None = None,
) -> str:
    digest = hashlib.sha256()
    with _open_verified(path, expected_signature, root_final_path) as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            raise_if_cancelled(cancellation_event)
            digest.update(chunk)
    return digest.hexdigest()


def _close_windows_frame(frame) -> None:
    _, manager, entries = frame
    try:
        entries.close()
    finally:
        manager.__exit__(None, None, None)


def _open_windows_frame(path: Path, root_final_path: str):
    manager = _windows_open_directory(path, root_final_path)
    manager.__enter__()
    try:
        entries = os.scandir(path)
    except BaseException:
        manager.__exit__(*sys.exc_info())
        raise
    return path, manager, entries


def _collect_windows_candidates(
    root: Path,
    root_final_path: str,
    by_size: dict[int, list[_FileCandidate]],
    cancellation_event: Event | None = None,
    excluded_roots: tuple[Path, ...] = (),
) -> None:
    frames = [_open_windows_frame(root, root_final_path)]
    try:
        while frames:
            raise_if_cancelled(cancellation_event)
            current, _, entries = frames[-1]
            try:
                entry = next(entries)
            except StopIteration:
                _close_windows_frame(frames.pop())
                continue
            except OSError:
                _logger.warning("Skipped an inaccessible directory during duplicate scan.")
                _close_windows_frame(frames.pop())
                continue

            path = current / entry.name
            if path.name.casefold() == STORE_NAME.casefold():
                reserved_quarantine_store(path)
                continue
            if any(_path_is_within(path, excluded) for excluded in excluded_roots):
                continue
            try:
                info = entry.stat(follow_symlinks=False)
                attributes = getattr(info, "st_file_attributes", 0)
                if stat.S_ISLNK(info.st_mode) or attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
                    continue
                if stat.S_ISDIR(info.st_mode):
                    try:
                        frames.append(_open_windows_frame(path, root_final_path))
                    except OSError:
                        _logger.warning("Skipped an inaccessible directory during duplicate scan.")
                    continue
                if stat.S_ISREG(info.st_mode):
                    file_info = path.lstat()
                    file_attributes = getattr(file_info, "st_file_attributes", 0)
                    if (
                        stat.S_ISREG(file_info.st_mode)
                        and not file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT
                        and file_info.st_size > 0
                    ):
                        by_size[file_info.st_size].append(
                            _FileCandidate(path, _file_signature(file_info))
                        )
            except OSError:
                _logger.warning("Skipped an inaccessible file during duplicate scan.")
    finally:
        while frames:
            _close_windows_frame(frames.pop())


class DuplicateEngine:
    """Read-only exact duplicate scanner."""

    def scan(
        self,
        folder: str | Path,
        *,
        cancellation_event: Event | None = None,
        excluded_roots: tuple[Path, ...] = (),
    ) -> list[list[DuplicateItem]]:
        root = validate_user_scan_root(folder)
        if is_within_quarantine_store(root):
            raise ValueError("A quarantine store cannot be analyzed as a scan root.")
        if os.name == "nt":
            with _windows_root_guard(root) as root_final_path:
                if is_protected_path(
                    Path(_normalize_windows_path(root_final_path)),
                    resolve=False,
                ):
                    raise ValueError("Protected system location. Choose a personal data folder.")
                if any(_path_is_within(root, excluded) for excluded in excluded_roots):
                    return []
                return self._scan_root(root, root_final_path, cancellation_event, excluded_roots)
        if any(_path_is_within(root, excluded) for excluded in excluded_roots):
            return []
        return self._scan_root(root, None, cancellation_event, excluded_roots)

    def _scan_root(
        self,
        root: Path,
        root_final_path: str | None,
        cancellation_event: Event | None = None,
        excluded_roots: tuple[Path, ...] = (),
    ) -> list[list[DuplicateItem]]:
        by_size: dict[int, list[_FileCandidate]] = defaultdict(list)

        if os.name == "nt":
            _collect_windows_candidates(
                root,
                root_final_path or str(root),
                by_size,
                cancellation_event,
                excluded_roots,
            )
        else:
            for current, dirs, names in os.walk(
                root,
                followlinks=False,
                onerror=lambda _error: _logger.warning(
                    "Skipped an inaccessible directory during duplicate scan."
                ),
            ):
                raise_if_cancelled(cancellation_event)
                current_path = Path(current)
                if any(_path_is_within(current_path, excluded) for excluded in excluded_roots):
                    dirs[:] = []
                    continue
                dirs[:] = [
                    name
                    for name in dirs
                    if not is_link_or_junction(Path(current) / name)
                    and not (
                        (Path(current) / name).name.casefold() == STORE_NAME.casefold()
                        and reserved_quarantine_store(Path(current) / name)
                    )
                    and not any(
                        _path_is_within(Path(current) / name, excluded)
                        for excluded in excluded_roots
                    )
                ]
                for name in names:
                    raise_if_cancelled(cancellation_event)
                    path = Path(current) / name
                    try:
                        if path.name.casefold() == STORE_NAME.casefold():
                            reserved_quarantine_store(path)
                            continue
                        if any(_path_is_within(path, excluded) for excluded in excluded_roots):
                            continue
                        if is_link_or_junction(path):
                            continue
                        file_stat = path.lstat()
                        if not stat.S_ISREG(file_stat.st_mode):
                            continue
                        if file_stat.st_size > 0:
                            by_size[file_stat.st_size].append(
                                _FileCandidate(path, _file_signature(file_stat))
                            )
                    except OSError:
                        _logger.warning("Skipped an inaccessible file during duplicate scan.")

        by_sample: dict[str, list[tuple[int, _FileCandidate]]] = defaultdict(list)
        for size, paths in by_size.items():
            raise_if_cancelled(cancellation_event)
            if len(paths) < 2:
                continue
            for candidate in paths:
                raise_if_cancelled(cancellation_event)
                try:
                    path = candidate.path
                    before = path.lstat()
                    if before.st_size != size:
                        continue
                    fingerprint = _quick_fingerprint(
                        path,
                        size,
                        candidate.signature,
                        root_final_path,
                        cancellation_event,
                    )
                    after = path.lstat()
                    if _file_signature(before) != _file_signature(after):
                        continue
                    by_sample[fingerprint].append((size, candidate))
                except OSError:
                    _logger.warning("Skipped a file changed or inaccessible during duplicate scan.")

        by_hash: dict[tuple[int, str], list[DuplicateItem]] = defaultdict(list)
        for candidates in by_sample.values():
            raise_if_cancelled(cancellation_event)
            if len(candidates) < 2:
                continue
            for size, candidate in candidates:
                raise_if_cancelled(cancellation_event)
                try:
                    path = candidate.path
                    before = path.lstat()
                    if before.st_size != size:
                        continue
                    digest = _sha256_file(
                        path,
                        candidate.signature,
                        root_final_path,
                        cancellation_event,
                    )
                    after = path.lstat()
                    if _file_signature(before) != _file_signature(after):
                        continue
                    file_info = path.lstat()
                    if _file_signature(file_info) != candidate.signature:
                        continue
                    file_id = (file_info.st_dev, file_info.st_ino)
                    by_hash[(size, digest)].append(
                        DuplicateItem(str(path), size, digest, file_id, _file_signature(file_info))
                    )
                except OSError:
                    _logger.warning("Skipped a file changed or inaccessible during duplicate scan.")

        return [
            sorted(group, key=lambda item: (item.path.casefold(), item.path))
            for group in by_hash.values()
            if len(group) > 1
        ]
