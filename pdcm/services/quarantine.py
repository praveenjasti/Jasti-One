from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from threading import Event, Lock
from typing import Iterable

from .. import __version__
from ..engines.duplicate_engine import (
    _FILE_ATTRIBUTE_DIRECTORY,
    _FILE_ATTRIBUTE_REPARSE_POINT,
    _FILE_FLAG_OPEN_REPARSE_POINT,
    _FILE_READ_ATTRIBUTES,
    _FILE_SHARE_READ,
    _FILE_SHARE_WRITE,
    _INVALID_HANDLE_VALUE,
    _OPEN_EXISTING,
    _FileAttributeTagInfo,
    _file_signature,
    _normalize_windows_path,
    _sha256_file,
    _windows_final_path,
    _windows_open_handle,
    _windows_path_is_within,
    _windows_root_guard,
)
from .path_policy import validate_user_scan_root
from .quarantine_store import (
    MARKER_NAME,
    STORE_NAME,
    STORE_VERSION,
    QuarantineStoreError,
    is_within_quarantine_store,
    strict_object_pairs,
    validate_quarantine_store,
    valid_store_id,
)
from .scan_control import raise_if_cancelled

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_DELETE = 0x00010000
_FILE_ADD_FILE = 0x0002
_FILE_LIST_DIRECTORY = 0x0001
_OPEN_ALWAYS = 4
_ERROR_SHARING_VIOLATION = 32
_CHUNK_SIZE = 1024 * 1024
_MAX_MANIFEST_SIZE = 64 * 1024
_OPERATION_LOCK_NAME = ".operations.lock"
_PROCESS_OPERATION_LOCK = Lock()
_FILE_MOVES_ENABLED = False
_HASH_PATTERN = re.compile(r"[0-9a-f]{64}")
_MANIFEST_FIELDS = {
    "schema_version",
    "application_version",
    "store_id",
    "operation_id",
    "original_root",
    "original_path",
    "object_id",
    "size",
    "sha256",
    "modified_ns",
    "file_identity",
    "created_at",
    "status",
}
_STATUSES = {
    "PREPARED",
    "MOVING",
    "QUARANTINED",
    "RESTORING",
    "RESTORED",
    "FAILED",
    "RECOVERY_REQUIRED",
}

if os.name == "nt":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _create_file = _kernel32.CreateFileW
    _create_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    _create_file.restype = ctypes.c_void_p
    _set_file_info = _kernel32.SetFileInformationByHandle
    _set_file_info.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    )
    _set_file_info.restype = ctypes.c_int
    _read_file = _kernel32.ReadFile
    _read_file.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
    )
    _read_file.restype = ctypes.c_int
    _set_file_pointer = _kernel32.SetFilePointerEx
    _set_file_pointer.argtypes = (
        ctypes.c_void_p,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        ctypes.c_uint32,
    )
    _set_file_pointer.restype = ctypes.c_int
    _close_handle = _kernel32.CloseHandle
    _close_handle.argtypes = (ctypes.c_void_p,)
    _close_handle.restype = ctypes.c_int
    _get_file_info = _kernel32.GetFileInformationByHandleEx
    _get_file_info.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    )
    _get_file_info.restype = ctypes.c_int
    _get_handle_file_info = _kernel32.GetFileInformationByHandle
    _get_handle_file_info.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    _get_handle_file_info.restype = ctypes.c_int


class QuarantineError(ValueError):
    pass


class ManifestValidationError(QuarantineError):
    pass


class DuplicateKeeperError(QuarantineError):
    pass


class BatchQuarantineError(QuarantineError):
    def __init__(self, completed: list[str], message: str):
        super().__init__(message)
        self.completed = completed


@dataclass(frozen=True)
class QuarantineCandidate:
    root: str
    path: str
    size: int
    modified_ns: int
    file_signature: tuple[int, int, int, int, int] | None
    sha256: str | None
    category: str
    reason: str
    consequence: str


@dataclass(frozen=True)
class QuarantineOperation:
    operation_id: str
    original_path: str
    size: int
    sha256: str
    status: str
    created_at: str


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", ctypes.c_uint32),
        ("creation_low", ctypes.c_uint32),
        ("creation_high", ctypes.c_uint32),
        ("access_low", ctypes.c_uint32),
        ("access_high", ctypes.c_uint32),
        ("write_low", ctypes.c_uint32),
        ("write_high", ctypes.c_uint32),
        ("volume_serial", ctypes.c_uint32),
        ("size_high", ctypes.c_uint32),
        ("size_low", ctypes.c_uint32),
        ("links", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    ]


class _FileRenameInfo(ctypes.Structure):
    _fields_ = [
        ("replace_if_exists", ctypes.c_ubyte),
        ("root_directory", ctypes.c_void_p),
        ("file_name_length", ctypes.c_uint32),
        ("file_name", ctypes.c_wchar * 1),
    ]


def _is_within(path: Path, root: Path) -> bool:
    path = Path(os.path.abspath(path))
    root = Path(os.path.abspath(root))
    if os.name == "nt":
        return _windows_path_is_within(str(path), str(root))
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _same_path(left: Path, right: Path) -> bool:
    if os.name == "nt":
        return _normalize_windows_path(str(left)) == _normalize_windows_path(str(right))
    return left.resolve(strict=False) == right.resolve(strict=False)


def _contains_quarantine_component(path: Path) -> bool:
    return any(part.casefold() == STORE_NAME.casefold() for part in path.parts[1:])


def _has_unsafe_path_component(path: Path) -> bool:
    if ".." in path.parts:
        return True
    if os.name == "nt":
        return any(
            ":" in part or part.endswith((".", " "))
            for part in path.parts[1:]
        )
    return False


def _lstat_regular_file(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as error:
        raise QuarantineError("The selected file is no longer available.") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    ):
        raise QuarantineError("Only unchanged regular files can be quarantined or restored.")
    return info


def _file_id(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _validate_manifest(value: object, folder_id: str, expected_store_id: str) -> dict:
    if type(value) is not dict or set(value) != _MANIFEST_FIELDS:
        raise ManifestValidationError("Quarantine manifest fields do not match the supported schema.")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or type(value["application_version"]) is not str
        or not value["application_version"]
        or value["store_id"] != expected_store_id
        or not valid_store_id(value["store_id"])
        or value["operation_id"] != folder_id
        or not valid_store_id(value["operation_id"])
        or value["object_id"] != folder_id
        or not valid_store_id(value["object_id"])
        or type(value["original_root"]) is not str
        or not value["original_root"]
        or type(value["original_path"]) is not str
        or not value["original_path"]
        or type(value["size"]) is not int
        or value["size"] < 0
        or type(value["modified_ns"]) is not int
        or type(value["sha256"]) is not str
        or not _HASH_PATTERN.fullmatch(value["sha256"])
        or type(value["file_identity"]) is not dict
        or set(value["file_identity"]) != {"device", "file_id"}
        or any(type(value["file_identity"][key]) is not int for key in ("device", "file_id"))
        or type(value["created_at"]) is not str
        or type(value["status"]) is not str
        or value["status"] not in _STATUSES
    ):
        raise ManifestValidationError("Quarantine manifest contains invalid or unsupported values.")
    try:
        datetime.fromisoformat(value["created_at"])
        original_root = Path(value["original_root"])
        original_path = Path(value["original_path"])
        if (
            not original_root.is_absolute()
            or not original_path.is_absolute()
            or _has_unsafe_path_component(original_root)
            or _has_unsafe_path_component(original_path)
        ):
            raise ValueError
    except (ValueError, OSError) as error:
        raise ManifestValidationError("Quarantine manifest paths or timestamp are invalid.") from error
    return value


def _handle_file_identity(handle) -> tuple[int, int, int, int]:
    information = _ByHandleFileInformation()
    if not _get_handle_file_info(
        handle,
        ctypes.byref(information),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    size = (information.size_high << 32) | information.size_low
    file_id = (information.file_index_high << 32) | information.file_index_low
    write_time = (information.write_high << 32) | information.write_low
    modified_ns = (write_time - 116444736000000000) * 100
    return information.volume_serial, file_id, size, modified_ns


def _open_move_file(path: Path, root_final_path: str):
    handle = _create_file(
        str(path),
        _GENERIC_READ | _DELETE | _FILE_READ_ATTRIBUTES,
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
        if (
            attributes.file_attributes & (_FILE_ATTRIBUTE_REPARSE_POINT | _FILE_ATTRIBUTE_DIRECTORY)
            or not _windows_path_is_within(_windows_final_path(handle), root_final_path)
        ):
            raise QuarantineError("The selected file is a reparse point or outside the approved scan root.")
        final_path = _windows_final_path(handle)
        if not _same_path(Path(final_path), path):
            raise QuarantineError("The selected path now identifies a different filesystem entry.")
        yield_handle = handle
        handle = None
        return _HandleOwner(yield_handle, final_path)
    finally:
        if handle is not None:
            _close_handle(handle)


class _HandleOwner:
    def __init__(self, handle, final_path: str):
        self.handle = handle
        self.final_path = final_path

    def close(self) -> None:
        if self.handle is not None:
            _close_handle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def _hash_handle(handle, cancellation_event: Event | None = None) -> str:
    new_position = ctypes.c_longlong()
    if not _set_file_pointer(handle, 0, ctypes.byref(new_position), 0):
        raise ctypes.WinError(ctypes.get_last_error())
    digest = hashlib.sha256()
    buffer = ctypes.create_string_buffer(_CHUNK_SIZE)
    count = ctypes.c_uint32()
    while True:
        raise_if_cancelled(cancellation_event)
        count.value = 0
        if not _read_file(handle, buffer, _CHUNK_SIZE, ctypes.byref(count), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if count.value == 0:
            break
        digest.update(buffer.raw[: count.value])
    return digest.hexdigest()


def _rename_handle(handle, destination: Path) -> None:
    if not destination.is_absolute():
        raise QuarantineError("The quarantine destination path is not absolute.")
    encoded_name = str(destination).encode("utf-16le")
    storage_size = ctypes.sizeof(_FileRenameInfo) + len(encoded_name) - ctypes.sizeof(ctypes.c_wchar)
    storage = ctypes.create_string_buffer(storage_size)
    information = ctypes.cast(storage, ctypes.POINTER(_FileRenameInfo)).contents
    information.replace_if_exists = 0
    information.root_directory = None
    information.file_name_length = len(encoded_name)
    ctypes.memmove(
        ctypes.addressof(information) + _FileRenameInfo.file_name.offset,
        encoded_name,
        len(encoded_name),
    )
    if not _set_file_info(handle, 3, storage, len(storage)):
        raise ctypes.WinError(ctypes.get_last_error())


@contextmanager
def _open_destination_directory(path: Path, root_final_path: str):
    access = _FILE_LIST_DIRECTORY | _FILE_ADD_FILE | _FILE_READ_ATTRIBUTES
    with _windows_open_handle(
        path,
        access,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        directory=True,
        root_final_path=root_final_path,
    ) as (handle, final_path):
        if not _same_path(Path(final_path), path):
            raise QuarantineError("A quarantine directory no longer matches its validated path.")
        yield handle, final_path


def _read_handle(handle, limit: int) -> bytes:
    chunks = []
    total = 0
    buffer = ctypes.create_string_buffer(min(_CHUNK_SIZE, limit + 1))
    count = ctypes.c_uint32()
    while True:
        count.value = 0
        if not _read_file(handle, buffer, len(buffer), ctypes.byref(count), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if count.value == 0:
            break
        total += count.value
        if total > limit:
            raise ManifestValidationError("Quarantine manifest exceeds the size limit.")
        chunks.append(buffer.raw[: count.value])
    return b"".join(chunks)


def _read_posix_file(path: Path, expected: os.stat_result, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        expected_signature = _file_signature(expected)
        if not stat.S_ISREG(opened.st_mode) or _file_signature(opened) != expected_signature:
            raise ManifestValidationError("Quarantine manifest changed during validation.")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(_CHUNK_SIZE, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ManifestValidationError("Quarantine manifest exceeds the size limit.")
        if _file_signature(os.fstat(descriptor)) != expected_signature:
            raise ManifestValidationError("Quarantine manifest changed while being read.")
        after = path.lstat()
        if _file_signature(after) != expected_signature:
            raise ManifestValidationError("Quarantine manifest was replaced while being read.")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


class QuarantineService:
    """Reversible same-volume quarantine for explicitly approved Windows files."""

    def __init__(self, root: str | os.PathLike[str]):
        self.root = validate_user_scan_root(root)
        if is_within_quarantine_store(self.root):
            raise QuarantineError("A quarantine store cannot be used as a scan or restore root.")
        self.store_path = self.root / STORE_NAME

    @contextmanager
    def _operation_lock(self):
        if os.name != "nt":
            with _PROCESS_OPERATION_LOCK:
                yield
            return
        with _windows_root_guard(self.root) as root_final_path:
            with _open_destination_directory(self.store_path, root_final_path) as (_, store_final_path):
                lock_path = self.store_path / _OPERATION_LOCK_NAME
                handle = _create_file(
                    str(lock_path),
                    _GENERIC_READ | _GENERIC_WRITE | _FILE_READ_ATTRIBUTES,
                    0,
                    None,
                    _OPEN_ALWAYS,
                    _FILE_FLAG_OPEN_REPARSE_POINT,
                    None,
                )
                if handle == _INVALID_HANDLE_VALUE:
                    error = ctypes.get_last_error()
                    if error == _ERROR_SHARING_VIOLATION:
                        raise QuarantineError("Another quarantine operation is already in progress.")
                    raise ctypes.WinError(error)
                try:
                    attributes = _FileAttributeTagInfo()
                    if not _get_file_info(handle, 9, ctypes.byref(attributes), ctypes.sizeof(attributes)):
                        raise ctypes.WinError(ctypes.get_last_error())
                    final_path = _windows_final_path(handle)
                    if (
                        attributes.file_attributes
                        & (_FILE_ATTRIBUTE_REPARSE_POINT | _FILE_ATTRIBUTE_DIRECTORY)
                        or not _windows_path_is_within(final_path, store_final_path)
                        or not _same_path(Path(final_path), lock_path)
                        or _handle_file_identity(handle)[2] != 0
                    ):
                        raise QuarantineError("The quarantine operation lock is not a safe regular file.")
                    yield
                finally:
                    _close_handle(handle)

    def list_operations(self) -> list[QuarantineOperation]:
        if not self.store_path.exists() and not os.path.lexists(self.store_path):
            return []
        with self._operation_lock():
            return self._list_operations_locked()

    def _list_operations_locked(self) -> list[QuarantineOperation]:
        if not self.store_path.exists() and not os.path.lexists(self.store_path):
            return []
        records = []
        with ExitStack() as stack:
            root_final_path = stack.enter_context(_windows_root_guard(self.root))
            if os.name == "nt":
                stack.enter_context(_open_destination_directory(self.store_path, root_final_path))
            store_id = validate_quarantine_store(self.store_path)
            try:
                entries = list(os.scandir(self.store_path))
            except OSError as error:
                raise QuarantineError("The quarantine store cannot be read.") from error
            for entry in entries:
                if entry.name == MARKER_NAME:
                    continue
                if entry.name == _OPERATION_LOCK_NAME:
                    info = (self.store_path / entry.name).lstat()
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or stat.S_ISLNK(info.st_mode)
                        or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
                    ):
                        raise ManifestValidationError("The quarantine operation lock is not a safe regular file.")
                    continue
                if not valid_store_id(entry.name):
                    raise ManifestValidationError("The quarantine store contains an unknown entry.")
                operation_dir = self.store_path / entry.name
                info = operation_dir.lstat()
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
                ):
                    raise ManifestValidationError("A quarantine operation directory is not a safe directory.")
                manifest = self._read_manifest(operation_dir, entry.name, store_id)
                self._validate_manifest_scope(manifest)
                self._reconcile(operation_dir, manifest)
                records.append(
                    QuarantineOperation(
                        manifest["operation_id"],
                        manifest["original_path"],
                        manifest["size"],
                        manifest["sha256"],
                        manifest["status"],
                        manifest["created_at"],
                    )
                )
        return sorted(records, key=lambda operation: operation.created_at, reverse=True)

    def quarantine_selected(
        self,
        candidates: Iterable[QuarantineCandidate],
        duplicate_groups: Iterable[Iterable[QuarantineCandidate]] = (),
        cancellation_event: Event | None = None,
    ) -> list[QuarantineOperation]:
        if not _FILE_MOVES_ENABLED:
            raise QuarantineError("Quarantine is disabled until the security gate is cleared.")
        selected = list(candidates)
        if not selected:
            raise QuarantineError("Select at least one file to quarantine.")
        selected_paths = {self._candidate_key(item.path) for item in selected}
        if len(selected_paths) != len(selected):
            raise QuarantineError("A file was selected more than once.")
        survivor_groups = []
        for group in duplicate_groups:
            members = list(group)
            group_paths = {self._candidate_key(item.path) for item in members}
            selected_members = selected_paths & group_paths
            if selected_members and not (group_paths - selected_paths):
                raise DuplicateKeeperError(
                    "At least one verified copy from every duplicate group must remain outside quarantine."
                )
            if selected_members:
                survivor_groups.append((group_paths, [item for item in members if self._candidate_key(item.path) not in selected_paths]))

        store_id = self._ensure_store()
        with self._operation_lock():
            if validate_quarantine_store(self.store_path) != store_id:
                raise QuarantineStoreError("The quarantine store changed before the approved operation.")
            operations = self._list_operations_locked()
            if any(operation.status == "RECOVERY_REQUIRED" for operation in operations):
                raise QuarantineError("Resolve the existing recovery-required operation before quarantining more files.")
            completed: list[QuarantineOperation] = []
            completed_ids: list[str] = []
            for candidate in selected:
                raise_if_cancelled(cancellation_event)
                survivors = next(
                    (remaining for group_paths, remaining in survivor_groups if self._candidate_key(candidate.path) in group_paths),
                    [],
                )
                try:
                    record = self._quarantine_one(candidate, store_id, survivors, cancellation_event)
                except Exception as error:
                    raise BatchQuarantineError(
                        completed_ids,
                        f"Quarantine stopped after {len(completed_ids)} file(s): {error}",
                    ) from error
                completed.append(record)
                completed_ids.append(record.operation_id)
            return completed

    def restore(self, operation_id: str, cancellation_event: Event | None = None) -> QuarantineOperation:
        if not _FILE_MOVES_ENABLED:
            raise QuarantineError("Restore is disabled until the security gate is cleared.")
        if not valid_store_id(operation_id):
            raise QuarantineError("The selected quarantine operation identifier is invalid.")
        with self._operation_lock():
            return self._restore_locked(operation_id, cancellation_event)

    def _restore_locked(self, operation_id: str, cancellation_event: Event | None = None) -> QuarantineOperation:
        store_id = validate_quarantine_store(self.store_path)
        operation_dir = self.store_path / operation_id
        manifest = self._read_manifest(operation_dir, operation_id, store_id)
        self._validate_manifest_scope(manifest)
        self._reconcile(operation_dir, manifest)
        if manifest["status"] != "QUARANTINED":
            raise QuarantineError("This operation is not in a restorable state.")
        if os.name != "nt":
            raise QuarantineError("Quarantine restore is supported only on Windows in this milestone.")

        payload = operation_dir / "payload"
        destination = Path(manifest["original_path"])
        if not _is_within(destination, self.root) or _is_within(destination, self.store_path):
            raise ManifestValidationError("The restore destination is outside the permitted original scope.")
        try:
            destination.lstat()
        except FileNotFoundError:
            pass
        else:
            raise QuarantineError("The original destination already exists; it will not be overwritten.")
        parent_info = destination.parent.lstat()
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or stat.S_ISLNK(parent_info.st_mode)
            or getattr(parent_info, "st_file_attributes", 0) & _REPARSE_POINT
        ):
            raise QuarantineError("The original parent directory is not a safe regular directory.")

        with _windows_root_guard(self.root) as root_final_path:
            with ExitStack() as stack:
                qroot_handle, qroot_final = stack.enter_context(
                    _open_destination_directory(self.store_path, root_final_path)
                )
                operation_handle, operation_final = stack.enter_context(
                    _open_destination_directory(operation_dir, qroot_final)
                )
                parent_handle, _ = stack.enter_context(
                    _open_destination_directory(destination.parent, root_final_path)
                )
                payload_owner = self._open_and_verify_payload(
                    payload,
                    operation_final,
                    manifest,
                    cancellation_event,
                )
                stack.enter_context(payload_owner)
                if _handle_file_identity(payload_owner.handle)[0] != _handle_file_identity(parent_handle)[0]:
                    raise QuarantineError(
                        "The restore destination is on another volume; cross-volume moves are disabled."
                    )
                manifest["status"] = "RESTORING"
                self._write_manifest(operation_dir, manifest, operation_final)
                try:
                    _rename_handle(payload_owner.handle, destination)
                    moved_path = _windows_final_path(payload_owner.handle)
                    if (
                        not _windows_path_is_within(moved_path, root_final_path)
                        or not _same_path(Path(moved_path), destination)
                    ):
                        raise QuarantineError("The restored file resolved outside the approved root.")
                    self._verify_open_handle(payload_owner.handle, manifest, cancellation_event)
                    manifest["status"] = "RESTORED"
                    self._write_manifest(operation_dir, manifest, operation_final)
                except Exception:
                    current_path = Path(_windows_final_path(payload_owner.handle))
                    if _same_path(current_path, destination):
                        try:
                            _rename_handle(payload_owner.handle, payload)
                            manifest["status"] = "QUARANTINED"
                            self._write_manifest(operation_dir, manifest, operation_final)
                        except Exception:
                            manifest["status"] = "RECOVERY_REQUIRED"
                            self._write_manifest(operation_dir, manifest, operation_final)
                    elif _same_path(current_path, payload):
                        manifest["status"] = "QUARANTINED"
                        self._write_manifest(operation_dir, manifest, operation_final)
                    else:
                        manifest["status"] = "RECOVERY_REQUIRED"
                        self._write_manifest(operation_dir, manifest, operation_final)
                    raise
        return QuarantineOperation(
            operation_id,
            manifest["original_path"],
            manifest["size"],
            manifest["sha256"],
            manifest["status"],
            manifest["created_at"],
        )

    def _quarantine_one(
        self,
        candidate: QuarantineCandidate,
        store_id: str,
        survivors: list[QuarantineCandidate],
        cancellation_event: Event | None,
    ) -> QuarantineOperation:
        if os.name != "nt":
            raise QuarantineError("Quarantine moves are supported only on Windows in this milestone.")
        source = self._validate_candidate(candidate)
        self._ensure_same_volume(source)
        for survivor in survivors:
            self._verify_survivor(survivor, cancellation_event)
        operation_id = str(uuid.uuid4())
        operation_dir = self.store_path / operation_id
        payload = operation_dir / "payload"
        created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        manifest = {
            "schema_version": 1,
            "application_version": __version__,
            "store_id": store_id,
            "operation_id": operation_id,
            "original_root": str(self.root),
            "original_path": str(source),
            "object_id": operation_id,
            "size": candidate.size,
            "sha256": candidate.sha256,
            "modified_ns": candidate.modified_ns,
            "file_identity": {
                "device": candidate.file_signature[0],
                "file_id": candidate.file_signature[1],
            },
            "created_at": created_at,
            "status": "PREPARED",
        }
        with _windows_root_guard(self.root) as root_final_path:
            with ExitStack() as stack:
                qroot_handle, qroot_final = stack.enter_context(
                    _open_destination_directory(self.store_path, root_final_path)
                )
                if validate_quarantine_store(self.store_path) != store_id:
                    raise QuarantineStoreError("The quarantine store changed during the approved operation.")
                file_owner = self._open_candidate(source, root_final_path, candidate)
                stack.enter_context(file_owner)
                if _handle_file_identity(file_owner.handle)[0] != _handle_file_identity(qroot_handle)[0]:
                    raise QuarantineError(
                        "This file is on a different volume from the approved quarantine store; "
                        "cross-volume moves are disabled."
                    )
                operation_dir.mkdir()
                operation_handle, operation_final = stack.enter_context(
                    _open_destination_directory(operation_dir, qroot_final)
                )
                self._verify_open_handle(file_owner.handle, manifest, cancellation_event)
                self._write_manifest(operation_dir, manifest, operation_final)
                manifest["status"] = "MOVING"
                self._write_manifest(operation_dir, manifest, operation_final)
                try:
                    _rename_handle(file_owner.handle, payload)
                    moved_path = _windows_final_path(file_owner.handle)
                    if (
                        not _windows_path_is_within(moved_path, qroot_final)
                        or not _same_path(Path(moved_path), payload)
                    ):
                        raise QuarantineError("The quarantine payload resolved outside its approved store.")
                    self._verify_open_handle(file_owner.handle, manifest, cancellation_event)
                    manifest["status"] = "QUARANTINED"
                    self._write_manifest(operation_dir, manifest, operation_final)
                except Exception:
                    if _same_path(Path(_windows_final_path(file_owner.handle)), payload):
                        manifest["status"] = "RECOVERY_REQUIRED"
                        self._write_manifest(operation_dir, manifest, operation_final)
                    else:
                        manifest["status"] = "FAILED"
                        self._write_manifest(operation_dir, manifest, operation_final)
                    raise
        return QuarantineOperation(
            operation_id,
            str(source),
            candidate.size,
            candidate.sha256,
            manifest["status"],
            created_at,
        )

    def _validate_candidate(self, candidate: QuarantineCandidate) -> Path:
        if (
            not _same_path(Path(candidate.root), self.root)
            or candidate.file_signature is None
            or type(candidate.size) is not int
            or type(candidate.modified_ns) is not int
            or candidate.size < 0
            or candidate.sha256 is None
            or not _HASH_PATTERN.fullmatch(candidate.sha256)
        ):
            raise QuarantineError("The selected file lacks valid scan-time identity and hash evidence.")
        source = Path(candidate.path).absolute()
        if (
            not _is_within(source, self.root)
            or _contains_quarantine_component(source)
            or _is_within(source, self.store_path)
        ):
            raise QuarantineError("The selected file is outside the approved scan root.")
        info = _lstat_regular_file(source)
        if (
            _file_signature(info) != candidate.file_signature
            or info.st_size != candidate.size
            or info.st_mtime_ns != candidate.modified_ns
        ):
            raise QuarantineError("The selected file changed after the scan; analyze the folder again.")
        return source

    def _verify_survivor(
        self,
        candidate: QuarantineCandidate,
        cancellation_event: Event | None,
    ) -> None:
        source = self._validate_candidate(candidate)
        with _windows_root_guard(self.root) as root_final_path:
            with self._open_candidate(source, root_final_path, candidate) as owner:
                self._verify_open_handle(owner.handle, {
                    "size": candidate.size,
                    "sha256": candidate.sha256,
                    "modified_ns": candidate.modified_ns,
                    "file_identity": {
                        "device": candidate.file_signature[0],
                        "file_id": candidate.file_signature[1],
                    },
                }, cancellation_event)

    def _open_candidate(
        self,
        path: Path,
        root_final_path: str,
        candidate: QuarantineCandidate,
    ) -> _HandleOwner:
        owner = _open_move_file(path, root_final_path)
        try:
            info = path.lstat()
            if _file_signature(info) != candidate.file_signature:
                raise QuarantineError("The selected file was replaced while being validated.")
            identity = _handle_file_identity(owner.handle)
            if (
                identity[1] != candidate.file_signature[1]
                or identity[2] != candidate.size
                or identity[3] != candidate.file_signature[3]
            ):
                raise QuarantineError("The open file identity does not match the completed scan.")
            return owner
        except Exception:
            owner.close()
            raise

    def _verify_open_handle(self, handle, manifest: dict, cancellation_event: Event | None) -> None:
        identity = _handle_file_identity(handle)
        expected_identity = manifest["file_identity"]
        if (
            identity[2] != manifest["size"]
            or identity[3] != manifest["modified_ns"]
            or identity[1] != expected_identity["file_id"]
        ):
            raise QuarantineError("The open file identity or metadata no longer matches the manifest.")
        digest = _hash_handle(handle, cancellation_event)
        if digest != manifest["sha256"]:
            raise QuarantineError("The file content no longer matches the verified SHA-256.")
        final_identity = _handle_file_identity(handle)
        if final_identity != identity:
            raise QuarantineError("The file changed while its content was being verified.")

    def _open_and_verify_payload(
        self,
        payload: Path,
        operation_final: str,
        manifest: dict,
        cancellation_event: Event | None,
    ) -> _HandleOwner:
        owner = _open_move_file(payload, operation_final)
        try:
            info = _lstat_regular_file(payload)
            if (
                info.st_size != manifest["size"]
                or info.st_mtime_ns != manifest["modified_ns"]
                or _file_id(info)
                != (
                    manifest["file_identity"]["device"],
                    manifest["file_identity"]["file_id"],
                )
            ):
                raise QuarantineError("The quarantined file identity does not match its manifest.")
            self._verify_open_handle(owner.handle, manifest, cancellation_event)
            return owner
        except Exception:
            owner.close()
            raise

    def _ensure_store(self) -> str:
        if os.name == "nt":
            with _windows_root_guard(self.root) as root_final_path:
                if not os.path.lexists(self.store_path):
                    try:
                        self.store_path.mkdir()
                    except FileExistsError:
                        pass
                with _open_destination_directory(self.store_path, root_final_path):
                    if os.path.lexists(self.store_path / MARKER_NAME):
                        return validate_quarantine_store(self.store_path)
                    store_id = str(uuid.uuid4())
                    marker_data = {
                        "magic": "JASTI_ONE_QUARANTINE",
                        "version": STORE_VERSION,
                        "store_id": store_id,
                    }
                    self._create_marker(marker_data)
                    return validate_quarantine_store(self.store_path)
        if os.path.lexists(self.store_path):
            return validate_quarantine_store(self.store_path)
        try:
            self.store_path.mkdir()
        except FileExistsError:
            return validate_quarantine_store(self.store_path)
        store_id = str(uuid.uuid4())
        self._create_marker(
            {"magic": "JASTI_ONE_QUARANTINE", "version": STORE_VERSION, "store_id": store_id}
        )
        return validate_quarantine_store(self.store_path)

    def _create_marker(self, marker_data: dict) -> None:
        marker = self.store_path / MARKER_NAME
        try:
            with marker.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(marker_data, sort_keys=True, separators=(",", ":")))
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as error:
            raise QuarantineStoreError("The quarantine store marker could not be created safely.") from error

    def _ensure_same_volume(self, source: Path) -> None:
        try:
            if os.stat(source).st_dev != os.stat(self.store_path).st_dev:
                raise QuarantineError(
                    "This file is on a different volume from the approved quarantine store; "
                    "cross-volume moves are disabled because a verified recovery protocol is not available."
                )
        except OSError as error:
            raise QuarantineError("The file volume could not be verified.") from error

    def _candidate_key(self, path: str) -> str:
        absolute = str(Path(path).absolute())
        return _normalize_windows_path(absolute) if os.name == "nt" else os.path.normcase(absolute)

    def _read_manifest(self, operation_dir: Path, operation_id: str, store_id: str) -> dict:
        manifest_path = operation_dir / "manifest.json"
        info = _lstat_regular_file(manifest_path)
        if info.st_size > _MAX_MANIFEST_SIZE:
            raise ManifestValidationError("Quarantine manifest exceeds the size limit.")
        if os.name == "nt":
            with _windows_root_guard(self.root) as root_final_path:
                with ExitStack() as stack:
                    _, qroot_final = stack.enter_context(
                        _open_destination_directory(self.store_path, root_final_path)
                    )
                    _, operation_final = stack.enter_context(
                        _open_destination_directory(operation_dir, qroot_final)
                    )
                    handle = _open_read_handle(manifest_path, operation_final)
                    stack.enter_context(handle)
                    raw = _read_handle(handle.handle, _MAX_MANIFEST_SIZE)
                    self._validate_operation_entries(operation_dir)
        else:
            raw = _read_posix_file(manifest_path, info, _MAX_MANIFEST_SIZE)
            self._validate_operation_entries(operation_dir)
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_object_pairs)
        except (UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise ManifestValidationError("Quarantine manifest is not valid UTF-8 JSON.") from error
        manifest = _validate_manifest(value, operation_id, store_id)
        return manifest

    def _validate_operation_entries(self, operation_dir: Path) -> None:
        allowed = {"manifest.json", "payload"}
        try:
            entries = list(os.scandir(operation_dir))
        except OSError as error:
            raise QuarantineError("A quarantine operation directory cannot be read.") from error
        for entry in entries:
            if entry.name in allowed:
                item_path = operation_dir / entry.name
                try:
                    info = item_path.lstat()
                except FileNotFoundError:
                    if entry.name == "payload":
                        continue
                    raise ManifestValidationError("A quarantine manifest disappeared during validation.")
                if (
                    not stat.S_ISREG(info.st_mode)
                    or stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
                ):
                    raise ManifestValidationError("A quarantine operation contains an unsafe file.")
                continue
            if re.fullmatch(r"\.manifest-[0-9a-f-]{36}\.tmp", entry.name):
                info = (operation_dir / entry.name).lstat()
                if stat.S_ISREG(info.st_mode) and not getattr(info, "st_file_attributes", 0) & _REPARSE_POINT:
                    continue
            raise ManifestValidationError("A quarantine operation contains an unknown or unsafe entry.")

    def _validate_manifest_scope(self, manifest: dict) -> None:
        if not _same_path(Path(manifest["original_root"]), self.root):
            raise ManifestValidationError("The manifest belongs to a different selected scan root.")
        original = Path(manifest["original_path"])
        if (
            not _is_within(original, self.root)
            or _contains_quarantine_component(original)
            or _is_within(original, self.store_path)
        ):
            raise ManifestValidationError("The manifest restore path is outside the permitted original scope.")
        if not _same_path(original.parent, Path(manifest["original_root"])) and not _is_within(
            original.parent, self.root
        ):
            raise ManifestValidationError("The manifest parent path is outside the permitted original scope.")

    def _reconcile(self, operation_dir: Path, manifest: dict) -> None:
        status = manifest["status"]
        if status not in {"PREPARED", "MOVING", "RESTORING"}:
            return
        payload = operation_dir / "payload"
        original = Path(manifest["original_path"])
        payload_exists = os.path.lexists(payload)
        original_exists = os.path.lexists(original)
        if status == "PREPARED" and original_exists and not payload_exists:
            manifest["status"] = "FAILED"
        elif status == "MOVING" and payload_exists and not original_exists:
            if self._path_matches_manifest(payload, manifest):
                manifest["status"] = "QUARANTINED"
            else:
                manifest["status"] = "RECOVERY_REQUIRED"
        elif status == "MOVING" and original_exists and not payload_exists:
            manifest["status"] = "FAILED"
        elif status == "RESTORING" and original_exists and not payload_exists:
            manifest["status"] = (
                "RESTORED" if self._path_matches_manifest(original, manifest) else "RECOVERY_REQUIRED"
            )
        elif status == "RESTORING" and payload_exists and not original_exists:
            manifest["status"] = "QUARANTINED"
        else:
            manifest["status"] = "RECOVERY_REQUIRED"
        if os.name == "nt":
            with _windows_root_guard(self.root) as root_final_path:
                with ExitStack() as stack:
                    _, qroot_final = stack.enter_context(
                        _open_destination_directory(self.store_path, root_final_path)
                    )
                    _, operation_final = stack.enter_context(
                        _open_destination_directory(operation_dir, qroot_final)
                    )
                    self._write_manifest(operation_dir, manifest, operation_final)
        else:
            self._write_manifest(operation_dir, manifest, None)

    def _path_matches_manifest(self, path: Path, manifest: dict) -> bool:
        try:
            info = _lstat_regular_file(path)
            if (
                info.st_size != manifest["size"]
                or info.st_mtime_ns != manifest["modified_ns"]
                or _file_id(info)
                != (
                    manifest["file_identity"]["device"],
                    manifest["file_identity"]["file_id"],
                )
            ):
                return False
            if os.name == "nt":
                with _windows_root_guard(self.root) as root_final_path:
                    with _open_move_file(path, root_final_path) as owner:
                        return _hash_handle(owner.handle) == manifest["sha256"]
            return _sha256_file(path, _file_signature(info)) == manifest["sha256"]
        except (OSError, QuarantineError):
            return False

    def _write_manifest(self, operation_dir: Path, manifest: dict, operation_final: str | None) -> None:
        temporary = operation_dir / f".manifest-{uuid.uuid4()}.tmp"
        destination = operation_dir / "manifest.json"
        serialized = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            with temporary.open("xb") as stream:
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
            if os.name == "nt" and operation_final is not None:
                info = temporary.lstat()
                if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT:
                    raise ManifestValidationError("The temporary manifest is not a safe regular file.")
            os.replace(temporary, destination)
        except OSError as error:
            raise QuarantineError("The quarantine operation state could not be saved atomically.") from error


def _open_read_handle(path: Path, approved_root_final_path: str) -> _HandleOwner:
    handle = _create_file(
        str(path),
        _GENERIC_READ,
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
        final_path = _windows_final_path(handle)
        if (
            attributes.file_attributes & (_FILE_ATTRIBUTE_REPARSE_POINT | _FILE_ATTRIBUTE_DIRECTORY)
            or not _windows_path_is_within(final_path, approved_root_final_path)
            or not _same_path(Path(final_path), path)
        ):
            raise ManifestValidationError("A quarantine manifest is a reparse point or outside its store.")
        return _HandleOwner(handle, final_path)
    except Exception:
        _close_handle(handle)
        raise
