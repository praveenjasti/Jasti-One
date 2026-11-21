from __future__ import annotations

import json
import ctypes
import ntpath
import os
from pathlib import Path
import re
import stat
import uuid

STORE_NAME = ".jasti-one-quarantine"
MARKER_NAME = ".store.json"
STORE_VERSION = 1
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x0001
_OPEN_EXISTING = 3
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_ATTRIBUTE_DIRECTORY = 0x0010
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


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
    _get_file_info = _kernel32.GetFileInformationByHandleEx
    _get_file_info.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    )
    _get_file_info.restype = ctypes.c_int
    _get_final_path = _kernel32.GetFinalPathNameByHandleW
    _get_final_path.argtypes = (
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    )
    _get_final_path.restype = ctypes.c_uint32
    _close_handle = _kernel32.CloseHandle
    _close_handle.argtypes = (ctypes.c_void_p,)
    _close_handle.restype = ctypes.c_int


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = [("file_attributes", ctypes.c_uint32), ("reparse_tag", ctypes.c_uint32)]


class QuarantineStoreError(ValueError):
    pass


def strict_object_pairs(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON object key.")
        value[key] = item
    return value


def _read_marker(path: Path) -> dict:
    marker = path / MARKER_NAME
    try:
        info = marker.lstat()
    except OSError as error:
        raise QuarantineStoreError("The reserved quarantine folder has no valid store marker.") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
        or info.st_size > 4096
    ):
        raise QuarantineStoreError("The quarantine store marker is not a safe regular file.")
    try:
        if os.name == "nt":
            raw = _read_marker_windows(marker)
        else:
            raw = _read_marker_posix(marker, info)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_object_pairs)
    except (OSError, UnicodeError, ValueError) as error:
        raise QuarantineStoreError("The quarantine store marker is invalid.") from error
    if (
        type(value) is not dict
        or set(value) != {"magic", "version", "store_id"}
        or value.get("magic") != "JASTI_ONE_QUARANTINE"
        or type(value.get("version")) is not int
        or value["version"] != STORE_VERSION
        or type(value.get("store_id")) is not str
    ):
        raise QuarantineStoreError("The quarantine store marker has an unsupported schema.")
    try:
        parsed_id = uuid.UUID(value["store_id"])
    except (ValueError, AttributeError) as error:
        raise QuarantineStoreError("The quarantine store identifier is invalid.") from error
    if str(parsed_id) != value["store_id"]:
        raise QuarantineStoreError("The quarantine store identifier is not canonical.")
    return value


def _read_marker_posix(marker: Path, expected: os.stat_result) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(marker, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (expected.st_dev, expected.st_ino, expected.st_size, expected.st_mtime_ns)
        ):
            raise QuarantineStoreError("The quarantine store marker changed during validation.")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise QuarantineStoreError("The quarantine store marker exceeds the size limit.")
        return raw
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_marker_windows(marker: Path) -> bytes:
    handle = _create_file(
        str(marker),
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
        if (
            attributes.file_attributes & (_REPARSE_POINT | _FILE_ATTRIBUTE_DIRECTORY)
            or not _windows_path_matches(_final_path(handle), marker)
        ):
            raise QuarantineStoreError("The quarantine store marker is a reparse point or moved path.")
        import msvcrt

        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        handle = None
        with os.fdopen(descriptor, "rb") as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise QuarantineStoreError("The quarantine store marker exceeds the size limit.")
        return raw
    finally:
        if handle is not None:
            _close_handle(handle)


def _final_path(handle) -> str:
    buffer = ctypes.create_unicode_buffer(32768)
    length = _get_final_path(handle, buffer, len(buffer), 0)
    if not length:
        raise ctypes.WinError(ctypes.get_last_error())
    if length >= len(buffer):
        raise OSError("The quarantine store marker path is too long.")
    return buffer.value


def _windows_path_matches(left: str, right: Path) -> bool:
    if left.startswith("\\\\?\\UNC\\"):
        left = "\\\\" + left[8:]
    elif left.startswith("\\\\?\\"):
        left = left[4:]
    normalized_left = ntpath.normcase(ntpath.normpath(left))
    normalized_right = ntpath.normcase(ntpath.normpath(str(right.absolute())))
    return normalized_left == normalized_right


def validate_quarantine_store(path: str | os.PathLike[str]) -> str:
    store = Path(path)
    if store.name.casefold() != STORE_NAME.casefold():
        raise QuarantineStoreError("The path is not the reserved quarantine store.")
    try:
        info = store.lstat()
    except OSError as error:
        raise QuarantineStoreError("The quarantine store is unavailable.") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    ):
        raise QuarantineStoreError("The quarantine store is not a regular directory.")
    return _read_marker(store)["store_id"]


def reserved_quarantine_store(path: str | os.PathLike[str]) -> bool:
    candidate = Path(path)
    if candidate.name.casefold() != STORE_NAME.casefold():
        return False
    try:
        candidate.lstat()
    except FileNotFoundError:
        return False
    return bool(validate_quarantine_store(candidate))


def is_within_quarantine_store(path: str | os.PathLike[str]) -> bool:
    candidate = Path(path).absolute()
    for ancestor in (candidate, *candidate.parents):
        if ancestor.name.casefold() == STORE_NAME.casefold():
            validate_quarantine_store(ancestor)
            return True
    return False


def valid_store_id(value: object) -> bool:
    if type(value) is not str or not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        value,
    ):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False
