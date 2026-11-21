from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime
import heapq
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from threading import Event
from typing import Callable

from ..services.path_policy import (
    is_protected_path,
    validate_user_scan_root,
)
from ..services.scan_control import raise_if_cancelled
from .duplicate_engine import (
    DuplicateEngine,
    DuplicateItem,
    _file_signature,
    _normalize_windows_path,
    _sha256_file,
    _windows_open_directory,
    _windows_root_guard,
)
from ..services.quarantine_store import (
    STORE_NAME,
    is_within_quarantine_store,
    reserved_quarantine_store,
)

MAX_FILE_ROWS = 500
MAX_DIRECTORY_ROWS = 100
MAX_TYPE_BUCKETS = 512
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
_VIDEO = {".avi", ".m4v", ".mkv", ".mov", ".mp4", ".mpeg", ".mpg", ".webm", ".wmv"}
_ARCHIVE = {".7z", ".bz2", ".gz", ".rar", ".tar", ".zip"}
_INSTALLER = {".appx", ".appxbundle", ".exe", ".msi", ".msix", ".msixbundle"}
_DISK_IMAGE = {".img", ".iso", ".vhd", ".vhdx"}
_INCOMPLETE_DOWNLOAD = {
    ".aria2",
    ".crdownload",
    ".download",
    ".filepart",
    ".opdownload",
    ".part",
    ".partial",
}

ProgressCallback = Callable[[str, int, int], None]


@dataclass(frozen=True)
class FileFinding:
    path: str
    name: str
    size: int
    modified_ns: int
    extension: str
    kind: str
    location_category: str
    reason: str
    recommendation: str
    consequence: str
    file_signature: tuple[int, int, int, int, int] | None = None
    sha256: str | None = None


@dataclass(frozen=True)
class DirectoryFinding:
    path: str
    size: int


@dataclass
class _DirectoryFrame:
    path: Path
    manager: object | None
    entries: os.ScandirIterator
    total_size: int = 0


@dataclass
class CleanerScanResult:
    root: str
    started_at: str
    elapsed_seconds: float
    files_scanned: int
    directories_scanned: int
    bytes_scanned: int
    inaccessible_entries: int
    largest_files: list[FileFinding]
    largest_directories: list[DirectoryFinding]
    old_files: list[FileFinding]
    location_files: dict[str, list[FileFinding]]
    location_totals: dict[str, dict[str, int]]
    type_totals: dict[str, dict[str, int]]
    kind_totals: dict[str, dict[str, int]]
    old_totals: dict[int, dict[str, int]]
    large_totals: dict[int, dict[str, int]]
    duplicates: list[list[DuplicateItem]] = field(default_factory=list)
    all_files: list[FileFinding] = field(default_factory=list)
    location_all_files: dict[str, list[FileFinding]] = field(default_factory=dict)
    location_scope: dict[str, bool] = field(default_factory=dict)

    @property
    def duplicate_potential_bytes(self) -> int:
        total = 0
        for group in self.duplicates:
            identities = {
                item.file_id if item.file_id and item.file_id[1] else ("path", item.path)
                for item in group
            }
            total += max(0, len(identities) - 1) * group[0].size
        return total


class _TopFindings:
    def __init__(self, limit: int):
        self.limit = limit
        self._counter = 0
        self._items: list[tuple[int, int, FileFinding]] = []

    def add(self, finding: FileFinding) -> None:
        self._counter += 1
        entry = (finding.size, self._counter, finding)
        if len(self._items) < self.limit:
            heapq.heappush(self._items, entry)
        elif entry[0] > self._items[0][0]:
            heapq.heapreplace(self._items, entry)

    def values(self) -> list[FileFinding]:
        return [
            item[2]
            for item in sorted(self._items, key=lambda item: (-item[0], item[2].path.casefold()))
        ]


class _TopDirectories:
    def __init__(self):
        self._counter = 0
        self._items: list[tuple[int, int, DirectoryFinding]] = []

    def add(self, finding: DirectoryFinding) -> None:
        self._counter += 1
        entry = (finding.size, self._counter, finding)
        if len(self._items) < MAX_DIRECTORY_ROWS:
            heapq.heappush(self._items, entry)
        elif entry[0] > self._items[0][0]:
            heapq.heapreplace(self._items, entry)

    def values(self) -> list[DirectoryFinding]:
        return [
            item[2]
            for item in sorted(self._items, key=lambda item: (-item[0], item[2].path.casefold()))
        ]


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        if os.name == "nt":
            try:
                normalized_path = os.path.normcase(str(path))
                normalized_root = os.path.normcase(str(root))
                return os.path.commonpath((normalized_path, normalized_root)) == normalized_root
            except ValueError:
                return False
        return False


def known_analysis_locations(home: Path | None = None) -> dict[str, list[Path]]:
    home = home or Path.home()
    local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
    roaming = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    locations: dict[str, list[Path]] = {
        "temporary": [Path(tempfile.gettempdir())],
        "browser_cache": [
            local / "Microsoft" / "Edge" / "User Data",
            local / "Google" / "Chrome" / "User Data",
            roaming / "Mozilla" / "Firefox" / "Profiles",
            local / "Mozilla" / "Firefox" / "Profiles",
        ],
        "developer_cache": [
            local / "pip" / "Cache",
            local / "npm-cache",
            local / "Yarn" / "Cache",
            local / "pnpm" / "store",
            home / ".cache" / "yarn",
            home / ".m2" / "repository",
            home / ".gradle" / "caches",
            home / ".nuget" / "packages",
            home / ".cargo" / "registry",
        ],
        "downloads": [home / "Downloads"],
    }
    return locations


def classify_location(
    path: str | os.PathLike[str],
    locations: dict[str, list[Path]] | None = None,
) -> tuple[str, str, str, str]:
    candidate = Path(path).absolute()
    locations = locations or known_analysis_locations()
    rules = {
        "temporary": (
            "Located under a recognized temporary directory",
            "Review carefully",
            "The file may be active or locked; usage is not tested and no file is changed.",
        ),
        "browser_cache": (
            "Located under a supported browser cache/profile directory",
            "Review carefully",
            "The browser may be using the cache; rebuilding it can affect startup performance.",
        ),
        "developer_cache": (
            "Located under a recognized developer package/build cache",
            "Review carefully",
            "Removing a developer cache can require downloads or rebuilds.",
        ),
        "downloads": (
            "Located in the current user's Downloads folder",
            "Safe to review",
            "Downloads may contain personal or important files; age and size do not imply junk.",
        ),
    }
    for category, roots in locations.items():
        if category == "browser_cache":
            cache_names = {
                "cache",
                "cache2",
                "code cache",
                "gpucache",
                "dawncache",
                "grshadercache",
            }
            matches = any(
                _is_within(candidate, root.absolute())
                and any(
                    part.casefold() in cache_names
                    for part in _relative_parts(candidate, root.absolute())
                )
                for root in roots
            )
        else:
            matches = any(_is_within(candidate, root.absolute()) for root in roots)
        if matches:
            reason, recommendation, consequence = rules[category]
            if category == "developer_cache":
                matching_root = max(
                    (root.absolute() for root in roots if _is_within(candidate, root.absolute())),
                    key=lambda root: len(root.parts),
                )
                parts = tuple(part.casefold() for part in matching_root.parts)
                if matching_root.name.casefold() == "npm-cache":
                    label = "npm cache"
                elif matching_root.name.casefold() == "cache" and "yarn" in parts:
                    label = "Yarn cache"
                elif matching_root.name.casefold() == "cache" and "pip" in parts:
                    label = "pip cache"
                elif matching_root.name.casefold() == "store":
                    label = "pnpm store"
                elif matching_root.name.casefold() == "repository":
                    label = "Maven repository"
                elif matching_root.name.casefold() == "caches":
                    label = "Gradle cache"
                elif matching_root.name.casefold() == "packages":
                    label = "NuGet package cache"
                elif matching_root.name.casefold() == "registry":
                    label = "Cargo registry cache"
                else:
                    label = "developer cache"
                reason = f"Located under a recognized {label}"
            return category, reason, recommendation, consequence
    return (
        "other",
        "Found in the user-selected folder",
        "Do not recommend cleaning",
        "No cleanup suitability is inferred from file age or size.",
    )


def _open_directory_frame(path: Path, root_final_path: str | None) -> _DirectoryFrame:
    manager = None
    if os.name == "nt":
        manager = _windows_open_directory(path, root_final_path or str(path))
        manager.__enter__()
    try:
        entries = os.scandir(path)
    except BaseException:
        if manager is not None:
            manager.__exit__(*sys.exc_info())
        raise
    return _DirectoryFrame(path, manager, entries)


def _close_frame(frame: _DirectoryFrame) -> None:
    try:
        frame.entries.close()
    finally:
        if frame.manager is not None:
            frame.manager.__exit__(None, None, None)


def _relative_parts(path: Path, root: Path) -> tuple[str, ...]:
    try:
        return path.relative_to(root).parts
    except ValueError:
        if os.name == "nt":
            try:
                relative = os.path.relpath(path, root)
                return Path(relative).parts if relative != "." else ()
            except ValueError:
                return ()
        return ()


def _browser_profile_root(path: Path, locations: dict[str, list[Path]]) -> Path | None:
    for root in locations.get("browser_cache", []):
        if _is_within(path, root.absolute()):
            return root.absolute()
    return None


def _is_browser_cache_path(path: Path, locations: dict[str, list[Path]]) -> bool:
    root = _browser_profile_root(path, locations)
    if root is None:
        return False
    cache_names = {"cache", "cache2", "code cache", "gpucache", "dawncache", "grshadercache"}
    return any(part.casefold() in cache_names for part in _relative_parts(path, root))


class CleanerScanEngine:
    """Read-only metadata inventory for one explicitly selected directory."""

    def scan(
        self,
        folder: str | Path,
        *,
        cancellation_event: Event | None = None,
        progress_callback: ProgressCallback | None = None,
        include_duplicates: bool = True,
    ) -> CleanerScanResult:
        root = validate_user_scan_root(folder)
        if is_within_quarantine_store(root):
            raise ValueError("A quarantine store cannot be analyzed as a scan root.")
        started = time.monotonic()
        timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
        result_data = {
            "files_scanned": 0,
            "directories_scanned": 0,
            "bytes_scanned": 0,
            "inaccessible_entries": 0,
        }
        largest_files = _TopFindings(MAX_FILE_ROWS)
        old_files = _TopFindings(MAX_FILE_ROWS)
        location_files = {
            category: _TopFindings(200)
            for category in ("temporary", "browser_cache", "developer_cache", "downloads")
        }
        largest_directories = _TopDirectories()
        location_totals: dict[str, dict[str, int]] = defaultdict(lambda: {"files": 0, "bytes": 0})
        type_totals: dict[str, dict[str, int]] = defaultdict(lambda: {"files": 0, "bytes": 0})
        kind_totals: dict[str, dict[str, int]] = defaultdict(lambda: {"files": 0, "bytes": 0})
        old_totals = {days: {"files": 0, "bytes": 0} for days in (30, 90, 180)}
        large_totals = {
            size: {"files": 0, "bytes": 0}
            for size in (100 * 1024**2, 500 * 1024**2, 1024**3)
        }
        locations = known_analysis_locations()
        selected_root = root.absolute()
        location_scope = {
            category: any(
                _is_within(selected_root, known_root.absolute())
                or _is_within(known_root.absolute(), selected_root)
                for known_root in roots
            )
            for category, roots in locations.items()
        }
        all_files: list[FileFinding] = []
        now = time.time()
        top_directory_heap = largest_directories

        def report(stage: str) -> None:
            if progress_callback is not None:
                progress_callback(
                    stage,
                    result_data["files_scanned"],
                    result_data["bytes_scanned"],
                )

        def walk(root_final_path: str | None) -> None:
            frames: list[_DirectoryFrame] = []
            try:
                try:
                    frames.append(_open_directory_frame(root, root_final_path))
                    result_data["directories_scanned"] += 1
                except OSError:
                    result_data["inaccessible_entries"] += 1
                    raise

                while frames:
                    raise_if_cancelled(cancellation_event)
                    frame = frames[-1]
                    try:
                        entry = next(frame.entries)
                    except StopIteration:
                        _close_frame(frames.pop())
                        if frame.total_size and (
                            _browser_profile_root(frame.path, locations) is None
                            or _is_browser_cache_path(frame.path, locations)
                        ):
                            top_directory_heap.add(DirectoryFinding(str(frame.path), frame.total_size))
                        if frames:
                            frames[-1].total_size += frame.total_size
                        continue
                    except OSError:
                        result_data["inaccessible_entries"] += 1
                        _close_frame(frames.pop())
                        continue

                    path = frame.path / entry.name
                    try:
                        if path.name.casefold() == STORE_NAME.casefold():
                            reserved_quarantine_store(path)
                            continue
                        browser_root = _browser_profile_root(path, locations)
                        if browser_root is not None and not _is_browser_cache_path(path, locations):
                            if entry.is_dir(follow_symlinks=False):
                                info = entry.stat(follow_symlinks=False)
                                if not (
                                    stat.S_ISLNK(info.st_mode)
                                    or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
                                ):
                                    try:
                                        frames.append(_open_directory_frame(path, root_final_path))
                                        result_data["directories_scanned"] += 1
                                    except OSError:
                                        result_data["inaccessible_entries"] += 1
                            continue
                        info = entry.stat(follow_symlinks=False)
                        attributes = getattr(info, "st_file_attributes", 0)
                        if stat.S_ISLNK(info.st_mode) or attributes & _REPARSE_POINT:
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            try:
                                frames.append(_open_directory_frame(path, root_final_path))
                                result_data["directories_scanned"] += 1
                            except OSError:
                                result_data["inaccessible_entries"] += 1
                            continue
                        if not stat.S_ISREG(info.st_mode):
                            continue
                        # Metadata-only scan: do not open or read file contents.
                        current = path.lstat()
                        if (
                            stat.S_ISLNK(current.st_mode)
                            or getattr(current, "st_file_attributes", 0) & _REPARSE_POINT
                            or info.st_size != current.st_size
                            or info.st_mtime_ns != current.st_mtime_ns
                            or stat.S_IFMT(info.st_mode) != stat.S_IFMT(current.st_mode)
                        ):
                            result_data["inaccessible_entries"] += 1
                            continue
                        after = path.lstat()
                        if _file_signature(current) != _file_signature(after):
                            result_data["inaccessible_entries"] += 1
                            continue
                        size = current.st_size
                        modified_ns = current.st_mtime_ns
                        age_days = max(0, int((now - modified_ns / 1_000_000_000) // 86400))
                        category, reason, recommendation, consequence = classify_location(path, locations)
                        extension = path.suffix.casefold() or "(no extension)"
                        kind = next(
                            (
                                name
                                for name, extensions in (
                                    ("Video", _VIDEO),
                                    ("Archive", _ARCHIVE),
                                    ("Installer", _INSTALLER),
                                    ("Disk image", _DISK_IMAGE),
                                )
                                if extension in extensions
                            ),
                            "Other",
                        )
                        if category == "downloads":
                            if extension in _INCOMPLETE_DOWNLOAD:
                                reason = (
                                    f"Possible incomplete download ({extension}); "
                                    "confirm that the download is no longer active."
                                )
                                recommendation = "Review carefully"
                                consequence = (
                                    "This file may still be written by a download manager; "
                                    "no file is changed."
                                )
                            elif kind != "Other":
                                reason = f"{kind} located in the current user's Downloads folder"
                                if age_days >= 90:
                                    reason += "; modified more than 90 days ago"
                                consequence = (
                                    "This may be a useful installer, archive, or disk image; "
                                    "age and size do not imply it is unnecessary."
                                )
                            elif age_days >= 90:
                                reason = (
                                    "Download is older than 90 days; its purpose and continued need "
                                    "are unknown."
                                )
                        finding = FileFinding(
                            str(path),
                            path.name,
                            size,
                            modified_ns,
                            extension,
                            kind,
                            category,
                            reason,
                            recommendation,
                            consequence,
                            _file_signature(current),
                        )
                        result_data["files_scanned"] += 1
                        result_data["bytes_scanned"] += size
                        all_files.append(finding)
                        frame.total_size += size
                        largest_files.add(finding)
                        if category in location_files:
                            location_files[category].add(finding)
                        location_totals[category]["files"] += 1
                        location_totals[category]["bytes"] += size
                        type_bucket = (
                            extension
                            if extension in type_totals or len(type_totals) < MAX_TYPE_BUCKETS
                            else "(other extensions)"
                        )
                        type_totals[type_bucket]["files"] += 1
                        type_totals[type_bucket]["bytes"] += size
                        kind_totals[kind]["files"] += 1
                        kind_totals[kind]["bytes"] += size
                        for days in old_totals:
                            if age_days >= days:
                                old_totals[days]["files"] += 1
                                old_totals[days]["bytes"] += size
                        if age_days >= 30:
                            old_files.add(finding)
                        for threshold in large_totals:
                            if size >= threshold:
                                large_totals[threshold]["files"] += 1
                                large_totals[threshold]["bytes"] += size
                        if result_data["files_scanned"] % 100 == 0:
                            report("Inventory")
                    except OSError:
                        result_data["inaccessible_entries"] += 1
            finally:
                while frames:
                    _close_frame(frames.pop())

        if os.name == "nt":
            with _windows_root_guard(root) as root_final_path:
                if is_protected_path(Path(_normalize_windows_path(root_final_path)), resolve=False):
                    raise ValueError("Protected system location. Choose a personal data folder.")
                walk(root_final_path)
        else:
            walk(None)

        raise_if_cancelled(cancellation_event)
        report("Duplicate verification")
        duplicates = (
            DuplicateEngine().scan(
                root,
                cancellation_event=cancellation_event,
                excluded_roots=(
                    *locations.get("browser_cache", ()),
                    root / STORE_NAME,
                ),
            )
            if include_duplicates
            else []
        )
        findings_by_path: dict[str, FileFinding] = {}
        for finding in (
            *largest_files.values(),
            *old_files.values(),
            *(item for values in location_files.values() for item in values.values()),
        ):
            key = os.path.normcase(os.path.abspath(finding.path))
            findings_by_path[key] = finding
        duplicate_by_path = {
            os.path.normcase(os.path.abspath(item.path)): item
            for group in duplicates
            for item in group
        }
        if os.name == "nt":
            with _windows_root_guard(root) as root_final_path:
                hash_review_candidates(
                    findings_by_path,
                    duplicate_by_path,
                    root_final_path,
                    cancellation_event,
                    result_data,
                    report,
                )
        else:
            hash_review_candidates(
                findings_by_path,
                duplicate_by_path,
                None,
                cancellation_event,
                result_data,
                report,
            )
        def reviewed_findings(items: list[FileFinding]) -> list[FileFinding]:
            return [
                findings_by_path.get(os.path.normcase(os.path.abspath(item.path)), item)
                for item in items
            ]

        location_all_files = {
            category: sorted(
                (finding for finding in all_files if finding.location_category == category),
                key=lambda finding: (-finding.size, finding.path.casefold()),
            )
            for category in ("temporary", "browser_cache", "developer_cache", "downloads")
        }
        report("Complete")
        return CleanerScanResult(
            root=str(root),
            started_at=timestamp,
            elapsed_seconds=time.monotonic() - started,
            files_scanned=result_data["files_scanned"],
            directories_scanned=result_data["directories_scanned"],
            bytes_scanned=result_data["bytes_scanned"],
            inaccessible_entries=result_data["inaccessible_entries"],
            largest_files=reviewed_findings(largest_files.values()),
            largest_directories=largest_directories.values(),
            old_files=reviewed_findings(old_files.values()),
            location_files={key: reviewed_findings(value.values()) for key, value in location_files.items()},
            location_totals=dict(location_totals),
            type_totals=dict(type_totals),
            kind_totals=dict(kind_totals),
            old_totals=old_totals,
            large_totals=large_totals,
            duplicates=duplicates,
            all_files=all_files,
            location_all_files=location_all_files,
            location_scope=location_scope,
        )


def hash_review_candidates(
    findings: dict[str, FileFinding],
    duplicates: dict[str, DuplicateItem],
    root_final_path: str | None,
    cancellation_event: Event | None,
    result_data: dict[str, int],
    report: Callable[[str], None],
) -> None:
    """Hash only bounded, user-visible findings so they can be revalidated for review actions."""
    for index, (key, finding) in enumerate(tuple(findings.items()), start=1):
        raise_if_cancelled(cancellation_event)
        duplicate = duplicates.get(key)
        if duplicate is not None and duplicate.file_signature == finding.file_signature:
            findings[key] = replace(finding, sha256=duplicate.sha256)
            continue
        if finding.file_signature is None:
            result_data["inaccessible_entries"] += 1
            continue
        try:
            digest = _sha256_file(
                Path(finding.path),
                finding.file_signature,
                root_final_path,
                cancellation_event,
            )
        except OSError:
            result_data["inaccessible_entries"] += 1
            continue
        findings[key] = replace(finding, sha256=digest)
        if index % 20 == 0:
            report("Verifying review candidates")
