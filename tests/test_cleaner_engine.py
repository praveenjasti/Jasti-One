from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import os
from pathlib import Path
from threading import Event

import pytest

import pdcm.engines.cleaner_engine as cleaner_engine
from pdcm.engines.cleaner_engine import CleanerScanEngine, classify_location
from pdcm.services.scan_control import ScanCancelled
from pdcm.services.scan_history import ScanHistory


def _snapshot(path: Path):
    return {
        child.relative_to(path): (child.stat().st_size, child.stat().st_mtime_ns, child.read_bytes())
        for child in path.rglob("*")
        if child.is_file()
    }


def test_scan_reports_storage_types_and_exact_duplicates_without_modifying_files(tmp_path):
    root = tmp_path / "Selected"
    root.mkdir()
    first = root / "one.mp4"
    second = root / "copy.mp4"
    archive = root / "archive.zip"
    first.write_bytes(b"identical video sample")
    second.write_bytes(b"identical video sample")
    archive.write_bytes(b"archive")
    before = _snapshot(root)

    result = CleanerScanEngine().scan(root)

    assert result.files_scanned == 3
    assert result.bytes_scanned == sum(item[0] for item in before.values())
    assert result.kind_totals["Video"]["files"] == 2
    assert result.kind_totals["Archive"]["files"] == 1
    assert len(result.duplicates) == 1
    assert result.duplicate_potential_bytes == first.stat().st_size
    assert _snapshot(root) == before


def test_executable_files_are_not_misclassified_as_changed_during_inventory(tmp_path):
    root = tmp_path / "Downloads"
    root.mkdir()
    (root / "setup-one.exe").write_bytes(b"same installer payload")
    (root / "setup-renamed.exe").write_bytes(b"same installer payload")

    result = CleanerScanEngine().scan(root)

    assert result.files_scanned == 2
    assert {finding.extension for finding in result.all_files} == {".exe"}
    assert len(result.duplicates) == 1
    assert len(result.duplicates[0]) == 2


def test_scan_counts_large_and_old_file_thresholds(tmp_path):
    root = tmp_path / "Selected"
    root.mkdir()
    large = root / "large.bin"
    with large.open("wb") as stream:
        stream.truncate(100 * 1024**2)
    old = root / "old.txt"
    old.write_bytes(b"old")
    old_time = (datetime.now().astimezone() - timedelta(days=181)).timestamp()
    os.utime(old, (old_time, old_time))

    result = CleanerScanEngine().scan(root, include_duplicates=False)

    assert result.large_totals[100 * 1024**2] == {"files": 1, "bytes": 100 * 1024**2}
    assert result.large_totals[500 * 1024**2]["files"] == 0
    assert result.old_totals[30]["files"] == 1
    assert result.old_totals[90]["files"] == 1
    assert result.old_totals[180]["files"] == 1
    assert [finding.name for finding in result.old_files] == ["old.txt"]


def test_complete_inventory_supports_filters_beyond_top_file_limit(monkeypatch, tmp_path):
    home = tmp_path / "home"
    downloads = home / "Downloads"
    downloads.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("LOCALAPPDATA", str(home / "AppData" / "Local"))
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    monkeypatch.setattr(cleaner_engine.tempfile, "gettempdir", lambda: home / "Temp")

    for index in range(500):
        (downloads / f"ordinary-{index:03}.bin").write_bytes(bytes([index % 251]) * (index + 2))
    target = downloads / "needle.mp3"
    target.write_bytes(b"x")

    result = CleanerScanEngine().scan(downloads, include_duplicates=False)

    assert result.files_scanned == 501
    assert len(result.all_files) == 501
    assert len(result.largest_files) == 500
    assert all(finding.path != str(target) for finding in result.largest_files)
    assert next(finding for finding in result.all_files if finding.path == str(target)).name == "needle.mp3"
    assert result.location_scope["downloads"]
    assert not result.location_scope["temporary"]


def test_download_findings_explain_partial_installer_archive_and_old_files(monkeypatch, tmp_path):
    home = tmp_path / "home"
    downloads = home / "Downloads"
    downloads.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("LOCALAPPDATA", str(home / "AppData" / "Local"))
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    monkeypatch.setattr(cleaner_engine.tempfile, "gettempdir", lambda: home / "Temp")
    (downloads / "setup.exe").write_bytes(b"installer")
    (downloads / "archive.zip").write_bytes(b"archive")
    (downloads / "in-progress.crdownload").write_bytes(b"partial")
    old = downloads / "old.txt"
    old.write_bytes(b"unknown purpose")
    old_timestamp = (datetime.now().astimezone() - timedelta(days=120)).timestamp()
    os.utime(old, (old_timestamp, old_timestamp))

    result = CleanerScanEngine().scan(downloads, include_duplicates=False)
    findings = {finding.name: finding for finding in result.all_files}

    assert "Installer" in findings["setup.exe"].reason
    assert "not imply it is unnecessary" in findings["setup.exe"].consequence
    assert "Archive" in findings["archive.zip"].reason
    assert "Possible incomplete download" in findings["in-progress.crdownload"].reason
    assert findings["in-progress.crdownload"].recommendation == "Review carefully"
    assert "older than 90 days" in findings["old.txt"].reason


def test_visible_findings_have_scan_time_hash_and_identity(tmp_path):
    root = tmp_path / "Selected"
    root.mkdir()
    source = root / "candidate.txt"
    source.write_bytes(b"candidate content")

    result = CleanerScanEngine().scan(root, include_duplicates=False)

    finding = next(item for item in result.largest_files if item.path == str(source))
    assert finding.sha256 == hashlib.sha256(b"candidate content").hexdigest()
    assert finding.file_signature is not None


def test_scan_does_not_follow_symbolic_link(tmp_path, make_symlink):
    root = tmp_path / "Selected"
    root.mkdir()
    outside = tmp_path / "Outside"
    outside.mkdir()
    (outside / "one.bin").write_bytes(b"outside")
    link = root / "linked"
    make_symlink(link, outside, target_is_directory=True)

    result = CleanerScanEngine().scan(root, include_duplicates=False)

    assert result.files_scanned == 0


@pytest.mark.skipif(os.name != "nt", reason="Windows junction test")
def test_scan_does_not_follow_junction_outside_selected_root(tmp_path, make_junction):
    root = tmp_path / "Selected"
    root.mkdir()
    (root / "inside.bin").write_bytes(b"inside")
    outside = tmp_path / "Outside"
    outside.mkdir()
    (outside / "one.bin").write_bytes(b"outside")
    (outside / "two.bin").write_bytes(b"outside")
    junction = root / "redirect"
    make_junction(junction, outside)
    try:
        result = CleanerScanEngine().scan(root, include_duplicates=False)
    finally:
        if junction.exists():
            os.rmdir(junction)

    assert [finding.name for finding in result.largest_files] == ["inside.bin"]


@pytest.mark.skipif(os.name != "nt", reason="Windows protected-root validation test")
def test_scan_rejects_protected_root_after_handle_validation(monkeypatch, tmp_path):
    root = tmp_path / "Selected"
    root.mkdir()
    monkeypatch.setattr(cleaner_engine, "is_protected_path", lambda *args, **kwargs: True)

    with pytest.raises(ValueError, match="Protected system location"):
        CleanerScanEngine().scan(root, include_duplicates=False)


@pytest.mark.skipif(os.name != "nt", reason="Windows concurrent junction test")
def test_scan_stays_confined_when_directory_is_replaced_with_junction(
    monkeypatch, tmp_path, make_junction
):
    root = tmp_path / "Selected"
    changing = root / "changing"
    changing.mkdir(parents=True)
    (changing / "inside.bin").write_bytes(b"inside")
    outside = tmp_path / "Outside"
    outside.mkdir()
    (outside / "outside.bin").write_bytes(b"outside")
    moved = tmp_path / "changing-before-replacement"
    original_open = cleaner_engine._windows_open_directory
    replaced = False

    def replace_before_open(path, root_final_path):
        nonlocal replaced
        if path == changing and not replaced:
            changing.rename(moved)
            make_junction(changing, outside)
            replaced = True
        return original_open(path, root_final_path)

    monkeypatch.setattr(cleaner_engine, "_windows_open_directory", replace_before_open)
    try:
        result = CleanerScanEngine().scan(root, include_duplicates=False)
    finally:
        if changing.exists() and cleaner_engine.os.name == "nt":
            os.rmdir(changing)

    assert replaced
    assert result.files_scanned == 0


def test_file_modification_during_metadata_scan_is_reported_as_changed(monkeypatch, tmp_path):
    root = tmp_path / "Selected"
    root.mkdir()
    changing = root / "changing.txt"
    changing.write_text("before", encoding="utf-8")
    original_lstat = Path.lstat
    changed = False

    def modify_before_validation(path):
        nonlocal changed
        if path == changing and not changed:
            changing.write_text("after, different size", encoding="utf-8")
            changed = True
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", modify_before_validation)
    result = CleanerScanEngine().scan(root, include_duplicates=False)

    assert changed
    assert result.files_scanned == 0
    assert result.inaccessible_entries == 1


def test_file_replacement_during_metadata_scan_is_reported(monkeypatch, tmp_path):
    root = tmp_path / "Selected"
    root.mkdir()
    target = root / "changing.bin"
    target.write_bytes(b"original")
    replacement = tmp_path / "replacement.bin"
    original_lstat = Path.lstat
    replaced = False

    def replace_before_validation(path):
        nonlocal replaced
        if path == target and not replaced:
            replacement.write_bytes(b"replacement")
            replacement.replace(target)
            replaced = True
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", replace_before_validation)
    result = CleanerScanEngine().scan(root, include_duplicates=False)

    assert replaced
    assert result.files_scanned == 0
    assert result.inaccessible_entries == 1


def test_inaccessible_file_is_counted_without_hiding_successful_entries(monkeypatch, tmp_path):
    root = tmp_path / "Selected"
    root.mkdir()
    blocked = root / "blocked.bin"
    visible = root / "visible.bin"
    blocked.write_bytes(b"blocked")
    visible.write_bytes(b"visible")
    original_lstat = Path.lstat

    def deny_blocked(path):
        if path == blocked:
            raise PermissionError("synthetic access denied")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", deny_blocked)
    result = CleanerScanEngine().scan(root, include_duplicates=False)

    assert result.files_scanned == 1
    assert result.inaccessible_entries == 1
    assert [finding.name for finding in result.largest_files] == ["visible.bin"]


def test_browser_profile_sensitive_files_are_not_inspected_or_hashed(monkeypatch, tmp_path):
    home = tmp_path / "home"
    local = home / "AppData" / "Local"
    profile = local / "Microsoft" / "Edge" / "User Data"
    default = profile / "Default"
    cache = default / "Cache"
    cache.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setattr(cleaner_engine.tempfile, "gettempdir", lambda: home / "Temp")
    for name in ("Cookies", "History", "Login Data", "Web Data"):
        (default / name).write_bytes(b"sensitive profile data")
    (cache / "cache.bin").write_bytes(b"cache metadata only")

    result = CleanerScanEngine().scan(local, include_duplicates=True)

    assert result.files_scanned == 1
    assert result.location_totals["browser_cache"]["files"] == 1
    assert [finding.name for finding in result.largest_files] == ["cache.bin"]
    assert result.duplicates == []


def test_cache_classifier_only_identifies_cache_subdirectories():
    profile = Path("C:/Users/test/AppData/Local/Google/Chrome/User Data")
    roots = {"browser_cache": [profile]}

    assert classify_location(profile / "Default" / "Cache" / "cache.bin", roots)[0] == "browser_cache"
    assert classify_location(profile / "Default" / "Cookies", roots)[0] == "other"
    assert classify_location(profile / "Default" / "History", roots)[0] == "other"


def test_temporary_developer_cache_and_download_classifiers(tmp_path):
    locations = {
        "temporary": [tmp_path / "Temp"],
        "developer_cache": [tmp_path / ".npm-cache"],
        "downloads": [tmp_path / "Downloads"],
    }

    assert classify_location(tmp_path / "Temp" / "scratch.tmp", locations)[0] == "temporary"
    assert classify_location(tmp_path / ".npm-cache" / "package", locations)[0] == "developer_cache"
    assert classify_location(tmp_path / "Downloads" / "archive.zip", locations)[0] == "downloads"


def test_same_size_non_duplicates_are_not_grouped(tmp_path):
    root = tmp_path / "Selected"
    root.mkdir()
    (root / "one.bin").write_bytes(b"first")
    (root / "two.bin").write_bytes(b"other")

    result = CleanerScanEngine().scan(root)

    assert result.duplicates == []


def test_duplicate_potential_does_not_count_hardlink_aliases(tmp_path):
    root = tmp_path / "Selected"
    root.mkdir()
    original = root / "original.bin"
    alias = root / "alias.bin"
    copy = root / "copy.bin"
    original.write_bytes(b"identical payload")
    try:
        os.link(original, alias)
    except OSError as error:
        pytest.skip(f"Hard-link creation is unavailable: {error}")
    copy.write_bytes(b"identical payload")

    result = CleanerScanEngine().scan(root)

    assert len(result.duplicates) == 1
    assert len(result.duplicates[0]) == 3
    assert result.duplicate_potential_bytes == original.stat().st_size


def test_cancellation_stops_scan_without_mutating_files(tmp_path):
    root = tmp_path / "Selected"
    root.mkdir()
    file_path = root / "original.txt"
    file_path.write_text("unchanged", encoding="utf-8")
    before = _snapshot(root)
    cancellation = Event()
    cancellation.set()

    with pytest.raises(ScanCancelled):
        CleanerScanEngine().scan(
            root,
            cancellation_event=cancellation,
            include_duplicates=False,
        )

    assert _snapshot(root) == before


def test_cancellation_during_inventory_stops_before_completion(tmp_path):
    root = tmp_path / "Selected"
    root.mkdir()
    for index in range(120):
        (root / f"item-{index:03}.txt").write_text("unchanged", encoding="utf-8")
    cancellation = Event()
    progress_calls = 0

    def cancel_after_progress(_stage, _files, _size):
        nonlocal progress_calls
        progress_calls += 1
        cancellation.set()

    with pytest.raises(ScanCancelled):
        CleanerScanEngine().scan(
            root,
            cancellation_event=cancellation,
            progress_callback=cancel_after_progress,
            include_duplicates=False,
        )

    assert progress_calls == 1


def test_history_stores_aggregate_statistics_without_scan_paths(tmp_path):
    root = tmp_path / "PrivateFolder"
    root.mkdir()
    (root / "private-name.txt").write_text("content", encoding="utf-8")
    result = CleanerScanEngine().scan(root, include_duplicates=False)
    history = ScanHistory(tmp_path / "history.sqlite3")

    history.record(result)
    entries = history.recent()

    assert len(entries) == 1
    assert entries[0].files_scanned == 1
    with history._connect() as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(scan_history)")}
    assert "root" not in columns
    assert "file_path" not in columns
