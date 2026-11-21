from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import os
from pathlib import Path
import time
from threading import Event

os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

import pdcm.ui.cleaner_dashboard as cleaner_dashboard
from pdcm.engines.cleaner_engine import CleanerScanResult, FileFinding
from pdcm.engines.duplicate_engine import DuplicateItem
from pdcm.services.scan_control import ScanCancelled
from pdcm.services.scan_history import ScanHistory
from pdcm.ui.cleaner_dashboard import CleanerDashboard


@pytest.fixture
def app(monkeypatch):
    application = QApplication.instance() or QApplication([])
    monkeypatch.setattr(cleaner_dashboard, "drive_summaries", lambda: ([], 0))
    return application


def _dashboard(monkeypatch, tmp_path):
    monkeypatch.setattr(
        cleaner_dashboard,
        "ScanHistory",
        lambda: ScanHistory(tmp_path / "history.sqlite3"),
    )
    return CleanerDashboard()


def _wait_for(app, predicate, timeout_ms=5000):
    deadline = time.monotonic() + timeout_ms / 1000
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return
        QTest.qWait(10)
    assert predicate(), "Timed out waiting for the UI operation to finish."


def _finding(path, size, *, modified_days=0, extension=".bin", kind="Other", category="other", index=1):
    modified_ns = int(
        (datetime.now().astimezone() - timedelta(days=modified_days)).timestamp() * 1_000_000_000
    )
    content_hash = hashlib.sha256(f"{path}:{size}".encode("utf-8")).hexdigest()
    signature = (1, index, size, modified_ns, modified_ns)
    reason = "Found in the user-selected folder"
    return FileFinding(
        str(path),
        Path(path).name,
        size,
        modified_ns,
        extension,
        kind,
        category,
        reason,
        "Do not recommend cleaning",
        "No cleanup suitability is inferred from file age or size.",
        signature,
        content_hash,
    )


def _result(root, findings, duplicates=None, location_scope=None):
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    largest = sorted(findings, key=lambda item: (-item.size, item.path.casefold()))[:500]
    old_files = sorted(
        (item for item in findings if (datetime.now().timestamp() - item.modified_ns / 1e9) >= 30 * 86400),
        key=lambda item: (-item.size, item.path.casefold()),
    )[:500]
    location_files = {
        category: sorted(
            (item for item in findings if item.location_category == category),
            key=lambda item: (-item.size, item.path.casefold()),
        )[:200]
        for category in ("temporary", "browser_cache", "developer_cache", "downloads")
    }
    location_totals = {
        category: {
            "files": sum(item.location_category == category for item in findings),
            "bytes": sum(
                item.size for item in findings if item.location_category == category
            ),
        }
        for category in ("temporary", "browser_cache", "developer_cache", "downloads", "other")
    }
    type_totals = {}
    kind_totals = {}
    for item in findings:
        type_bucket = type_totals.setdefault(item.extension, {"files": 0, "bytes": 0})
        type_bucket["files"] += 1
        type_bucket["bytes"] += item.size
        kind_bucket = kind_totals.setdefault(item.kind, {"files": 0, "bytes": 0})
        kind_bucket["files"] += 1
        kind_bucket["bytes"] += item.size
    return CleanerScanResult(
        root=str(root),
        started_at=now,
        elapsed_seconds=0.1,
        files_scanned=len(findings),
        directories_scanned=1,
        bytes_scanned=sum(item.size for item in findings),
        inaccessible_entries=0,
        largest_files=largest,
        largest_directories=[],
        old_files=old_files,
        location_files=location_files,
        location_totals=location_totals,
        type_totals=type_totals,
        kind_totals=kind_totals,
        old_totals={days: {"files": 0, "bytes": 0} for days in (30, 90, 180)},
        large_totals={
            size: {"files": 0, "bytes": 0}
            for size in (100 * 1024**2, 500 * 1024**2, 1024**3)
        },
        duplicates=duplicates or [],
        all_files=list(findings),
        location_all_files={
            category: sorted(
                (item for item in findings if item.location_category == category),
                key=lambda item: (-item.size, item.path.casefold()),
            )
            for category in ("temporary", "browser_cache", "developer_cache", "downloads")
        },
        location_scope=location_scope
        or {
            category: False
            for category in ("temporary", "browser_cache", "developer_cache", "downloads")
        },
    )


def test_dashboard_tabs_and_destructive_controls_remain_gated(monkeypatch, tmp_path, app):
    dashboard = _dashboard(monkeypatch, tmp_path)
    tab_names = [dashboard.tabs.tabText(index) for index in range(dashboard.tabs.count())]
    button_names = [
        button.text().casefold()
        for button in dashboard.findChildren(cleaner_dashboard.QPushButton)
    ]

    assert {
        "Storage",
        "Large & old files",
        "Duplicates",
        "Temporary files",
        "Browser cache",
        "Developer caches",
        "Downloads",
        "Startup & performance",
        "History",
        "Settings",
        "Quarantine & restore",
    }.issubset(tab_names)
    assert any("analyze selected folder" in name for name in button_names)
    assert "cancel" in button_names
    assert any("refresh restore points" in name for name in button_names)
    assert not any("delete" in name or "clean" in name for name in button_names)
    assert not dashboard.quarantine_button.isEnabled()
    assert not dashboard.restore_button.isEnabled()

    dashboard._quarantine_selected()
    dashboard._restore_selected()

    assert dashboard._quarantine_worker is None
    assert "disabled" in dashboard.status.text().casefold()
    dashboard.close()
    app.processEvents()


def test_choose_folder_clears_stale_results_and_enables_analysis(monkeypatch, tmp_path, app):
    dashboard = _dashboard(monkeypatch, tmp_path)
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    dashboard._refresh_quarantine = lambda: None
    folders = iter((str(first), str(second)))
    monkeypatch.setattr(
        cleaner_dashboard.QFileDialog,
        "getExistingDirectory",
        lambda *_args, **_kwargs: next(folders),
    )

    QTest.mouseClick(dashboard.choose_button, Qt.MouseButton.LeftButton)
    dashboard._result = _result(first, [])
    QTest.mouseClick(dashboard.choose_button, Qt.MouseButton.LeftButton)

    assert dashboard.root_label.text() == str(second)
    assert dashboard._result is None
    assert dashboard.scan_button.isEnabled()
    assert dashboard.storage_summary.text() == "Selected folder has not been analyzed."
    dashboard.close()
    app.processEvents()


def test_scan_button_completes_read_only_scan_of_synthetic_folder(monkeypatch, tmp_path, app):
    root = tmp_path / "selected"
    root.mkdir()
    file_path = root / "example.txt"
    file_path.write_text("unchanged", encoding="utf-8")
    before = file_path.read_bytes()
    dashboard = _dashboard(monkeypatch, tmp_path)
    dashboard.root_label.setText(str(root))
    dashboard.scan_button.setEnabled(True)
    dashboard._refresh_quarantine = lambda: None

    QTest.mouseClick(dashboard.scan_button, Qt.MouseButton.LeftButton)
    _wait_for(app, lambda: dashboard._worker is None)

    assert dashboard._result is not None
    assert dashboard._result.files_scanned == 1
    assert "analysis complete" in dashboard.status.text().casefold()
    assert file_path.read_bytes() == before
    assert dashboard.choose_button.isEnabled()
    assert not dashboard.cancel_button.isEnabled()
    dashboard.close()
    app.processEvents()


def test_cancel_stops_scan_and_does_not_present_partial_results(monkeypatch, tmp_path, app):
    root = tmp_path / "selected"
    root.mkdir()
    file_path = root / "unchanged.txt"
    file_path.write_text("synthetic", encoding="utf-8")
    started = Event()
    dashboard = _dashboard(monkeypatch, tmp_path)
    dashboard.root_label.setText(str(root))
    dashboard.scan_button.setEnabled(True)
    dashboard._refresh_quarantine = lambda: None

    class CancellableEngine:
        def scan(self, _root, *, cancellation_event, progress_callback):
            started.set()
            while not cancellation_event.is_set():
                time.sleep(0.005)
            raise ScanCancelled()

    monkeypatch.setattr(cleaner_dashboard, "CleanerScanEngine", CancellableEngine)
    QTest.mouseClick(dashboard.scan_button, Qt.MouseButton.LeftButton)
    assert started.wait(2)
    assert dashboard.cancel_button.isEnabled()
    QTest.mouseClick(dashboard.cancel_button, Qt.MouseButton.LeftButton)
    _wait_for(app, lambda: dashboard._worker is None)

    assert dashboard._result is None
    assert "cancelled" in dashboard.status.text().casefold()
    assert file_path.read_text(encoding="utf-8") == "synthetic"
    dashboard.close()
    app.processEvents()


def test_large_file_search_extension_age_and_folder_grouping_cover_full_inventory(
    monkeypatch, tmp_path, app
):
    findings = [
        _finding(
            tmp_path / "z-folder" / "needle.mp3",
            1,
            modified_days=200,
            extension=".mp3",
            index=1,
        )
    ]
    findings.extend(
        _finding(
            tmp_path / ("b-folder" if index % 2 else "a-folder") / f"other-{index:03}.bin",
            index + 10,
            index=index + 2,
        )
        for index in range(500)
    )
    dashboard = _dashboard(monkeypatch, tmp_path)
    dashboard._render_result(_result(tmp_path, findings))

    assert dashboard.large_table.rowCount() == 500
    dashboard.large_search_input.setText("needle")
    QTest.qWait(200)
    assert dashboard.large_table.rowCount() == 1
    assert dashboard.large_table.item(0, 0).text() == "needle.mp3"

    dashboard.large_search_input.clear()
    dashboard.extension_combo.setCurrentText(".mp3")
    assert dashboard.large_table.rowCount() == 1
    dashboard.old_age_combo.setCurrentIndex(3)
    assert dashboard.large_table.rowCount() == 1

    dashboard.extension_combo.setCurrentIndex(0)
    dashboard.old_age_combo.setCurrentIndex(0)
    dashboard.large_sort_combo.setCurrentIndex(1)
    folders = [
        dashboard.large_table.item(row, 1).text()
        for row in range(dashboard.large_table.rowCount())
    ]
    assert folders == sorted(folders, key=str.casefold)

    dashboard.large_sort_combo.setCurrentIndex(0)
    sizes = [
        int(dashboard.large_table.item(row, 2).data(cleaner_dashboard._SORT_ROLE))
        for row in range(dashboard.large_table.rowCount())
    ]
    assert sizes == sorted(sizes, reverse=True)
    dashboard.close()
    app.processEvents()


def test_duplicate_selection_keeps_a_copy_unselected_and_shows_selection_summary(
    monkeypatch, tmp_path, app
):
    first = _finding(tmp_path / "a.bin", 16, index=1)
    second = _finding(tmp_path / "b.bin", 16, index=2)
    group = [
        DuplicateItem(first.path, 16, first.sha256, (1, 1), first.file_signature),
        DuplicateItem(second.path, 16, first.sha256, (1, 2), second.file_signature),
    ]
    dashboard = _dashboard(monkeypatch, tmp_path)
    dashboard._render_result(_result(tmp_path, [first, second], duplicates=[group]))

    rows_by_path = {
        dashboard.review_table.item(row, 1).text(): row
        for row in range(dashboard.review_table.rowCount())
    }
    first_row = rows_by_path[first.path]
    second_row = rows_by_path[second.path]
    dashboard.review_table.item(first_row, 0).setCheckState(Qt.CheckState.Checked)
    dashboard.review_table.item(second_row, 0).setCheckState(Qt.CheckState.Checked)

    assert len(dashboard._selected_candidates()) == 1
    assert dashboard.review_table.item(second_row, 0).checkState() == Qt.CheckState.Unchecked
    assert "leave at least one verified copy" in dashboard.status.text().casefold()
    assert "16.0 B logical size selected" in dashboard.review_selection_summary.text()
    assert not dashboard.quarantine_button.isEnabled()
    dashboard.close()
    app.processEvents()


def test_large_review_and_duplicate_tables_are_paged(monkeypatch, tmp_path, app):
    findings = [
        _finding(tmp_path / f"file-{index:03}.bin", index // 2 + 1, index=index + 1)
        for index in range(203)
    ]
    duplicate_groups = [
        [
            DuplicateItem(
                findings[index].path,
                findings[index].size,
                findings[index].sha256,
                (1, index + 1),
                findings[index].file_signature,
            ),
            DuplicateItem(
                findings[index + 1].path,
                findings[index + 1].size,
                findings[index].sha256,
                (1, index + 2),
                findings[index + 1].file_signature,
            ),
        ]
        for index in range(0, 202, 2)
    ]
    dashboard = _dashboard(monkeypatch, tmp_path)
    dashboard._render_result(_result(tmp_path, findings, duplicates=duplicate_groups))

    assert dashboard.review_table.rowCount() == 200
    assert dashboard.review_next_button.isEnabled()
    dashboard.review_table.item(0, 0).setCheckState(Qt.CheckState.Checked)
    dashboard.review_next_button.click()
    assert dashboard.review_table.rowCount() == 3
    assert "Page 2/2" in dashboard.review_page_label.text()
    assert len(dashboard._selected_candidates()) == 1
    dashboard.review_previous_button.click()
    assert dashboard.review_table.rowCount() == 200
    assert any(
        dashboard.review_table.item(row, 0).checkState() == Qt.CheckState.Checked
        for row in range(dashboard.review_table.rowCount())
    )
    assert dashboard.duplicate_table.rowCount() == 200
    assert dashboard.duplicate_next_button.isEnabled()
    dashboard.duplicate_next_button.click()
    assert dashboard.duplicate_table.rowCount() == 2
    dashboard.close()
    app.processEvents()


def test_category_empty_states_explain_scope_and_privacy(monkeypatch, tmp_path, app):
    dashboard = _dashboard(monkeypatch, tmp_path)
    dashboard._render_result(_result(tmp_path, []))

    assert "outside recognized temporary-file locations" in dashboard.location_summaries["temporary"].text()
    assert "No supported browser-cache location" in dashboard.location_summaries["browser_cache"].text()
    assert "Sensitive browser-profile data is not scanned" in dashboard.location_summaries["browser_cache"].text()
    assert "outside recognized Downloads locations" in dashboard.location_summaries["downloads"].text()
    assert "No exact duplicate groups" in dashboard.duplicate_summary.text()
    assert "No completed scans" in dashboard.history_status.text()

    in_scope = _result(
        tmp_path,
        [],
        location_scope={
            "temporary": True,
            "browser_cache": True,
            "developer_cache": True,
            "downloads": True,
        },
    )
    in_scope.inaccessible_entries = 2
    dashboard._render_result(in_scope)
    assert "recognized temporary-file location" in dashboard.location_summaries["temporary"].text()
    assert "no matching files were found" in dashboard.location_summaries["temporary"].text()
    assert "2 inaccessible or changed entries" in dashboard.location_summaries["temporary"].text()
    dashboard.close()
    app.processEvents()


def test_location_pages_show_all_downloads_and_duplicate_context(monkeypatch, tmp_path, app):
    findings = [
        _finding(
            tmp_path / "Downloads" / f"file-{index:03}.exe",
            1 if index < 2 else index + 1,
            extension=".exe",
            kind="Installer",
            category="downloads",
            index=index + 1,
        )
        for index in range(201)
    ]
    group = [
        DuplicateItem(findings[0].path, 1, findings[0].sha256, (1, 1), findings[0].file_signature),
        DuplicateItem(findings[1].path, 1, findings[0].sha256, (1, 2), findings[1].file_signature),
    ]
    scope = {
        "temporary": False,
        "browser_cache": False,
        "developer_cache": False,
        "downloads": True,
    }
    dashboard = _dashboard(monkeypatch, tmp_path)
    dashboard._render_result(_result(tmp_path, findings, duplicates=[group], location_scope=scope))

    assert dashboard.location_tables["downloads"].rowCount() == 200
    assert dashboard.location_next_buttons["downloads"].isEnabled()
    dashboard.location_next_buttons["downloads"].click()
    assert "Exact SHA-256 duplicate group" in dashboard.location_tables["downloads"].item(0, 4).text()
    assert dashboard.location_tables["downloads"].rowCount() == 1
    dashboard.close()
    app.processEvents()


def test_refresh_restore_points_works_without_enabling_restore(monkeypatch, tmp_path, app):
    root = tmp_path / "selected"
    root.mkdir()
    dashboard = _dashboard(monkeypatch, tmp_path)
    dashboard.root_label.setText(str(root))

    QTest.mouseClick(dashboard.quarantine_refresh_button, Qt.MouseButton.LeftButton)
    _wait_for(app, lambda: dashboard._quarantine_worker is None)

    assert "Loaded 0 quarantine operation" in dashboard.status.text()
    assert "Loaded 0 recorded restore point" in dashboard.restore_note.text()
    assert not dashboard.quarantine_button.isEnabled()
    assert not dashboard.restore_button.isEnabled()
    dashboard.close()
    app.processEvents()


def test_system_snapshot_refresh_is_background_and_tab_navigation_works(
    monkeypatch, tmp_path, app
):
    dashboard = _dashboard(monkeypatch, tmp_path)
    started = Event()
    release = Event()

    def delayed_process_snapshot():
        started.set()
        release.wait(2)
        return 12.5, [], 0

    monkeypatch.setattr(cleaner_dashboard, "process_summaries", delayed_process_snapshot)
    monkeypatch.setattr(cleaner_dashboard, "startup_entries", lambda: ([], 0))
    monkeypatch.setattr(cleaner_dashboard, "memory_summary", lambda: "42% used · 8.0 GB available")
    monkeypatch.setattr(cleaner_dashboard.psutil, "process_iter", lambda *_args, **_kwargs: [])

    performance_index = next(
        index
        for index in range(dashboard.tabs.count())
        if dashboard.tabs.tabText(index) == "Startup & performance"
    )
    dashboard.tabs.setCurrentIndex(performance_index)
    assert started.wait(2)
    assert not dashboard.refresh_system_button.isEnabled()
    dashboard.tabs.setCurrentIndex(0)
    assert dashboard.tabs.currentIndex() == 0
    release.set()
    _wait_for(app, lambda: dashboard._system_worker is None)
    assert "12.5%" in dashboard.performance_summary.text()

    monkeypatch.setattr(cleaner_dashboard, "process_summaries", lambda: (12.5, [], 0))
    dashboard.tabs.setCurrentIndex(performance_index)
    _wait_for(app, lambda: dashboard._system_worker is None)
    QTest.mouseClick(dashboard.refresh_system_button, Qt.MouseButton.LeftButton)
    _wait_for(app, lambda: dashboard._system_worker is None)
    assert "read-only snapshots" in dashboard.performance_summary.text()
    assert dashboard.refresh_system_button.isEnabled()
    dashboard.close()
    app.processEvents()
