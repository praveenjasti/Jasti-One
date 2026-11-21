from __future__ import annotations

from datetime import datetime
import os
import sqlite3
from threading import Event

import psutil
from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..engines.cleaner_engine import CleanerScanEngine, CleanerScanResult, FileFinding
from ..services.scan_control import ScanCancelled
from ..services.quarantine import (
    QuarantineCandidate,
    QuarantineOperation,
    QuarantineService,
)
from ..services.scan_history import ScanHistory
from ..services.system_info import (
    drive_summaries,
    memory_summary,
    process_summaries,
    startup_entries,
)

QUARANTINE_OPERATIONS_ENABLED = False


def _format_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if amount < 1024 or unit == "TB":
            return f"{amount:,.1f} {unit}"
        amount /= 1024
    return f"{amount:,.1f} TB"


def _format_timestamp(value_ns: int) -> str:
    try:
        return datetime.fromtimestamp(value_ns / 1_000_000_000).astimezone().isoformat(timespec="minutes")
    except (OSError, OverflowError, ValueError):
        return "Unknown"


def _table(headers: list[str]) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setAlternatingRowColors(True)
    table.setWordWrap(False)
    table.setSortingEnabled(True)
    table.horizontalHeader().setStretchLastSection(True)
    return table


def _put_rows(table: QTableWidget, rows: list[list[str]]) -> None:
    table.setSortingEnabled(False)
    table.setRowCount(len(rows))
    for row_index, values in enumerate(rows):
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            table.setItem(row_index, column, item)
    table.setSortingEnabled(True)
    table.resizeColumnsToContents()


class _ScanWorker(QThread):
    progress = Signal(str, int, int)
    completed = Signal(object)
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, root: str):
        super().__init__()
        self.root = root
        self.cancellation_event = Event()

    def cancel(self) -> None:
        self.cancellation_event.set()

    def run(self) -> None:
        try:
            result = CleanerScanEngine().scan(
                self.root,
                cancellation_event=self.cancellation_event,
                progress_callback=self.progress.emit,
            )
        except ScanCancelled:
            self.cancelled.emit()
        except Exception as error:
            self.failed.emit(str(error) or error.__class__.__name__)
        else:
            self.completed.emit(result)


class _QuarantineWorker(QThread):
    completed = Signal(object)
    failed = Signal(str, object)

    def __init__(
        self,
        action: str,
        root: str,
        candidates: list[QuarantineCandidate] | None = None,
        duplicate_groups: list[list[QuarantineCandidate]] | None = None,
        operation_ids: list[str] | None = None,
    ):
        super().__init__()
        self.action = action
        self.root = root
        self.candidates = candidates or []
        self.duplicate_groups = duplicate_groups or []
        self.operation_ids = operation_ids or []

    def run(self) -> None:
        completed: list[QuarantineOperation] = []
        try:
            if self.action in {"quarantine", "restore"} and not QUARANTINE_OPERATIONS_ENABLED:
                raise RuntimeError("Quarantine and restore are disabled until the security gate is cleared.")
            service = QuarantineService(self.root)
            if self.action == "list":
                completed = service.list_operations()
            elif self.action == "quarantine":
                service.quarantine_selected(self.candidates, self.duplicate_groups)
                completed = service.list_operations()
            elif self.action == "restore":
                for operation_id in self.operation_ids:
                    service.restore(operation_id)
                completed = service.list_operations()
            else:
                raise ValueError("Unsupported quarantine action.")
        except Exception as error:
            if self.action in {"quarantine", "restore"}:
                try:
                    completed = QuarantineService(self.root).list_operations()
                except Exception as listing_error:
                    self.failed.emit(
                        f"{error} The quarantine operation list could not be refreshed: {listing_error}",
                        completed,
                    )
                    return
            self.failed.emit(str(error) or error.__class__.__name__, completed)
        else:
            self.completed.emit(completed)


class CleanerDashboard(QWidget):
    def __init__(self):
        super().__init__()
        self._worker: _ScanWorker | None = None
        self._quarantine_worker: _QuarantineWorker | None = None
        self._result: CleanerScanResult | None = None
        self._review_candidates: dict[str, QuarantineCandidate] = {}
        self._review_groups: list[list[QuarantineCandidate]] = []
        self._history = ScanHistory()
        self._browser_note = "Browser process state has not been checked."
        self.setObjectName("cleanerDashboard")
        self.setStyleSheet(
            "#cleanerDashboard { background: #F6F8FB; } "
            "#cleanerDashboard QPushButton { border: 1px solid #C9D3E0; border-radius: 5px; background: white; } "
            "#cleanerDashboard QPushButton:hover { border-color: #2878C8; color: #155B9A; } "
            "#cleanerDashboard QTabBar::tab { padding: 8px 12px; } "
            "#cleanerDashboard QTabBar::tab:selected { color: #155B9A; font-weight: 600; } "
            "#cleanerDashboard QTableWidget { background: white; gridline-color: #E5EAF0; }"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        brand = QLabel("JASTI CLEANER  ·  ANALYSIS ONLY")
        brand.setStyleSheet("font-size: 12px; font-weight: 750; letter-spacing: 2px; color: #2878C8;")
        layout.addWidget(brand)
        title = QLabel("Understand your storage")
        title.setStyleSheet("font-size: 26px; font-weight: 700;")
        layout.addWidget(title)
        description = QLabel(
            "Choose a folder to review its storage and duplicates. Analysis is local and read-only. "
            "Quarantine and restore are disabled while the security review is open; no files are moved."
        )
        description.setWordWrap(True)
        layout.addWidget(description)

        controls = QHBoxLayout()
        self.root_label = QLabel("No folder selected")
        self.root_label.setStyleSheet("padding: 8px; border: 1px solid #D5DCE5; border-radius: 5px;")
        self.root_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.choose_button = QPushButton("Choose folder…")
        self.choose_button.clicked.connect(self._choose_folder)
        self.scan_button = QPushButton("Analyze selected folder")
        self.scan_button.setEnabled(False)
        self.scan_button.clicked.connect(self._start_scan)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel_scan)
        controls.addWidget(self.root_label, 1)
        controls.addWidget(self.choose_button)
        controls.addWidget(self.scan_button)
        controls.addWidget(self.cancel_button)
        layout.addLayout(controls)

        self.status = QLabel("No scan has been run.")
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        layout.addWidget(self.status)
        layout.addWidget(self.progress)

        metrics = QGridLayout()
        self.metric_values: dict[str, QLabel] = {}
        for column, (key, title) in enumerate(
            (
                ("files", "Files analyzed"),
                ("size", "Logical size"),
                ("groups", "Exact duplicate groups"),
                ("potential", "Potential duplicate bytes"),
            )
        ):
            card = QFrame()
            card.setFrameShape(QFrame.Shape.StyledPanel)
            card.setStyleSheet("QFrame { background: white; border: 1px solid #E1E7EF; border-radius: 6px; }")
            card_layout = QVBoxLayout(card)
            label = QLabel(title)
            value = QLabel("—")
            value.setStyleSheet("font-size: 19px; font-weight: 650; color: #203248;")
            card_layout.addWidget(label)
            card_layout.addWidget(value)
            metrics.addWidget(card, 0, column)
            self.metric_values[key] = value
        layout.addLayout(metrics)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self.overview_tab = QScrollArea()
        self.overview_tab.setWidgetResizable(True)
        overview_content = QWidget()
        self.storage_summary = QLabel("Select a folder and start an analysis to see measured results.")
        self.storage_summary.setWordWrap(True)
        self.drives_table = _table(["Drive", "Total", "Used", "Free"])
        self.drive_status = QLabel("Drive capacity is not a storage scan.")
        self.directory_table = _table(["Largest directories within selected folder", "Logical size"])
        self.type_table = _table(["File type", "Files", "Logical size"])
        overview_layout = QVBoxLayout(overview_content)
        overview_layout.addWidget(self.storage_summary)
        drives_heading = QLabel("Available drives (capacity metadata only; not scanned):")
        drives_heading.setWordWrap(True)
        overview_layout.addWidget(drives_heading)
        overview_layout.addWidget(self.drives_table)
        self.drive_status.setWordWrap(True)
        overview_layout.addWidget(self.drive_status)
        overview_layout.addWidget(self.directory_table)
        overview_layout.addWidget(self.type_table)
        self.directory_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.overview_tab.setWidget(overview_content)
        self.tabs.addTab(self.overview_tab, "Storage")

        self.large_tab = QWidget()
        large_layout = QVBoxLayout(self.large_tab)
        large_filters = QHBoxLayout()
        self.large_size_combo = QComboBox()
        self.large_size_combo.addItems(["Any size", "At least 100 MB", "At least 500 MB", "At least 1 GB"])
        self.large_size_combo.currentIndexChanged.connect(self._update_large_files)
        self.old_age_combo = QComboBox()
        self.old_age_combo.addItems(["Any age", "Older than 30 days", "Older than 90 days", "Older than 180 days"])
        self.old_age_combo.currentIndexChanged.connect(self._update_large_files)
        self.file_kind_combo = QComboBox()
        self.file_kind_combo.addItems(["Any type", "Video", "Archive", "Installer", "Disk image"])
        self.file_kind_combo.currentIndexChanged.connect(self._update_large_files)
        large_filters.addWidget(QLabel("Size:"))
        large_filters.addWidget(self.large_size_combo)
        large_filters.addWidget(QLabel("Modified:"))
        large_filters.addWidget(self.old_age_combo)
        large_filters.addWidget(QLabel("Type:"))
        large_filters.addWidget(self.file_kind_combo)
        large_filters.addStretch()
        large_layout.addLayout(large_filters)
        self.large_summary = QLabel("Filters identify files for review only; age or size does not mean a file is unnecessary.")
        self.large_summary.setWordWrap(True)
        self.large_table = _table(["File", "Size", "Modified", "Type", "Review guidance"])
        large_layout.addWidget(self.large_summary)
        large_layout.addWidget(self.large_table, 1)
        self.tabs.addTab(self.large_tab, "Large & old files")

        self.duplicate_tab = QWidget()
        duplicate_layout = QVBoxLayout(self.duplicate_tab)
        self.duplicate_summary = QLabel("Exact duplicates are verified by SHA-256 after size and quick-fingerprint grouping.")
        self.duplicate_summary.setWordWrap(True)
        self.duplicate_table = _table(["Group", "File", "Size", "SHA-256"])
        duplicate_layout.addWidget(self.duplicate_summary)
        duplicate_layout.addWidget(self.duplicate_table, 1)
        self.tabs.addTab(self.duplicate_tab, "Duplicates")

        self.location_tables: dict[str, QTableWidget] = {}
        self.location_summaries: dict[str, QLabel] = {}
        for tab_name, key, label in (
            ("Temporary files", "temporary", "Recognized temporary directory"),
            ("Browser cache", "browser_cache", "Edge, Chrome, and Firefox cache/profile locations"),
            ("Developer caches", "developer_cache", "Package and build caches; rebuilds or downloads may be needed"),
            ("Downloads", "downloads", "Downloads are reviewed, never assumed disposable"),
        ):
            page = QWidget()
            page_layout = QVBoxLayout(page)
            summary = QLabel(
                f"Only files inside the selected folder are analyzed. {label} findings are shown when that "
                "known location is within the selected scope."
            )
            summary.setWordWrap(True)
            table = _table(
                ["File", "Size", "Modified", "Review category", "Why identified", "Consequences", "Usage status"]
            )
            page_layout.addWidget(summary)
            page_layout.addWidget(table, 1)
            self.tabs.addTab(page, tab_name)
            self.location_tables[key] = table
            self.location_summaries[key] = summary

        self.performance_tab = QWidget()
        performance_layout = QVBoxLayout(self.performance_tab)
        self.performance_summary = QLabel("RAM and process metrics are read-only system snapshots.")
        self.performance_summary.setWordWrap(True)
        self.startup_table = _table(["Startup application", "Source", "Configured command (not executed)"])
        self.process_table = _table(["Process", "PID", "RAM", "CPU"])
        self.refresh_system_button = QPushButton("Refresh startup and process snapshot")
        self.refresh_system_button.clicked.connect(self._load_system_overview)
        performance_layout.addWidget(self.performance_summary)
        performance_layout.addWidget(self.refresh_system_button)
        performance_layout.addWidget(QLabel("Startup entries"))
        performance_layout.addWidget(self.startup_table, 1)
        performance_layout.addWidget(QLabel("Processes with highest reported RAM use"))
        performance_layout.addWidget(self.process_table, 1)
        self.tabs.addTab(self.performance_tab, "Startup & performance")

        self.history_tab = QWidget()
        history_layout = QVBoxLayout(self.history_tab)
        self.history_table = _table(
            ["Time", "Files", "Folders", "Logical size", "Duplicate groups", "Potential duplicate bytes", "Seconds", "Inaccessible"]
        )
        history_note = QLabel("Only aggregate statistics are stored locally; scanned paths and file names are not stored.")
        history_note.setWordWrap(True)
        history_layout.addWidget(history_note)
        history_layout.addWidget(self.history_table, 1)
        self.tabs.addTab(self.history_tab, "History")

        settings = QWidget()
        settings_layout = QVBoxLayout(settings)
        settings_layout.addWidget(QLabel("Analysis and recovery settings"))
        settings_note = QLabel(
            "This build is analysis-only. Quarantine and restore remain disabled until independent security "
            "review is complete. There is no permanent deletion, automatic cleanup, telemetry, or cloud upload. "
            "Select each scan scope explicitly. Temporary and cache locations are analyzed only if they fall "
            "inside the selected folder."
        )
        settings_note.setWordWrap(True)
        settings_layout.addWidget(settings_note)
        settings_layout.addStretch()
        self.tabs.addTab(settings, "Settings")

        self.review_tab = QWidget()
        review_layout = QVBoxLayout(self.review_tab)
        self.quarantine_summary = QLabel(
            "Quarantine and restore are disabled pending independent security review. No files are moved."
        )
        self.quarantine_summary.setWordWrap(True)
        self.review_table = _table(
            ["Select", "File", "Size", "Review category", "Why identified", "Potential consequence", "Verification"]
        )
        self.review_table.setSortingEnabled(False)
        self.review_table.setColumnWidth(0, 60)
        self.quarantine_button = QPushButton("Quarantine disabled — security review pending")
        self.quarantine_button.setEnabled(False)
        self.quarantine_button.clicked.connect(self._quarantine_selected)
        review_layout.addWidget(QLabel("Review files from the completed scan"))
        review_layout.addWidget(self.review_table, 1)
        review_layout.addWidget(self.quarantine_summary)
        review_layout.addWidget(self.quarantine_button)
        review_layout.addWidget(QLabel("Restore points for the currently selected scan root"))
        self.quarantine_refresh_button = QPushButton("Refresh restore points")
        self.quarantine_refresh_button.clicked.connect(self._refresh_quarantine)
        self.restore_table = _table(["Operation", "Original file", "Size", "Status", "Operation time"])
        self.restore_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.restore_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.restore_button = QPushButton("Restore disabled — security review pending")
        self.restore_button.setEnabled(False)
        self.restore_button.clicked.connect(self._restore_selected)
        restore_controls = QHBoxLayout()
        restore_controls.addWidget(self.quarantine_refresh_button)
        restore_controls.addWidget(self.restore_button)
        restore_controls.addStretch()
        review_layout.addLayout(restore_controls)
        review_layout.addWidget(self.restore_table, 1)
        self.tabs.addTab(self.review_tab, "Quarantine & restore")

        self._load_drives()
        self._load_history()
        self.tabs.currentChanged.connect(self._tab_changed)

    def _choose_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Choose a folder to analyze")
        if folder:
            self.root_label.setText(folder)
            self.scan_button.setEnabled(True)
            self._result = None
            self._clear_results()
            self.status.setText("Folder selected; no scan has been run for this folder.")
            self._refresh_quarantine()

    def _start_scan(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        root = self.root_label.text()
        if not root or root == "No folder selected":
            QMessageBox.information(self, "Choose a folder", "Select a folder before starting an analysis.")
            return
        self._result = None
        self._clear_results()
        self.scan_button.setEnabled(False)
        self.choose_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.progress.setRange(0, 0)
        self.status.setText(
            "Scanning selected folder; file contents are read only for duplicate and review-candidate hashing."
        )
        worker = _ScanWorker(root)
        worker.progress.connect(self._update_progress)
        worker.completed.connect(self._scan_complete)
        worker.failed.connect(self._scan_failed)
        worker.cancelled.connect(self._scan_cancelled)
        worker.finished.connect(self._worker_finished)
        self._worker = worker
        worker.start()

    def _clear_results(self) -> None:
        self.storage_summary.setText("Selected folder has not been analyzed.")
        for value in self.metric_values.values():
            value.setText("—")
        self.directory_table.setRowCount(0)
        self.type_table.setRowCount(0)
        self.large_table.setRowCount(0)
        self.duplicate_table.setRowCount(0)
        self.review_table.setRowCount(0)
        self.restore_table.setRowCount(0)
        self._review_candidates.clear()
        self._review_groups.clear()
        self.quarantine_button.setEnabled(False)
        self.restore_button.setEnabled(False)
        self.large_summary.setText(
            "Filters identify files for review only; age or size does not mean a file is unnecessary."
        )
        self.duplicate_summary.setText(
            "Exact duplicates are verified by SHA-256 after size and quick-fingerprint grouping."
        )
        for category, table in self.location_tables.items():
            table.setRowCount(0)
            self.location_summaries[category].setText(
                "No completed scan. Only files within the selected scope can appear here."
            )

    def _cancel_scan(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self.status.setText("Cancellation requested; safely stopping the current read-only scan…")
            self.cancel_button.setEnabled(False)

    def _update_progress(self, stage: str, files: int, total_bytes: int) -> None:
        self.status.setText(f"{stage}: {files:,} files inspected · {_format_bytes(total_bytes)} logical size")

    def _scan_complete(self, result: CleanerScanResult) -> None:
        self._result = result
        try:
            self._history.record(result)
        except (sqlite3.Error, OSError) as error:
            self.status.setText(f"Scan complete; local history could not be saved: {error}")
        else:
            self.status.setText(
                f"Analysis complete in {result.elapsed_seconds:.1f}s · {result.files_scanned:,} files · "
                f"{result.inaccessible_entries:,} inaccessible/changed entries"
            )
        self._render_result(result)
        self._load_history()

    def _scan_failed(self, message: str) -> None:
        self.status.setText("Scan failed; no results were presented as successful.")
        QMessageBox.warning(self, "Analysis failed", message)

    def _scan_cancelled(self) -> None:
        self.status.setText("Analysis cancelled. Partial results were not saved or presented as a completed scan.")

    def _worker_finished(self) -> None:
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.choose_button.setEnabled(True)
        self.scan_button.setEnabled(bool(self.root_label.text() and self.root_label.text() != "No folder selected"))
        self.cancel_button.setEnabled(False)
        self._worker = None
        if self._result is not None:
            self._refresh_quarantine()

    def _render_result(self, result: CleanerScanResult) -> None:
        self.metric_values["files"].setText(f"{result.files_scanned:,}")
        self.metric_values["size"].setText(_format_bytes(result.bytes_scanned))
        self.metric_values["groups"].setText(f"{len(result.duplicates):,}")
        self.metric_values["potential"].setText(_format_bytes(result.duplicate_potential_bytes))
        self.storage_summary.setText(
            f"Selected scope: {result.root}\n"
            f"{result.files_scanned:,} files in {result.directories_scanned:,} folders; "
            f"{_format_bytes(result.bytes_scanned)} logical file size. "
            f"{result.inaccessible_entries:,} entries were inaccessible or changed during inspection. "
            "Logical sizes can count hard-linked files more than once and do not equal reclaimable space."
        )
        _put_rows(
            self.directory_table,
            [[item.path, _format_bytes(item.size)] for item in result.largest_directories],
        )
        type_rows = [
            [extension, f"{values['files']:,}", _format_bytes(values["bytes"])]
            for extension, values in sorted(
                result.type_totals.items(),
                key=lambda item: (-item[1]["bytes"], item[0]),
            )
        ]
        _put_rows(self.type_table, type_rows[:200])
        self.large_summary.setText(
            self._large_summary_text(result)
        )
        self._update_large_files()

        duplicate_rows = []
        for group_number, group in enumerate(result.duplicates, start=1):
            for item in group:
                duplicate_rows.append(
                    [str(group_number), item.path, _format_bytes(item.size), item.sha256]
                )
        _put_rows(self.duplicate_table, duplicate_rows)
        self.duplicate_summary.setText(
            f"{len(result.duplicates):,} exact duplicate groups · "
            f"{_format_bytes(result.duplicate_potential_bytes)} potential duplicate bytes "
            "(calculated without selecting a copy; nothing was changed)."
        )
        self._populate_review(result)

        for category, table in self.location_tables.items():
            findings = result.location_files.get(category, [])
            totals = result.location_totals.get(category, {"files": 0, "bytes": 0})
            _put_rows(
                table,
                [
                    [
                        finding.path,
                        _format_bytes(finding.size),
                        _format_timestamp(finding.modified_ns),
                        finding.recommendation,
                        finding.reason,
                        finding.consequence,
                        "Not tested; may be in use",
                    ]
                    for finding in findings
                ],
            )
            self.location_summaries[category].setText(
                f"{totals['files']:,} matching files in selected scope · {_format_bytes(totals['bytes'])}. "
                "Showing up to 200 largest entries. This is analysis only; files may be active or important."
            )
            if category == "browser_cache":
                self.location_summaries[category].setText(
                    self.location_summaries[category].text() + " " + self._browser_note
                )

    def _path_key(self, path: str) -> str:
        absolute = os.path.abspath(path)
        return os.path.normcase(absolute)

    def _populate_review(self, result: CleanerScanResult) -> None:
        self._review_candidates.clear()
        self._review_groups.clear()
        source_findings = [
            *result.largest_files,
            *result.old_files,
            *(finding for values in result.location_files.values() for finding in values),
        ]
        for finding in source_findings:
            key = self._path_key(finding.path)
            self._review_candidates[key] = QuarantineCandidate(
                result.root,
                finding.path,
                finding.size,
                finding.modified_ns,
                finding.file_signature,
                finding.sha256,
                finding.location_category,
                finding.reason,
                finding.consequence,
            )
        for group_number, group in enumerate(result.duplicates, start=1):
            candidates = []
            for item in group:
                key = self._path_key(item.path)
                candidate = QuarantineCandidate(
                    result.root,
                    item.path,
                    item.size,
                    item.file_signature[3] if item.file_signature else 0,
                    item.file_signature,
                    item.sha256,
                    "Exact duplicate",
                    f"SHA-256 matches other file(s) in duplicate group {group_number}.",
                    "At least one verified copy in this group must remain outside quarantine.",
                )
                existing = self._review_candidates.get(key)
                if existing is None:
                    self._review_candidates[key] = candidate
                else:
                    candidate = QuarantineCandidate(
                        existing.root,
                        existing.path,
                        existing.size,
                        existing.modified_ns,
                        item.file_signature,
                        item.sha256,
                        "Exact duplicate",
                        candidate.reason,
                        candidate.consequence,
                    )
                    self._review_candidates[key] = candidate
                candidates.append(self._review_candidates[key])
            self._review_groups.append(candidates)

        self.review_table.setSortingEnabled(False)
        self.review_table.setRowCount(len(self._review_candidates))
        for row, (key, candidate) in enumerate(self._review_candidates.items()):
            checkbox = QTableWidgetItem()
            checkbox.setFlags(
                Qt.ItemFlag.ItemIsEnabled
                | Qt.ItemFlag.ItemIsSelectable
                | Qt.ItemFlag.ItemIsUserCheckable
            )
            checkbox.setCheckState(Qt.CheckState.Unchecked)
            path_item = QTableWidgetItem(candidate.path)
            path_item.setData(Qt.ItemDataRole.UserRole, key)
            verification = (
                "Verified at scan time"
                if candidate.file_signature is not None and candidate.sha256 is not None
                else "Not eligible: scan-time hash/identity unavailable"
            )
            if verification.startswith("Not eligible"):
                checkbox.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.review_table.setItem(row, 0, checkbox)
            self.review_table.setItem(row, 1, path_item)
            for column, value in enumerate(
                (
                    _format_bytes(candidate.size),
                    candidate.category,
                    candidate.reason,
                    candidate.consequence,
                    verification,
                ),
                start=2,
            ):
                self.review_table.setItem(row, column, QTableWidgetItem(value))
        self.review_table.setSortingEnabled(True)
        self.review_table.resizeColumnsToContents()
        self.quarantine_button.setEnabled(
            QUARANTINE_OPERATIONS_ENABLED and bool(self._review_candidates)
        )
        self.quarantine_summary.setText(
            f"{len(self._review_candidates):,} distinct review candidates. "
            "Candidates without scan-time identity and SHA-256 are not selectable. "
            "Quarantined bytes are not freed space; files can be restored."
        )

    def _selected_candidates(self) -> list[QuarantineCandidate]:
        selected = []
        for row in range(self.review_table.rowCount()):
            item = self.review_table.item(row, 0)
            path_item = self.review_table.item(row, 1)
            if item is not None and item.checkState() == Qt.CheckState.Checked and path_item is not None:
                key = path_item.data(Qt.ItemDataRole.UserRole)
                candidate = self._review_candidates.get(key)
                if candidate is not None:
                    selected.append(candidate)
        return selected

    def _quarantine_selected(self) -> None:
        if not QUARANTINE_OPERATIONS_ENABLED:
            self.status.setText("Quarantine is disabled until the independent security review is complete.")
            return
        if self._quarantine_worker is not None and self._quarantine_worker.isRunning():
            return
        selected = self._selected_candidates()
        if not selected:
            QMessageBox.information(self, "Select files", "Select one or more verified files to quarantine.")
            return
        size = sum(candidate.size for candidate in selected)
        answer = QMessageBox.question(
            self,
            "Approve quarantine",
            f"Move {len(selected):,} selected file(s), totaling {_format_bytes(size)}, into a same-volume "
            "quarantine folder under the selected scan root?\n\n"
            "This does not free disk space or permanently delete files. You can restore them later, but an "
            "existing destination will never be overwritten. At least one verified copy must remain in every "
            "selected duplicate group.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        root = self._result.root if self._result is not None else self.root_label.text()
        worker = _QuarantineWorker(
            "quarantine",
            root,
            selected,
            self._review_groups,
        )
        self._start_quarantine_worker(worker)

    def _refresh_quarantine(self) -> None:
        if self._quarantine_worker is not None and self._quarantine_worker.isRunning():
            return
        root = self._result.root if self._result is not None else self.root_label.text()
        if not root or root == "No folder selected":
            self.restore_table.setRowCount(0)
            return
        self._start_quarantine_worker(_QuarantineWorker("list", root))

    def _restore_selected(self) -> None:
        if not QUARANTINE_OPERATIONS_ENABLED:
            self.status.setText("Restore is disabled until the independent security review is complete.")
            return
        if self._quarantine_worker is not None and self._quarantine_worker.isRunning():
            return
        operation_ids = []
        for row in sorted({index.row() for index in self.restore_table.selectionModel().selectedRows()}):
            if self.restore_table.item(row, 3) and self.restore_table.item(row, 3).text() == "QUARANTINED":
                operation_ids.append(self.restore_table.item(row, 0).text())
        if not operation_ids:
            QMessageBox.information(self, "Select restore points", "Select one or more files in QUARANTINED state.")
            return
        answer = QMessageBox.question(
            self,
            "Approve restore",
            f"Restore {len(operation_ids):,} selected file(s) to their original locations? "
            "The operation will fail rather than overwrite any existing destination.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        root = self._result.root if self._result is not None else self.root_label.text()
        self._start_quarantine_worker(_QuarantineWorker("restore", root, operation_ids=operation_ids))

    def _start_quarantine_worker(self, worker: _QuarantineWorker) -> None:
        if worker.action in {"quarantine", "restore"} and not QUARANTINE_OPERATIONS_ENABLED:
            self.status.setText("Quarantine and restore are disabled until the security gate is cleared.")
            return
        if self._quarantine_worker is not None and self._quarantine_worker.isRunning():
            return
        self.quarantine_button.setEnabled(False)
        self.quarantine_refresh_button.setEnabled(False)
        self.restore_button.setEnabled(False)
        self.choose_button.setEnabled(False)
        self.scan_button.setEnabled(False)
        self.status.setText("Validating and recording the approved quarantine operation…")
        worker.completed.connect(self._quarantine_complete)
        worker.failed.connect(self._quarantine_failed)
        worker.finished.connect(self._quarantine_worker_finished)
        self._quarantine_worker = worker
        worker.start()

    def _populate_operations(self, operations: list[QuarantineOperation]) -> None:
        self.restore_table.setSortingEnabled(False)
        self.restore_table.setRowCount(len(operations))
        for row, operation in enumerate(operations):
            for column, value in enumerate(
                (
                    operation.operation_id,
                    operation.original_path,
                    _format_bytes(operation.size),
                    operation.status,
                    operation.created_at,
                )
            ):
                self.restore_table.setItem(row, column, QTableWidgetItem(value))
        self.restore_table.setSortingEnabled(True)
        self.restore_table.resizeColumnsToContents()

    def _quarantine_complete(self, operations: list[QuarantineOperation]) -> None:
        action = self._quarantine_worker.action if self._quarantine_worker is not None else ""
        if action in {"quarantine", "restore"} and self._result is not None:
            self._result = None
            self._clear_results()
            self.quarantine_summary.setText(
                "The folder changed. Analyze it again before reviewing or approving additional files."
            )
        self._populate_operations(operations)
        if action == "list":
            self.status.setText(f"Loaded {len(operations):,} quarantine operation(s).")
        else:
            self.status.setText("Quarantine/restore operation complete; inspect each recorded status.")

    def _quarantine_failed(self, message: str, completed: list[QuarantineOperation]) -> None:
        if completed and (
                self._quarantine_worker is not None
                and self._quarantine_worker.action in {"quarantine", "restore"}
        ):
            self._result = None
            self._clear_results()
        if completed:
            self._populate_operations(completed)
        self.status.setText("Quarantine/restore did not fully complete; inspect the operation status before retrying.")
        QMessageBox.warning(self, "Quarantine/restore operation failed", message)

    def _quarantine_worker_finished(self) -> None:
        self._quarantine_worker = None
        self.quarantine_refresh_button.setEnabled(True)
        self.quarantine_button.setEnabled(
            QUARANTINE_OPERATIONS_ENABLED and bool(self._review_candidates)
        )
        self.restore_button.setEnabled(QUARANTINE_OPERATIONS_ENABLED)
        self.choose_button.setEnabled(True)
        self.scan_button.setEnabled(bool(self.root_label.text() and self.root_label.text() != "No folder selected"))

    def _large_summary_text(self, result: CleanerScanResult) -> str:
        sizes = ", ".join(
            f"{threshold // (1024**2)} MB+: {values['files']:,} files / {_format_bytes(values['bytes'])}"
            for threshold, values in result.large_totals.items()
        )
        ages = ", ".join(
            f"{days} days+: {values['files']:,} files / {_format_bytes(values['bytes'])}"
            for days, values in result.old_totals.items()
        )
        return (
            f"Measured thresholds in the selected folder — {sizes}. Modified-time groups: {ages}. "
            "Tables show at most 500 largest matching entries. Age and size are not cleanup recommendations."
        )

    def _update_large_files(self) -> None:
        if self._result is None:
            return
        size_threshold = {
            0: 0,
            1: 100 * 1024**2,
            2: 500 * 1024**2,
            3: 1024**3,
        }[self.large_size_combo.currentIndex()]
        age_threshold = {0: 0, 1: 30, 2: 90, 3: 180}[self.old_age_combo.currentIndex()]
        now = datetime.now().astimezone().timestamp()
        rows = []
        source = self._result.old_files if age_threshold else self._result.largest_files
        kind_filter = self.file_kind_combo.currentText()
        for finding in source:
            age_days = max(0, int((now - finding.modified_ns / 1_000_000_000) // 86400))
            if (
                finding.size < size_threshold
                or age_days < age_threshold
                or (kind_filter != "Any type" and finding.kind != kind_filter)
            ):
                continue
            rows.append(
                [
                    finding.path,
                    _format_bytes(finding.size),
                    _format_timestamp(finding.modified_ns),
                    finding.extension,
                    finding.recommendation,
                ]
            )
        _put_rows(self.large_table, rows)

    def _load_drives(self) -> None:
        drives, inaccessible = drive_summaries()
        rows = [
            [
                drive.mountpoint,
                _format_bytes(drive.total_bytes),
                _format_bytes(drive.used_bytes),
                _format_bytes(drive.free_bytes),
            ]
            for drive in drives
        ]
        _put_rows(self.drives_table, rows)
        self.drive_status.setText(
            f"{inaccessible} drive(s) could not be queried." if inaccessible else
            "Drive capacity is system-reported; no drive contents are scanned here."
        )

    def _load_system_overview(self) -> None:
        cpu, processes, inaccessible_processes = process_summaries()
        startup, inaccessible_startup = startup_entries()
        browser_names = {"chrome.exe", "msedge.exe", "firefox.exe"}
        running_browsers = set()
        for process in psutil.process_iter(["name"]):
            try:
                name = (process.info["name"] or "").casefold()
            except psutil.Error:
                continue
            if name in browser_names:
                running_browsers.add(name)
        self._browser_note = (
            "Browser process detected; cache files may be in use."
            if running_browsers
            else "No supported browser process detected in this snapshot."
        )
        self.performance_summary.setText(
            f"RAM: {memory_summary()} · System CPU snapshot: {cpu:.1f}% · "
            f"{len(startup):,} startup entries found. {inaccessible_startup:,} startup locations and "
            f"{inaccessible_processes:,} process records could not be inspected. "
            f"These are read-only snapshots. {self._browser_note}"
        )
        _put_rows(
            self.startup_table,
            [[entry.name, entry.source, entry.command] for entry in startup],
        )
        _put_rows(
            self.process_table,
            [
                [
                    process.name,
                    str(process.pid),
                    _format_bytes(process.memory_bytes),
                    f"{process.cpu_percent:.1f}%",
                ]
                for process in processes
            ],
        )

    def _load_history(self) -> None:
        try:
            entries = self._history.recent()
        except (sqlite3.Error, OSError) as error:
            self.status.setText(f"Local scan history is unavailable: {error}")
            self.history_table.setRowCount(0)
            return
        _put_rows(
            self.history_table,
            [
                [
                    entry.scanned_at,
                    f"{entry.files_scanned:,}",
                    f"{entry.directories_scanned:,}",
                    _format_bytes(entry.bytes_scanned),
                    f"{entry.duplicate_groups:,}",
                    _format_bytes(entry.duplicate_potential_bytes),
                    f"{entry.elapsed_seconds:.1f}",
                    f"{entry.inaccessible_entries:,}",
                ]
                for entry in entries
            ],
        )

    def _tab_changed(self, index: int) -> None:
        if self.tabs.tabText(index) == "Startup & performance":
            self._load_system_overview()

    def closeEvent(self, event) -> None:
        if self._quarantine_worker is not None and self._quarantine_worker.isRunning():
            if not self._quarantine_worker.wait(5000):
                event.ignore()
                self.status.setText("Waiting for the quarantine/restore operation to reach a safe state before closing.")
                return
        if self._worker is not None and self._worker.isRunning():
            self._worker.cancel()
            if not self._worker.wait(5000):
                event.ignore()
                self.status.setText("Waiting for the current read-only operation to stop before closing.")
                return
        event.accept()
