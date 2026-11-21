import os

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication

import pdcm.ui.cleaner_dashboard as cleaner_dashboard
from pdcm.services.scan_history import ScanHistory
from pdcm.ui.cleaner_dashboard import CleanerDashboard


def test_dashboard_exposes_review_and_recovery_controls_without_permanent_deletion(monkeypatch, tmp_path):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(
        cleaner_dashboard,
        "ScanHistory",
        lambda: ScanHistory(tmp_path / "history.sqlite3"),
    )

    dashboard = CleanerDashboard()
    tab_names = [dashboard.tabs.tabText(index) for index in range(dashboard.tabs.count())]
    button_names = [button.text().casefold() for button in dashboard.findChildren(cleaner_dashboard.QPushButton)]

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
    assert any("cancel" == name for name in button_names)
    assert any("quarantine" in name for name in button_names)
    assert any("restore" in name for name in button_names)
    assert not any("delete" in name or "clean" in name for name in button_names)
    assert not dashboard.quarantine_button.isEnabled()
    assert not dashboard.restore_button.isEnabled()

    dashboard._quarantine_selected()
    dashboard._restore_selected()

    assert dashboard._quarantine_worker is None
    assert "disabled" in dashboard.status.text().casefold()

    dashboard.close()
    app.processEvents()
