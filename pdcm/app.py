import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QLabel
from .ui.cleaner_dashboard import CleanerDashboard
from .ui.dashboard import Dashboard

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Jasti One — Your digital life, one place.")
        self.resize(1280, 900)
        tabs = QTabWidget()
        tabs.addTab(Dashboard(), "Overview")
        tabs.addTab(CleanerDashboard(), "Jasti Cleaner")
        tabs.addTab(self.placeholder("Gmail", "Not connected. Configure Google OAuth before inventory."), "Gmail")
        tabs.addTab(self.placeholder("iPhone", "iPhone inventory is a separate, not-yet-integrated milestone."), "iPhone")
        self.setCentralWidget(tabs)
        self.setStyleSheet(
            "QWidget { font-size: 13px; } "
            "QPushButton { padding: 7px 12px; } "
            "QTabWidget::pane { border: 1px solid #D5DCE5; }"
        )

    def placeholder(self, title, message):
        page = QWidget()
        layout = QVBoxLayout(page)
        heading = QLabel(title)
        heading.setStyleSheet("font-size: 22px; font-weight: 600;")
        body = QLabel(message)
        body.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(body)
        layout.addStretch()
        return page

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
