import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QLabel
from .ui.dashboard import Dashboard

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Jasti One — Digital Care & Cleanup")
        self.resize(1100, 760)
        tabs = QTabWidget()
        tabs.addTab(Dashboard(), "Overview")
        tabs.addTab(self.placeholder("Jasti Cleaner", "Windows storage inventory and safe temporary-file scanning."), "Windows")
        tabs.addTab(self.placeholder("Duplicates", "Read-only exact duplicate scan. Cleanup awaits quarantine/restore tests."), "Duplicates")
        tabs.addTab(self.placeholder("Gmail", "Not connected. Configure Google OAuth before inventory."), "Gmail")
        tabs.addTab(self.placeholder("iPhone", "Install the native companion to inventory authorized Photos and Contacts."), "iPhone")
        self.setCentralWidget(tabs)

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
