from PySide6.QtWidgets import QWidget, QVBoxLayout, QGridLayout, QLabel, QFrame
from ..services.system_info import memory_summary

class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        brand = QLabel("JASTI ONE")
        brand.setStyleSheet("font-size: 13px; font-weight: 750; letter-spacing: 3px; color: #2878C8;")
        layout.addWidget(brand)
        title = QLabel("Your digital life, one place")
        title.setStyleSheet("font-size: 24px; font-weight: 650;")
        subtitle = QLabel("Local-first analysis. Nothing is deleted without review and approval.")
        subtitle.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        grid = QGridLayout()
        for i, (name, status) in enumerate([
            ("Jasti Cleaner", "Local PC analysis · read-only"),
            ("Gmail", "Not connected"),
            ("iPhone", "Separate milestone · not integrated")
        ]):
            frame = QFrame()
            frame.setFrameShape(QFrame.StyledPanel)
            box = QVBoxLayout(frame)
            label = QLabel(name)
            label.setStyleSheet("font-size: 17px; font-weight: 600;")
            value = QLabel(status)
            value.setWordWrap(True)
            box.addWidget(label)
            box.addWidget(value)
            grid.addWidget(frame, i // 2, i % 2)
        layout.addLayout(grid)
        layout.addWidget(QLabel("Windows RAM: " + memory_summary()))
        layout.addStretch()
