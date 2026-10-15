"""Shared appearance for the single ISO-builder page."""
from pathlib import Path
from typing import Callable
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QPushButton, QFrame, QVBoxLayout

ROOT = Path(__file__).resolve().parent.parent
ICON = ROOT / "assets" / "pi5-nvme.png"
STYLE = """
QWidget { background: #0e1727; color: #e8eef6; font-family: 'DejaVu Sans'; font-size: 13px; }
QMainWindow { background: #0e1727; }
QFrame#sidebar { background: #0a111e; border-right: 1px solid #253047; }
QFrame#card { background: #152135; border: 1px solid #2a3850; border-radius: 14px; }
QFrame#drop { background: #12283a; border: 1px dashed #36899c; border-radius: 14px; }
QFrame#warning { background: #2c271e; border: 1px solid #73613a; border-radius: 12px; }
QLabel { background: transparent; border: none; }
QLabel#eyebrow { color: #57c6da; font-size: 11px; font-weight: 700; }
QLabel#title { font-size: 28px; font-weight: 700; color: #f5f8fc; }
QLabel#heading { font-size: 16px; font-weight: 700; }
QLabel#muted { color: #a6b7cc; font-size: 12px; }
QLabel#badge { background: #173849; color: #79d8e8; border: 1px solid #285e70; border-radius: 9px; padding: 5px 9px; font-size: 11px; }
QLabel#amber { color: #f4cf89; font-size: 12px; }
QLabel#step { background: #24364e; color: #8edfec; border-radius: 16px; font-size: 13px; font-weight: 700; }
QPushButton { background: #22334b; border: 1px solid #344b65; border-radius: 9px; padding: 8px 12px; color: #e5edf7; font-weight: 600; }
QPushButton:hover { background: #2e4662; border-color: #51bcd0; }
QPushButton:pressed { background: #334f6e; }
QPushButton:focus { border: 2px solid #73dfed; }
QPushButton#primary { background: #3bc4d7; color: #071723; border: 1px solid #5ad5e5; }
QPushButton#primary:hover { background: #70ddea; }
QPushButton:disabled { background: #192437; color: #73869f; border-color: #2a364a; }
QPushButton#nav { text-align: left; background: transparent; border: 1px solid transparent; padding: 12px; font-weight: 500; color: #a8bbd2; }
QPushButton#nav:checked { background: #162c40; border: 1px solid #275a6d; color: #9aeaf1; }
QPushButton#nav:hover { background: #17273c; }
QLineEdit, QComboBox { background: #0e192b; border: 1px solid #35455c; border-radius: 8px; padding: 8px; selection-background-color: #267c92; }
QLineEdit:focus, QComboBox:focus { border-color: #52c4d9; }
QLineEdit:disabled, QComboBox:disabled { color: #76859b; }
QComboBox QAbstractItemView { background: #16263c; selection-background-color: #26596b; padding: 6px; }
QComboBox::drop-down { border: none; width: 27px; }
QCheckBox { background: transparent; spacing: 9px; padding: 2px 0px; }
QCheckBox::indicator { width: 17px; height: 17px; border-radius: 4px; border: 1px solid #537086; background: #0d1829; }
QCheckBox::indicator:checked { background: #3bc4d7; border: 3px solid #254959; }
QProgressBar { border: none; border-radius: 4px; background: #243349; height: 7px; color: transparent; }
QProgressBar::chunk { background: #43c7d8; border-radius: 4px; }
QPlainTextEdit { background: #0a1220; border: 1px solid #2b3b52; border-radius: 9px; padding: 10px; color: #bccee0; font-family: 'DejaVu Sans Mono'; font-size: 11px; }
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical { background: #101a2b; width: 8px; margin: 0; }
QScrollBar::handle:vertical { background: #3a506a; min-height: 25px; border-radius: 4px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QToolTip { background: #24384f; color: white; border: 1px solid #4ba0b2; padding: 6px; }
"""


def label(text: str, name: str = "", wrap: bool = True) -> QLabel:
    widget = QLabel(text)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setWordWrap(wrap)
    if name:
        widget.setObjectName(name)
    return widget


def button(text: str, action: Callable, primary: bool = False) -> QPushButton:
    widget = QPushButton(text)
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    if primary:
        widget.setObjectName("primary")
    widget.clicked.connect(action)
    return widget


def card(name: str = "card") -> tuple:
    frame = QFrame()
    frame.setObjectName(name)
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(8)
    return frame, layout
