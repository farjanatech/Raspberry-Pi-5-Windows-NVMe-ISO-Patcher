"""Single-page ISO patcher: one source ISO, one finished ISO."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import sys

from PySide6.QtCore import QObject, QThread, QTimer, QUrl, Signal, Slot, Qt
from PySide6.QtGui import QDesktopServices, QIcon, QPixmap
from PySide6.QtWidgets import (QApplication, QFileDialog, QHBoxLayout, QLabel,
                              QLineEdit, QMainWindow, QMessageBox, QProgressBar,
                              QPushButton, QVBoxLayout, QWidget)
from . import APP_NAME, APP_DESCRIPTION, APP_ID, __version__
from .backend import Cancellation
from .iso_builder import Build
from .widgets import STYLE, ICON, button, card, label


class Worker(QObject):
    progress = Signal(int, str)
    result = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, source, output, cancel):
        super().__init__()
        self.source, self.output, self.cancel = source, output, cancel
        self.builder = Build(cancel, self.progress.emit)

    @Slot()
    def run(self):
        try:
            self.result.emit(self.builder.run(self.source, self.output))
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()


class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(QIcon(str(ICON)))
        self.resize(1000, 720)
        self.setMinimumSize(760, 640)
        self.thread = self.worker = None
        self.log_directory = None
        self.cancel = Cancellation()
        self.successful_output = None
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(38, 32, 38, 28)
        layout.setSpacing(18)
        header = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(QPixmap(str(ICON)).scaled(68, 68, Qt.AspectRatioMode.KeepAspectRatio,
                                                Qt.TransformationMode.SmoothTransformation))
        header.addWidget(icon)
        titles = QVBoxLayout()
        titles.addWidget(label(APP_NAME, 'title'))
        titles.addWidget(label(APP_DESCRIPTION, 'muted'))
        header.addLayout(titles, 1)
        header.addWidget(label(__version__, 'badge', False))
        layout.addLayout(header)
        layout.addWidget(label('Prepare your Windows ARM64 ISO.', 'heading'))
        layout.addWidget(label('Choose the original ISO and the destination. The patcher handles the preparation automatically.', 'muted'))
        box, content = card()
        content.setSpacing(12)
        content.addWidget(label('INPUT ISO', 'eyebrow'))
        row = QHBoxLayout()
        self.source = QLineEdit()
        self.source.setPlaceholderText('Choose a Windows 11 ARM64 ISO')
        self.source.setAccessibleName('Input Windows ARM64 ISO')
        self.source_browse = button('Browse...', self.choose_source)
        row.addWidget(self.source, 1)
        row.addWidget(self.source_browse)
        content.addLayout(row)
        content.addWidget(label('OUTPUT ISO', 'eyebrow'))
        row = QHBoxLayout()
        self.output = QLineEdit()
        self.output.setPlaceholderText('Where to save your finished ISO')
        self.output.setAccessibleName('Output installation ISO')
        self.output_browse = button('Save as...', self.choose_output)
        row.addWidget(self.output, 1)
        row.addWidget(self.output_browse)
        content.addLayout(row)
        content.addWidget(label('The original ISO stays unchanged. All included Windows editions are retained.', 'muted'))
        layout.addWidget(box)
        actions = QHBoxLayout()
        self.build_button = button('Build ISO', self.start_build, True)
        self.build_button.setMinimumHeight(46)
        self.cancel_button = button('Cancel build', self.cancel_build)
        self.cancel_button.hide()
        actions.addWidget(self.build_button, 1)
        actions.addWidget(self.cancel_button)
        layout.addLayout(actions)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        layout.addWidget(self.progress)
        self.status = label('Ready when you are.', 'muted')
        self.status.setMinimumHeight(46)
        layout.addWidget(self.status)
        links = QHBoxLayout()
        self.folder_button = button('Open output folder', self.open_output)
        self.log_button = button('Open build log', self.open_log)
        self.folder_button.hide()
        self.log_button.hide()
        links.addWidget(self.folder_button)
        links.addWidget(self.log_button)
        links.addStretch()
        layout.addLayout(links)
        layout.addStretch()
        layout.addWidget(label('Automatic driver preparation  |  Windows + recovery  |  Logs saved locally', 'muted'))
        layout.addWidget(label('Preserves Microsoft Setup. No Pi firmware, custom installer or USB writing is included.', 'muted'))
        self.source.textChanged.connect(self.update_actions)
        self.output.textChanged.connect(self.update_actions)
        self.update_actions()

    def choose_source(self):
        value, _ = QFileDialog.getOpenFileName(self, 'Choose Windows ARM64 ISO', str(Path.home()), 'ISO images (*.iso *.ISO)')
        if value:
            self.source.setText(value)
            if not self.output.text().strip():
                self.output.setText(str(Path(value).with_name(Path(value).stem+'-Pi5.iso')))

    def choose_output(self):
        value, _ = QFileDialog.getSaveFileName(self, 'Save the Pi5 installation ISO',
                                              self.output.text() or str(Path.home()/'Pi5-Windows.iso'),
                                              'ISO image (*.iso)', options=QFileDialog.Option.DontConfirmOverwrite)
        if value:
            self.output.setText(value if value.lower().endswith('.iso') else value+'.iso')

    @Slot()
    def update_actions(self):
        idle = self.thread is None
        for control in (self.source, self.output, self.source_browse, self.output_browse):
            control.setEnabled(idle)
        self.build_button.setEnabled(idle and bool(self.source.text().strip()) and bool(self.output.text().strip()))
        self.cancel_button.setVisible(not idle)

    @Slot()
    def start_build(self):
        if self.thread is not None:
            return
        source, output = Path(self.source.text()).expanduser(), Path(self.output.text()).expanduser()
        if not source.is_file() or not output.parent.is_dir() or output.exists():
            QMessageBox.information(self, 'Choose ISO paths', 'Choose an existing input ISO and a new output filename in an existing folder.')
            return
        self.cancel = Cancellation()
        self.cancel_button.setEnabled(True)
        self.log_directory = self.successful_output = None
        self.folder_button.hide()
        self.log_button.hide()
        self.progress.setValue(0)
        self.status.setText('Starting the ISO build...')
        self.worker = Worker(source, output, self.cancel)
        self.thread = QThread(self)
        self.worker.moveToThread(self.thread)
        self.worker.progress.connect(self.on_progress)
        self.worker.result.connect(self.on_result)
        self.worker.failed.connect(self.on_failure)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.job_finished)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.started.connect(self.worker.run)
        self.update_actions()
        self.thread.start()

    @Slot(int, str)
    def on_progress(self, percent, text):
        self.progress.setValue(percent)
        self.status.setText(text)
        if self.worker and self.worker.builder.root:
            self.log_directory = self.worker.builder.root
            self.log_button.show()

    @Slot(object)
    def on_result(self, result):
        self.successful_output = Path(result['output_iso'])
        self.log_directory = Path(result['log_directory'])
        self.status.setText('ISO ready: '+self.successful_output.name+'\nBuild log saved automatically.')
        self.progress.setValue(100)
        self.folder_button.show()
        self.log_button.show()

    @Slot(str)
    def on_failure(self, message):
        if self.worker and self.worker.builder.root:
            self.log_directory = self.worker.builder.root
            self.log_button.show()
        self.status.setText('Build cancelled. Your source is unchanged.' if self.cancel.event.is_set()
                            else 'Build stopped. Details have been saved in the log.')
        if not self.cancel.event.is_set():
            QMessageBox.warning(self, 'ISO build stopped', message)

    @Slot()
    def job_finished(self):
        self.thread = self.worker = None
        self.update_actions()

    def cancel_build(self):
        self.cancel.cancel()
        self.cancel_button.setEnabled(False)
        self.status.setText('Stopping the build safely...')

    def open_output(self):
        if self.successful_output:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.successful_output.parent)))

    def open_log(self):
        if self.log_directory:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.log_directory/'build.log')))

    def closeEvent(self, event):
        if self.thread is not None:
            event.ignore()
            self.status.setText('Use Cancel build and wait for it to stop before closing the patcher.')
        else:
            event.accept()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--screenshot', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if hasattr(os, 'geteuid') and os.geteuid() == 0 and not args.screenshot:
        print('Open the patcher as your regular desktop user, without sudo.', file=sys.stderr)
        return 2
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)
    app.setDesktopFileName(APP_ID)
    app.setStyleSheet(STYLE + '\nQPushButton#primary:disabled { background: #22334b; color: #73869f; border-color: #344b65; }')
    window = Window()
    window.show()
    if args.screenshot:
        def capture():
            args.screenshot.parent.mkdir(parents=True, exist_ok=True)
            ok = window.grab().save(str(args.screenshot))
            app.exit(0 if ok else 2)
        QTimer.singleShot(400, capture)
    return app.exec()


if __name__ == '__main__':
    raise SystemExit(main())
