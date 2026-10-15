import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

try:
    from PySide6.QtWidgets import QApplication, QPushButton
    from pi5_studio.iso_gui import Window
    QT = True
except ImportError:
    QT = False


@unittest.skipUnless(QT, 'Requires PySide6')
class SimpleStudioGUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_single_build_flow_without_diagnostic_controls(self):
        window = Window()
        try:
            from pi5_studio import APP_NAME, APP_DESCRIPTION
            from PySide6.QtWidgets import QLabel
            self.assertEqual(window.windowTitle(), APP_NAME)
            labels = {w.text() for w in window.findChildren(QLabel)}
            self.assertIn(APP_NAME, labels)
            self.assertIn(APP_DESCRIPTION, labels)
            texts = {b.text() for b in window.findChildren(QPushButton)}
            self.assertIn('Build ISO', texts)
            self.assertFalse(any(word in text.lower() for text in texts for word in ('diagnostic', 'test', 'package', 'collect')))
            self.assertFalse(window.build_button.isEnabled())
            window.source.setText('/tmp/windows.iso');window.output.setText('/tmp/pi5.iso')
            self.assertTrue(window.build_button.isEnabled())
        finally:
            window.close()

    def test_worker_completion_returns_controls_and_reports_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp);source = root/'source.iso';source.write_bytes(b'fixture')
            out = root/'output.iso'
            window = Window()
            window.source.setText(str(source));window.output.setText(str(out))
            result = {'output_iso': str(out), 'log_directory': str(root)}
            try:
                with patch('pi5_studio.iso_gui.Build.run', return_value=result):
                    window.start_build()
                    self.assertFalse(window.build_button.isEnabled())
                    deadline = time.monotonic()+5
                    while window.thread is not None and time.monotonic()<deadline:
                        self.app.processEvents();time.sleep(.01)
                    self.assertIsNone(window.thread)
                self.assertEqual(window.successful_output, out)
                self.assertEqual(window.progress.value(), 100)
                self.assertTrue(window.build_button.isEnabled())
            finally:
                window.close()
