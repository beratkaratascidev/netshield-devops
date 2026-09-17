import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock
from netshield.core.agent_status import read_legacy_snapshot
from netshield.core.snapshot_reader import SnapshotReader


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.settings = Path(folder.name) / 'settings.json'

    def result(self, reader):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            value = reader.poll()
            if value is not None:
                return value
            time.sleep(.005)
        self.fail('Background read timed out')

    def test_single_flight_and_file_change_cache(self):
        loader = Mock(return_value=({}, None))
        reader = SnapshotReader(self.settings, loader)
        self.addCleanup(reader.close)
        self.assertTrue(reader.request())
        self.assertFalse(reader.request())
        self.assertEqual(self.result(reader), ({}, None))
        reader.request()
        self.result(reader)
        self.assertEqual(loader.call_count, 1)
        (self.settings.parent / 'agent-status.json').write_text('{}')
        reader.request()
        self.result(reader)
        self.assertEqual(loader.call_count, 2)

    def test_slow_read_does_not_block_caller_or_shutdown(self):
        release, entered = threading.Event(), threading.Event()
        def loader(_):
            entered.set()
            release.wait(2)
            return {}, None
        reader = SnapshotReader(self.settings, loader)
        try:
            self.assertTrue(reader.request())
            self.assertTrue(entered.wait(1))
            self.assertIsNone(reader.poll())
            reader.close()
            self.assertFalse(reader.request())
        finally:
            release.set()
            reader.close()

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'POSIX FIFO required')
    def test_legacy_fifo_is_rejected_without_blocking(self):
        os.mkfifo(self.settings.parent / 'agent-status.json')
        records, error = read_legacy_snapshot(self.settings)
        self.assertEqual(records, {})
        self.assertIsNotNone(error)
