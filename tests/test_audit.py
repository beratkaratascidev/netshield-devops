import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from netshield.core.audit import AuditReader, audit_path, read_recent
from netshield.core.enrollment import enroll, revoke
from netshield.core.settings import save_settings


class AuditTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.settings = self.root / 'settings.json'
        self.device = dict(id='pc1', name='Workstation', department='IT', ip='', interface='')

    def records(self):
        return read_recent(self.settings, limit=1000)

    def test_settings_changes_are_bounded_and_record_only_allowlisted_fields(self):
        save_settings(self.settings, {'devices': [self.device]})
        changed = dict(self.device, name='Renamed')
        save_settings(self.settings, {'devices': [changed]})
        save_settings(self.settings, {})

        records = self.records()
        self.assertTrue(audit_path(self.settings).is_file())
        self.assertEqual(audit_path(self.settings).stat().st_mode & 0o777, 0o600)
        self.assertEqual([(record['action'], record['target'], record['outcome']) for record in records], [
            ('device_remove', 'pc1', 'succeeded'),
            ('settings_save', '', 'succeeded'),
            ('device_edit', 'pc1', 'succeeded'),
            ('settings_save', '', 'succeeded'),
            ('device_add', 'pc1', 'succeeded'),
            ('settings_save', '', 'succeeded'),
        ])
        self.assertTrue(all(record['finished'] is not None for record in records))
        self.assertNotIn('Workstation', str(records))
        self.assertNotIn('Renamed', str(records))

    def test_failed_operations_are_recorded_without_replacing_settings(self):
        save_settings(self.settings, {})
        original = self.settings.read_bytes()
        with patch('netshield.core.settings.os.replace', side_effect=OSError('denied')):
            with self.assertRaises(OSError):
                save_settings(self.settings, {'density': 'Kompakt'})

        self.assertEqual(self.settings.read_bytes(), original)
        record = self.records()[0]
        self.assertEqual((record['action'], record['target'], record['outcome']),
                         ('settings_save', '', 'failed'))

    def test_credential_actions_do_not_store_generated_tokens(self):
        save_settings(self.settings, {'devices': [self.device]})
        output = self.root / 'agent.json'
        enroll(self.settings, 'pc1', 'https://receiver.example', output)
        token = output.read_text()
        revoke(self.settings, 'pc1')

        records = self.records()
        self.assertEqual([(record['action'], record['target'], record['outcome']) for record in records[:2]], [
            ('credential_revoke', 'pc1', 'succeeded'),
            ('credential_enroll', 'pc1', 'succeeded'),
        ])
        self.assertNotIn(token, str(records))

    def test_missing_journal_has_no_records_and_limits_are_validated(self):
        self.assertEqual(read_recent(self.settings), [])
        for limit in (0, 1001, True, '1'):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                read_recent(self.settings, limit)

    def test_reader_is_single_flight_caches_unchanged_file_and_closes(self):
        loader = unittest.mock.Mock(return_value=[])
        reader = AuditReader(self.settings, loader)
        self.addCleanup(reader.close)
        self.assertTrue(reader.request())
        self.assertFalse(reader.request())
        deadline = time.monotonic() + 2
        while reader.poll() is None:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.005)
        self.assertEqual(loader.call_count, 1)
        self.assertTrue(reader.request())
        deadline = time.monotonic() + 2
        while reader.poll() is None:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.005)
        self.assertEqual(loader.call_count, 1)
        reader.close()
        self.assertFalse(reader.request())


if __name__ == '__main__':
    unittest.main()
