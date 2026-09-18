import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from netshield.backup import create_backup, restore_backup
from netshield.core.agent_store import AgentStore, read_database
from netshield.core.settings import save_settings


class BackupTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.settings = self.root / 'settings.json'
        save_settings(self.settings, {'devices': [dict(id='pc1', name='Test', department='Test', ip='', interface='')]})
        self.store = AgentStore(self.settings)
        self.archive = self.root / 'backup.zip'
        self.dest = self.root / 'recovered'
        policy = patch('netshield.backup.load_managed_policy', return_value=({}, None))
        policy.start()
        self.addCleanup(policy.stop)

    def test_round_trip_full_history_and_context_without_credentials(self):
        for offset in (0, 100):
            events = [dict(id=f'{i:032x}', kind='session_lock', time='2026-09-18T08:00:00Z',
                           session_id=2, boot_time='2026-09-17T08:00:00Z') for i in range(offset, offset + 100)]
            self.store.accept('pc1', dict(boot_time='2026-09-18T07:00:00Z', session='locked',
                              session_id=3, events=events), {'pc1'})
        (self.root / 'agent-credentials.json').write_text('{"secret":"not-for-backup"}')
        before = read_database(self.settings, event_limit=1000)
        create_backup(self.settings, self.archive)
        self.assertEqual(self.archive.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(b'not-for-backup', self.archive.read_bytes())
        restore_backup(self.archive, self.dest)
        self.assertEqual(read_database(self.dest / 'settings.json', event_limit=1000), before)
        self.assertEqual(len(before['pc1']['events']), 200)
        self.assertFalse((self.dest / 'agent-credentials.json').exists())

    def test_no_overwrite_and_policy_denial(self):
        create_backup(self.settings, self.archive)
        original = self.archive.read_bytes()
        with self.assertRaises(FileExistsError):
            create_backup(self.settings, self.archive)
        self.assertEqual(self.archive.read_bytes(), original)
        self.dest.mkdir()
        with self.assertRaises(FileExistsError):
            restore_backup(self.archive, self.dest)
        self.assertEqual(list(self.dest.iterdir()), [])
        with patch('netshield.backup.load_managed_policy', return_value=({'allow_exports': False}, None)):
            with self.assertRaises(PermissionError):
                create_backup(self.settings, self.root / 'forbidden.zip')
        self.assertFalse((self.root / 'forbidden.zip').exists())

    def test_malformed_or_extra_member_archive_cannot_publish_recovery(self):
        with zipfile.ZipFile(self.archive, 'w') as bundle:
            bundle.writestr('../escape', 'unexpected')
        with self.assertRaises(ValueError):
            restore_backup(self.archive, self.dest)
        self.assertFalse(self.dest.exists())
        self.assertFalse((self.root.parent / 'escape').exists())
        self.archive.write_bytes(b'broken archive')
        with self.assertRaises(zipfile.BadZipFile):
            restore_backup(self.archive, self.dest)
        self.assertFalse(self.dest.exists())
