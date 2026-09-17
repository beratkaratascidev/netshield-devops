import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from netshield.core.agent_store import AgentStore, connection, read_database
from netshield.core.agent_status import read_snapshot


def status(index=1):
    return dict(boot_time='2026-09-17T08:00:00Z', session='unknown', events=[
        dict(id=f'{index:032x}', kind='agent_started', time='2026-09-17T08:01:00Z')])


class StoreTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.settings = Path(folder.name) / 'settings.json'

    def test_legacy_migration_is_atomic_canonical_and_runs_once(self):
        legacy = self.settings.parent / 'agent-status.json'
        old = dict(status(), received_at=123456)
        legacy.write_text(json.dumps({'pc': old}))
        store = AgentStore(self.settings)
        self.assertEqual(len(read_database(self.settings)['pc']['events']), 1)
        # A retry of the original Z-formatted message must match migrated ISO timestamps.
        store.accept('pc', status(), {'pc'}, received_at=123457)
        legacy.write_text('{corrupt stale copy')
        AgentStore(self.settings)
        self.assertEqual(len(read_database(self.settings)['pc']['events']), 1)

    def test_failed_migration_can_be_retried_without_partial_rows(self):
        legacy = self.settings.parent / 'agent-status.json'
        legacy.write_text('{corrupt')
        with self.assertRaises(ValueError):
            AgentStore(self.settings)
        self.assertIsNotNone(read_snapshot(self.settings)[1])
        legacy.write_text(json.dumps({'pc': dict(status(), received_at=1234)}))
        AgentStore(self.settings)
        self.assertEqual(set(read_database(self.settings)), {'pc'})

    def test_conflicting_event_rolls_back_device_state_and_entire_batch(self):
        store = AgentStore(self.settings)
        store.accept('pc', status(), {'pc'}, received_at=1000)
        before = read_database(self.settings)
        conflicting = status(2)
        conflicting['session'] = 'locked'
        conflicting['events'].append(dict(status()['events'][0], kind='session_lock'))
        with self.assertRaises(ValueError):
            store.accept('pc', conflicting, {'pc'}, received_at=1001)
        self.assertEqual(read_database(self.settings), before)

    def test_write_error_has_no_ack_and_no_partial_rows(self):
        store = AgentStore(self.settings)
        original = store._put
        def fail_after_write(*args):
            original(*args)
            raise sqlite3.OperationalError('disk full')
        with patch.object(store, '_put', side_effect=fail_after_write):
            with self.assertRaises(sqlite3.OperationalError):
                store.accept('pc', status(), {'pc'})
        self.assertEqual(read_database(self.settings), {})

    def test_retention_uses_receive_time_and_removes_deleted_devices(self):
        store = AgentStore(self.settings, retention_days=1)
        store.accept('pc', status(), {'pc', 'other'}, received_at=1000)
        store.accept('other', status(), {'pc', 'other'}, received_at=1001)
        store.maintain({'pc'}, now=1002)
        self.assertEqual(set(read_database(self.settings)), {'pc'})
        store.maintain({'pc'}, now=1000 + 86401)
        self.assertEqual(read_database(self.settings), {})

    def test_parallel_writers_and_readers_do_not_lose_devices(self):
        store = AgentStore(self.settings)
        valid = {f'pc{i}' for i in range(40)}
        def write(i):
            store.accept(f'pc{i}', status(i), valid)
            snapshot = read_database(self.settings)
            self.assertIn(f'pc{i}', snapshot)
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(write, range(40)))
        self.assertEqual(set(read_database(self.settings)), valid)

    def test_future_schema_and_unsafe_file_permissions_are_rejected(self):
        store = AgentStore(self.settings)
        with connection(store.path) as conn:
            conn.execute('PRAGMA user_version=99')
        with self.assertRaises(ValueError):
            AgentStore(self.settings)
        self.assertIsNotNone(read_snapshot(self.settings)[1])
        store.path.chmod(0o644)
        self.assertIsNotNone(read_snapshot(self.settings)[1])

    def test_symlink_is_never_opened_as_database(self):
        target = self.settings.parent / 'target'
        target.write_text('untouched')
        (self.settings.parent / 'agent-status.sqlite3').symlink_to(target)
        with self.assertRaises(ValueError):
            AgentStore(self.settings)
        self.assertEqual(target.read_text(), 'untouched')
