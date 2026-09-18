import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netshield.agent_receiver import Receiver, digest
from netshield.core.agent_status import read_snapshot, status_label, validate_status
from netshield.core.settings import save_settings


def payload():
    return dict(boot_time='2026-09-17T08:00:00Z', session='unknown', events=[
        dict(id='a' * 32, kind='agent_started', time='2026-09-17T08:01:00Z')])


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.settings = Path(self.folder.name) / 'settings.json'
        save_settings(self.settings, dict(devices=[dict(id='pc1', name='Test', department='Dev', ip='192.0.2.1', interface='')]))
        self.credentials = self.settings.parent / 'agent-credentials.json'
        self.credentials.write_text(json.dumps({'pc1': digest('secret')}))
        self.receiver = Receiver(self.settings)

    def test_authentication_revocation_and_no_identity_from_ip(self):
        for identity, token in [('pc1', 'wrong'), ('other', 'secret')]:
            with self.assertRaises(PermissionError):
                self.receiver.accept(identity, token, payload())
        self.assertEqual(read_snapshot(self.settings), ({}, None))
        self.receiver.accept('pc1', 'secret', payload())
        self.credentials.write_text('{}')
        with self.assertRaises(PermissionError):
            self.receiver.accept('pc1', 'secret', payload())
        self.credentials.write_text(json.dumps({'pc1': digest('secret')}))
        save_settings(self.settings, {})
        with self.assertRaises(PermissionError):
            self.receiver.accept('pc1', 'secret', payload())

    def test_strict_fields_and_limits(self):
        for changes in ({'session': 'active'}, {'events': [{}]}, {'boot_time': 'yesterday'},
                        {'events': payload()['events'] * 101}, {'screen': 'private'},
                        {'boot_time': '2026-09-17T08:00:00'}):
            with self.assertRaises(ValueError):
                validate_status(dict(payload(), **changes))

    def test_session_context_is_optional_strict_and_scoped_in_label(self):
        data = payload()
        data['session_id'] = 3
        data['events'][0].update(session_id=1, boot_time='2026-09-16T08:00:00Z')
        normalized = validate_status(data)
        self.assertEqual(normalized['events'][0]['session_id'], 1)
        self.assertIn('oturum #3', status_label(dict(normalized, received_at=100), now=100))
        for bad in (True, -1, 2147483648, '1', None):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                validate_status(dict(data, session_id=bad))
            changed = dict(data['events'][0], session_id=bad)
            with self.assertRaises(ValueError):
                validate_status(dict(data, events=[changed]))
        for key in ('session_id', 'boot_time'):
            incomplete = dict(data['events'][0])
            del incomplete[key]
            with self.assertRaises(ValueError):
                validate_status(dict(data, events=[incomplete]))

    def test_deduplication_rate_limit_persistence_and_disconnect(self):
        with patch('netshield.agent_receiver.time.monotonic', return_value=100):
            self.assertTrue(self.receiver.accept('pc1', 'secret', payload()))
            self.assertFalse(self.receiver.accept('pc1', 'secret', payload()))
        with patch('netshield.agent_receiver.time.monotonic', return_value=103):
            self.assertTrue(self.receiver.accept('pc1', 'secret', payload()))
        records, error = read_snapshot(self.settings)
        self.assertIsNone(error)
        record = records['pc1']
        self.assertEqual(len(record['events']), 1)
        self.assertEqual(self.receiver.status_path.stat().st_mode & 0o777, 0o600)
        self.assertIn('Bağlı', status_label(record, record['received_at'] + 30))
        self.assertIn('kapanış bilinmiyor', status_label(record, record['received_at'] + 91))
        record['events'][-1]['kind'] = 'agent_stopped'
        self.assertEqual(status_label(record, record['received_at']), 'Ajan durduruldu')
        self.assertNotIn(b'secret', self.receiver.status_path.read_bytes())

    def test_event_history_is_bounded_and_survives_restart(self):
        first = payload()
        first['events'] = [dict(id=f'{index:032x}', kind='session_lock', time='2026-09-17T08:01:00Z') for index in range(100)]
        self.receiver.accept('pc1', 'secret', first)
        restarted = Receiver(self.settings)
        second = payload()
        second['events'] = [dict(id=f'{index:032x}', kind='session_unlock', time='2026-09-17T08:02:00Z') for index in range(100, 200)]
        restarted.accept('pc1', 'secret', second)
        events = read_snapshot(self.settings)[0]['pc1']['events']
        self.assertEqual(len(events), 100)
        self.assertEqual(events[0]['id'], f'{100:032x}')

    def test_cli_enrollment_rotation_and_revoke(self):
        from netshield.agent_receiver import main
        output = self.settings.parent / 'client.json'
        prefix = ['receiver', '--settings', str(self.settings)]
        arguments = ['enroll', '--device-id', 'pc1', '--server', 'https://localhost:8443', '--output', str(output)]
        with patch('sys.argv', prefix + arguments), patch('builtins.print'):
            main()
        config = json.loads(output.read_text())
        self.assertEqual(config['device_id'], 'pc1')
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(config['token'], self.credentials.read_text())
        self.assertEqual(self.receiver.authorize('pc1', 'secret'), {'pc1'})
        self.assertTrue(self.receiver.accept('pc1', config['token'], payload()))
        with self.assertRaises(PermissionError):
            self.receiver.authorize('pc1', 'secret')
        with patch('sys.argv', prefix + ['revoke', '--device-id', 'pc1']), patch('builtins.print'):
            main()
        with self.assertRaises(PermissionError):
            self.receiver.accept('pc1', config['token'], payload())

    def test_corrupt_snapshot_fails_closed(self):
        self.receiver.status_path.write_text('{broken')
        self.assertEqual(read_snapshot(self.settings)[0], {})
        with self.assertRaises(sqlite3.DatabaseError):
            Receiver(self.settings)

    def test_backlogged_stop_does_not_mark_running_agent_stopped(self):
        data = payload()
        data['events'][0]['kind'] = 'agent_stopped'
        data.update(agent_state='running', dropped_events=3, pending_events=40)
        self.receiver.accept('pc1', 'secret', data)
        record = read_snapshot(self.settings)[0]['pc1']
        self.assertIn('Bağlı', status_label(record, record['received_at']))
        record['agent_state'] = 'stopped'
        self.assertEqual(status_label(record, record['received_at']), 'Ajan durduruldu')
        for key, value in [('pending_events', -1), ('dropped_events', True), ('agent_state', 'invented')]:
            with self.assertRaises(ValueError):
                validate_status(dict(data, **{key: value}))
