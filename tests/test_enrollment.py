import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from netshield.core.enrollment import enroll, revoke, read_credentials, digest, server_origin, credential_matches
from netshield.core.settings import save_settings
from netshield.core.inventory import validate_devices, device_activity


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.directory = Path(folder.name)
        self.settings = self.directory / 'settings.json'
        self.devices = [dict(id=f'pc{i}', name=f'PC {i}', department='Dev', ip='', interface='') for i in range(2)]
        save_settings(self.settings, dict(devices=self.devices))

    def test_multiple_agent_devices_need_no_ip(self):
        self.assertEqual(validate_devices(self.devices), self.devices)
        for device in self.devices:
            self.assertEqual(device_activity(device, [], [])['status'], 'IP tanımlı değil')

    def test_invalid_origins_are_rejected_before_writing(self):
        for server in ('http://host', 'https://host/path', 'https://user:pass@host', 'https://host:70000',
                       'https://host?', 'https://host#', 'https://host\n', 'https://host:0'):
            with self.assertRaises(ValueError):
                enroll(self.settings, 'pc0', server, self.directory / 'output.json')
            self.assertFalse((self.directory / 'output.json').exists())
        self.assertEqual(server_origin('https://host:8443/'), 'https://host:8443')

    def test_parallel_enrollment_preserves_both_credentials_and_revoke_one(self):
        def work(i):
            return enroll(self.settings, f'pc{i}', 'https://host:8443', self.directory / f'client{i}.json')
        with ThreadPoolExecutor(max_workers=2) as pool:
            outputs = list(pool.map(work, range(2)))
        credentials = read_credentials(self.directory / 'agent-credentials.json')
        self.assertEqual(set(credentials), {'pc0', 'pc1'})
        for i, output in enumerate(outputs):
            config = json.loads(output.read_text())
            self.assertEqual(credentials[f'pc{i}'], digest(config['token']))
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertNotIn('name', config)
            self.assertNotIn('department', config)
        revoke(self.settings, 'pc0')
        self.assertEqual(set(read_credentials(self.directory / 'agent-credentials.json')), {'pc1'})

    def test_failed_credential_commit_removes_new_config_and_preserves_old_key(self):
        enroll(self.settings, 'pc0', 'https://host', self.directory / 'old.json')
        before = (self.directory / 'agent-credentials.json').read_bytes()
        output = self.directory / 'new.json'
        with patch('netshield.core.enrollment.private_write', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                enroll(self.settings, 'pc0', 'https://host', output)
        self.assertFalse(output.exists())
        self.assertEqual((self.directory / 'agent-credentials.json').read_bytes(), before)

    def test_existing_output_and_internal_paths_are_not_overwritten(self):
        output = self.directory / 'existing.json'
        output.write_text('keep')
        with self.assertRaises(FileExistsError):
            enroll(self.settings, 'pc0', 'https://host', output)
        self.assertEqual(output.read_text(), 'keep')
        for path in (self.settings, self.directory / 'agent-credentials.json', self.directory / 'agent-status.sqlite3'):
            with self.assertRaises(ValueError):
                enroll(self.settings, 'pc0', 'https://host', path)

    def test_pending_rotation_expires_without_disabling_active_key(self):
        enroll(self.settings, 'pc0', 'https://host', self.directory / 'old.json')
        old = json.loads((self.directory / 'old.json').read_text())['token']
        enroll(self.settings, 'pc0', 'https://host', self.directory / 'new.json')
        new = json.loads((self.directory / 'new.json').read_text())['token']
        value = read_credentials(self.directory / 'agent-credentials.json')['pc0']
        self.assertTrue(credential_matches(value, old))
        self.assertTrue(credential_matches(value, new))
        with patch('netshield.core.enrollment.time.time', return_value=value['pending_until']):
            self.assertTrue(credential_matches(value, old))
            self.assertFalse(credential_matches(value, new))

    def test_rotation_activation_requires_valid_commit_and_survives_write_failure(self):
        from netshield.agent_receiver import Receiver
        from netshield.core.agent_status import read_snapshot
        enroll(self.settings, 'pc0', 'https://host', self.directory / 'old.json')
        old = json.loads((self.directory / 'old.json').read_text())['token']
        enroll(self.settings, 'pc0', 'https://host', self.directory / 'new.json')
        new = json.loads((self.directory / 'new.json').read_text())['token']
        receiver = Receiver(self.settings)
        data = dict(boot_time='2026-09-18T08:00:00Z', session='unknown', events=[
            dict(id='a' * 32, kind='agent_started', time='2026-09-18T08:00:01Z')])
        with self.assertRaises(ValueError):
            receiver.accept('pc0', new, dict(data, session='invalid'))
        receiver.authorize('pc0', old)
        with patch('netshield.core.enrollment.private_write', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                receiver.accept('pc0', new, data)
        receiver.authorize('pc0', old)
        receiver.authorize('pc0', new)
        self.assertTrue(receiver.accept('pc0', new, data))
        self.assertEqual(len(read_snapshot(self.settings)[0]['pc0']['events']), 1)
        with self.assertRaises(PermissionError):
            receiver.authorize('pc0', old)
