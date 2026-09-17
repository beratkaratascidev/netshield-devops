import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from netshield.core.enrollment import enroll, revoke, read_credentials, digest, server_origin
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
