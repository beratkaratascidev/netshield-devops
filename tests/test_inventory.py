import json
import tempfile
import unittest
from pathlib import Path
from netshield.core.inventory import validate_devices, device_activity
from netshield.core.settings import save_settings, load_settings
from netshield.core.security import PrivateSnapshot


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.device = dict(id='device-1', name='Test Çalışanı', department='Yazılım', ip='192.0.2.10', interface='lan1')
        self.packet = dict(src='192.0.2.10', dst='192.0.2.20', proto='TCP', length=60, ts='12:00:00', interface='lan1')

    def test_validation_and_interface_identity(self):
        self.assertEqual(len(validate_devices([self.device, dict(self.device, id='2', interface='lan2')])), 2)
        for changes in ({'ip': 'invalid'}, {'name': ''}, {'department': '\nfoo'}, {'name': 'x' * 101}):
            with self.assertRaises(ValueError):
                validate_devices([dict(self.device, **changes)])
        with self.assertRaises(ValueError):
            validate_devices([self.device, dict(self.device, id='2')])
        with self.assertRaises(ValueError):
            validate_devices([self.device, dict(self.device, interface='lan2')])

    def test_bidirectional_counts_and_interface_isolation(self):
        packets = [self.packet, dict(self.packet, src=self.packet['dst'], dst=self.packet['src']),
                   dict(self.packet, interface='lan2', length=500)]
        alarms = [dict(ip=self.device['ip'], interface='lan1'), dict(ip=self.device['ip'], interface='lan2')]
        activity = device_activity(self.device, packets, alarms)
        self.assertEqual((activity['sent_bytes'], activity['received_bytes'], activity['alerts']), (60, 60, 1))
        self.assertEqual(len(activity['conversations']), 1)
        self.assertEqual(device_activity(self.device, [], [])['status'], 'Gözlenmedi')
        self.assertEqual(device_activity(self.device, [], alarms)['status'], 'Yalnızca alarm')

    def test_private_persistence_and_legacy_defaults(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'settings.json'
            save_settings(path, {'devices': [self.device]})
            data, error = load_settings(path)
            self.assertIsNone(error)
            self.assertEqual(data['devices'], [self.device])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            path.write_text('{}')
            self.assertEqual(load_settings(path)[0]['devices'], [])

    def test_export_allowlist_excludes_identity(self):
        data = PrivateSnapshot().session([dict(self.packet, name=self.device['name'], department='Yazılım')], [], 1)
        serialized = json.dumps(data, ensure_ascii=False)
        self.assertNotIn(self.device['name'], serialized)
        self.assertNotIn('Yazılım', serialized)
