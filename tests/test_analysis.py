import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netshield.core.filters import compile_filter
from netshield.core.audit import audit_path, read_recent
from netshield.core.settings import load_settings, save_settings, validate_settings
from netshield.core.tracking import summarize
from netshield.config import ESIKLER


def packet(**changes):
    return dict(dict(src='192.168.1.10', dst='192.168.1.20', sport=50000, dport=443,
                     transport='TCP', proto='TCP', length=60, ts='12:00:00'), **changes)


class AdvancedFilterTests(unittest.TestCase):
    def test_networks_ports_and_ipv6(self):
        self.assertTrue(compile_filter('ip=192.168.1.0/24 sport=50000 dport=443')(packet()))
        self.assertFalse(compile_filter('src=192.168.2.0/24')(packet()))
        self.assertFalse(compile_filter('ip=192.168.1.1')(packet()))
        p = packet(src='2001:db8::1', dst='2001:db8::2', network='IPv6')
        self.assertTrue(compile_filter('proto=IPv6 ip=2001:db8::/32')(p))
        self.assertFalse(compile_filter('ip=192.168.1.0/24')(p))

    def test_capture_modes_are_explicit(self):
        self.assertTrue(compile_filter('mode=demo')(packet(simulated=True)))
        self.assertFalse(compile_filter('mode=live')(packet(simulated=True)))
        self.assertTrue(compile_filter('mode=live')(packet(simulated=False)))
        with self.assertRaises(ValueError):
            compile_filter('mode=unknown')

    def test_flow_matches_reverse_but_not_crossed_ports(self):
        matches = compile_filter('flow=TCP,192.168.1.10,50000,192.168.1.20,443')
        self.assertTrue(matches(packet()))
        self.assertTrue(matches(packet(src='192.168.1.20', dst='192.168.1.10', sport=443, dport=50000)))
        self.assertFalse(matches(packet(sport=443, dport=50000)))
        self.assertFalse(matches(packet(transport='UDP')))
        arp = compile_filter('flow=ARP,192.168.1.10,None,192.168.1.20,None')
        self.assertTrue(arp(packet(transport='ARP', sport=None, dport=None)))

    def test_bad_networks_and_flows_rejected(self):
        for expression in ('ip=bad', 'src=192.0.2.0/90', 'sport=-1', 'flow=TCP,1,2',
                           'flow=TCP,192.0.2.1,70000,192.0.2.2,80'):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                compile_filter(expression)


class TrackingTests(unittest.TestCase):
    def test_bidirectional_traffic_and_quiet_watched_hosts(self):
        packets = [packet(), packet(src='192.168.1.20', dst='192.168.1.10', sport=443, dport=50000, length=120)]
        result = summarize(packets, [dict(ip='192.168.1.10', dst='192.168.1.20')], ['192.168.1.99'])
        hosts = {h['ip']: h for h in result['hosts']}
        self.assertEqual(hosts['192.168.1.10']['sent'], 1)
        self.assertEqual(hosts['192.168.1.10']['received'], 1)
        self.assertEqual(hosts['192.168.1.10']['bytes'], 180)
        self.assertEqual(hosts['192.168.1.10']['alerts'], 1)
        self.assertEqual(hosts['192.168.1.99']['bytes'], 0)
        self.assertEqual(len(result['conversations']), 1)
        self.assertEqual(result['conversations'][0]['packets'], 2)
        self.assertEqual(result['conversations'][0]['bytes'], 180)

    def test_loopback_not_double_counted_and_distributed_source_not_host(self):
        result = summarize([packet(src='127.0.0.1', dst='127.0.0.1')],
                           [dict(ip='Çoklu kaynak', dst='127.0.0.1')])
        self.assertEqual(len(result['hosts']), 1)
        self.assertEqual(result['hosts'][0]['bytes'], 60)


class SettingsTests(unittest.TestCase):
    def test_roundtrip_validation_and_corrupt_file_fallback(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'nested' / 'settings.json'
            data = dict(density='Kompakt', watchlist=['2001:db8::1', '2001:db8::1'], thresholds={'syn_per_sec': 42})
            save_settings(path, data)
            restored, error = load_settings(path)
            self.assertIsNone(error)
            self.assertEqual(restored['density'], 'Kompakt')
            self.assertEqual(restored['watchlist'], ['2001:db8::1'])
            self.assertEqual(restored['thresholds']['syn_per_sec'], 42)
            path.write_text('{broken')
            restored, error = load_settings(path)
            self.assertIsNotNone(error)
            self.assertEqual(restored['thresholds'], ESIKLER)

    def test_failed_replace_preserves_previous_file_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'settings.json'
            save_settings(path, {})
            original = path.read_text()
            with patch('netshield.core.settings.os.replace', side_effect=OSError('denied')):
                with self.assertRaises(OSError):
                    save_settings(path, {'density': 'Kompakt'})
            self.assertEqual(path.read_text(), original)
            self.assertFalse(list(Path(folder).glob('.settings-*')))
            self.assertEqual({item.name for item in Path(folder).iterdir()},
                             {'settings.json', audit_path(path).name})
            self.assertEqual(read_recent(path, limit=1)[0]['outcome'], 'failed')

    def test_invalid_preferences_rejected(self):
        for data in ({'watchlist': ['bad']}, {'watchlist': [1]}, {'density': 'bad'},
                     {'thresholds': {'port_scan': 1025}}, {'thresholds': {'syn_per_sec': True}}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                validate_settings(data)


if __name__ == '__main__':
    unittest.main()
