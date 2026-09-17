import json
import os
import queue
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from contextlib import ExitStack
from types import SimpleNamespace

import ids
from netshield.core import motor
from netshield.config import ESIKLER
from netshield.core.security import (PrivateSnapshot, private_write, render_report,
                                     effective_policy, load_managed_policy, validate_security)
from netshield.core.settings import validate_settings


class SecurityTests(unittest.TestCase):
    def test_profile_defaults_and_managed_restrictions(self):
        personal = validate_security({})
        self.assertTrue(personal['allow_exports'])
        self.assertFalse(personal['allow_clipboard'])
        self.assertFalse(personal['allow_firewall'])
        enterprise = validate_security(dict(profile='Kurumsal', allow_exports=True, allow_clipboard=True, allow_firewall=True))
        for key in ('allow_exports', 'allow_clipboard', 'allow_firewall'):
            self.assertFalse(enterprise[key])
        self.assertFalse(effective_policy(personal, {'allow_exports': False})['allow_exports'])

    def test_snapshot_omits_content_and_addresses_and_uses_fresh_aliases(self):
        raw = dict(ts='12:00:00', src='192.168.1.1', dst='2001:db8::1', sport=5000,
                   dport=80, proto='HTTP', transport='TCP', info='password=SECRET',
                   payload='SECRET', hex='53 45 43 52 45 54', interface='internal-secret', length=123)
        event = dict(ip=raw['src'], dst=raw['dst'], tur='HTTP Flood', detay='SECRET', count=100)
        export = PrivateSnapshot().session([raw], [event], 1)
        serialized = json.dumps(export)
        for forbidden in ('192.168.1.1', '2001:db8::1', 'SECRET', '53 45', 'internal-secret', 'payload', 'hex'):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(export['packets'][0]['src'], export['alerts'][0]['ip'])
        other = PrivateSnapshot().session([raw], [event], 1)
        self.assertNotEqual(other['packets'][0]['src'], export['packets'][0]['src'])

    def test_private_file_mode_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'report.json'
            private_write(path, 'one')
            path.chmod(0o644)
            private_write(path, 'two')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            link = Path(folder) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                private_write(link, 'bad')
            self.assertEqual(path.read_text(), 'two')
            with patch('netshield.core.security.os.replace', side_effect=OSError('failed')):
                with self.assertRaises(OSError):
                    private_write(path, 'three')
            self.assertEqual(path.read_text(), 'two')
            self.assertEqual(len(list(Path(folder).iterdir())), 2)

    def test_managed_policy_fails_closed_and_accepts_trusted_restrictions(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'policy.json'
            self.assertEqual(load_managed_policy(path), ({}, None))
            path.write_text('{broken')
            policy, error = load_managed_policy(path)
            self.assertIsNotNone(error)
            self.assertFalse(any(policy.values()))
            path.write_text('{"allow_exports": false}')
            metadata = SimpleNamespace(st_mode=0o100600, st_uid=0, st_size=24)
            with patch('netshield.core.security.os.fstat', return_value=metadata):
                policy, error = load_managed_policy(path)
            self.assertIsNone(error)
            self.assertFalse(policy['allow_exports'])
            metadata.st_mode = 0o100666
            with patch('netshield.core.security.os.fstat', return_value=metadata):
                policy, error = load_managed_policy(path)
            self.assertIsNotNone(error)
            self.assertFalse(any(policy.values()))

    def test_report_escapes_untrusted_values_and_disallows_active_content(self):
        html = render_report({'alerts': [{'tur': '<script>alert(1)</script>', 'ip': '<img src=https://example.test>'}]})
        self.assertNotIn('<script>', html)
        self.assertNotIn('<img', html)
        self.assertIn('&lt;script&gt;', html)
        self.assertIn("default-src 'none'", html)

    def test_policy_is_checked_before_firewall_and_each_sensitive_action(self):
        app = ids.App.__new__(ids.App)
        app.preferences = validate_settings({})
        app.motor = Mock(sim=True)
        app._syslog = Mock()
        app.banned = {}
        with patch.object(ids.subprocess, 'run') as run:
            app._ban_ip('192.0.2.1', 'Manuel')
            run.assert_not_called()
        app.preferences['security']['allow_firewall'] = True
        with patch.object(ids.subprocess, 'run') as run, patch.object(ids, 'is_root', return_value=True):
            app._ban_ip('192.0.2.1', 'Manuel')
            run.assert_not_called()
        with patch.object(ids, 'load_managed_policy', return_value=({'allow_exports': False}, None)):
            self.assertFalse(app._security_allows('allow_exports'))

    def test_export_rechecks_policy_after_file_dialog(self):
        app = ids.App.__new__(ids.App)
        app.preferences = validate_settings({})
        app.root = Mock()
        app._syslog = Mock()
        with patch.object(ids, 'load_managed_policy', side_effect=[({}, None), ({'allow_exports': False}, None)]), \
                patch('netshield.ui.workspace.filedialog.asksaveasfilename', return_value='/tmp/not-written.json'), \
                patch('netshield.ui.workspace.private_write') as write:
            app._export()
            write.assert_not_called()

    @unittest.skipUnless(motor.SCAPY_OK, 'Scapy optional')
    def test_packet_processing_does_not_send_or_resolve_and_discards_http_secrets(self):
        m = motor.Motor(queue.Queue(), ESIKLER, simulation=True)
        packet = motor.IP(src='192.0.2.1', dst='192.0.2.2') / motor.TCP(dport=80) / b'GET /?token=SECRET HTTP/1.1\r\nCookie: SECRET\r\n\r\n'
        with ExitStack() as stack:
            for name in ('connect', 'connect_ex', 'send', 'sendall', 'sendto'):
                stack.enter_context(patch.object(socket.socket, name, side_effect=AssertionError('Unexpected network write')))
            for name in ('getaddrinfo', 'gethostbyname', 'create_connection'):
                stack.enter_context(patch.object(socket, name, side_effect=AssertionError('Unexpected resolution/connect')))
            m._pkt(packet)
            records = m.consume_packets()
            self.assertEqual(records[0]['proto'], 'HTTP')
            self.assertNotIn('SECRET', json.dumps(records))
            self.assertEqual(records[0]['payload'], '')
            self.assertEqual(records[0]['hex'], '')


if __name__ == '__main__':
    unittest.main()
