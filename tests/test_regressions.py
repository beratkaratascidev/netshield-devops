import queue
import subprocess
import unittest
import tempfile
from pathlib import Path
from netshield.core.settings import validate_settings
from collections import deque
from types import SimpleNamespace
from unittest.mock import Mock, patch

import ids
from netshield.config import ESIKLER
from netshield.core import motor


class AppTests(unittest.TestCase):
    def setUp(self):
        self.app = ids.App.__new__(ids.App)
        self.app.banned = {}
        self.app.root = Mock()
        self.app._firewall_tag = 'netshield-test'
        self.app.preferences = validate_settings({'security': {'allow_firewall': True}})
        self.app.managed_policy = {}
        root_patch = patch.object(ids, 'is_root', return_value=True)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        self.app._closed = False
        self.app._refresh_tracking = Mock()
        self.app._resort_tables = Mock()
        self.app._autoscroll = Mock()
        self.app._autoscroll.get.return_value = False
        self.app.motor = motor.Motor(queue.Queue(), dict(ESIKLER))
        self.app.motor.sim = False
        self.app._packet_total = 0
        self.app._grafik_ciz = Mock()
        self.app._ban_list = Mock()
        self.app._syslog = Mock()
        self.app._log_yaz = Mock()

    def test_report_is_masked_and_does_not_launch_browser(self):
        self.app.olaylar = [dict(ip='192.0.2.1', dst='192.0.2.2', tip='FLOOD', tur='<test>',
                                ts='12:00:00', detay='secret')]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'report.html'
            with patch.object(ids.filedialog, 'asksaveasfilename', return_value=str(path)), \
                    patch.object(ids.subprocess, 'Popen') as launch:
                self.app._rapor()
            html = path.read_text()
            self.assertNotIn('192.0.2.1', html)
            self.assertNotIn('secret', html)
            self.assertIn('&lt;test&gt;', html)
            launch.assert_not_called()

    def test_failed_ban_does_not_record_or_block_retry(self):
        with patch.object(ids.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'iptables')):
            self.app._ban_ip('192.0.2.1', 'Manuel')
        self.assertEqual(self.app.banned, {})
        self.app._ban_list.insert.assert_not_called()
        with patch.object(ids.subprocess, 'run') as run:
            self.app._ban_ip('192.0.2.1', 'Manuel')
        run.assert_called_once()
        self.assertIn('192.0.2.1', self.app.banned)

    def test_failed_unban_preserves_record(self):
        self.app.banned['192.0.2.1'] = {'tur': 'Manuel'}
        self.app._ban_list.curselection.return_value = (0,)
        self.app._ban_list.get.return_value = '192.0.2.1 [Manuel]'
        with patch.object(ids.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'iptables')):
            self.app._ban_kaldir()
        self.assertIn('192.0.2.1', self.app.banned)
        self.app._ban_list.delete.assert_not_called()
        with patch.object(ids.subprocess, 'run'):
            self.app._ban_kaldir()
        self.assertEqual(self.app.banned, {})

    def test_traffic_rate_and_idle(self):
        a = self.app
        a.q = queue.Queue()
        a.trafik = deque([0] * 90, maxlen=90)
        a._traffic_count = 0
        a._traffic_since = 100.0
        a._guncelle = Mock()
        a.root = Mock()
        for _ in range(500):
            a.motor._record_traffic(1)
        with patch.object(ids.time, 'monotonic', return_value=100.5):
            a._poll()
        self.assertEqual(a.trafik[-1], 0)
        for _ in range(500):
            a.motor._record_traffic(1)
        with patch.object(ids.time, 'monotonic', return_value=101.0):
            a._poll()
        self.assertEqual(a.trafik[-1], 1000)
        self.assertEqual(a._packet_total, 1000)
        with patch.object(ids.time, 'monotonic', return_value=102.0):
            a._poll()
        self.assertEqual(a.trafik[-1], 0)

    def test_poll_yields_with_queue_backlog(self):
        a = self.app
        a.q = queue.Queue()
        a.trafik = deque([0], maxlen=90)
        a._traffic_count = 0
        a._traffic_since = 100.0
        a._guncelle = Mock()
        a.root = Mock()
        for _ in range(1001):
            a.q.put(('LOG', 'SİSTEM', 'test'))
        with patch.object(ids.time, 'monotonic', return_value=100.1):
            a._poll()
        self.assertEqual(a.q.qsize(), 1)
        a.root.after.assert_called_once()


class MotorTests(unittest.TestCase):
    def test_high_volume_traffic_does_not_fill_queue(self):
        q = queue.Queue()
        m = motor.Motor(q, dict(ESIKLER))
        for _ in range(100000):
            m._record_traffic(1)
        self.assertTrue(q.empty())
        self.assertEqual(m.consume_traffic(), 100000)
        self.assertEqual(m.consume_traffic(), 0)

    def test_simulation_stops_and_start_is_idempotent(self):
        m = motor.Motor(queue.Queue(), dict(ESIKLER))
        m.sim = True
        m.baslat()
        m.baslat()
        self.assertEqual(len(m._threads), 1)
        m.dur()
        self.assertFalse(m._threads[0].is_alive())

    def test_idle_capture_has_timeout_and_stops(self):
        m = motor.Motor(queue.Queue(), dict(ESIKLER))
        def idle_capture(**kwargs):
            self.assertEqual(kwargs['timeout'], 1.0)
            m._stop.set()
        socket = Mock()
        config = SimpleNamespace(L2listen=Mock(return_value=socket))
        with patch.object(motor, 'conf', config), \
                patch.object(motor, 'sniff', side_effect=idle_capture) as capture:
            m._dinle('test-interface')
        capture.assert_called_once()
        self.assertIs(capture.call_args.kwargs['opened_socket'], socket)
        socket.close.assert_called_once()

    def events_for(self, payload):
        q = queue.Queue()
        m = motor.Motor(q, dict(ESIKLER))
        if not motor.SCAPY_OK:
            self.skipTest('Scapy is optional')
        packet = motor.IP(src='192.0.2.1', dst='192.0.2.2') / motor.TCP(flags='A', dport=80) / payload
        with patch.object(motor.time, 'monotonic', return_value=1000.0):
            for _ in range(ESIKLER['http_per_sec']):
                m._pkt(packet)
        return [msg[1] for msg in list(q.queue) if msg[0] == 'OLAY']

    def test_ack_and_tls_do_not_trigger_http_alarm(self):
        self.assertEqual(self.events_for(b''), [])
        self.assertEqual(self.events_for(b'\x16\x03\x01encrypted'), [])

    def test_http_requests_trigger_alarm(self):
        events = self.events_for(b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n')
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['tur'], 'HTTP Flood')



if __name__ == '__main__':
    unittest.main()
