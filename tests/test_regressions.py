import queue
import subprocess
import unittest
from collections import deque
from types import SimpleNamespace
from unittest.mock import Mock, mock_open, patch

import ids
from netshield.config import ESIKLER
from netshield.core import motor
from netshield.net import utils


class AppTests(unittest.TestCase):
    def setUp(self):
        self.app = ids.App.__new__(ids.App)
        self.app.banned = {}
        self.app.motor = motor.Motor(queue.Queue(), dict(ESIKLER))
        self.app._packet_total = 0
        self.app._grafik_ciz = Mock()
        self.app._ban_list = Mock()
        self.app._syslog = Mock()
        self.app._log_yaz = Mock()

    def test_report_with_event_and_cached_geo(self):
        self.app.olaylar = [dict(ip='192.0.2.1', tip='PAKET', tur='ICMP',
                                ts='12:00:00', detay='test')]
        output = mock_open()
        with patch.object(ids, 'get_cached_geo', return_value={'country': '<test>'}), \
                patch('builtins.open', output), patch.object(ids.subprocess, 'Popen'):
            self.app._rapor()
        html = output().write.call_args.args[0]
        self.assertIn('192.0.2.1', html)
        self.assertIn('&lt;test&gt;', html)

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
        packet = {'IP': SimpleNamespace(src='192.0.2.1'),
                  'TCP': SimpleNamespace(flags=16, dport=80, payload=payload)}
        with patch.multiple(motor, IP='IP', TCP='TCP', UDP='UDP', ICMP='ICMP'), \
                patch.object(motor.time, 'monotonic', return_value=1000.0):
            for _ in range(20):
                m._pkt(packet)
        return [msg[1] for msg in list(q.queue) if msg[0] == 'OLAY']

    def test_ack_and_tls_do_not_trigger_http_alarm(self):
        self.assertEqual(self.events_for(b''), [])
        self.assertEqual(self.events_for(b'\x16\x03\x01encrypted'), [])

    def test_http_requests_trigger_alarm(self):
        events = self.events_for(b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n')
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['tur'], 'HTTP Flood')

    def test_geo_snapshot_cannot_mutate_cache(self):
        with patch.dict(utils._geo_cache, {'192.0.2.1': {'country': 'Test'}}):
            result = utils.get_cached_geo('192.0.2.1')
            result['country'] = 'changed'
            self.assertEqual(utils.get_cached_geo('192.0.2.1')['country'], 'Test')


if __name__ == '__main__':
    unittest.main()
