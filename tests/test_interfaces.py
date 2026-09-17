import queue
import threading
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
from netshield.core import motor
from netshield.core.tracking import summarize
from netshield.core.filters import compile_filter
from netshield.config import ESIKLER


class InterfaceTests(unittest.TestCase):
    def test_missing_library_and_missing_privilege_have_distinct_errors(self):
        for scapy, text in ((False, 'kurulu değil'), (True, 'yetkisi yok')):
            q = queue.Queue()
            m = motor.Motor(q, ESIKLER, simulation=False)
            with patch.object(motor, 'SCAPY_OK', scapy), patch.object(motor, 'is_root', return_value=False):
                m.baslat()
            self.assertEqual(m.status, 'Hata')
            self.assertIn(text, q.get_nowait()[2])
            self.assertEqual(m._threads, [])

    def test_selected_interfaces_start_once_and_stop_together(self):
        m = motor.Motor(queue.Queue(), ESIKLER, iface=['lan1', 'lan2', 'lan1'], simulation=False)
        ready = threading.Event()
        names = []
        def listen(name):
            with m._state_lock:
                names.append(name)
                if len(names) == 2:
                    ready.set()
            m._stop.wait(1)
        with patch.object(motor, 'SCAPY_OK', True), patch.object(motor, 'is_root', return_value=True), patch.object(m, '_dinle', side_effect=listen):
            m.baslat()
            m.baslat()
            self.assertTrue(ready.wait(1))
            m.dur()
        self.assertCountEqual(names, ['lan1', 'lan2'])
        self.assertEqual(len(m._threads), 2)
        self.assertFalse(any(t.is_alive() for t in m._threads))

    def test_overlapping_addresses_do_not_share_detection_counters(self):
        q = queue.Queue()
        m = motor.Motor(q, {**ESIKLER, 'syn_per_sec': 3}, iface=['a', 'b'], simulation=True)
        p = dict(ts='12:00:00', src='192.168.1.1', dst='192.168.1.2', sport=5000, dport=80,
                 proto='TCP', transport='TCP', flags_value=2, payload_size=0)
        for name in ('a', 'a', 'b', 'b'):
            m._ingest(dict(p, interface=name), 100)
        self.assertTrue(q.empty())
        m._ingest(dict(p, interface='a'), 100)
        self.assertEqual(q.get_nowait()[1]['interface'], 'a')
        m._ingest(dict(p, interface='b'), 100)
        self.assertEqual(q.get_nowait()[1]['interface'], 'b')
        self.assertEqual(m.interface_snapshot()['a']['packets'], 3)
        self.assertEqual(m.interface_snapshot()['b']['packets'], 3)

    def test_one_interface_failure_does_not_hide_healthy_capture(self):
        m = motor.Motor(queue.Queue(), ESIKLER, iface=['a', 'b'], simulation=False)
        m._interface_status('a', 'Canlı')
        with patch.object(motor, 'conf', SimpleNamespace(L2listen=Mock(side_effect=PermissionError('denied')))):
            m._dinle('b')
        self.assertEqual(m.status, 'Kısmi canlı')
        self.assertEqual(m.interface_snapshot()['a']['status'], 'Canlı')
        self.assertEqual(m.interface_snapshot()['b']['status'], 'Hata')

    def test_interface_filter_and_flow_summary_preserve_network_identity(self):
        p = dict(src='192.168.1.1', dst='192.168.1.2', sport=5000, dport=80,
                 transport='TCP', proto='TCP', length=60, ts='12:00:00')
        records = [dict(p, interface='a'), dict(p, interface='b')]
        self.assertEqual(len(summarize(records, [])['conversations']), 2)
        self.assertTrue(compile_filter('iface=a')(records[0]))
        self.assertFalse(compile_filter('iface=a')(records[1]))

    @unittest.skipUnless(motor.SCAPY_OK, 'Scapy optional')
    def test_capture_callback_marks_the_actual_interface(self):
        m = motor.Motor(queue.Queue(), ESIKLER, iface=['a', 'b'], simulation=True)
        packet = motor.IP(src='192.0.2.1', dst='192.0.2.2') / motor.TCP(flags='A')
        m._pkt(packet, 'a')
        m._pkt(packet, 'b')
        self.assertEqual([p['interface'] for p in m.consume_packets()], ['a', 'b'])


if __name__ == '__main__':
    unittest.main()
