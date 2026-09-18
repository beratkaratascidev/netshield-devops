import queue
import unittest
from unittest.mock import Mock, patch
from netshield.core.detection import Detector
from netshield.core.filters import compile_filter
from netshield.core.motor import Motor
from netshield.config import ESIKLER, PACKET_HISTORY


def packet(**changes):
    p = dict(ts='12:00:00', src='192.168.1.20', dst='192.168.1.10',
             sport=49152, dport=80, proto='TCP', transport='TCP',
             flags_value=2, payload_size=0, simulated=True)
    p.update(changes)
    return p


class DetectionTests(unittest.TestCase):
    def test_all_rate_rules_trigger_at_threshold_not_before(self):
        rules = [
            ('ICMP', 'icmp_per_sec', dict(transport='ICMP', icmp_type=8)),
            ('SYN', 'syn_per_sec', dict(flags_value=2)),
            ('UDP', 'udp_per_sec', dict(transport='UDP')),
            ('HTTP Flood', 'http_per_sec', dict(flags_value=24, http_request=True)),
            ('ACK Flood', 'ack_per_sec', dict(flags_value=16)),
            ('RST Flood', 'rst_per_sec', dict(flags_value=4)),
            ('DNS Flood', 'dns_per_sec', dict(transport='UDP', dns_query=True, dport=53)),
        ]
        for kind, setting, changes in rules:
            with self.subTest(kind=kind):
                detector = Detector({setting: 3})
                for _ in range(2):
                    self.assertFalse(any(e['tur'] == kind for e in detector.process(packet(**changes), 100)))
                alarms = [e for e in detector.process(packet(**changes), 100) if e['tur'] == kind]
                self.assertEqual(len(alarms), 1)
                self.assertEqual(alarms[0]['count'], 3)
                self.assertEqual(alarms[0]['threshold'], 3)
                self.assertEqual(alarms[0]['dst'], '192.168.1.10')

    def test_windows_expire_and_destinations_are_independent(self):
        detector = Detector({'syn_per_sec': 3})
        detector.process(packet(), 100)
        detector.process(packet(), 100)
        self.assertEqual(detector.process(packet(dst='192.168.1.11'), 100), [])
        self.assertEqual(detector.process(packet(), 101.1), [])

    def test_cooldown_does_not_suppress_different_targets(self):
        detector = Detector({'syn_per_sec': 1})
        self.assertEqual(len(detector.process(packet(), 100)), 1)
        self.assertEqual(detector.process(packet(), 100.1), [])
        self.assertEqual(len(detector.process(packet(dst='192.168.1.11'), 100.1)), 1)
        self.assertEqual(len(detector.process(packet(), 101.2)), 1)

    def test_scan_counts_unique_ports_per_target_and_only_attempts(self):
        detector = Detector({'port_scan': 3})
        for port in (80, 80, 80):
            self.assertEqual(detector.process(packet(dport=port), 100), [])
        self.assertEqual(detector.process(packet(dst='192.168.1.11', dport=443), 100), [])
        self.assertEqual(detector.process(packet(dport=443, flags_value=16), 100), [])
        detector.process(packet(dport=443), 100)
        alarms = detector.process(packet(dport=22), 100)
        self.assertEqual([e['tur'] for e in alarms], ['Port Tarama'])

    def test_replies_and_data_are_not_requests_or_pure_ack(self):
        detector = Detector({'dns_per_sec': 1, 'icmp_per_sec': 1, 'ack_per_sec': 1})
        self.assertEqual(detector.process(packet(transport='UDP', dns_query=False), 100), [])
        self.assertEqual(detector.process(packet(transport='ICMP', icmp_type=0), 100), [])
        self.assertEqual(detector.process(packet(flags_value=16, payload_size=20), 100), [])

    def test_distributed_alarm_requires_multiple_sources(self):
        detector = Detector({'target_per_sec': 4, 'target_sources': 3})
        for _ in range(5):
            self.assertEqual(detector.process(packet(flags_value=24), 100), [])
        self.assertEqual(detector.process(packet(src='192.168.1.21', flags_value=24), 100), [])
        events = detector.process(packet(src='192.168.1.22', flags_value=24), 100)
        self.assertEqual(events[0]['tur'], 'Dağıtık Flood Şüphesi')
        self.assertEqual(events[0]['sources'], 3)

    def test_demo_exercises_all_nine_detectors_without_network(self):
        thresholds = {key: 3 for key in ESIKLER}
        thresholds.update(target_per_sec=12, target_sources=3, port_win=5)
        q = queue.Queue()
        motor = Motor(q, thresholds, simulation=True)
        motor._stop = Mock()
        motor._stop.wait.side_effect = [False] * 10 + [True]
        motor._stop.is_set.return_value = False
        with patch('netshield.core.motor.time.monotonic', return_value=1000.0):
            motor._sim()
        detected = {message[1]['tur'] for message in list(q.queue) if message[0] == 'OLAY'}
        self.assertEqual(detected, {'ICMP', 'SYN', 'UDP', 'HTTP Flood', 'ACK Flood',
                                    'RST Flood', 'DNS Flood', 'Port Tarama', 'Dağıtık Flood Şüphesi'})

    def test_state_and_preview_buffers_are_bounded(self):
        detector = Detector(max_flows=8)
        for i in range(100):
            detector.process(packet(src=f'10.0.0.{i}'), 100)
        for store in (detector.rates, detector.ports, detector.targets, detector.cooldown):
            self.assertLessEqual(len(store), 8)
        motor = Motor(queue.Queue(maxsize=1), ESIKLER, simulation=True)
        for _ in range(PACKET_HISTORY + 10):
            motor._ingest(packet(transport='ARP'), 100)
        self.assertEqual(motor.preview_dropped, 10)
        self.assertEqual(motor.consume_traffic(), PACKET_HISTORY + 10)
        self.assertEqual(len(motor.consume_packets(PACKET_HISTORY + 10)), PACKET_HISTORY)
        motor._emit(('LOG', 'SİSTEM', 'one'))
        motor._emit(('LOG', 'SİSTEM', 'two'))
        self.assertEqual(motor.event_dropped, 1)


class FilterTests(unittest.TestCase):
    def test_combined_filter_and_transport_alias(self):
        matches = compile_filter('src=192.168.1. proto=TCP port=80')
        self.assertTrue(matches(packet(proto='HTTP')))
        self.assertFalse(matches(packet(dport=443)))
        self.assertTrue(compile_filter('info="GET /"')({**packet(), 'info': 'GET / HTTP/1.1'}))

    def test_invalid_filters_are_rejected(self):
        for expression in ('unknown=x', 'port=abc', 'port=70000', 'src=', '"unterminated'):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                compile_filter(expression)


class PacketNormalizationTests(unittest.TestCase):
    def setUp(self):
        from netshield.core import motor
        if not motor.SCAPY_OK:
            self.skipTest('Scapy is optional')
        self.module = motor
        self.motor = Motor(queue.Queue(), ESIKLER, iface='test0', simulation=True)

    def test_ipv6_transport_and_arp_preview(self):
        m = self.module
        record = self.motor._normalize(m.IPv6(src='2001:db8::1', dst='2001:db8::2') /
                                       m.TCP(sport=50000, dport=443, flags='S'))
        self.assertEqual(record['network'], 'IPv6')
        self.assertEqual(record['proto'], 'TCP')
        self.assertEqual(record['flags_value'], 2)
        record = self.motor._normalize(m.ARP(psrc='192.168.1.1', pdst='192.168.1.2'))
        self.assertEqual(record['proto'], 'ARP')
        self.assertEqual(record['src'], '192.168.1.1')

    def test_ipv6_echo_requests_trigger_but_replies_do_not(self):
        from scapy.all import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
        detector = Detector({'icmp_per_sec': 2})
        base = IPv6(src='2001:db8::1', dst='2001:db8::2')
        request = self.motor._normalize(base / ICMPv6EchoRequest())
        reply = self.motor._normalize(base / ICMPv6EchoReply())
        self.assertEqual(request['transport'], 'ICMPv6')
        self.assertEqual(detector.process(reply, 100), [])
        self.assertEqual(detector.process(request, 100), [])
        self.assertEqual([e['tur'] for e in detector.process(request, 100)], ['ICMP'])

    def test_http_request_split_between_packets_is_detected_once(self):
        from scapy.all import IP, TCP, Raw
        base = IP(src='192.0.2.1', dst='192.0.2.2')
        first = base / TCP(sport=5000, dport=80, seq=100, flags='PA') / Raw(b'GET / HT')
        second = base / TCP(sport=5000, dport=80, seq=108, flags='PA') / Raw(b'TP/1.1\r\n')
        self.assertFalse(self.motor._normalize(first, 'lan1').get('http_request', False))
        self.assertFalse(self.motor._normalize(second, 'lan2').get('http_request', False))
        result = self.motor._normalize(second, 'lan1')
        self.assertTrue(result['http_request'])
        self.assertEqual(result['payload'], '')

    def test_dns_direction_and_payload_preview_limit(self):
        m = self.module
        for response in (0, 1):
            wire = m.IP(src='192.0.2.1', dst='192.0.2.2') / m.UDP(dport=53) / m.DNS(qr=response)
            record = self.motor._normalize(wire)
            self.assertEqual(record['proto'], 'DNS')
            self.assertEqual(record['dns_query'], response == 0)
        wire = m.IP(src='192.0.2.1', dst='192.0.2.2') / m.TCP(dport=80) / (b'x' * 5000)
        record = self.motor._normalize(wire)
        self.assertEqual(record['payload_size'], 5000)
        self.assertEqual(record['payload'], '')
        self.assertEqual(record['hex'], '')


if __name__ == '__main__':
    unittest.main()
