"""Capture, bounded packet previews and a shared live/demo detection pipeline."""
import queue
import random
import re
import threading
import time
from collections import deque
from datetime import datetime

try:
    from scapy.all import (sniff, IP, IPv6, ARP, TCP, UDP, ICMP, DNS,
                           get_if_list, conf, ETH_P_ALL)
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    sniff = conf = IP = IPv6 = ARP = TCP = UDP = ICMP = DNS = None
    ETH_P_ALL = 3

    def get_if_list():
        return []

from netshield.config import ESIKLER, HTTP_PORTS, PACKET_HISTORY
from netshield.core.detection import Detector
from netshield.net.utils import is_root

HTTP_LINE = re.compile(rb'^(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) [^ \r\n]+ HTTP/1\.[01]\r\n')


def ts_str():
    return datetime.now().strftime('%H:%M:%S.%f')[:-3]


class Motor:
    def __init__(self, q, esik, iface=None, simulation=None):
        self.q = q
        self.esik = {**ESIKLER, **esik}
        self.iface = iface
        self.sim = not (SCAPY_OK and is_root()) if simulation is None else simulation
        self.detector = Detector(self.esik)
        self._go = True
        self._stop = threading.Event()
        self._packet_lock = threading.Lock()
        self._traffic_lock = threading.Lock()
        self._traffic_count = 0
        self._previews = deque(maxlen=PACKET_HISTORY)
        self.preview_dropped = 0
        self.event_dropped = 0
        self._sequence = 0
        self._threads = []
        self.status = 'Hazır'

    def _emit(self, message):
        try:
            self.q.put_nowait(message)
        except queue.Full:
            self.event_dropped += 1

    def baslat(self):
        if self._threads or self._stop.is_set():
            return
        if not self.sim and not (SCAPY_OK and is_root()):
            self.status = 'Hata'
            self._emit(('LOG', 'HATA', 'Canlı yakalama için Scapy ve root yetkisi gerekiyor.'))
            return
        self.status = 'Simülasyon' if self.sim else 'Başlatılıyor'
        target = self._sim if self.sim else self._dinle
        args = () if self.sim else (self.iface or self._ifaces()[0],)
        t = threading.Thread(target=target, args=args, daemon=True, name='netshield-capture')
        self._threads.append(t)
        t.start()

    def dur(self):
        self._go = False
        self._stop.set()
        deadline = time.monotonic() + 1.5
        for thread in self._threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        self.status = 'Durduruldu'

    def _record_traffic(self, count):
        with self._traffic_lock:
            self._traffic_count += count

    def consume_traffic(self):
        with self._traffic_lock:
            count = self._traffic_count
            self._traffic_count = 0
            return count

    def consume_packets(self, limit=500):
        with self._traffic_lock:
            return [self._previews.popleft() for _ in range(min(limit, len(self._previews)))]

    def _ifaces(self):
        interfaces = get_if_list()
        return interfaces or ['lo']

    def _dinle(self, iface):
        self.iface = iface
        capture_socket = None
        try:
            capture_socket = conf.L2listen(iface=iface, type=ETH_P_ALL)
            self.status = 'Canlı'
            self._emit(('LOG', 'SİSTEM', f'Dinleniyor: {iface}'))
            while not self._stop.is_set():
                sniff(opened_socket=capture_socket, prn=self._pkt, store=False,
                      timeout=1.0, stop_filter=lambda _: self._stop.is_set())
        except Exception as exc:
            self.status = 'Hata'
            self._emit(('LOG', 'HATA', f'{iface}: {exc}'))
        finally:
            if capture_socket is not None:
                capture_socket.close()

    def _pkt(self, packet):
        if not self._go:
            return
        with self._packet_lock:
            normalized = self._normalize(packet)
            if normalized:
                self._ingest(normalized, time.monotonic())

    def _normalize(self, packet):
        if IP in packet:
            layer = packet[IP]
            version = 'IPv4'
        elif IPv6 in packet:
            layer = packet[IPv6]
            version = 'IPv6'
        elif ARP in packet:
            layer = packet[ARP]
            return dict(ts=ts_str(), src=layer.psrc, dst=layer.pdst, sport=None, dport=None,
                        proto='ARP', transport='ARP', length=len(packet), flags='',
                        info=f'ARP op={layer.op} · {layer.hwsrc}', interface=self.iface or '',
                        hex=bytes(packet)[:256].hex(' '), payload='', simulated=False)
        else:
            return None
        record = dict(ts=ts_str(), src=layer.src, dst=getattr(layer, 'dst', ''),
                      sport=None, dport=None, proto=version, transport=version, network=version,
                      length=len(packet), flags='', flags_value=0, payload_size=0,
                      info=version, interface=self.iface or '', simulated=False,
                      hex=bytes(packet)[:256].hex(' '), payload='')
        if TCP in packet or UDP in packet:
            transport = 'TCP' if TCP in packet else 'UDP'
            layer = packet[TCP] if transport == 'TCP' else packet[UDP]
            payload = bytes(layer.payload)
            record.update(transport=transport, proto=transport, sport=layer.sport,
                          dport=layer.dport, payload_size=len(payload),
                          payload=payload[:256].decode('utf-8', errors='replace'))
            if transport == 'TCP':
                record.update(flags=str(layer.flags), flags_value=int(layer.flags))
                if layer.dport in HTTP_PORTS and HTTP_LINE.match(payload):
                    record.update(proto='HTTP', http_request=True)
            if DNS in packet:
                record.update(proto='DNS', dns_query=int(packet[DNS].qr) == 0)
            record['info'] = f"{layer.sport} → {layer.dport}  {record['flags']}  yük={len(payload)} B"
            if record.get('http_request'):
                record['info'] = payload.split(b'\r\n', 1)[0][:160].decode('utf-8', errors='replace')
        elif ICMP in packet:
            record.update(proto='ICMP', transport='ICMP', icmp_type=packet[ICMP].type,
                          info=f'ICMP type={packet[ICMP].type} code={packet[ICMP].code}')
        return record

    def _ingest(self, record, ts):
        self._sequence += 1
        record['id'] = self._sequence
        with self._traffic_lock:
            self._traffic_count += 1
            if len(self._previews) == self._previews.maxlen:
                self.preview_dropped += 1
            self._previews.append(record)
        if record['transport'] not in ('ARP', 'IPv6', 'IPv4'):
            for event in self.detector.process(record, ts):
                self._emit(('OLAY', event))

    def _sim(self):
        self._emit(('LOG', 'SİSTEM', 'Simülasyon: sentetik paketler, ağa gönderim yok.'))
        rng = random.Random(42)
        scenarios = [('ICMP', 'icmp_per_sec'), ('SYN', 'syn_per_sec'),
                     ('UDP', 'udp_per_sec'), ('HTTP', 'http_per_sec'),
                     ('ACK', 'ack_per_sec'), ('RST', 'rst_per_sec'),
                     ('DNS', 'dns_per_sec'), ('SCAN', 'port_scan'),
                     ('DISTRIBUTED', 'target_per_sec'), ('NORMAL', None)]
        index = 0
        while not self._stop.wait(0.65):
            kind, setting = scenarios[index % len(scenarios)]
            index += 1
            count = self.esik[setting] + 3 if setting else 8
            if kind == 'DISTRIBUTED':
                count = max(count, self.esik['target_sources'] + 1)
            count = min(count, 5000)
            src = f'192.168.1.{rng.randint(20, 80)}'
            for number in range(count):
                if self._stop.is_set():
                    return
                transport = 'ICMP' if kind == 'ICMP' else 'UDP' if kind in ('UDP', 'DNS') else 'TCP'
                flags = {'SYN': 2, 'ACK': 16, 'RST': 4, 'SCAN': 2}.get(kind, 24)
                source = src
                if kind == 'DISTRIBUTED':
                    host = number % self.esik['target_sources']
                    source = f'10.20.{host // 250}.{host % 250 + 1}'
                record = dict(ts=ts_str(), src=source, dst='192.168.1.200' if kind == 'DISTRIBUTED' else '192.168.1.10', sport=49152,
                              dport=number + 1 if kind == 'SCAN' else 53 if kind == 'DNS' else 80,
                              transport=transport, proto=kind if kind in ('DNS', 'HTTP') else transport,
                              flags_value=flags, flags={2: 'S', 16: 'A', 4: 'R', 24: 'PA'}[flags],
                              length=60, payload_size=0 if kind == 'ACK' else 20,
                              icmp_type=8, http_request=kind == 'HTTP', dns_query=kind == 'DNS',
                              info=f'Simülasyon · {kind}', interface='demo', simulated=True,
                              payload='Sentetik örnek; ham paket yok.', hex='')
                with self._packet_lock:
                    self._ingest(record, time.monotonic())
