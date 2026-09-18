"""Capture, bounded packet previews and a shared live/demo detection pipeline."""
import queue
import random
import threading
import time
from collections import deque
from datetime import datetime

try:
    from scapy.all import (sniff, IP, IPv6, ARP, TCP, UDP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply, DNS,
                           get_if_list, conf, ETH_P_ALL)
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    sniff = conf = IP = IPv6 = ARP = TCP = UDP = ICMP = DNS = None
    ICMPv6EchoRequest = ICMPv6EchoReply = None
    ETH_P_ALL = 3

    def get_if_list():
        return []

from netshield.config import ESIKLER, HTTP_PORTS, PACKET_HISTORY
from netshield.core.detection import Detector
from netshield.net.utils import is_root

from netshield.core.http_prefix import HTTPPrefixes



def ts_str():
    return datetime.now().strftime('%H:%M:%S.%f')[:-3]


class Motor:
    def __init__(self, q, esik, iface=None, simulation=None):
        self.q = q
        self.esik = {**ESIKLER, **esik}
        self.interfaces = list(dict.fromkeys([iface] if isinstance(iface, str) else (iface or [])))
        self.iface = self.interfaces[0] if len(self.interfaces) == 1 else None
        self.sim = not (SCAPY_OK and is_root()) if simulation is None else simulation
        self._detectors = {}
        self._http_prefixes = HTTPPrefixes()
        self._state_lock = threading.Lock()
        self._interface_state = {}
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
        if not self.sim and not SCAPY_OK:
            self.status = 'Hata'
            reason = 'Scapy bu Python ortamında kurulu değil.'
            self._emit(('LOG', 'HATA', reason))
            return
        self.status = 'Simülasyon' if self.sim else 'Başlatılıyor'
        if self.sim:
            targets = [(self._sim, (), 'demo')]
        else:
            self.interfaces = self.interfaces or [self._ifaces()[0]]
            self._interface_state = {name: {'status': 'Başlatılıyor', 'packets': 0} for name in self.interfaces}
            targets = [(self._dinle, (name,), name) for name in self.interfaces]
        for target, args, name in targets:
            thread = threading.Thread(target=target, args=args, daemon=True, name=f'netshield-{name}')
            self._threads.append(thread)
            thread.start()

    def interface_snapshot(self):
        with self._state_lock:
            return {name: dict(value) for name, value in self._interface_state.items()}

    def _interface_status(self, iface, status):
        with self._state_lock:
            entry = self._interface_state.setdefault(iface, {'packets': 0})
            entry['status'] = status
            statuses = {value['status'] for value in self._interface_state.values()}
            if self._stop.is_set():
                self.status = 'Durduruldu'
            elif 'Canlı' in statuses:
                self.status = 'Kısmi canlı' if 'Hata' in statuses else 'Canlı'
            elif 'Başlatılıyor' in statuses:
                self.status = 'Başlatılıyor'
            else:
                self.status = 'Hata'

    def dur(self):
        self._go = False
        self._stop.set()
        deadline = time.monotonic() + 1.5
        for thread in self._threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        with self._packet_lock:
            self._http_prefixes.pending.clear()
        self.status = 'Durduruldu'
        with self._state_lock:
            for entry in self._interface_state.values():
                entry['status'] = 'Durduruldu'

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
        capture_socket = None
        try:
            capture_socket = conf.L2listen(iface=iface, type=ETH_P_ALL)
            self._interface_status(iface, 'Canlı')
            self._emit(('LOG', 'SİSTEM', f'Dinleniyor: {iface}'))
            while not self._stop.is_set():
                sniff(opened_socket=capture_socket, prn=lambda packet: self._pkt(packet, iface), store=False,
                      timeout=1.0, stop_filter=lambda _: self._stop.is_set())
                with self._packet_lock:
                    self._http_prefixes.expire(time.monotonic())
        except PermissionError:
            self._interface_status(iface, 'Hata')
            self._emit(('LOG', 'HATA', f'{iface}: Paket yakalama yetkisi yok. Yakalama sürücüsü ve hesap izinlerini kontrol edin.'))
        except Exception as exc:
            self._interface_status(iface, 'Hata')
            self._emit(('LOG', 'HATA', f'{iface}: {exc}'))
        finally:
            with self._packet_lock:
                for flow in list(self._http_prefixes.pending):
                    if flow[0] == iface:
                        del self._http_prefixes.pending[flow]
            if capture_socket is not None:
                capture_socket.close()

    def _pkt(self, packet, iface=None):
        if not self._go:
            return
        with self._packet_lock:
            normalized = self._normalize(packet, iface)
            if normalized:
                if iface is not None:
                    normalized['interface'] = iface
                self._ingest(normalized, time.monotonic())

    def _normalize(self, packet, iface=None):
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
                        info=f'ARP op={layer.op}', interface=self.iface or '',
                        hex='', payload='', simulated=False)
        else:
            return None
        record = dict(ts=ts_str(), src=layer.src, dst=getattr(layer, 'dst', ''),
                      sport=None, dport=None, proto=version, transport=version, network=version,
                      length=len(packet), flags='', flags_value=0, payload_size=0,
                      info=version, interface=self.iface or '', simulated=False,
                      hex='', payload='')
        if TCP in packet or UDP in packet:
            transport = 'TCP' if TCP in packet else 'UDP'
            layer = packet[TCP] if transport == 'TCP' else packet[UDP]
            payload = bytes(layer.payload)[:512]
            payload_size = len(layer.payload)
            record.update(transport=transport, proto=transport, sport=layer.sport,
                          dport=layer.dport, payload_size=payload_size)
            if transport == 'TCP':
                record.update(flags=str(layer.flags), flags_value=int(layer.flags))
                flow = (iface or self.iface or '', record['src'], record['dst'], layer.sport, layer.dport)
                if layer.dport in HTTP_PORTS and self._http_prefixes.feed(
                        flow, (int(layer.seq) + bool(int(layer.flags) & 2)) & 0xffffffff, payload,
                        time.monotonic(), reset=bool(int(layer.flags) & 6)):
                    record.update(proto='HTTP', http_request=True)
            if DNS in packet:
                record.update(proto='DNS', dns_query=int(packet[DNS].qr) == 0)
            record['info'] = f"{layer.sport} → {layer.dport}  {record['flags']}  yük={payload_size} B"
            if record.get('http_request'):
                record['info'] = 'HTTP/1 isteği · içerik saklanmadı'
        elif ICMP in packet:
            record.update(proto='ICMP', transport='ICMP', icmp_type=packet[ICMP].type,
                          info=f'ICMP type={packet[ICMP].type} code={packet[ICMP].code}')
        elif ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet:
            layer = packet[ICMPv6EchoRequest] if ICMPv6EchoRequest in packet else packet[ICMPv6EchoReply]
            record.update(proto='ICMPv6', transport='ICMPv6', icmp_type=int(layer.type),
                          info=f'ICMPv6 type={layer.type} code={layer.code}')
        return record

    def _ingest(self, record, ts):
        self._sequence += 1
        record['id'] = self._sequence
        record['payload'] = ''
        record['hex'] = ''
        interface = record.get('interface', '')
        with self._state_lock:
            entry = self._interface_state.setdefault(interface, {'status': 'Simülasyon' if self.sim else 'Canlı', 'packets': 0})
            entry['packets'] += 1
        with self._traffic_lock:
            self._traffic_count += 1
            if len(self._previews) == self._previews.maxlen:
                self.preview_dropped += 1
            self._previews.append(record)
        if record['transport'] not in ('ARP', 'IPv6', 'IPv4'):
            if interface not in self._detectors:
                self._detectors[interface] = Detector(self.esik)
            for event in self._detectors[interface].process(record, ts):
                event['interface'] = interface
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
