"""Bounded, destination-aware rate heuristics; alarms are not proof of an attack."""
from collections import OrderedDict
from math import floor

from netshield.config import ESIKLER, COOLDOWN


class Detector:
    def __init__(self, thresholds=None, max_flows=4096):
        self.thresholds = {**ESIKLER, **(thresholds or {})}
        self.max_flows = max_flows
        self.rates = OrderedDict()
        self.ports = OrderedDict()
        self.targets = OrderedDict()
        self.cooldown = OrderedDict()

    def _entry(self, store, key, factory):
        if key not in store:
            if len(store) >= self.max_flows:
                store.popitem(last=False)
            store[key] = factory()
        store.move_to_end(key)
        return store[key]

    def _rate(self, key, ts):
        # Ten 100 ms buckets; one flow uses at most ten counters.
        bins = self._entry(self.rates, key, dict)
        tick = floor(ts * 10)
        for old in list(bins):
            if old <= tick - 10:
                del bins[old]
        bins[tick] = bins.get(tick, 0) + 1
        return sum(bins.values())

    def _alarm(self, packet, kind, count, limit, ts, window=1, sources=None):
        key = (packet['src'], packet['dst'], kind)
        if sources is not None:
            key = ('*', packet['dst'], kind)
        if key in self.cooldown and ts - self.cooldown[key] < COOLDOWN:
            return None
        self._entry(self.cooldown, key, lambda: ts)
        self.cooldown[key] = ts
        unit = 'farklı port' if kind == 'Port Tarama' else 'paket/istek'
        detail = f'{count} {unit} / {window} sn · eşik {limit}'
        if sources is not None:
            detail += f' · {sources} kaynak'
        return dict(ts=packet['ts'], ip=packet['src'] if sources is None else 'Çoklu kaynak',
                    dst=packet['dst'], tur=kind, tip='FLOOD', detay=detail,
                    count=count, threshold=limit, window=window,
                    severity='Kritik' if count >= limit * 2 else 'Yüksek',
                    sources=sources, proto=packet['proto'], simulated=packet.get('simulated', False))

    def process(self, packet, ts):
        events = []
        proto = packet['transport']
        flags = packet.get('flags_value', 0)
        rules = []
        if proto == 'ICMP' and packet.get('icmp_type') == 8:
            rules.append(('ICMP', 'icmp_per_sec'))
        if proto == 'UDP':
            rules.append(('UDP', 'udp_per_sec'))
        if proto == 'TCP':
            if flags & 2 and not flags & 16:
                rules.append(('SYN', 'syn_per_sec'))
            if flags == 16 and not packet.get('payload_size', 0):
                rules.append(('ACK Flood', 'ack_per_sec'))
            if flags & 4:
                rules.append(('RST Flood', 'rst_per_sec'))
            if packet.get('http_request'):
                rules.append(('HTTP Flood', 'http_per_sec'))
        if packet.get('dns_query'):
            rules.append(('DNS Flood', 'dns_per_sec'))
        for kind, setting in rules:
            count = self._rate((kind, packet['src'], packet['dst']), ts)
            limit = self.thresholds[setting]
            if count >= limit:
                event = self._alarm(packet, kind, count, limit, ts)
                if event:
                    events.append(event)

        # Only connection attempts and UDP destinations, not server TCP replies.
        if proto == 'UDP' or (proto == 'TCP' and flags & 2 and not flags & 16):
            key = (packet['src'], packet['dst'], proto)
            ports = self._entry(self.ports, key, dict)
            window = self.thresholds['port_win']
            for port, seen in list(ports.items()):
                if ts - seen >= window:
                    del ports[port]
            ports[packet['dport']] = ts
            limit = self.thresholds['port_scan']
            if len(ports) >= limit:
                event = self._alarm(packet, 'Port Tarama', len(ports), limit, ts, window)
                if event:
                    events.append(event)
            # Bound per-flow storage even under very wide scans.
            if len(ports) > 1024:
                del ports[min(ports, key=ports.get)]

        count = self._rate(('target', packet['dst']), ts)
        sources = self._entry(self.targets, packet['dst'], dict)
        for source, seen in list(sources.items()):
            if ts - seen >= 1:
                del sources[source]
        sources[packet['src']] = ts
        if len(sources) > 1024:
            del sources[min(sources, key=sources.get)]
        limit = self.thresholds['target_per_sec']
        if count >= limit and len(sources) >= self.thresholds['target_sources']:
            event = self._alarm(packet, 'Dağıtık Flood Şüphesi', count, limit, ts,
                                sources=len(sources))
            if event:
                events.append(event)
        return events
