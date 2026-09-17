"""Local employee/device directory and passive, bounded traffic summaries."""
import ipaddress
from collections import defaultdict
from netshield.core.tracking import summarize


def validate_devices(devices):
    if not isinstance(devices, list) or len(devices) > 500:
        raise ValueError('Envanter en fazla 500 kayıt içerebilir.')
    result, ids, addresses = [], set(), set()
    for device in devices:
        if not isinstance(device, dict):
            raise ValueError('Geçersiz envanter kaydı.')
        clean = {}
        for key, limit in (('id', 64), ('name', 100), ('department', 100), ('ip', 64), ('interface', 64)):
            value = device.get(key, '')
            if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise ValueError(f'Geçersiz envanter alanı: {key}')
            clean[key] = value.strip()
        if not all(clean[k] for k in ('id', 'name', 'department', 'ip')):
            raise ValueError('Ad, bölüm ve IP adresi zorunludur.')
        clean['ip'] = str(ipaddress.ip_address(clean['ip']))
        address = (clean['ip'], clean['interface'])
        if clean['id'] in ids or address in addresses:
            raise ValueError('Bu IP ve arayüz için zaten bir kayıt var.')
        ids.add(clean['id'])
        addresses.add(address)
        result.append(clean)
    return result


def device_activity(device, packets, alerts):
    ip, interface = device['ip'], device['interface']
    def matches(record, fields):
        return (not interface or record.get('interface') == interface) and ip in (record.get(k) for k in fields)
    packets = [p for p in packets if matches(p, ('src', 'dst'))]
    alerts = [e for e in alerts if matches(e, ('ip', 'dst'))]
    summary = summarize(packets, alerts, [ip])
    host = next(h for h in summary['hosts'] if h['ip'] == ip)
    return dict(**host, sent_bytes=sum(p.get('length', 0) for p in packets if p['src'] == ip),
                received_bytes=sum(p.get('length', 0) for p in packets if p['dst'] == ip),
                conversations=summary['conversations'], events=alerts,
                status='Gözlendi' if packets else 'Yalnızca alarm' if alerts else 'Gözlenmedi')


class DeviceActivityIndex:
    """Index a retained preview once, instead of rescanning it for every device."""
    def __init__(self, packets, alerts):
        self.packets = defaultdict(list)
        self.alerts = defaultdict(list)
        for packet in packets:
            for ip in {packet['src'], packet['dst']}:
                self.packets[(ip, '')].append(packet)
                interface = packet.get('interface', '')
                if interface:
                    self.packets[(ip, interface)].append(packet)
        for event in alerts:
            for ip in {event.get('ip'), event.get('dst')} - {None, '', 'Çoklu kaynak'}:
                self.alerts[(ip, '')].append(event)
                interface = event.get('interface', '')
                if interface:
                    self.alerts[(ip, interface)].append(event)

    def activity(self, device):
        key = (device['ip'], device['interface'])
        return device_activity(device, self.packets.get(key, ()), self.alerts.get(key, ()))
