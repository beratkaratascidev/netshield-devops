"""Display filters with IP/CIDR support and conjunctive conditions."""
import ipaddress
import shlex

FIELDS = {'src', 'dst', 'ip', 'proto', 'port', 'sport', 'dport', 'info', 'flow', 'mode'}


def compile_filter(expression):
    terms = []
    for token in shlex.split(expression):
        if '=' not in token:
            terms.append(('*', token.casefold(), None))
            continue
        field, value = token.split('=', 1)
        if field not in FIELDS or not value:
            raise ValueError('Alanlar: src, dst, ip, proto, port, sport, dport, info.')
        if field == 'mode' and value not in ('live', 'demo'):
            raise ValueError('Mod filtresi: mode=live veya mode=demo')
        network = None
        if field == 'flow':
            parts = value.split(',')
            if len(parts) != 5 or not parts[0]:
                raise ValueError('Geçersiz bağlantı filtresi.')
            try:
                protocol, a, ap, b, bp = parts
                a, b = str(ipaddress.ip_address(a)), str(ipaddress.ip_address(b))
                ap, bp = (None if port == 'None' else int(port) for port in (ap, bp))
                if any(port is not None and not 0 <= port <= 65535 for port in (ap, bp)):
                    raise ValueError()
            except ValueError as exc:
                raise ValueError('Geçersiz bağlantı uçları.') from exc
            terms.append(('flow', protocol.casefold(), ((a, ap), (b, bp))))
            continue
        if field in ('port', 'sport', 'dport'):
            if not value.isdigit() or not 0 <= int(value) <= 65535:
                raise ValueError('Port 0–65535 arasında olmalı.')
        if field in ('src', 'dst', 'ip') and ('/' in value or field == 'ip'):
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError('Geçerli IP veya CIDR girin: ip=192.168.1.0/24') from exc
        terms.append((field, value.casefold(), network))

    def matches(packet):
        for field, value, network in terms:
            if field == 'flow':
                actual = ((packet.get('src'), packet.get('sport')), (packet.get('dst'), packet.get('dport')))
                if str(packet.get('transport', packet.get('proto', ''))).casefold() != value or actual not in (network, network[::-1]):
                    return False
            elif network is not None:
                addresses = (packet.get('src'), packet.get('dst')) if field == 'ip' else (packet.get(field),)
                matched = False
                for address in addresses:
                    try:
                        matched |= ipaddress.ip_address(address) in network
                    except ValueError:
                        pass
                if not matched:
                    return False
            elif field in ('port', 'sport', 'dport'):
                ports = (packet.get('sport'), packet.get('dport')) if field == 'port' else (packet.get(field),)
                if int(value) not in ports:
                    return False
            elif field == 'mode':
                if bool(packet.get('simulated')) != (value == 'demo'):
                    return False
            elif field == 'proto':
                if value not in tuple(str(packet.get(k, '')).casefold() for k in ('proto', 'transport', 'network')):
                    return False
            elif field == '*':
                if value not in ' '.join(str(v) for v in packet.values()).casefold():
                    return False
            elif value not in str(packet.get(field, '')).casefold():
                return False
        return True
    return matches
