"""Small display filter language; deliberately not Wireshark syntax."""
import shlex

FIELDS = {'src', 'dst', 'proto', 'port', 'info'}


def compile_filter(expression):
    terms = []
    for token in shlex.split(expression):
        if '=' in token:
            field, value = token.split('=', 1)
            if field not in FIELDS or not value:
                raise ValueError('Alanlar: src, dst, proto, port, info. Örnek: proto=TCP port=443')
            if field == 'port' and (not value.isdigit() or not 0 <= int(value) <= 65535):
                raise ValueError('Port 0–65535 arasında olmalı.')
            terms.append((field, value.casefold()))
        else:
            terms.append(('*', token.casefold()))

    def matches(packet):
        for field, value in terms:
            if field == 'port':
                if int(value) not in (packet.get('sport'), packet.get('dport')):
                    return False
            elif field == 'proto':
                if value not in (packet.get('proto', '').casefold(), packet.get('transport', '').casefold()):
                    return False
            elif field == '*':
                if value not in ' '.join(str(v) for v in packet.values()).casefold():
                    return False
            elif value not in str(packet.get(field, '')).casefold():
                return False
        return True
    return matches
