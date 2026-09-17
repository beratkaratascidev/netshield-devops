"""Summaries of retained previews, not full-session or whole-network totals."""
from collections import Counter


def summarize(packets, alerts, watched=()):
    hosts = {}
    protocols = Counter()
    conversations = {}
    def host(ip):
        return hosts.setdefault(ip, dict(ip=ip, sent=0, received=0, bytes=0, alerts=0, last='—'))
    for p in packets:
        src, dst = p['src'], p['dst']
        size = max(0, int(p.get('length', 0)))
        protocols[p['proto']] += 1
        host(src)['sent'] += 1
        host(dst)['received'] += 1
        for ip in set((src, dst)):
            host(ip)['bytes'] += size
            host(ip)['last'] = p['ts']
        ends = sorted(((src, p.get('sport')), (dst, p.get('dport'))),
                      key=lambda endpoint: (endpoint[0], str(endpoint[1])))
        key = (p.get('transport', p['proto']), *ends)
        flow = conversations.setdefault(key, dict(protocol=key[0], a=ends[0], b=ends[1],
                                                   packets=0, bytes=0, last='—'))
        flow['packets'] += 1
        flow['bytes'] += size
        flow['last'] = p['ts']
    for event in alerts:
        for ip in set((event.get('ip'), event.get('dst'))) - {None, '', 'Çoklu kaynak'}:
            host(ip)['alerts'] += 1
    for ip in watched:
        host(ip)
    return dict(hosts=sorted(hosts.values(), key=lambda h: (-h['bytes'], h['ip'])),
                protocols=protocols,
                conversations=sorted(conversations.values(), key=lambda f: -f['bytes']))
