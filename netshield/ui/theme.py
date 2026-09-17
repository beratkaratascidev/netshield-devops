BG = '#101722'
SURF = '#151f2d'
CARD = '#1b2839'
BRD = '#2c3c51'
ACC = '#65b7ff'
GRN = '#65dbb0'
RED = '#ff7f91'
YLW = '#edca80'
PRP = '#bba8ff'
TXT = '#dce6f2'
MUT = '#94a6bc'
WHT = '#ffffff'

TUR_RENK = {'ICMP': YLW, 'SYN': RED, 'UDP': PRP, 'HTTP Flood': GRN,
            'ACK Flood': ACC, 'RST Flood': RED, 'DNS Flood': YLW,
            'Port Tarama': '#f5ac77', 'Dağıtık Flood Şüphesi': RED}

THRESHOLD_LABELS = {
    'icmp_per_sec': 'ICMP echo / sn', 'syn_per_sec': 'TCP SYN / sn',
    'udp_per_sec': 'UDP / sn', 'http_per_sec': 'HTTP/1 istek / sn',
    'ack_per_sec': 'Saf TCP ACK / sn', 'rst_per_sec': 'TCP RST / sn',
    'dns_per_sec': 'DNS sorgu / sn', 'port_scan': 'Farklı hedef port',
    'port_win': 'Port tarama penceresi (sn)', 'target_per_sec': 'Hedef toplam paket / sn',
    'target_sources': 'Hedefe gelen farklı kaynak',
}

