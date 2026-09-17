"""NetShield IDS genel yapılandırma değerleri."""

HTTP_PORTS = {
    80,
    443,
    3000,
    5000,
    8000,
    8080,
    8443,
    8888,
}

ESIKLER = {
    "icmp_per_sec": 100,
    "syn_per_sec": 150,
    "udp_per_sec": 300,
    "http_per_sec": 100,
    "ack_per_sec": 500,
    "rst_per_sec": 100,
    "dns_per_sec": 150,
    "port_scan": 20,
    "port_win": 5,
    "target_per_sec": 1000,
    "target_sources": 10,
}

PACKET_HISTORY = 2000
ALERT_HISTORY = 2000

# Aynı IP, protokol ve olay türü için bildirim aralığı
COOLDOWN = 1.0
