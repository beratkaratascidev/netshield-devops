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
    "icmp_per_sec": 5,
    "syn_per_sec": 10,
    "udp_per_sec": 10,
    "http_per_sec": 20,
    "port_scan": 4,
    "port_win": 5,
}

# Aynı IP, protokol ve olay türü için bildirim aralığı
COOLDOWN = 1.0
