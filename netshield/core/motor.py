import time
import re
import queue
import threading

from collections import deque, defaultdict
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, conf, ETH_P_ALL
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    sniff = None
    conf = None
    ETH_P_ALL = 3
    IP = TCP = UDP = ICMP = None

    def get_if_list():
        return []

from netshield.core.sliding_window import SW
from netshield.config import COOLDOWN, HTTP_PORTS
from netshield.net.utils import is_root
from datetime import datetime

def ts_str():
    return datetime.now().strftime("%H:%M:%S")

class Motor:
    """
    Her ağ arayüzü için ayrı sniff thread'i başlatır.
    Tüm paketler ortak _pkt() fonksiyonundan geçer.
    Olaylar queue, trafik sayısı kilit korumalı sayaç üzerinden aktarılır.
    """

    def __init__(self, q: queue.Queue, esik: dict):
        self.q    = q
        self.esik = esik
        self._go  = True
        self._packet_lock = threading.Lock()
        self._traffic_lock = threading.Lock()
        self._traffic_count = 0
        self._stop = threading.Event()
        self.sim  = not (SCAPY_OK and is_root())

        self.sw_icmp = SW(1.0)
        self.sw_syn  = SW(1.0)
        self.sw_udp  = SW(1.0)
        self.sw_http = SW(1.0)

        # Port tarama
        self._pt_ts  = defaultdict(deque)   # ip → deque[(ts,port)]
        self._pt_set = defaultdict(set)     # ip → set(ports)

        # Cooldown: (ip, tur) → last_ts
        self._cd: dict = {}
        self._last_purge = time.monotonic()

        self._threads: list[threading.Thread] = []

    def baslat(self):
        if self._threads or self._stop.is_set():
            return
        if self.sim:
            self.q.put(("LOG","SİSTEM","Motor başladı ▸ SİMÜLASYON MODU"))
            t = threading.Thread(target=self._sim, daemon=True, name="sim")
            t.start(); self._threads.append(t)
        else:
            ifaces = self._ifaces()
            self.q.put(("LOG","SİSTEM",f"Motor başladı ▸ CANLI — arayüzler: {ifaces}"))
            for iface in ifaces:
                t = threading.Thread(target=self._dinle, args=(iface,),
                                     daemon=True, name=f"sniff-{iface}")
                t.start(); self._threads.append(t)

    def dur(self):
        self._go = False
        self._stop.set()
        deadline = time.monotonic() + 1.5
        for thread in self._threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))

    def _record_traffic(self, count):
        with self._traffic_lock:
            self._traffic_count += count

    def consume_traffic(self):
        """Return and reset packets since the last UI sample atomically."""
        with self._traffic_lock:
            count = self._traffic_count
            self._traffic_count = 0
            return count

    def _ifaces(self):
        try:
            lst = get_if_list()
            return lst if lst else ["lo","eth0"]
        except:
            return ["lo","eth0"]

    # ── Her arayüz için ayrı thread ────────
    def _dinle(self, iface):
        self.q.put(("LOG","SİSTEM",f"Dinleniyor: {iface}"))
        capture_socket = None
        try:
            # Keep the socket open between timed polls so packets remain buffered.
            capture_socket = conf.L2listen(iface=iface, type=ETH_P_ALL)
            while not self._stop.is_set():
                sniff(
                    opened_socket=capture_socket,
                    prn=self._pkt,
                    store=False,
                    timeout=1.0,
                    stop_filter=lambda _: self._stop.is_set(),
                )
        except Exception as e:
            self.q.put(("LOG","HATA",f"{iface} dinleme hatası: {e}"))
        finally:
            if capture_socket is not None:
                capture_socket.close()

    # ── Paket işleme (tüm arayüzlerden) ───
    def _pkt(self, pkt):
        with self._packet_lock:
            self._process_packet(pkt)

    def _process_packet(self, pkt):
        if not self._go or IP not in pkt:
            return

        src = pkt[IP].src
        ts = time.monotonic()

        # Canlı trafik grafiğine paket bilgisini gönder
        self._record_traffic(1)

        # ICMP / Ping
        if ICMP in pkt:
            n = self.sw_icmp.add(src, ts)
            self._bildir(
                src,
                "ICMP",
                f"type={pkt[ICMP].type} count={n}",
                ts,
                flood=(n >= self.esik["icmp_per_sec"])
            )

        # TCP
        if TCP in pkt:
            fl = int(pkt[TCP].flags)
            dport = pkt[TCP].dport

            # SYN paketi: SYN=1, ACK=0
            if (fl & 0x02) and not (fl & 0x10):
                n = self.sw_syn.add(src, ts)
                self._bildir(
                    src,
                    "SYN",
                    f"→:{dport} count={n}",
                    ts,
                    flood=(n >= self.esik["syn_per_sec"])
                )

            # Count visible HTTP/1 request lines, not ACKs or TLS packets.
            # Stream reassembly and encrypted HTTP are not supported.
            payload = bytes(pkt[TCP].payload)
            if dport in HTTP_PORTS and re.match(
                rb"^(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) [^ \r\n]+ HTTP/1\.[01]\r\n",
                payload,
            ):
                n = self.sw_http.add(src, ts)
                if n >= self.esik["http_per_sec"]:
                    self._bildir(
                        src,
                        "HTTP Flood",
                        f"{n} istek/sn →:{dport}",
                        ts,
                        flood=True
                    )

            # TCP port tarama kontrolü
            self._pt(src, dport, ts)

        # UDP
        if UDP in pkt:
            n = self.sw_udp.add(src, ts)
            self._bildir(
                src,
                "UDP",
                f"→:{pkt[UDP].dport} count={n}",
                ts,
                flood=(n >= self.esik["udp_per_sec"])
            )

            self._pt(src, pkt[UDP].dport, ts)

        # Eski sayaç kayıtlarını temizle
        if ts - self._last_purge > 60:
            for sw in (
                self.sw_icmp,
                self.sw_syn,
                self.sw_udp,
                self.sw_http
            ):
                sw.purge()

            dead = [
                key for key, value in self._cd.items()
                if ts - value > 300
            ]

            for key in dead:
                del self._cd[key]

            self._last_purge = ts

    # ── Port tarama ────────────────────────
    def _pt(self, ip, port, ts):
        win = self.esik["port_win"]
        d, s = self._pt_ts[ip], self._pt_set[ip]
        d.append((ts, port)); s.add(port)
        cutoff = ts - win
        while d and d[0][0] < cutoff:
            _, op = d.popleft()
            if not any(p == op for _, p in d):
                s.discard(op)
        if len(s) >= self.esik["port_scan"]:
            self._bildir(ip, "Port Tarama",
                         f"{len(s)} port/{win}sn", ts, flood=True)
            d.clear(); s.clear()

    # ── Bildirim (cooldown korumalı) ───────
    def _bildir(self, ip, tur, detay, ts, flood=False):
        tip = "FLOOD" if flood else "PAKET"

        # Normal paket ve flood bildirimleri birbirini engellemesin
        key = (ip, tur, tip)

        last = self._cd.get(key, 0.0)
        if ts - last < COOLDOWN:
            return

        self._cd[key] = ts

        olay = {
            "ts": ts_str(),
            "ip": ip,
            "tur": tur,
            "detay": detay,
            "tip": tip,
        }

        self.q.put(("OLAY", olay))
    # ── Simülasyon ─────────────────────────
    def _sim(self):
        import random
        rng  = random.Random()
        pool = [f"{rng.randint(1,223)}.{rng.randint(0,254)}."
                f"{rng.randint(0,254)}.{rng.randint(1,254)}" for _ in range(8)]
        # Yerel IP de ekle (gerçekçilik)
        pool += ["192.168.1.100","10.0.0.5","127.0.0.1"]

        SENARYOLAR = ["ping","ping_flood","syn","syn_flood",
                      "udp","udp_flood","port_scan","http_flood","normal"]
        AGIRLIK    = [10,   8,           8,   7,
                      7,   6,            8,   6,          20]

        while not self._stop.wait(0.08):
            ts = time.monotonic()
            ip = rng.choice(pool)
            sc = rng.choices(SENARYOLAR, weights=AGIRLIK, k=1)[0]

            if sc == "ping":
                n = self.sw_icmp.add(ip, ts)
                self._bildir(ip,"ICMP",f"echo-req count={n}",ts,flood=False)
                self._record_traffic(1)

            elif sc == "ping_flood":
                burst = self.esik["icmp_per_sec"] + rng.randint(3,20)
                for _ in range(burst): n = self.sw_icmp.add(ip, ts)
                self._bildir(ip,"ICMP",f"FLOOD {n}/sn",ts,flood=True)
                self._record_traffic(burst)

            elif sc == "syn":
                n = self.sw_syn.add(ip, ts)
                self._bildir(ip,"SYN",f"→:{rng.randint(1,65535)} count={n}",ts,flood=False)
                self._record_traffic(1)

            elif sc == "syn_flood":
                burst = self.esik["syn_per_sec"] + rng.randint(5,30)
                for _ in range(burst): n = self.sw_syn.add(ip, ts)
                self._bildir(ip,"SYN",f"FLOOD {n}/sn",ts,flood=True)
                self._record_traffic(burst)

            elif sc == "udp":
                n = self.sw_udp.add(ip, ts)
                self._bildir(ip,"UDP",f"→:{rng.randint(1,65535)} count={n}",ts,flood=False)
                self._record_traffic(1)

            elif sc == "udp_flood":
                burst = self.esik["udp_per_sec"] + rng.randint(5,30)
                for _ in range(burst): n = self.sw_udp.add(ip, ts)
                self._bildir(ip,"UDP",f"FLOOD {n}/sn",ts,flood=True)
                self._record_traffic(burst)

            elif sc == "port_scan":
                ports = rng.sample(range(1,65535), rng.randint(5,15))
                for p in ports: self._pt(ip, p, ts)
                self._record_traffic(len(ports))

            elif sc == "http_flood":
                burst = self.esik["http_per_sec"] + rng.randint(5,20)
                for _ in range(burst): n = self.sw_http.add(ip, ts)
                self._bildir(ip,"HTTP Flood",f"{n}/sn",ts,flood=True)
                self._record_traffic(burst)

            else:
                self._record_traffic(rng.randint(1,10))


