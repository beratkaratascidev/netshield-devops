#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, json, time, queue, socket, threading, subprocess, urllib.request
from collections import deque, defaultdict
from datetime import datetime
from netshield.core.sliding_window import SW
from netshield.config import ESIKLER, COOLDOWN
from netshield.net.utils import is_private
from netshield.core.motor import Motor

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MPL_OK = True
except Exception:
    MPL_OK = False

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

# ══════════════════════════════════════════
#  SABİTLER
# ══════════════════════════════════════════
TITLE    = " DDO IDS "
GEO_URL  = "http://ip-api.com/json/{ip}?fields=status,country,city,isp"
HTTP_PORTS = {80,443,8000,8080,8443,8888,3000,5000}

# Varsayılan eşikler — kasıtlı düşük (gerçek trafik tespit edilsin)
ESIKLER = {
    "icmp_per_sec":  5,    # ping -f kolayca aşar
    "syn_per_sec":  10,
    "udp_per_sec":  10,
    "http_per_sec": 20,
    "port_scan":     4,    # 4 farklı port = şüpheli
    "port_win":      5,    # 5 saniyelik pencere
}

COOLDOWN = 1.0   # aynı IP+tür için bildirim aralığı (sn)

def is_root():
    try:    return os.geteuid() == 0
    except: return False


def now_str():
    return datetime.now().strftime("%H:%M:%S")

def ts_str():
    return datetime.now().strftime("%H:%M:%S.%f")[:-4]

# ══════════════════════════════════════════
#  SLIDING WINDOW
# ══════════════════════════════════════════


# ══════════════════════════════════════════
#  TESPİT MOTORU
# ══════════════════════════════════════════
BG   = "#0a0e17"
SURF = "#0f1520"
CARD = "#141e2e"
BRD  = "#1e2d45"
ACC  = "#00cfff"
GRN  = "#00e87a"
RED  = "#ff3355"
YLW  = "#ffd060"
PRP  = "#b48eff"
ORG  = "#ff9f1c"
TXT  = "#c8d8e8"
MUT  = "#4a6080"
WHT  = "#ffffff"

TUR_RENK = {
    "ICMP":        YLW,
    "SYN":         RED,
    "UDP":         PRP,
    "HTTP Flood":  GRN,
    "Port Tarama": ORG,
}

class App:
    def __init__(self, root):
        self.root  = root
        self.root.title(TITLE)
        self.root.geometry("1200x800")
        self.root.configure(bg=BG)
        self.root.minsize(900, 600)

        self.q       = queue.Queue()
        self.esik    = dict(ESIKLER)
        self.motor   = None
        self.banned  = {}                    # ip → {tur, ts, geo}
        self.olaylar = []                    # tüm olaylar (rapor için)
        self.sayac   = defaultdict(int)      # tur → count
        self.trafik  = deque([0]*90, maxlen=90)
        self._geo_pending = set()

        self._build()
        self._motor_baslat()
        self._poll()

    # ── UI inşa ────────────────────────────
    def _build(self):
        # ── Üst bar ─────────────────────
        top = tk.Frame(self.root, bg=BG, pady=8)
        top.pack(fill="x", padx=14)

        tk.Label(top, text="◈ DDO IDS", fg=ACC, bg=BG,
                 font=("Courier New",15,"bold")).pack(side="left")

        self._mod_lbl = tk.Label(top, text="", fg=GRN, bg=BG,
                                  font=("Courier New",10,"bold"))
        self._mod_lbl.pack(side="right", padx=6)
        self._mod_lbl.configure(text=(
            "● CANLI" if (SCAPY_OK and is_root()) else "● SİMÜLASYON"))
        self._mod_lbl.configure(fg=(GRN if (SCAPY_OK and is_root()) else YLW))

        tk.Frame(self.root, bg=BRD, height=1).pack(fill="x")

        # ── Özet kartlar ────────────────
        kf = tk.Frame(self.root, bg=BG, padx=14, pady=8)
        kf.pack(fill="x")
        self._k_toplam = self._kart(kf, "TOPLAM OLAY", "0",  ACC)
        self._k_flood  = self._kart(kf, "FLOOD",       "0",  RED)
        self._k_paket  = self._kart(kf, "PAKET",       "0",  YLW)
        self._k_ban    = self._kart(kf, "BANLI",        "0",  PRP)
        self._k_pps    = self._kart(kf, "PKT/SN",       "0",  GRN)

        tk.Frame(self.root, bg=BRD, height=1).pack(fill="x")

        # ── Ana alan: sol log + sağ grafik ─
        main = tk.Frame(self.root, bg=BG)
        main.pack(fill="both", expand=True, padx=0)

        # Sol: olay akışı
        left = tk.Frame(main, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(14,6), pady=10)

        hdr = tk.Frame(left, bg=BG)
        hdr.pack(fill="x", pady=(0,4))
        tk.Label(hdr, text="OLAY AKIŞI", fg=MUT, bg=BG,
                 font=("Courier New",9,"bold")).pack(side="left")

        # Filtre butonları
        self._ff = tk.BooleanVar(value=True)   # flood göster
        self._fp = tk.BooleanVar(value=True)   # paket göster
        for txt, var, col in [("FLOOD",self._ff,RED),("PAKET",self._fp,YLW)]:
            tk.Checkbutton(hdr, text=txt, variable=var, fg=col, bg=BG,
                           selectcolor=BG, activebackground=BG,
                           font=("Courier New",8,"bold"),
                           command=self._filtre_uygula).pack(side="right", padx=4)

        tk.Label(hdr, text="Filtre:", fg=MUT, bg=BG,
                 font=("Courier New",8)).pack(side="right", padx=(0,2))

        self._log = scrolledtext.ScrolledText(
            left, bg=SURF, fg=TXT, font=("Courier New",9),
            relief="flat", wrap="none", state="disabled",
            insertbackground=TXT, selectbackground=BRD)
        self._log.pack(fill="both", expand=True)

        # Log renk tagleri
        for tag, col in {
            "FLOOD_ICMP":  YLW, "FLOOD_SYN":   RED,
            "FLOOD_UDP":   PRP, "FLOOD_PORT":   ORG,
            "FLOOD_HTTP":  GRN, "PAKET":        MUT,
            "SYS":         MUT, "HATA":         RED,
            "OK":          GRN, "BAN":          YLW,
        }.items():
            self._log.tag_config(tag, foreground=col)

        # Sağ: trafik grafiği + istatistik
        right = tk.Frame(main, bg=BG, width=340)
        right.pack(side="right", fill="y", padx=(0,14), pady=10)
        right.pack_propagate(False)

        tk.Label(right, text="TRAFİK (PKT/SN)", fg=MUT, bg=BG,
                 font=("Courier New",9,"bold")).pack(anchor="w")

        if MPL_OK:
            self._fig = Figure(figsize=(3.4,2.0), dpi=96, facecolor=CARD)
            self._ax  = self._fig.add_subplot(111)
            self._grafik_ciz()
            self._cv  = FigureCanvasTkAgg(self._fig, master=right)
            self._cv.get_tk_widget().pack(fill="x")
        else:
            tk.Label(right, text="(matplotlib yok)", fg=MUT, bg=BG).pack()

        tk.Frame(right, bg=BRD, height=1).pack(fill="x", pady=8)

        # İstatistik tablosu (sağda, sade)
        tk.Label(right, text="TÜR İSTATİSTİKLERİ", fg=MUT, bg=BG,
                 font=("Courier New",9,"bold")).pack(anchor="w")

        self._stat_frame = tk.Frame(right, bg=BG)
        self._stat_frame.pack(fill="x", pady=4)
        self._stat_lbls = {}
        for tur, col in TUR_RENK.items():
            row = tk.Frame(self._stat_frame, bg=BG)
            row.pack(fill="x", pady=1)
            tk.Label(row, text=f"  {tur:<14}", fg=col, bg=BG,
                     font=("Courier New",9)).pack(side="left")
            lbl = tk.Label(row, text="0", fg=WHT, bg=BG,
                           font=("Courier New",9,"bold"))
            lbl.pack(side="right"); self._stat_lbls[tur] = lbl

        tk.Frame(right, bg=BRD, height=1).pack(fill="x", pady=8)

        # Alt butonlar
        btn_f = tk.Frame(right, bg=BG)
        btn_f.pack(fill="x")
        for txt, cmd, col in [
            ("⛔ Manuel Ban", self._manuel_ban, RED),
            ("📊 Rapor",      self._rapor,      ACC),
            ("🔄 Sıfırla",    self._sifirla,    MUT),
        ]:
            tk.Button(btn_f, text=txt, command=cmd,
                      bg=CARD, fg=col, font=("Courier New",9,"bold"),
                      relief="flat", bd=0, padx=8, pady=5,
                      activebackground=BRD, activeforeground=col,
                      cursor="hand2").pack(fill="x", pady=2)

        # Banlı IP listesi
        tk.Frame(right, bg=BRD, height=1).pack(fill="x", pady=6)
        tk.Label(right, text="BANLI IP'LER", fg=MUT, bg=BG,
                 font=("Courier New",9,"bold")).pack(anchor="w")
        self._ban_list = tk.Listbox(right, bg=SURF, fg=YLW,
                                     font=("Courier New",8), relief="flat",
                                     selectbackground=BRD, height=6)
        self._ban_list.pack(fill="both", expand=True)
        tk.Button(right, text="✅ Seçili Kaldır",
                  command=self._ban_kaldir,
                  bg=CARD, fg=GRN, font=("Courier New",9,"bold"),
                  relief="flat", bd=0, padx=8, pady=4,
                  activebackground=BRD, activeforeground=GRN,
                  cursor="hand2").pack(fill="x", pady=(2,0))

    def _kart(self, parent, label, val, col):
        f = tk.Frame(parent, bg=CARD, padx=14, pady=8)
        f.pack(side="left", fill="both", expand=True, padx=(0,6))
        tk.Frame(f, bg=col, height=2).pack(fill="x", pady=(0,4))
        tk.Label(f, text=label, fg=MUT, bg=CARD,
                 font=("Courier New",8,"bold")).pack(anchor="w")
        lbl = tk.Label(f, text=val, fg=WHT, bg=CARD,
                        font=("Courier New",22,"bold"))
        lbl.pack(anchor="w"); return lbl

    # ── Grafik ─────────────────────────────
    def _grafik_ciz(self):
        if not MPL_OK: return
        ax = self._ax; ax.clear()
        ax.set_facecolor(CARD)
        for sp in ax.spines.values(): sp.set_color(BRD)
        ax.tick_params(colors=MUT, labelsize=7)
        data = list(self.trafik)
        ax.plot(data, color=ACC, lw=1.4)
        ax.fill_between(range(len(data)), data, color=ACC, alpha=0.08)
        mx = max(data) if any(data) else 10
        ax.set_ylim(0, mx*1.3 or 5)
        ax.axhline(mx*0.8, ls="--", color=RED, lw=0.6, alpha=0.5)
        self._fig.tight_layout(pad=0.3)
        if hasattr(self, "_cv"):
            self._cv.draw_idle()

    # ── Motor başlatma ─────────────────────
    def _motor_baslat(self):
        self.motor = Motor(self.q, self.esik)
        self.motor.baslat()

    # ── Poll (100ms — çok anlık) ───────────
    def _poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                k   = msg[0]
                if   k == "OLAY":   self._on_olay(msg[1])
                elif k == "TRAFIK": self.trafik.append(msg[1])
                elif k == "LOG":    self._syslog(msg[1], msg[2])
                elif k == "GEO":    self._on_geo(msg[1], msg[2])
        except queue.Empty:
            pass
        self._guncelle()
        self.root.after(100, self._poll)   # 100ms — çok anlık

    # ── Olay işleme ────────────────────────
    def _on_olay(self, ev):
        ip, tur, detay, ts, tip = (ev["ip"], ev["tur"], ev["detay"],
                                    ev["ts"],  ev["tip"])

        # Sayaç
        self.sayac["toplam"] += 1
        self.sayac[tip]      += 1
        self.sayac[tur]      += 1

        # Olaylar listesi (rapor için)
        self.olaylar.append(ev)

        # Log tag seç
        if tip == "FLOOD":
            tag_map = {
                "ICMP":"FLOOD_ICMP","SYN":"FLOOD_SYN",
                "UDP":"FLOOD_UDP","Port Tarama":"FLOOD_PORT",
                "HTTP Flood":"FLOOD_HTTP",
            }
            tag = tag_map.get(tur, "FLOOD_ICMP")
            prefix = f"[{ts}] ⚠ FLOOD  {tur:<14} {ip:<18} {detay}"
        else:
            tag    = "PAKET"
            prefix = f"[{ts}]   paket  {tur:<14} {ip:<18} {detay}"

        # Filtre
        goster = (tip=="FLOOD" and self._ff.get()) or \
                 (tip=="PAKET" and self._fp.get())
        if goster:
            self._log_yaz(prefix + "\n", tag)

        # GEO
        if ip not in self._geo_pending:
            self._geo_pending.add(ip)
            threading.Thread(target=geo_lookup, args=(ip, self.q),
                             daemon=True).start()

        # Oto ban (sadece flood)
        if tip == "FLOOD" and ip not in self.banned and not is_private(ip):
            pass   # oto ban kapalı varsayılan, kullanıcı açar

    def _on_geo(self, ip, geo):
        # Rapor için kaydet (geo cache zaten dolu)
        pass

    # ── Görsel güncelleme ──────────────────
    def _guncelle(self):
        self._k_toplam.configure(text=str(self.sayac["toplam"]))
        self._k_flood.configure( text=str(self.sayac.get("FLOOD",0)))
        self._k_paket.configure( text=str(self.sayac.get("PAKET",0)))
        self._k_ban.configure(   text=str(len(self.banned)))
        self._k_pps.configure(   text=str(self.trafik[-1] if self.trafik else 0))

        for tur, lbl in self._stat_lbls.items():
            lbl.configure(text=str(self.sayac.get(tur,0)))

        self._grafik_ciz()

    # ── Filtre ─────────────────────────────
    def _filtre_uygula(self):
        # Log'u yeniden yaz (son 300 olaydan)
        self._log.configure(state="normal")
        self._log.delete("1.0","end")
        for ev in self.olaylar[-300:]:
            ip, tur, detay, ts, tip = (ev["ip"],ev["tur"],ev["detay"],
                                        ev["ts"],ev["tip"])
            goster = (tip=="FLOOD" and self._ff.get()) or \
                     (tip=="PAKET" and self._fp.get())
            if not goster: continue
            if tip == "FLOOD":
                tag_map={"ICMP":"FLOOD_ICMP","SYN":"FLOOD_SYN",
                         "UDP":"FLOOD_UDP","Port Tarama":"FLOOD_PORT",
                         "HTTP Flood":"FLOOD_HTTP"}
                tag    = tag_map.get(tur,"FLOOD_ICMP")
                prefix = f"[{ts}] ⚠ FLOOD  {tur:<14} {ip:<18} {detay}\n"
            else:
                tag    = "PAKET"
                prefix = f"[{ts}]   paket  {tur:<14} {ip:<18} {detay}\n"
            self._log.insert("end", prefix, tag)
        self._log.configure(state="disabled")
        self._log.see("end")

    # ── Log yazma ──────────────────────────
    def _log_yaz(self, msg, tag="SYS"):
        self._log.configure(state="normal")
        self._log.insert("end", msg, tag)
        # Max 2000 satır
        lines = int(self._log.index("end-1c").split(".")[0])
        if lines > 2000:
            self._log.delete("1.0", f"{lines-2000}.0")
        self._log.configure(state="disabled")
        self._log.see("end")

    def _syslog(self, seviye, msg):
        tag = "HATA" if seviye=="HATA" else "SYS"
        self._log_yaz(f"[{now_str()}] [{seviye}] {msg}\n", tag)

    # ── Ban işlemleri ──────────────────────
    def _manuel_ban(self):
        win = tk.Toplevel(self.root)
        win.title("Manuel IP Banla")
        win.configure(bg=CARD); win.geometry("340x130")
        win.resizable(False,False)
        tk.Label(win,text="Banlanacak IP:",fg=TXT,bg=CARD,
                 font=("Courier New",10)).pack(pady=(14,4),padx=14,anchor="w")
        e = tk.Entry(win,bg=SURF,fg=WHT,font=("Courier New",10),
                     insertbackground=WHT,relief="flat")
        e.pack(fill="x",padx=14); e.focus()
        def _ok():
            ip = e.get().strip()
            try: socket.inet_aton(ip)
            except: messagebox.showerror("Hata","Geçerli IPv4 girin.",parent=win); return
            self._ban_ip(ip,"Manuel"); win.destroy()
        tk.Button(win,text="Banla",command=_ok,bg=RED,fg=WHT,
                  font=("Courier New",10,"bold"),relief="flat",
                  padx=10,pady=5).pack(pady=12)

    def _ban_ip(self, ip, sebep):
        if ip in self.banned: return
        ok = True
        try:
            subprocess.run(["sudo","iptables","-A","INPUT","-s",ip,"-j","DROP"],
                           check=True,timeout=5,capture_output=True)
        except Exception as ex:
            ok = False
            self._syslog("HATA",f"iptables başarısız ({ip}): {ex}")
        self.banned[ip] = {"tur":sebep,"ts":now_str()}
        self._ban_list.insert("end", f"{ip}  [{sebep}]")
        durum = "banlandı" if ok else "kaydedildi (iptables hatası)"
        self._log_yaz(f"[{now_str()}] [BAN] {ip} {durum} — {sebep}\n","BAN")

    def _ban_kaldir(self):
        sel = self._ban_list.curselection()
        if not sel: return
        item = self._ban_list.get(sel[0])
        ip   = item.split()[0]
        try:
            subprocess.run(["sudo","iptables","-D","INPUT","-s",ip,"-j","DROP"],
                           check=True,timeout=5,capture_output=True)
        except Exception as ex:
            self._syslog("HATA",f"Kural silinemedi ({ip}): {ex}")
        self.banned.pop(ip,None)
        self._ban_list.delete(sel[0])
        self._log_yaz(f"[{now_str()}] [OK] {ip} ban listesinden kaldırıldı.\n","OK")

    def _sifirla(self):
        if not messagebox.askyesno("Sıfırla","Tüm sayaçlar ve loglar temizlenecek."): return
        self.sayac.clear(); self.olaylar.clear()
        self.trafik  = deque([0]*90,maxlen=90)
        self._log.configure(state="normal")
        self._log.delete("1.0","end")
        self._log.configure(state="disabled")
        self._log_yaz(f"[{now_str()}] Sistem sıfırlandı.\n","OK")

    # ── RAPOR ──────────────────────────────
    def _rapor(self):
        """Detaylı HTML raporu oluştur ve tarayıcıda aç."""
        if not self.olaylar:
            messagebox.showinfo("Rapor","Henüz kayıtlı olay yok."); return

        # İstatistikler
        flood_olaylar  = [o for o in self.olaylar if o["tip"]=="FLOOD"]
        paket_olaylar  = [o for o in self.olaylar if o["tip"]=="PAKET"]
        ip_sayac       = defaultdict(int)
        tur_sayac      = defaultdict(int)
        for o in self.olaylar:
            ip_sayac[o["ip"]] += 1
            tur_sayac[o["tur"]] += 1

        top_ip  = sorted(ip_sayac.items(), key=lambda x:-x[1])[:10]
        top_tur = sorted(tur_sayac.items(), key=lambda x:-x[1])

        # Zaman aralığı
        if self.olaylar:
            ilk = self.olaylar[0]["ts"]
            son = self.olaylar[-1]["ts"]
        else:
            ilk = son = "-"

        # Geo cache
        geo_tablo = ""
        for ip, cnt in top_ip:
            geo = _geo_cache.get(ip, {})
            ulke = geo.get("country","-"); sehir = geo.get("city","-")
            isp  = geo.get("isp","-")
            geo_tablo += f"""
            <tr>
              <td>{ip}</td>
              <td>{cnt}</td>
              <td>{ulke}</td>
              <td>{sehir}</td>
              <td>{isp}</td>
            </tr>"""

        tur_satirlar = ""
        for tur,cnt in top_tur:
            tur_satirlar += f"<tr><td>{tur}</td><td>{cnt}</td></tr>"

        # Son 100 olay tablosu
        son_olaylar = ""
        for o in reversed(self.olaylar[-100:]):
            renk = "#ff3355" if o["tip"]=="FLOOD" else "#4a6080"
            son_olaylar += f"""
            <tr style='color:{renk}'>
              <td>{o['ts']}</td>
              <td>{o['tip']}</td>
              <td>{o['tur']}</td>
              <td>{o['ip']}</td>
              <td>{o['detay']}</td>
            </tr>"""

        # Banlı IP'ler
        ban_satirlar = ""
        for ip,d in self.banned.items():
            ban_satirlar += f"<tr><td>{ip}</td><td>{d['tur']}</td><td>{d['ts']}</td></tr>"
        if not ban_satirlar:
            ban_satirlar = "<tr><td colspan='3'>Banlı IP yok</td></tr>"

        html = f"""<!DOCTYPE html>
<html lang='tr'>
<head>
<meta charset='UTF-8'>
<title>DDO IDS — Güvenlik Raporu</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:#07090f; color:#c8d8e8; font-family:'Courier New',monospace;
          padding:30px; font-size:13px; }}
  h1 {{ color:#00cfff; font-size:22px; border-bottom:1px solid #1e2d45;
        padding-bottom:10px; margin-bottom:20px; }}
  h2 {{ color:#00cfff; font-size:15px; margin:24px 0 10px; }}
  .meta {{ color:#4a6080; font-size:12px; margin-bottom:20px; }}
  .kart-row {{ display:flex; gap:12px; margin-bottom:20px; }}
  .kart {{ background:#141e2e; border-top:3px solid; padding:14px 18px;
           flex:1; border-radius:4px; }}
  .kart h3 {{ font-size:10px; color:#4a6080; margin-bottom:6px; }}
  .kart .val {{ font-size:28px; font-weight:bold; color:#fff; }}
  table {{ width:100%; border-collapse:collapse; margin-bottom:20px; }}
  th {{ background:#141e2e; color:#4a6080; padding:7px 10px;
        text-align:left; font-size:11px; border-bottom:1px solid #1e2d45; }}
  td {{ padding:6px 10px; border-bottom:1px solid #0f1520; font-size:12px; }}
  tr:hover td {{ background:#0f1520; }}
  .flood {{ color:#ff3355; font-weight:bold; }}
  .paket {{ color:#4a6080; }}
  footer {{ margin-top:30px; color:#4a6080; font-size:11px;
            border-top:1px solid #1e2d45; padding-top:10px; }}
</style>
</head>
<body>

<h1>◈ DDO  IDS — Güvenlik Raporu</h1>
<div class='meta'>
  Oluşturma tarihi: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')} |
  Oturum: {ilk} → {son} |
  Mod: {'CANLI' if (SCAPY_OK and is_root()) else 'SİMÜLASYON'}
</div>

<div class='kart-row'>
  <div class='kart' style='border-color:#00cfff'>
    <h3>TOPLAM OLAY</h3>
    <div class='val'>{len(self.olaylar)}</div>
  </div>
  <div class='kart' style='border-color:#ff3355'>
    <h3>FLOOD ALARMI</h3>
    <div class='val'>{len(flood_olaylar)}</div>
  </div>
  <div class='kart' style='border-color:#ffd060'>
    <h3>TEKİL PAKET</h3>
    <div class='val'>{len(paket_olaylar)}</div>
  </div>
  <div class='kart' style='border-color:#b48eff'>
    <h3>BANLI IP</h3>
    <div class='val'>{len(self.banned)}</div>
  </div>
  <div class='kart' style='border-color:#00e87a'>
    <h3>FARKLI IP</h3>
    <div class='val'>{len(ip_sayac)}</div>
  </div>
</div>

<h2>Tür Dağılımı</h2>
<table>
  <tr><th>Saldırı Türü</th><th>Olay Sayısı</th></tr>
  {tur_satirlar}
</table>

<h2>En Aktif IP Adresleri (GeoIP ile)</h2>
<table>
  <tr><th>IP</th><th>Olay</th><th>Ülke</th><th>Şehir</th><th>ISP</th></tr>
  {geo_tablo}
</table>

<h2>Banlı IP'ler</h2>
<table>
  <tr><th>IP</th><th>Sebep</th><th>Zaman</th></tr>
  {ban_satirlar}
</table>

<h2>Son 100 Olay</h2>
<table>
  <tr><th>Saat</th><th>Tip</th><th>Tür</th><th>IP</th><th>Detay</th></tr>
  {son_olaylar}
</table>

<footer>
  DDO IDS — Rapor otomatik oluşturuldu |
  {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}
</footer>
</body>
</html>"""

        # Dosyaya yaz
        rapor_dosya = f"/tmp/ddo_rapor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(rapor_dosya, "w", encoding="utf-8") as f:
            f.write(html)

        # Aç
        try:
            subprocess.Popen(["xdg-open", rapor_dosya])
        except:
            try:
                subprocess.Popen(["firefox", rapor_dosya])
            except:
                messagebox.showinfo("Rapor", f"Rapor kaydedildi:\n{rapor_dosya}")

        self._log_yaz(f"[{now_str()}] Rapor oluşturuldu: {rapor_dosya}\n","OK")

    # ── Kapat ──────────────────────────────
    def kapat(self):
        if self.motor: self.motor.dur()
        self.root.destroy()


# ══════════════════════════════════════════
#  GİRİŞ
# ══════════════════════════════════════════
def main():
    if os.name == "posix" and not is_root():
        print("[!] Root yetkisi yok → Simülasyon modu.")
        print(f"    Gerçek dinleme için: sudo python3 {sys.argv[0]}")
        print()
    root = tk.Tk()
    app  = App(root)
    root.protocol("WM_DELETE_WINDOW", app.kapat)
    root.mainloop()

if __name__ == "__main__":
    main()
