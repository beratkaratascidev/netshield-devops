#!/usr/bin/env python3
"""NetShield desktop entry point."""
import time
import queue
import subprocess
import ipaddress
from html import escape
from collections import OrderedDict, deque, defaultdict
from datetime import datetime
import tkinter as tk
from tkinter import messagebox

from netshield.config import ESIKLER, PACKET_HISTORY, ALERT_HISTORY
from netshield.core.motor import Motor, SCAPY_OK
from netshield.core.filters import compile_filter
from netshield.net.utils import is_root, get_cached_geo
from netshield.ui.workspace import WorkspaceUI, BG, SURF, CARD, ACC, GRN, RED, YLW, TXT, MUT, WHT

TITLE = 'NetShield — Ağ Analizi'


def now_str():
    return datetime.now().strftime('%H:%M:%S')


class App(WorkspaceUI):
    def __init__(self, root, autostart=True):
        self.root = root
        root.title(TITLE)
        root.geometry('1440x920')
        root.minsize(1200, 820)
        root.configure(bg=BG)
        self.q = queue.Queue(maxsize=4096)
        self.esik = dict(ESIKLER)
        self.motor = None
        self.banned = {}
        self.olaylar = []
        self.sayac = defaultdict(int)
        self.trafik = deque([0] * 90, maxlen=90)
        self._traffic_count = self._packet_total = 0
        self._traffic_since = time.monotonic()
        self._packets = OrderedDict()
        self._packet_sequence = self._alert_sequence = 0
        self._preview_dropped_total = self._event_dropped_total = 0
        self._filter_match = compile_filter('')
        self._active_protocol = 'Tümü'
        self._closed = False
        self._after_id = None
        self._build()
        if autostart:
            self._motor_baslat()
            self._poll()

    def _motor_baslat(self):
        simulation = self._mode.get() == 'Simülasyon'
        self.motor = Motor(self.q, self.esik, iface=self._iface.get() or None, simulation=simulation)
        self.motor.baslat()
        running = self.motor.status != 'Hata'
        self._capture_btn.configure(text='■ Durdur' if running else '▶ Başlat')
        self._mode_box.configure(state='disabled' if running else 'readonly')
        self._iface_box.configure(state='disabled' if running else 'readonly')

    def _toggle_capture(self):
        if self.motor and self.motor.status not in ('Durduruldu', 'Hata', 'Hazır'):
            self.motor.dur()
            self._capture_btn.configure(text='▶ Başlat')
            self._mode_box.configure(state='readonly')
            self._iface_box.configure(state='readonly')
            self._syslog('SİSTEM', 'Yakalama durduruldu; kayıtlar inceleme için korundu.')
        else:
            if self.motor:
                self.motor.dur()
                self._drain_motor(PACKET_HISTORY, 4096)
                self._preview_dropped_total += self.motor.preview_dropped
                self._event_dropped_total += self.motor.event_dropped
            self._motor_baslat()

    def _drain_motor(self, packet_limit=500, event_limit=1000):
        packets = self.motor.consume_traffic()
        self._traffic_count += packets
        self._packet_total += packets
        for packet in self.motor.consume_packets(packet_limit):
            self._on_packet(packet)
        try:
            for _ in range(event_limit):
                msg = self.q.get_nowait()
                if msg[0] == 'OLAY':
                    self._on_olay(msg[1])
                elif msg[0] == 'LOG':
                    self._syslog(msg[1], msg[2])
        except queue.Empty:
            pass

    def _poll(self):
        if self._closed:
            return
        self._drain_motor()
        now = time.monotonic()
        elapsed = now - self._traffic_since
        if elapsed >= 1:
            self.trafik.append(round(self._traffic_count / elapsed))
            self._traffic_count = 0
            self._traffic_since = now
            self._grafik_ciz()
        self._guncelle()
        if self._autoscroll.get():
            for tree in (self._packet_tree, self._alert_tree):
                children = tree.get_children()
                if children:
                    tree.see(children[-1])
        self._after_id = self.root.after(100, self._poll)

    def _on_packet(self, packet):
        self._packet_sequence += 1
        key = str(self._packet_sequence)
        packet['ui_id'] = self._packet_sequence
        self._packets[key] = packet
        if len(self._packets) > PACKET_HISTORY:
            old, _ = self._packets.popitem(last=False)
            if self._packet_tree.exists(old):
                self._packet_tree.delete(old)
        self._insert_packet(key, packet)

    def _on_olay(self, event):
        self.sayac['toplam'] += 1
        self.sayac[event['tip']] += 1
        self.sayac[event['tur']] += 1
        self._alert_sequence += 1
        event = dict(event, id=self._alert_sequence)
        self.olaylar.append(event)
        if len(self.olaylar) > ALERT_HISTORY:
            old = self.olaylar.pop(0)
            self._alert_tree.delete(str(old['id']))
        self._alert_tree.insert('', 'end', iid=str(event['id']),
                                values=[event.get(k, '') for k in ('ts', 'severity', 'tur', 'ip', 'dst', 'detay')],
                                tags=(event.get('severity', 'Yüksek'),))

    def _guncelle(self):
        self._k_toplam.configure(text=str(len(self.olaylar)))
        self._k_flood.configure(text=str(self.sayac.get('FLOOD', 0)))
        self._k_paket.configure(text=f'{self._packet_total:,}')
        self._k_ban.configure(text=str(len(self.banned)))
        self._k_pps.configure(text=str(self.trafik[-1]))
        for kind, label in self._stat_lbls.items():
            label.configure(text=str(self.sayac.get(kind, 0)))
        self._mod_lbl.configure(text=f'● {self.motor.status.upper()}',
                                fg=RED if self.motor.status == 'Hata' else YLW if self.motor.sim else GRN)
        if self.motor.status == 'Hata':
            self._capture_btn.configure(text='▶ Başlat')
            self._mode_box.configure(state='readonly')
            self._iface_box.configure(state='readonly')
        dropped = self._preview_dropped_total + self.motor.preview_dropped
        event_dropped = self._event_dropped_total + self.motor.event_dropped
        self._status.configure(text=f"{self._iface.get() or 'Arayüz seçilmedi'}  ·  {len(self._packet_tree.get_children())}/{len(self._packets)} paket görünür"
                               f'  ·  Geçmiş: son {PACKET_HISTORY} paket / {ALERT_HISTORY} alarm'
                               f'  ·  Önizleme taşması: {dropped}  ·  Olay taşması: {event_dropped}')

    def _log_yaz(self, message, tag='SYS'):
        self._log.configure(state='normal')
        self._log.insert('end', message, tag)
        lines = int(self._log.index('end-1c').split('.')[0])
        if lines > 1000:
            self._log.delete('1.0', f'{lines-1000}.0')
        self._log.configure(state='disabled')
        self._log.see('end')

    def _syslog(self, level, message):
        self._log_yaz(f'[{now_str()}] [{level}] {message}\n', 'HATA' if level == 'HATA' else 'SYS')

    def _sifirla(self):
        if not messagebox.askyesno('Görünümü temizle', 'Paket ve alarm geçmişi temizlensin mi? Ban kuralları korunur.', parent=self.root):
            return
        self._packets.clear()
        self.olaylar.clear()
        self.sayac.clear()
        self.motor.consume_traffic()
        self.motor.consume_packets(PACKET_HISTORY)
        for _ in range(4096):
            try:
                self.q.get_nowait()
            except queue.Empty:
                break
        self._traffic_count = self._packet_total = 0
        self._traffic_since = time.monotonic()
        self.trafik = deque([0] * 90, maxlen=90)
        for tree in (self._packet_tree, self._alert_tree):
            if tree.get_children():
                tree.delete(*tree.get_children())
        self._log.configure(state='normal')
        self._log.delete('1.0', 'end')
        self._log.configure(state='disabled')
        self._show_details('Görünüm temizlendi. Bir paket veya alarm seçin.')
        self._grafik_ciz()
        self._syslog('SİSTEM', 'Görünüm temizlendi; tespit pencereleri ve ban kuralları korundu.')

    def kapat(self):
        self._closed = True
        if self._after_id is not None:
            self.root.after_cancel(self._after_id)
        if self.motor:
            self.motor.dur()
        self.root.destroy()

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
            try: ip = str(ipaddress.IPv4Address(ip))
            except: messagebox.showerror("Hata","Geçerli IPv4 girin.",parent=win); return
            self._ban_ip(ip,"Manuel"); win.destroy()
        tk.Button(win,text="Banla",command=_ok,bg=RED,fg=WHT,
                  font=("Courier New",10,"bold"),relief="flat",
                  padx=10,pady=5).pack(pady=12)

    def _ban_ip(self, ip, sebep):
        if ip in self.banned: return
        try:
            subprocess.run(["sudo","iptables","-A","INPUT","-s",ip,"-j","DROP"],
                           check=True,timeout=5,capture_output=True)
        except Exception as ex:
            self._syslog("HATA",f"iptables başarısız ({ip}): {ex}")
            return
        self.banned[ip] = {"tur":sebep,"ts":now_str()}
        self._ban_list.insert("end", f"{ip}  [{sebep}]")
        durum = "banlandı"
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
            return
        self.banned.pop(ip,None)
        self._ban_list.delete(sel[0])
        self._log_yaz(f"[{now_str()}] [OK] {ip} ban listesinden kaldırıldı.\n","OK")

    def _rapor(self):
        """Detaylı HTML raporu oluştur ve tarayıcıda aç."""
        if not self.olaylar:
            messagebox.showinfo("Rapor","Henüz kayıtlı olay yok."); return

        # İstatistikler
        flood_olaylar  = [o for o in self.olaylar if o["tip"]=="FLOOD"]
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
            geo = get_cached_geo(ip)
            ulke = escape(geo.get("country","-")); sehir = escape(geo.get("city","-"))
            isp  = escape(geo.get("isp","-"))
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
              <td>{escape(o.get('dst', '-'))}</td>
              <td>{escape(o.get('severity', '-'))}</td>
              <td>{escape(o['detay'])}</td>
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
<title>NetShield — Güvenlik Raporu</title>
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

<h1>◈ NetShield — Güvenlik Raporu</h1>
<div class='meta'>
  Oluşturma tarihi: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')} |
  Rapor kapsamı: bellekteki son {len(self.olaylar)} alarm | {ilk} → {son} |
  Mod: {'Karma / kayıt bazında' if any(o.get('simulated') for o in self.olaylar) and any(not o.get('simulated') for o in self.olaylar) else 'SİMÜLASYON' if any(o.get('simulated') for o in self.olaylar) else 'CANLI'}
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
    <h3>FARKLI HEDEF</h3>
    <div class='val'>{len({o["dst"] for o in self.olaylar if o.get("dst")})}</div>
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

<h2>En Aktif Kaynaklar</h2>
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
  <tr><th>Saat</th><th>Tip</th><th>Tür</th><th>IP</th><th>Hedef</th><th>Önem</th><th>Detay</th></tr>
  {son_olaylar}
</table>

<footer>
  NetShield — Rapor otomatik oluşturuldu |
  {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}
</footer>
</body>
</html>"""

        # Dosyaya yaz
        rapor_dosya = f"/tmp/netshield_rapor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
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


def main():
    root = tk.Tk()
    app = App(root)
    root.protocol('WM_DELETE_WINDOW', app.kapat)
    root.mainloop()


if __name__ == '__main__':
    main()
