#!/usr/bin/env python3
"""NetShield desktop entry point."""
import time
import queue
import subprocess
from concurrent.futures import ThreadPoolExecutor
import ipaddress
from collections import OrderedDict, deque, defaultdict
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, filedialog

from netshield.config import ESIKLER, PACKET_HISTORY, ALERT_HISTORY
from netshield.core.motor import Motor, SCAPY_OK
from netshield.core.firewall import Firewall
from netshield.core.filters import compile_filter
from netshield.core.settings import default_path, load_settings
from netshield.net.utils import is_root
from netshield.core.security import load_managed_policy, effective_policy, PrivateSnapshot, private_write, render_report
from netshield.ui.workspace import WorkspaceUI, BG, SURF, CARD, ACC, GRN, RED, YLW, TXT, MUT, WHT

TITLE = 'NetShield — Ağ Analizi'


def now_str():
    return datetime.now().strftime('%H:%M:%S')


class App(WorkspaceUI):
    def __init__(self, root, autostart=True, settings_path=None):
        self.root = root
        root.title(TITLE)
        root.geometry('1440x920')
        root.minsize(1200, 820)
        root.configure(bg=BG)
        self.q = queue.Queue(maxsize=4096)
        self.settings_path = settings_path or default_path()
        self.preferences, settings_error = load_settings(self.settings_path)
        self.esik = dict(self.preferences['thresholds'])
        self.managed_policy, policy_error = load_managed_policy()
        self.motor = None
        self.banned = {}
        self._firewall = Firewall()
        self._firewall_worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix='netshield-firewall')
        self._firewall_future = None
        self._firewall_after = None
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
        if policy_error:
            self._syslog('HATA', policy_error)
        if settings_error:
            self._syslog('HATA', settings_error)
        if autostart and is_root():
            self._refresh_firewall()
        if autostart:
            self._motor_baslat()
            self._poll()

    def _motor_baslat(self):
        simulation = self._mode.get() == 'Simülasyon'
        self.motor = Motor(self.q, self.esik, iface=self._selected_interfaces or None, simulation=simulation)
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
            self._refresh_tracking()
            if hasattr(self, '_agent_tree') and time.monotonic() - self._agent_refreshed >= 5:
                self._refresh_agent_panel()
            self._resort_tables()
        self._guncelle()
        if self._autoscroll.get():
            for tree in (self._packet_tree, self._alert_tree):
                children = tree.get_children()
                if children:
                    tree.see(children[-1])
        self._after_id = self.root.after(100, self._poll)

    def _on_packet(self, packet):
        self._tracking_dirty = True
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
        self._tracking_dirty = True
        self.sayac['toplam'] += 1
        self.sayac[event['tip']] += 1
        self.sayac[event['tur']] += 1
        self._alert_sequence += 1
        event = dict(event, id=self._alert_sequence)
        self.olaylar.append(event)
        if len(self.olaylar) > ALERT_HISTORY:
            old = self.olaylar.pop(0)
            if self._alert_tree.exists(str(old['id'])):
                self._alert_tree.delete(str(old['id']))
        self._insert_alert(event)

    def _guncelle(self):
        self._k_toplam.configure(text=str(len(self.olaylar)))
        self._k_flood.configure(text=str(self.sayac.get('FLOOD', 0)))
        self._k_paket.configure(text=f'{self._packet_total:,}')
        self._k_ban.configure(text=str(len(self.banned)))
        self._k_pps.configure(text=str(self.trafik[-1]))
        for kind, label in self._stat_lbls.items():
            label.configure(text=str(self.sayac.get(kind, 0)))
        self._mod_lbl.configure(text=f'● {self.motor.status.upper()}',
                                fg=RED if self.motor.status == 'Hata' else YLW if self.motor.sim or self.motor.status == 'Kısmi canlı' else GRN)
        if self.motor.status == 'Hata':
            self._capture_btn.configure(text='▶ Başlat')
            self._mode_box.configure(state='readonly')
            self._iface_box.configure(state='readonly')
        if hasattr(self, '_interfaces_tree'):
            self._refresh_interface_status()
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
        self._tracking_dirty = True
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
        self._refresh_tracking()
        self._syslog('SİSTEM', 'Görünüm temizlendi; tespit pencereleri ve ban kuralları korundu.')

    def kapat(self):
        self._closed = True
        if self._firewall_after is not None:
            self.root.after_cancel(self._firewall_after)
        self._firewall_worker.shutdown(wait=False, cancel_futures=True)
        if self._after_id is not None:
            self.root.after_cancel(self._after_id)
        if hasattr(self, '_agent_reader'):
            if self._agent_request_id is not None:
                self.root.after_cancel(self._agent_request_id)
            self._agent_reader.close()
        if self.motor:
            self.motor.dur()
        self.root.destroy()

    def _manuel_ban(self):
        if not self._security_allows('allow_firewall', firewall=True):
            return
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
        if not self._security_allows('allow_firewall', firewall=True):
            return
        try:
            address = ipaddress.IPv4Address(ip)
            if address.is_loopback or address.is_unspecified or address.is_multicast:
                raise ValueError('Bu adres engellenemez.')
            ip = str(address)
        except ValueError as exc:
            self._syslog('HATA', str(exc))
            return
        self._firewall_job(lambda: self._firewall.add(ip), f'{ip} engelleme işlemi tamamlandı.')

    def _ban_kaldir(self):
        if not self._security_allows('allow_firewall', firewall=True, removing=True):
            return
        selection = self._ban_list.curselection()
        if selection:
            ip = self._ban_list.get(selection[0]).split()[0]
            self._firewall_job(lambda: self._firewall.remove(ip), f'{ip} engeli kaldırıldı.')

    def _refresh_firewall(self):
        if not is_root():
            self._syslog('HATA', 'Firewall listesini okumak için Linux yakalama sunucusunda yetki gerekir.')
            return
        self._firewall_job(self._firewall.snapshot, 'Sistemdeki NetShield kuralları okundu.')

    def _firewall_job(self, operation, message):
        if self._closed or self._firewall_future is not None:
            self._syslog('SİSTEM', 'Firewall işlemi sürüyor; tamamlanmasını bekleyin.')
            return
        self._firewall_future = self._firewall_worker.submit(operation)
        self._syslog('SİSTEM', 'Firewall işlemi arka planda yürütülüyor…')
        def poll():
            self._firewall_after = None
            if self._closed:
                return
            if not self._firewall_future.done():
                self._firewall_after = self.root.after(25, poll)
                return
            try:
                self.banned = self._firewall_future.result()
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                self._syslog('HATA', f'Firewall işlemi tamamlanamadı: {exc}. Listeyi yenileyin; sistem kısmen değişmiş olabilir.')
            else:
                self._ban_list.delete(0, 'end')
                for ip, rules in self.banned.items():
                    self._ban_list.insert('end', f'{ip}  [{len(rules)} NetShield kuralı]')
                if hasattr(self, '_k_ban'):
                    self._k_ban.configure(text=str(len(self.banned)))
                self._syslog('SİSTEM', message)
            finally:
                self._firewall_future = None
        self._firewall_after = self.root.after(25, poll)

    def _rapor(self):
        if not self._security_allows('allow_exports'):
            return
        if not self.olaylar:
            messagebox.showinfo('Rapor', 'Henüz kayıtlı alarm yok.', parent=self.root)
            return
        path = filedialog.asksaveasfilename(parent=self.root, title='Maskeli HTML raporu kaydet',
                                           defaultextension='.html', filetypes=[('HTML', '*.html')])
        if not path:
            return
        if not self._security_allows('allow_exports'):
            return
        snapshot = PrivateSnapshot().session([], self.olaylar, self._packet_total)
        try:
            private_write(path, render_report(snapshot))
        except OSError as exc:
            messagebox.showerror('Rapor kaydedilemedi', str(exc), parent=self.root)
            return
        self._syslog('SİSTEM', 'Maskeli HTML raporu yerel dosyaya kaydedildi; tarayıcı açılmadı.')

    def _security_allows(self, action, firewall=False, removing=False):
        self.managed_policy, error = load_managed_policy()
        if error:
            self._syslog('HATA', error)
        policy = effective_policy(self.preferences['security'], self.managed_policy)
        if not policy[action]:
            self._syslog('HATA', 'Bu işlem etkin güvenlik politikası tarafından kapatıldı.')
            return False
        if firewall and (not is_root() or (not removing and (self.motor is None or self.motor.sim))):
            self._syslog('HATA', 'Firewall işlemi yalnızca yetkili canlı oturumda kullanılabilir.')
            return False
        return True


def main():
    root = tk.Tk()
    app = App(root)
    root.protocol('WM_DELETE_WINDOW', app.kapat)
    root.mainloop()


if __name__ == '__main__':
    main()
