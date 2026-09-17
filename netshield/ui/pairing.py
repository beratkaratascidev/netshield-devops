"""Explicit local enrollment wizard. No automatic network connections or installers."""
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from tkinter import ttk, filedialog

from netshield.core.agent_status import read_snapshot, status_label
from netshield.core.enrollment import enroll, revoke, server_origin
from netshield.ui.theme import SURF, TXT, MUT


class PairingDialog:
    def __init__(self, app, device):
        self.app, self.device = app, dict(device)
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='netshield-pairing')
        self.future = None
        self.after_id = None
        self.closed = False
        self.created_at = None
        self.win = tk.Toplevel(app.root)
        self.win.title('Windows cihazını eşleştir')
        self.win.configure(bg=SURF)
        self.win.transient(app.root)
        self.win.protocol('WM_DELETE_WINDOW', self.win.destroy)
        self.win.bind('<Destroy>', self._destroyed)
        tk.Label(self.win, text=f"1. Cihaz kaydedildi: {device['name']} · {device['department']}",
                 bg=SURF, fg=TXT, padx=20, pady=15, wraplength=550, justify='left').pack(anchor='w')
        tk.Label(self.win, text='2. NetShield alıcısının HTTPS adresi', bg=SURF, fg=TXT).pack(anchor='w', padx=20)
        self.server = tk.StringVar()
        ttk.Entry(self.win, textvariable=self.server, width=58).pack(fill='x', padx=20, pady=6)
        tk.Label(self.win, text='Örnek: https://netshield.sirketiniz:8443\nYeni yapılandırma oluşturmak bu cihazın önceki anahtarını geçersiz kılar.',
                 bg=SURF, fg=MUT, justify='left').pack(anchor='w', padx=20, pady=6)
        self.generate_button = app._button(self.win, 'Eşleştirme dosyasını oluştur / yenile', self.generate, True)
        self.generate_button.pack(fill='x', padx=20, pady=6)
        tk.Label(self.win, text='3. Dosyayı Windows bilgisayara güvenli biçimde taşıyın.\nNetShield-Agent.ps1 ile bu yapılandırmayı kullanarak ajanı başlatın.\nAjan görünür çalışır; IP adresi gerekmez.',
                 bg=SURF, fg=TXT, justify='left').pack(anchor='w', padx=20, pady=10)
        self.check_button = app._button(self.win, 'Cihaz bildirimini kontrol et', self.check)
        self.check_button.pack(fill='x', padx=20, pady=6)
        self.revoke_button = app._button(self.win, 'Bu cihazın eşleştirmesini iptal et', self.revoke)
        self.revoke_button.pack(fill='x', padx=20, pady=6)
        self.status = tk.StringVar(value='Cihaz kaydı hazır. Ajanı eşleştirmek için alıcı adresini girin.')
        tk.Label(self.win, textvariable=self.status, bg=SURF, fg=TXT, justify='left', wraplength=550,
                 padx=20, pady=15).pack(fill='x')
        tk.Label(self.win, text='Kontrol, bu panelin yerel alıcı kayıtlarını okur; başka bilgisayara bağlantı kurmaz.\nAlıcı kurulumu: docs/RECEIVER_OPERATIONS.md',
                 bg=SURF, fg=MUT, justify='left').pack(anchor='w', padx=20, pady=(0, 15))

    def _destroyed(self, event):
        if event.widget is not self.win:
            return
        self.closed = True
        if self.after_id is not None:
            self.app.root.after_cancel(self.after_id)
            self.after_id = None
        self.executor.shutdown(wait=False, cancel_futures=True)

    def _start(self, function, success):
        if self.closed or self.future is not None:
            return
        self.status.set('İşlem sürüyor…')
        for button in (self.generate_button, self.check_button, self.revoke_button):
            button.configure(state='disabled')
        self.future = self.executor.submit(function)
        def poll():
            self.after_id = None
            if self.closed:
                return
            if not self.future.done():
                self.after_id = self.app.root.after(25, poll)
                return
            try:
                result = self.future.result()
            except (OSError, ValueError) as exc:
                self.status.set(f'İşlem tamamlanamadı: {exc}')
            except Exception:
                self.status.set('İşlem tamamlanamadı. Alıcı yapılandırmasını ve dosya izinlerini kontrol edin.')
            else:
                success(result)
            finally:
                self.future = None
                for button in (self.generate_button, self.check_button, self.revoke_button):
                    button.configure(state='normal')
        self.after_id = self.app.root.after(25, poll)

    def generate(self):
        try:
            server = server_origin(self.server.get().strip())
        except ValueError as exc:
            self.status.set(str(exc))
            return
        output = filedialog.asksaveasfilename(parent=self.win, title='Cihaza özel eşleştirme dosyası',
            initialfile=f"agent-config-{self.device['id']}.json", defaultextension='.json', filetypes=[('JSON', '*.json')])
        if not output:
            return
        def success(path):
            self.created_at = time.time()
            self.status.set(f'Dosya oluşturuldu: {path}\nBu dosya gizli anahtar içerir. Windows bilgisayara güvenli biçimde taşıyın; ortak alanda paylaşmayın.')
        self._start(lambda: enroll(self.app.settings_path, self.device['id'], server, output), success)

    def check(self):
        def success(result):
            records, error = result
            if error:
                self.status.set(error)
                return
            record = records.get(self.device['id'])
            if not record or (self.created_at is not None and record['received_at'] <= self.created_at):
                self.status.set('Yeni cihaz bildirimi bekleniyor. Alıcıyı ve Windows ajanını başlatın; iki tarafın aynı yapılandırmayı kullandığını kontrol edin.')
            else:
                self.status.set('Alıcının bildirdiği cihaz durumu: ' + status_label(record))
            self.app._refresh_agent_panel()
        self._start(lambda: read_snapshot(self.app.settings_path), success)

    def revoke(self):
        def success(_):
            self.status.set('Eşleştirme iptal edildi. Sonraki bildirimler reddedilir; geçmiş durum kaydı bağlantı kanıtı değildir.')
        self._start(lambda: revoke(self.app.settings_path, self.device['id']), success)
