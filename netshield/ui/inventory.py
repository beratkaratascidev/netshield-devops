"""Local directory UI; no remote access, probing or background persistence."""
import shlex
import uuid
import time
from datetime import datetime
from netshield.core.agent_status import read_snapshot, status_label
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from netshield.core.inventory import device_activity
from netshield.ui.theme import SURF, CARD, TXT, MUT


class InventoryPanel:
    def _build_inventory(self, tabs):
        page = tk.Frame(tabs, bg=SURF)
        self._inventory_page = page
        tabs.add(page, text='Çalışan / cihaz envanteri')
        bar = tk.Frame(page, bg=SURF, padx=10, pady=8)
        bar.pack(fill='x')
        for label, callback in (('Ekle', self._edit_device), ('Düzenle', lambda: self._edit_device(True)),
                                ('Sil', self._remove_device), ('Paketleri göster', self._follow_device)):
            self._button(bar, label, callback).pack(side='left', padx=(0, 6))
        self._device_search = tk.StringVar()
        search = ttk.Entry(bar, textvariable=self._device_search, width=24)
        search.pack(side='right')
        tk.Label(bar, text='Ad / bölüm / IP ara', bg=SURF, fg=MUT).pack(side='right', padx=8)
        self._device_search.trace_add('write', lambda *_: self._change_tracking_scope())
        tk.Label(page, text='Yerel kayıt · yalnızca yakalamada görülen trafik · IP kaydı uzaktan erişim sağlamaz',
                 bg=SURF, fg=MUT, padx=10).pack(anchor='w')
        self._device_detail = scrolledtext.ScrolledText(page, height=9, bg=CARD, fg=TXT, relief='flat', wrap='word', state='disabled')
        self._device_detail.pack(side='bottom', fill='x', padx=10, pady=10)
        self._device_tree = self._table(page, [('name', 'Ad / cihaz', 140), ('department', 'Bölüm', 110),
            ('ip', 'IP', 130), ('interface', 'Arayüz', 90), ('status', 'Gözlem', 100),
            ('sent', 'Giden bayt', 90), ('received', 'Gelen bayt', 90), ('alerts', 'Alarm', 60), ('last', 'Son görülen', 95)])
        self._build_agent_panel(tabs)
        self._device_rows = {}
        self._device_tree.bind('<<TreeviewSelect>>', lambda _: self._device_details())
        self._device_tree.bind('<Double-1>', lambda _: self._follow_device())

    def _selected_device(self):
        selection = self._device_tree.selection()
        return next((d for d in self.preferences['devices'] if selection and d['id'] == selection[0]), None)

    def _save_device(self, device):
        records = [d for d in self.preferences['devices'] if d['id'] != device['id']] + [device]
        if not self._commit_preferences(devices=records):
            return False
        # Saving must reveal the row even when a stale search or another tab is active.
        agent_page_active = self._tracking_tabs.select() == str(self._agent_page)
        self._notebook.select(self._tracking_page)
        self._device_search.set('')
        self._change_tracking_scope()
        self._refresh_agent_panel()
        self._tracking_tabs.select(self._agent_page if agent_page_active else self._inventory_page)
        for tree in (self._device_tree, self._agent_tree):
            tree.selection_set(device['id'])
            tree.focus(device['id'])
            tree.see(device['id'])
        self._device_details()
        self._show_agent_details()
        return True

    def _edit_device(self, editing=False):
        device = self._selected_device() if editing else dict(id=uuid.uuid4().hex)
        if device is None:
            return
        win = tk.Toplevel(self.root)
        win.title('Çalışan / cihaz kaydı')
        win.configure(bg=SURF)
        win.transient(self.root)
        fields = {}
        for key, label in (('name', 'Ad / cihaz adı'), ('department', 'Bölüm'), ('ip', 'IP adresi'),
                           ('interface', 'Yakalama arayüzü (boş: tümü)')):
            tk.Label(win, text=label, bg=SURF, fg=TXT).pack(anchor='w', padx=20, pady=(10, 3))
            fields[key] = tk.StringVar(value=device.get(key, ''))
            if key == 'interface':
                entry = ttk.Combobox(win, textvariable=fields[key], values=['', *getattr(self, '_selected_interfaces', [])])
            else:
                entry = ttk.Entry(win, textvariable=fields[key], width=42)
            entry.pack(fill='x', padx=20)
        tk.Label(win, text='Aynı IP farklı ağlarda kullanılabilir; arayüz seçerek ayırın.\nDHCP ile IP değişirse kaydı güncelleyin. Kayıtlar yereldir.',
                 bg=SURF, fg=MUT, justify='left').pack(padx=20, pady=12)
        def save():
            if self._save_device(dict(id=device['id'], **{k: v.get() for k, v in fields.items()})):
                win.destroy()
        self._button(win, 'Kaydet', save, True).pack(fill='x', padx=20, pady=(0, 20))

    def _remove_device(self):
        device = self._selected_device()
        if device and messagebox.askyesno('Kaydı sil', f"{device['name']} envanterden silinsin mi?", parent=self.root):
            if self._commit_preferences(devices=[d for d in self.preferences['devices'] if d['id'] != device['id']]):
                self._change_tracking_scope()
                self._refresh_agent_panel()

    def _refresh_inventory(self, packets, alerts, replace):
        query = self._device_search.get().strip().casefold()
        self._device_rows = {}
        rows = []
        for device in self.preferences['devices']:
            if query and not any(query in device[k].casefold() for k in ('name', 'department', 'ip')):
                continue
            activity = device_activity(device, packets, alerts)
            self._device_rows[device['id']] = activity
            rows.append((device['id'], [device['name'], device['department'], device['ip'], device['interface'] or 'Tümü',
                activity['status'], activity['sent_bytes'], activity['received_bytes'], activity['alerts'], activity['last']]))
        replace(self._device_tree, rows)
        self._device_details()

    def _device_details(self):
        device = self._selected_device()
        activity = self._device_rows.get(device['id']) if device else None
        text = 'Bir kayıt seçin. Sayaçlar yalnızca bellekte tutulan önizlemeleri ve seçili mod / arayüz kapsamını gösterir.'
        if activity:
            text = (f"{device['name']} · {device['department']} · {device['ip']}\n"
                    f"{activity['status']} · Giden: {activity['sent']} paket · Gelen: {activity['received']} paket · "
                    f"İlişkili alarm: {activity['alerts']}\n"
                    'Gözlenmedi durumu çevrimdışı anlamına gelmez. IP eşleştirmesi kullanıcı kimliğini doğrulamaz.\n'
                    'Sonlu önizleme · en yoğun 20 bağlantı:\n')
            text += '\n'.join(f"{f['interface']} · {f['protocol']} · {self._endpoint(f['a'])} ↔ {self._endpoint(f['b'])} · {f['bytes']} bayt"
                              for f in activity['conversations'][:20]) or 'Bağlantı gözlenmedi.'
            text += '\nSon 10 ilişkili alarm:\n' + ('\n'.join(f"{e.get('ts', '')} · {e.get('tur', '')} · {e.get('severity', '')} · {e.get('ip', '')} → {e.get('dst', '')}"
                        for e in activity['events'][-10:]) or 'Alarm yok.')
        self._device_detail.configure(state='normal')
        self._device_detail.delete('1.0', 'end')
        self._device_detail.insert('1.0', text)
        self._device_detail.configure(state='disabled')

    def _follow_device(self):
        device = self._selected_device()
        if device:
            suffix = {'Canlı': ' mode=live', 'Simülasyon': ' mode=demo'}.get(self._tracking_scope.get(), '')
            interface = device['interface']
            scope = self._tracking_iface.get()
            # Both constraints must apply when the global scope differs from the device interface.
            if interface:
                suffix += ' iface=' + shlex.quote(interface)
            if scope != 'Tüm arayüzler' and scope != interface:
                suffix += ' iface=' + shlex.quote(scope)
            self._apply_expression('ip=' + device['ip'] + suffix)

    def _build_agent_panel(self, tabs):
        page = tk.Frame(tabs, bg=SURF)
        self._agent_page = page
        tabs.add(page, text='Windows cihaz durumu')
        tk.Label(page, text='HTTPS ajan bildirimi · IP yerine cihaz kimliği · ağ yakalamadan bağımsız',
                 bg=SURF, fg=MUT, padx=10, pady=10).pack(anchor='w')
        self._agent_notice = tk.Label(page, text='Alıcı ayrı başlatılır; otomatik ağ bağlantısı açılmaz.', bg=SURF, fg=MUT)
        self._agent_notice.pack(anchor='w', padx=10)
        actions = tk.Frame(page, bg=SURF)
        actions.pack(fill='x', padx=10, pady=6)
        self._button(actions, 'Cihaz ekle', self._edit_device).pack(side='left', padx=(0, 8))
        self._button(actions, 'Yenile', self._refresh_agent_panel).pack(side='left')
        self._agent_details = scrolledtext.ScrolledText(page, height=9, bg=CARD, fg=TXT, state='disabled')
        self._agent_details.pack(side='bottom', fill='x', padx=10, pady=8)
        self._agent_tree = self._table(page, [('name', 'Ad / cihaz', 130), ('department', 'Bölüm', 100),
            ('state', 'Ajan durumu', 270), ('seen', 'Son bildirim', 165), ('boot', 'Windows açılış bildirimi', 205)])
        self._agent_records = {}
        self._agent_tree.bind('<<TreeviewSelect>>', lambda _: self._show_agent_details())
        self._agent_refreshed = 0
        tabs.bind('<<NotebookTabChanged>>', lambda _: self._refresh_agent_panel())

    def _refresh_agent_panel(self):
        if not hasattr(self, '_agent_tree'):
            return
        self._agent_refreshed = time.monotonic()
        self._agent_records, error = read_snapshot(self.settings_path)
        self._agent_notice.configure(text=error or 'Son durum yerel alıcıdan okunur. Bağlantı kaybı bilgisayarın kapandığını kanıtlamaz.')
        wanted = {d['id'] for d in self.preferences['devices']}
        for key in set(self._agent_tree.get_children()) - wanted:
            self._agent_tree.delete(key)
        for device in self.preferences['devices']:
            record = self._agent_records.get(device['id'])
            values = (device['name'], device['department'], status_label(record),
                      datetime.fromtimestamp(record['received_at']).strftime('%Y-%m-%d %H:%M:%S') if record else '—',
                      record['boot_time'] if record else '—')
            if self._agent_tree.exists(device['id']):
                self._agent_tree.item(device['id'], values=values)
            else:
                self._agent_tree.insert('', 'end', iid=device['id'], values=values)
        self._apply_table_order(self._agent_tree)
        self._show_agent_details()

    def _show_agent_details(self):
        selection = self._agent_tree.selection()
        text = 'Envanterden bir cihaz ekleyin; eşleştirme için kayıt kimliği burada görünür.\nKurulum: agents/windows/README.md'
        if selection:
            identity = selection[0]
            record = self._agent_records.get(identity)
            text = f'Cihaz kimliği: {identity}\nSon 100 bildirilen olay · zamanlar cihaz saatindendir.\n'
            labels = dict(agent_started='Ajan başladı', agent_stopped='Ajan durduruldu (PC kapanışı değildir)',
                          session_lock='Oturum kilitlendi', session_unlock='Oturum kilidi açıldı',
                          session_logoff='Oturum kapatma bildirimi', suspend='Uyku bildirimi', resume='Uyanma bildirimi')
            text += '\n'.join(f"{event['time']} · {labels[event['kind']]}" for event in reversed(record['events'])) if record else 'Henüz ajan bildirimi yok.'
        self._agent_details.configure(state='normal')
        self._agent_details.delete('1.0', 'end')
        self._agent_details.insert('1.0', text)
        self._agent_details.configure(state='disabled')
