"""Local directory UI; no remote access, probing or background persistence."""
import shlex
import uuid
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from netshield.core.inventory import device_activity
from netshield.ui.theme import SURF, CARD, TXT, MUT


class InventoryPanel:
    def _build_inventory(self, tabs):
        page = tk.Frame(tabs, bg=SURF)
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
        self._change_tracking_scope()
        if self._device_tree.exists(device['id']):
            self._device_tree.selection_set(device['id'])
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
