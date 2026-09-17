"""Monitoring, review, keyboard actions and persistent workspace preferences."""
import tkinter as tk
from tkinter import ttk, messagebox
from netshield.core.settings import save_settings, validate_settings
from netshield.core.tracking import summarize
from netshield.core.security import effective_policy, PrivateSnapshot, load_managed_policy
import json
import shlex
from netshield.ui.theme import BG, SURF, CARD, TXT, MUT, ACC, GRN, YLW, RED, TUR_RENK


from netshield.ui.inventory import InventoryPanel


class AnalysisPanels(InventoryPanel):
    def _build_alarm_tools(self, parent):
        bar = tk.Frame(parent, bg=SURF, padx=8, pady=8)
        bar.pack(fill='x')
        self._alarm_level = tk.StringVar(value='Tüm önemler')
        self._alarm_kind = tk.StringVar(value='Tüm tespitler')
        self._alarm_review = tk.StringVar(value='Tüm kayıtlar')
        for variable, values, width in (
            (self._alarm_level, ['Tüm önemler', 'Yüksek', 'Kritik'], 13),
            (self._alarm_kind, ['Tüm tespitler', *TUR_RENK], 21),
            (self._alarm_review, ['Tüm kayıtlar', 'Yeni', 'İncelendi'], 13),
        ):
            box = ttk.Combobox(bar, textvariable=variable, values=values, width=width, state='readonly')
            box.pack(side='left', padx=(0, 6))
            box.bind('<<ComboboxSelected>>', lambda _: self._refresh_alerts())
        self._button(bar, 'İncelendi / geri al', self._toggle_review).pack(side='right')

    def _build_analysis_panels(self):
        page = tk.Frame(self._notebook, bg=SURF)
        self._tracking_page = page
        self._notebook.add(page, text='Cihazlar ve bağlantılar')
        self._tracking_caption = tk.Label(page, text='Bellekte tutulan paket ve alarm önizlemeleri · tam ağ envanteri değildir',
                                         bg=SURF, fg=MUT, anchor='w', padx=12, pady=10)
        self._tracking_caption.pack(fill='x')
        tabs = ttk.Notebook(page)
        tabs.pack(fill='both', expand=True)
        self._tracking_tabs = tabs
        hosts, flows, watched = (tk.Frame(tabs, bg=SURF) for _ in range(3))
        for frame, label in ((hosts, 'Cihazlar'), (flows, 'Bağlantılar'), (watched, 'Takip listem')):
            tabs.add(frame, text=label)
        host_columns = [('ip', 'IP adresi', 160), ('sent', 'Gönderim', 100),
                        ('received', 'Alınan', 95), ('bytes', 'Bayt', 100),
                        ('alerts', 'Alarm', 65), ('last', 'Son görülen', 115), ('watch', 'Takip', 70)]
        self._host_tree = self._table(hosts, host_columns)
        self._watch_tree = self._table(watched, host_columns)
        self._flow_tree = self._table(flows, [('interface', 'Arayüz', 90), ('proto', 'Protokol', 80), ('a', 'Uç A', 210),
                                             ('b', 'Uç B', 210), ('packets', 'Paket', 70),
                                             ('bytes', 'Bayt', 100), ('last', 'Son görülen', 115)])
        self._build_inventory(tabs)
        self._flow_rows = {}
        for tree in (self._host_tree, self._watch_tree):
            tree.bind('<Double-1>', lambda _, t=tree: self._follow_host(t))
            tree.bind('<<TreeviewSelect>>', lambda _, t=tree: self._host_details(t))
        self._flow_tree.bind('<Double-1>', lambda _: self._follow_flow())
        self._flow_tree.bind('<<TreeviewSelect>>', lambda _: self._flow_details())
        footer = tk.Frame(page, bg=SURF, padx=10, pady=8)
        footer.pack(fill='x', before=tabs)
        self._button(footer, 'Seçili kaydı filtrele', self._follow_tracking).pack(side='left')
        self._button(footer, 'IP takip listesi', self._preferences).pack(side='left', padx=8)
        self._tracking_scope = tk.StringVar(value='Tüm modlar')
        scope = ttk.Combobox(footer, textvariable=self._tracking_scope, state='readonly',
                             values=['Tüm modlar', 'Canlı', 'Simülasyon'], width=14)
        scope.pack(side='right')
        scope.bind('<<ComboboxSelected>>', lambda _: self._change_tracking_scope())
        self._tracking_iface = tk.StringVar(value='Tüm arayüzler')
        self._tracking_iface_box = ttk.Combobox(footer, textvariable=self._tracking_iface, state='readonly',
                                               values=['Tüm arayüzler'], width=15)
        self._tracking_iface_box.pack(side='right', padx=8)
        self._tracking_iface_box.bind('<<ComboboxSelected>>', lambda _: self._change_tracking_scope())
        networks = tk.Frame(self._notebook, bg=SURF)
        self._notebook.add(networks, text='Ağ arayüzleri')
        tk.Label(networks, text='Seçilen yerel arayüzlerin durumu · bu yakalama oturumundaki toplam paketler',
                 bg=SURF, fg=MUT, padx=12, pady=12).pack(anchor='w')
        self._interfaces_tree = self._table(networks, [('interface', 'Arayüz', 160), ('status', 'Durum', 180), ('packets', 'Paket', 160)])
        self._interfaces_tree.bind('<Double-1>', lambda _: self._follow_interface())
        self._tracking_dirty = True
        self._notebook.bind('<<NotebookTabChanged>>', lambda _: self._refresh_tracking())

        menubar = tk.Menu(self.root, bg=SURF, fg=TXT, activebackground=CARD, activeforeground=TXT)
        workspace = tk.Menu(menubar, tearoff=False)
        workspace.add_command(label='Güvenlik merkezi', command=self._security_center)
        workspace.add_command(label='Görünüm ve IP takip ayarları', command=self._preferences)
        workspace.add_command(label='Tespit eşikleri ve profilleri', command=self._thresholds)
        workspace.add_command(label='Ağ arayüzlerini yenile', command=self._refresh_interfaces)
        workspace.add_separator()
        workspace.add_command(label='JSON dışa aktar', command=self._export, accelerator='Ctrl+E')
        workspace.add_command(label='HTML rapor', command=self._rapor)
        menubar.add_cascade(label='Çalışma alanı', menu=workspace)
        view = tk.Menu(menubar, tearoff=False)
        self._sidebar_visible = tk.BooleanVar(value=True)
        self._inspector_visible = tk.BooleanVar(value=True)
        view.add_checkbutton(label='Sağ takip paneli', variable=self._sidebar_visible, command=self._toggle_sidebar)
        view.add_checkbutton(label='Paket ayrıntıları', variable=self._inspector_visible, command=self._toggle_inspector)
        view.add_command(label='Filtreyi temizle', command=lambda: self._apply_expression(''), accelerator='Esc')
        menubar.add_cascade(label='Görünüm', menu=view)
        menubar.add_command(label='Kısayollar / yardım', command=self._help)
        self.root.configure(menu=menubar)
        self.root.bind('<Control-f>', lambda _: self._focus_filter())
        self.root.bind('<Control-e>', lambda _: self._export())
        self._filter_entry.bind('<Escape>', lambda _: self._apply_expression(''))
        self._packet_tree.bind('<Button-3>', self._packet_menu)
        self._packet_tree.bind('<Control-c>', lambda _: self._copy_selected_packet())
        self._apply_density()

    def _sort_table(self, tree, column):
        state = getattr(self, '_table_orders', {})
        previous = state.get(str(tree))
        descending = not previous[1] if previous and previous[0] == column else True
        state[str(tree)] = (column, descending)
        self._table_orders = state
        self._apply_table_order(tree)
        self._autoscroll.set(False)

    def _apply_table_order(self, tree):
        order = getattr(self, '_table_orders', {}).get(str(tree))
        if order is None:
            return
        column, descending = order
        def value(item):
            text = tree.set(item, column)
            try:
                return (0, float(text.replace(',', '')))
            except ValueError:
                return (1, text.casefold())
        for index, item in enumerate(sorted(tree.get_children(), key=value, reverse=descending)):
            tree.move(item, '', index)

    def _resort_tables(self):
        for tree in (self._packet_tree, self._alert_tree):
            self._apply_table_order(tree)

    def _apply_density(self):
        ttk.Style(self.root).configure('Treeview', rowheight=22 if self.preferences['density'] == 'Kompakt' else 29)

    def _commit_preferences(self, **updates):
        try:
            candidate = validate_settings({**self.preferences, **updates})
            save_settings(self.settings_path, candidate)
        except (OSError, ValueError, TypeError) as exc:
            messagebox.showerror('Ayarlar kaydedilemedi', str(exc), parent=self.root)
            return False
        self.preferences = candidate
        return True

    def _preferences(self):
        win = tk.Toplevel(self.root)
        win.title('Çalışma alanı ayarları')
        win.configure(bg=SURF)
        win.transient(self.root)
        tk.Label(win, text='GÖRÜNÜM VE TAKİP', bg=SURF, fg=ACC, font=('DejaVu Sans', 12, 'bold')).pack(anchor='w', padx=20, pady=16)
        density = tk.StringVar(value=self.preferences['density'])
        tk.Label(win, text='Tablo yoğunluğu', bg=SURF, fg=TXT).pack(anchor='w', padx=20)
        ttk.Combobox(win, textvariable=density, state='readonly', values=['Rahat', 'Kompakt']).pack(fill='x', padx=20, pady=8)
        tk.Label(win, text='Takip edilen IP adresleri · satır başına bir adres', bg=SURF, fg=TXT).pack(anchor='w', padx=20, pady=(10, 5))
        addresses = tk.Text(win, width=48, height=8, bg=CARD, fg=TXT, insertbackground=TXT, relief='flat')
        addresses.pack(fill='both', expand=True, padx=20)
        addresses.insert('1.0', '\n'.join(self.preferences['watchlist']))
        tk.Label(win, text='Takip listesi alarm veya firewall kurallarını değiştirmez.\nAyarlar bu kullanıcı için saklanır; paketler kaydedilmez.',
                 bg=SURF, fg=MUT, justify='left').pack(anchor='w', padx=20, pady=12)
        def save():
            watched = [line.strip() for line in addresses.get('1.0', 'end').splitlines() if line.strip()]
            if self._commit_preferences(density=density.get(), watchlist=watched):
                self._apply_density()
                self._tracking_dirty = True
                self._refresh_tracking()
                win.destroy()
        self._button(win, 'Ayarları kaydet', save, True).pack(fill='x', padx=20, pady=(0, 20))

    def _refresh_tracking(self):
        if not self._tracking_dirty or self._notebook.select() != str(self._tracking_page):
            return
        scope = self._tracking_scope.get()
        def in_scope(record):
            return (scope == 'Tüm modlar' or bool(record.get('simulated')) == (scope == 'Simülasyon')) and (
                self._tracking_iface.get() == 'Tüm arayüzler' or record.get('interface') == self._tracking_iface.get())
        packets = [p for p in self._packets.values() if in_scope(p)]
        alerts = [e for e in self.olaylar if in_scope(e)]
        summary = summarize(packets, alerts, self.preferences['watchlist'])
        watched = set(self.preferences['watchlist'])
        def replace(tree, rows):
            existing = set(tree.get_children())
            wanted = {key for key, _ in rows}
            stale = existing - wanted
            if stale:
                tree.delete(*stale)
            for index, (key, values) in enumerate(rows):
                if key in existing:
                    if tree.item(key, 'values') != tuple(str(v) for v in values):
                        tree.item(key, values=values)
                else:
                    tree.insert('', 'end', iid=key, values=values)
                tree.move(key, '', index)
            self._apply_table_order(tree)
        rows = [(h['ip'], [h[k] for k in ('ip', 'sent', 'received', 'bytes', 'alerts', 'last')] + ['★' if h['ip'] in watched else ''])
                for h in summary['hosts']]
        replace(self._host_tree, rows)
        replace(self._watch_tree, [(key, values) for key, values in rows if key in watched])
        self._flow_rows = {str((f['interface'], f['protocol'], f['a'], f['b'])): f for f in summary['conversations']}
        replace(self._flow_tree, [(key, [f['interface'], f['protocol'], self._endpoint(f['a']), self._endpoint(f['b']),
                                       f['packets'], f['bytes'], f['last']]) for key, f in self._flow_rows.items()])
        self._refresh_inventory(packets, alerts, replace)
        protocols = '  ·  '.join(f'{name}: {count}' for name, count in summary['protocols'].most_common(6))
        self._tracking_caption.configure(text=f"{scope} · {self._tracking_iface.get()} · Önizleme kapsamı: {len(packets)} paket · {len(summary['hosts'])} IP · {len(self._flow_rows)} bağlantı\n{protocols or 'Henüz trafik yok.'} · IP toplamları seçili arayüz kapsamındadır")
        self._tracking_dirty = False

    def _change_tracking_scope(self):
        self._tracking_dirty = True
        self._refresh_tracking()

    @staticmethod
    def _endpoint(endpoint):
        ip, port = endpoint
        return f'[{ip}]:{port}' if ':' in ip and port is not None else f'{ip}:{port}' if port is not None else ip

    def _follow_tracking(self):
        index = self._tracking_tabs.index('current')
        if index == 3:
            self._follow_device()
        elif index == 1:
            self._follow_flow()
        else:
            self._follow_host(self._host_tree if index == 0 else self._watch_tree)

    def _follow_host(self, tree):
        if tree.selection():
            suffix = {'Canlı': ' mode=live', 'Simülasyon': ' mode=demo'}.get(self._tracking_scope.get(), '')
            self._apply_expression(f'ip={tree.selection()[0]}' + suffix + self._interface_filter_suffix())

    def _host_details(self, tree):
        if tree.selection():
            values = tree.item(tree.selection()[0], 'values')
            self._show_details(f'IP: {values[0]}\nGönderilen: {values[1]}  Alınan: {values[2]}  Bayt: {values[3]}\nİlişkili alarm: {values[4]}  Son görülen: {values[5]}\n\nSayaçlar bellekteki önizlemeleri kapsar. Çift tıklayarak bu IP için paketleri filtreleyin.')

    def _flow_details(self):
        if self._flow_tree.selection():
            flow = self._flow_rows.get(self._flow_tree.selection()[0])
            if flow:
                self._show_details(f"Arayüz: {flow['interface'] or '—'} · {flow['protocol']} · {self._endpoint(flow['a'])} ↔ {self._endpoint(flow['b'])}\nPaket: {flow['packets']}  Bayt: {flow['bytes']}\n\nİki yön birleştirilir; bu görünüm TCP akışını yeniden oluşturmaz.\nÇift tıklayarak bağlantının paketlerini filtreleyin.")

    def _follow_flow(self):
        if self._flow_tree.selection():
            flow = self._flow_rows.get(self._flow_tree.selection()[0])
            if flow:
                suffix = {'Canlı': ' mode=live', 'Simülasyon': ' mode=demo'}.get(self._tracking_scope.get(), '')
                self._apply_expression(self._flow_expression(flow['protocol'], flow['a'], flow['b']) + suffix + (' iface=' + shlex.quote(flow['interface']) if flow['interface'] else ''))

    @staticmethod
    def _flow_expression(protocol, a, b):
        # Exact directed endpoint pairs, with either direction accepted by the flow field.
        return f'flow={protocol},{a[0]},{a[1]},{b[0]},{b[1]}'

    def _apply_expression(self, expression):
        self._filter_text.set(expression)
        self._protocol.set('Tümü')
        self._filtre_uygula()
        self._notebook.select(0)

    def _packet_menu(self, event):
        row = self._packet_tree.identify_row(event.y)
        if not row or row not in self._packets:
            return
        self._packet_tree.selection_set(row)
        packet = self._packets[row]
        menu = tk.Menu(self.root, tearoff=False)
        menu.add_command(label='Kaynak IP paketlerini göster', command=lambda: self._apply_expression(f"ip={packet['src']}"))
        menu.add_command(label='Hedef IP paketlerini göster', command=lambda: self._apply_expression(f"ip={packet['dst']}"))
        menu.add_command(label='Bu bağlantıyı izle', command=lambda: self._apply_expression(self._flow_expression(
            packet.get('transport', packet['proto']), (packet['src'], packet.get('sport')), (packet['dst'], packet.get('dport')))))
        menu.add_separator()
        menu.add_command(label='Kaynak IP takip listesine ekle', command=lambda: self._watch_ip(packet['src']))
        menu.add_command(label='Hedef IP takip listesine ekle', command=lambda: self._watch_ip(packet['dst']))
        menu.add_command(label='Maskeli paket özetini kopyala', command=self._copy_selected_packet)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _watch_ip(self, ip):
        watched = list(dict.fromkeys([*self.preferences['watchlist'], ip]))
        if self._commit_preferences(watchlist=watched):
            self._tracking_dirty = True
            self._refresh_tracking()
            self._syslog('SİSTEM', f'Takip listesine eklendi: {ip}')

    def _copy_selected_packet(self):
        if not self._security_allows('allow_clipboard'):
            return 'break'
        selection = self._packet_tree.selection()
        if selection:
            self.root.clipboard_clear()
            packet = self._packets.get(selection[0])
            if packet:
                self.root.clipboard_append(json.dumps(PrivateSnapshot().packet(packet), ensure_ascii=False))
        return 'break'

    def _focus_filter(self):
        self._filter_entry.focus_set()
        self._filter_entry.selection_range(0, 'end')
        return 'break'

    def _alert_matches(self, event):
        return ((self._alarm_level.get() == 'Tüm önemler' or self._alarm_level.get() == event.get('severity'))
                and (self._alarm_kind.get() == 'Tüm tespitler' or self._alarm_kind.get() == event['tur'])
                and (self._alarm_review.get() == 'Tüm kayıtlar' or
                     self._alarm_review.get() == ('İncelendi' if event.get('reviewed') else 'Yeni')))

    def _insert_alert(self, event):
        if self._alert_matches(event):
            values = [event.get('ts'), event.get('interface', ''), 'İncelendi' if event.get('reviewed') else 'Yeni']
            values += [event.get(k, '') for k in ('severity', 'tur', 'ip', 'dst', 'detay')]
            self._alert_tree.insert('', 'end', iid=str(event['id']), values=values, tags=(event.get('severity', 'Yüksek'),))

    def _refresh_alerts(self):
        if self._alert_tree.get_children():
            self._alert_tree.delete(*self._alert_tree.get_children())
        for event in self.olaylar:
            self._insert_alert(event)
        self._apply_table_order(self._alert_tree)

    def _toggle_review(self):
        selection = self._alert_tree.selection()
        if not selection:
            return
        for event in self.olaylar:
            if str(event['id']) == selection[0]:
                event['reviewed'] = not event.get('reviewed', False)
                break
        self._refresh_alerts()
        if self._alert_tree.exists(selection[0]):
            self._alert_tree.selection_set(selection)

    def _toggle_sidebar(self):
        if self._sidebar_visible.get():
            self._main.add(self._sidebar, stretch='never', minsize=285)
        else:
            self._main.forget(self._sidebar)

    def _toggle_inspector(self):
        if self._inspector_visible.get():
            self._vertical.add(self._inspector, stretch='never', minsize=165, height=190)
        else:
            self._vertical.forget(self._inspector)

    def _refresh_interfaces(self):
        from netshield.core.motor import get_if_list
        if self.motor and self.motor.status not in ('Durduruldu', 'Hata', 'Hazır'):
            messagebox.showinfo('Arayüzler', 'Arayüz seçimini değiştirmek için yakalamayı durdurun.', parent=self.root)
            return False
        try:
            values = get_if_list()
            self._iface_box.configure(values=values)
            self._selected_interfaces = [name for name in self._selected_interfaces if name in values]
            if not self._selected_interfaces and values:
                self._selected_interfaces = [values[0]]
            self._iface.set(', '.join(self._selected_interfaces))
            return True
        except Exception as exc:
            messagebox.showerror('Arayüzler okunamadı', str(exc), parent=self.root)
            return False

    def _choose_interfaces(self):
        from netshield.core.motor import get_if_list
        if not self._refresh_interfaces():
            return
        win = tk.Toplevel(self.root)
        win.title('İzlenecek yerel ağ arayüzleri')
        win.configure(bg=SURF)
        win.transient(self.root)
        tk.Label(win, text='Birden fazla arayüz seçebilirsiniz.\nlo bilgisayar içi bağlantıdır; uzak ağ sensörü değildir.',
                 bg=SURF, fg=TXT, justify='left').pack(padx=18, pady=14)
        variables = {}
        for name in get_if_list():
            variable = tk.BooleanVar(value=name in self._selected_interfaces)
            variables[name] = variable
            tk.Checkbutton(win, text=name, variable=variable, bg=SURF, fg=TXT, selectcolor=CARD).pack(anchor='w', padx=18)
        def save():
            selected = [name for name, variable in variables.items() if variable.get()]
            if not selected:
                messagebox.showerror('Arayüzler', 'En az bir arayüz seçin.', parent=win)
                return
            self._selected_interfaces = selected
            self._iface.set(', '.join(selected))
            win.destroy()
        self._button(win, 'Seçimi uygula', save, True).pack(fill='x', padx=18, pady=14)

    def _refresh_interface_status(self):
        snapshot = self.motor.interface_snapshot()
        tree = self._interfaces_tree
        for old in set(tree.get_children()) - set(snapshot):
            tree.delete(old)
        for name, value in snapshot.items():
            key = name or '(belirtilmedi)'
            values = (name, value['status'], value['packets'])
            if tree.exists(key):
                tree.item(key, values=values)
            else:
                tree.insert('', 'end', iid=key, values=values)
        available = sorted(set(self._selected_interfaces) | {p.get('interface', '') for p in self._packets.values()} - {''})
        self._tracking_iface_box.configure(values=['Tüm arayüzler', *available])

    def _follow_interface(self):
        selection = self._interfaces_tree.selection()
        if selection:
            self._apply_expression('iface=' + shlex.quote(selection[0]))

    def _interface_filter_suffix(self):
        interface = self._tracking_iface.get()
        return '' if interface == 'Tüm arayüzler' else ' iface=' + shlex.quote(interface)

    def _help(self):
        messagebox.showinfo('Çalışma alanı kısayolları',
                            'Ctrl+F: paket filtresine odaklan\nEnter: filtreyi uygula\nEsc (filtrede): filtreyi temizle\n'
                            'Ctrl+E: JSON dışa aktar\nCtrl+C (paket tablosunda): özeti kopyala\n'
                            'Sağ tık: IP/bağlantı filtreleme ve takibe ekleme\nSütun başlığı: sırala, otomatik kaydırmayı kapat\n\n'
                            'Ağ filtresi: ip=192.168.1.0/24\nIPv6: proto=IPv6\nPort: sport=53 veya dport=443\n'
                            'Takip sayaçları yalnızca bellekteki önizlemeleri kapsar.', parent=self.root)


    def _security_center(self):
        self.managed_policy, policy_error = load_managed_policy()
        if policy_error:
            self._syslog('HATA', policy_error)
        win = tk.Toplevel(self.root)
        win.title('NetShield · Güvenlik merkezi')
        win.configure(bg=SURF)
        win.transient(self.root)
        tk.Label(win, text='YEREL VE PASİF ÇALIŞMA', bg=SURF, fg=GRN,
                 font=('DejaVu Sans', 13, 'bold')).pack(anchor='w', padx=20, pady=16)
        tk.Label(win, text='Harici GeoIP / telemetri / bulut aktarımı yok.\nPaket yükü, ham baytlar ve HTTP URL içeriği saklanmaz.\nRaporlar otomatik tarayıcı açmaz; IP adresleri maskelenir.',
                 bg=SURF, fg=TXT, justify='left').pack(anchor='w', padx=20)
        profile = tk.StringVar(value=self.preferences['security']['profile'])
        ttk.Combobox(win, textvariable=profile, state='readonly', values=['Bireysel', 'Kurumsal']).pack(fill='x', padx=20, pady=12)
        variables = {}
        for key, label in [('allow_exports', 'Maskeli yerel rapor / JSON kaydına izin ver'),
                           ('allow_clipboard', 'Maskeli paket özetini panoya kopyalamaya izin ver'),
                           ('allow_firewall', 'Yetkili canlı oturumda manuel INPUT engellemesine izin ver')]:
            variable = tk.BooleanVar(value=self.preferences['security'][key])
            variables[key] = variable
            tk.Checkbutton(win, text=label, variable=variable, bg=SURF, fg=TXT,
                           selectcolor=CARD, activebackground=SURF).pack(anchor='w', padx=16, pady=4)
        policy = effective_policy(self.preferences['security'], self.managed_policy)
        status = '\n'.join(f"{name}: {'Açık' if policy[key] else 'Kapalı'}" for key, name in
                           [('allow_exports', 'Yerel dışa aktarım'), ('allow_clipboard', 'Pano'), ('allow_firewall', 'Manuel firewall')])
        tk.Label(win, text='ETKİN POLİTİKA\n' + status, bg=CARD, fg=ACC, justify='left', padx=12, pady=12).pack(fill='x', padx=20, pady=12)
        tk.Label(win, text='Kurumsal profil üç işlemi de kapatır. Yönetici politikası kullanıcı seçimini daraltabilir.\n'
                           'Canlı analizde IP adresleri ekranda ve sınırlı bellekte görünür.\n'
                           'Dosya ve pano hedefleri işletim sistemi tarafından eşitleniyor olabilir.\n'
                           'Bu uygulama diğer programların ağ erişimini engellemez; bir OS sandbox değildir.',
                 bg=SURF, fg=MUT, justify='left', wraplength=570).pack(anchor='w', padx=20, pady=8)
        def save():
            security = dict(profile=profile.get(), **{key: value.get() for key, value in variables.items()})
            if self._commit_preferences(security=security):
                self._syslog('SİSTEM', 'Güvenlik politikası güncellendi.')
                win.destroy()
        self._button(win, 'Politikayı kaydet', save, True).pack(fill='x', padx=20, pady=16)
