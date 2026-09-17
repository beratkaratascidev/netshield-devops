import json
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox

from netshield.core.filters import compile_filter
from netshield.core.motor import get_if_list, SCAPY_OK
from netshield.net.utils import is_root

from netshield.ui.theme import (BG, SURF, CARD, BRD, ACC, GRN, RED, YLW, PRP, TXT, MUT, WHT, TUR_RENK, THRESHOLD_LABELS)
from netshield.ui.panels import AnalysisPanels


class WorkspaceUI(AnalysisPanels):
    def _button(self, parent, text, command, primary=False):
        button = tk.Button(parent, text=text, command=command, relief='flat', bd=0,
                           bg=ACC if primary else CARD, fg=BG if primary else TXT, highlightthickness=0,
                           activebackground=BRD, activeforeground=WHT, padx=13, pady=7,
                           font=('DejaVu Sans', 9), cursor='hand2')
        return button

    def _build(self):
        style = ttk.Style(self.root)
        style.theme_use('clam')
        style.configure('.', background=BG, foreground=TXT, font=('DejaVu Sans', 9))
        style.configure('Treeview', background=SURF, fieldbackground=SURF,
                        foreground=TXT, borderwidth=0, rowheight=27, bordercolor=BRD, lightcolor=BRD, darkcolor=BRD)
        style.configure('Treeview.Heading', background=CARD, foreground=MUT,
                        relief='flat', padding=(8, 8), bordercolor=BRD, lightcolor=BRD, darkcolor=BRD)
        style.map('Treeview', background=[('selected', '#294967')], foreground=[('selected', WHT)])
        style.configure('TNotebook', background=BG, borderwidth=0, bordercolor=BRD, lightcolor=BRD, darkcolor=BRD)
        style.configure('TScrollbar', background=BRD, troughcolor=SURF, bordercolor=SURF, arrowcolor=MUT)
        style.configure('TNotebook.Tab', padding=(16, 10), background=CARD, foreground=MUT)
        style.map('TNotebook.Tab', background=[('selected', SURF)], foreground=[('selected', ACC)])
        style.configure('TCombobox', fieldbackground=CARD, background=CARD, foreground=TXT)
        style.map('TCombobox', fieldbackground=[('readonly', CARD)], foreground=[('readonly', TXT)])
        style.configure('TEntry', fieldbackground=SURF, foreground=TXT, insertcolor=TXT)
        self.root.option_add('*TCombobox*Listbox.background', CARD)
        self.root.option_add('*TCombobox*Listbox.foreground', TXT)

        header = tk.Frame(self.root, bg=BG, padx=18, pady=14)
        header.pack(fill='x')
        tk.Label(header, text='NETSHIELD', bg=BG, fg=WHT,
                 font=('DejaVu Sans', 19, 'bold')).pack(side='left')
        tk.Label(header, text=' /  Ağ analiz çalışma alanı', bg=BG, fg=MUT,
                 font=('DejaVu Sans', 10)).pack(side='left', padx=8)
        self._mod_lbl = tk.Label(header, text='● HAZIR', bg=CARD, fg=GRN,
                                 padx=12, pady=6, font=('DejaVu Sans', 9, 'bold'))
        self._mod_lbl.pack(side='right')

        toolbar = tk.Frame(self.root, bg=SURF, padx=18, pady=10)
        toolbar.pack(fill='x')
        self._mode = tk.StringVar(value='Canlı' if SCAPY_OK and is_root() else 'Simülasyon')
        self._mode_box = ttk.Combobox(toolbar, textvariable=self._mode,
                                      values=['Simülasyon', 'Canlı'], width=13, state='readonly')
        self._mode_box.pack(side='left', padx=(0, 8))
        interfaces = get_if_list() if SCAPY_OK else []
        default = next((i for i in interfaces if i != 'lo'), interfaces[0] if interfaces else '')
        self._iface = tk.StringVar(value=default)
        tk.Label(toolbar, text='Arayüz', bg=SURF, fg=MUT).pack(side='left', padx=6)
        self._iface_box = ttk.Combobox(toolbar, textvariable=self._iface, values=interfaces,
                                       width=18, state='readonly')
        self._iface_box.pack(side='left', padx=(0, 10))
        self._capture_btn = self._button(toolbar, '■ Durdur', self._toggle_capture, primary=True)
        self._capture_btn.pack(side='left')
        self._button(toolbar, 'Eşikler', self._thresholds).pack(side='left', padx=8)
        self._button(toolbar, 'Ayarlar', self._preferences).pack(side='left')
        self._button(toolbar, 'JSON dışa aktar', self._export).pack(side='right', padx=(8, 0))
        self._button(toolbar, 'HTML rapor', self._rapor).pack(side='right', padx=(8, 0))
        self._button(toolbar, 'Görünümü temizle', self._sifirla).pack(side='right')

        cards = tk.Frame(self.root, bg=BG, padx=18, pady=12)
        cards.pack(fill='x')
        self._k_paket = self._kart(cards, 'YAKALANAN PAKET', '0', ACC)
        self._k_pps = self._kart(cards, 'PAKET / SANİYE', '0', GRN)
        self._k_flood = self._kart(cards, 'FLOOD / TARAMA ALARMI', '0', RED)
        self._k_toplam = self._kart(cards, 'KAYITLI ALARM', '0', YLW)
        self._k_ban = self._kart(cards, 'OTURUMDA BANLI', '0', PRP)

        main = tk.PanedWindow(self.root, orient='horizontal', bg=BG, sashwidth=7, bd=0)
        main.pack(fill='both', expand=True, padx=18)
        left = tk.Frame(main, bg=BG)
        sidebar = tk.Frame(main, bg=SURF, width=300)
        sidebar_canvas = tk.Canvas(sidebar, bg=SURF, width=285, highlightthickness=0)
        sidebar_scroll = ttk.Scrollbar(sidebar, orient='vertical', command=sidebar_canvas.yview)
        sidebar_canvas.configure(yscrollcommand=sidebar_scroll.set)
        sidebar_scroll.pack(side='right', fill='y')
        sidebar_canvas.pack(side='left', fill='both', expand=True)
        right = tk.Frame(sidebar_canvas, bg=SURF, padx=14, pady=12)
        sidebar_window = sidebar_canvas.create_window((0, 0), window=right, anchor='nw')
        right.bind('<Configure>', lambda _: sidebar_canvas.configure(scrollregion=sidebar_canvas.bbox('all')))
        sidebar_canvas.bind('<Configure>', lambda event: sidebar_canvas.itemconfigure(sidebar_window, width=event.width))
        main.add(left, stretch='always', minsize=650)
        main.add(sidebar, stretch='never', minsize=285)

        filterbar = tk.Frame(left, bg=BG, pady=7)
        filterbar.pack(fill='x')
        self._filter_text = tk.StringVar()
        entry = ttk.Entry(filterbar, textvariable=self._filter_text)
        self._filter_entry = entry
        entry.pack(side='left', fill='x', expand=True)
        entry.bind('<Return>', lambda _: self._filtre_uygula())
        self._protocol = tk.StringVar(value='Tümü')
        protocol = ttk.Combobox(filterbar, textvariable=self._protocol, width=9, state='readonly',
                                values=['Tümü', 'TCP', 'UDP', 'HTTP', 'DNS', 'ICMP', 'ARP', 'IPv6'])
        protocol.pack(side='left', padx=7)
        protocol.bind('<<ComboboxSelected>>', lambda _: self._filtre_uygula())
        self._button(filterbar, 'Uygula', self._filtre_uygula).pack(side='left')
        self._autoscroll = tk.BooleanVar(value=True)
        tk.Checkbutton(filterbar, text='Akışı izle', variable=self._autoscroll, bg=BG, fg=MUT,
                       selectcolor=SURF, activebackground=BG, highlightthickness=0).pack(side='left', padx=6)
        self._filter_status = tk.Label(left, text='Filtre: src=192.168.1. proto=TCP port=443  ·  Boş bırak: tüm paketler',
                                       bg=BG, fg=MUT, anchor='w', font=('DejaVu Sans', 8))
        self._filter_status.pack(fill='x', pady=(0, 8))

        vertical = tk.PanedWindow(left, orient='vertical', bg=BG, sashwidth=7, bd=0)
        vertical.pack(fill='both', expand=True)
        self._notebook = ttk.Notebook(vertical)
        vertical.add(self._notebook, stretch='always', minsize=180)
        packet_page = tk.Frame(self._notebook, bg=SURF)
        alert_page = tk.Frame(self._notebook, bg=SURF)
        log_page = tk.Frame(self._notebook, bg=SURF)
        self._notebook.add(packet_page, text='Paketler')
        self._notebook.add(alert_page, text='Alarmlar')
        self._notebook.add(log_page, text='Sistem günlüğü')
        self._packet_tree = self._table(packet_page, [
            ('id', 'No.', 55), ('ts', 'Zaman', 110), ('src', 'Kaynak', 140),
            ('dst', 'Hedef', 140), ('proto', 'Protokol', 75), ('mode', 'Mod', 80), ('length', 'Bayt', 55), ('info', 'Bilgi', 310)])
        for protocol_name, color in {'TCP': ACC, 'UDP': PRP, 'DNS': YLW, 'HTTP': GRN,
                                     'ICMP': '#f5ac77', 'ARP': '#91d0cb', 'IPv6': MUT}.items():
            self._packet_tree.tag_configure(protocol_name, foreground=color)
        self._packet_tree.bind('<<TreeviewSelect>>', self._packet_selected)
        self._build_alarm_tools(alert_page)
        self._alert_tree = self._table(alert_page, [
            ('ts', 'Zaman', 110), ('review', 'İnceleme', 90), ('severity', 'Önem', 70), ('tur', 'Tespit', 155),
            ('ip', 'Kaynak', 140), ('dst', 'Hedef', 140), ('detay', 'Ölçüm / eşik', 330)])
        self._alert_tree.tag_configure('Yüksek', foreground=YLW)
        self._alert_tree.tag_configure('Kritik', foreground=RED)
        self._alert_tree.bind('<<TreeviewSelect>>', self._alert_selected)
        self._log = scrolledtext.ScrolledText(log_page, bg=SURF, fg=MUT, relief='flat',
                                               font=('DejaVu Sans Mono', 9), state='disabled', highlightthickness=0)
        self._log.pack(fill='both', expand=True)
        for tag, color in [('HATA', RED), ('OK', GRN), ('BAN', YLW), ('SYS', MUT)]:
            self._log.tag_config(tag, foreground=color)

        inspector = tk.Frame(vertical, bg=SURF, padx=12, pady=10)
        vertical.add(inspector, stretch='never', minsize=165, height=190)
        tk.Label(inspector, text='PAKET / ALARM AYRINTILARI', bg=SURF, fg=ACC,
                 font=('DejaVu Sans', 9, 'bold')).pack(anchor='w', pady=(0, 7))
        self._details = scrolledtext.ScrolledText(inspector, bg=SURF, fg=TXT, relief='flat',
                                                  font=('DejaVu Sans Mono', 9), height=8, state='disabled', highlightthickness=0)
        self._details.pack(fill='both', expand=True)
        self._show_details('Bir paket veya alarm seçin.\nKaynak, hedef, protokol ve ham veri önizlemesi burada görünür.')

        tk.Label(right, text='TRAFİK · SON 90 ÖLÇÜM', bg=SURF, fg=MUT,
                 font=('DejaVu Sans', 9, 'bold')).pack(anchor='w')
        self._graph = tk.Canvas(right, bg=SURF, height=85, highlightthickness=0)
        self._graph.pack(fill='x', pady=(10, 15))
        self._graph.bind('<Configure>', lambda _: self._grafik_ciz())
        tk.Label(right, text='TESPİT DAĞILIMI', bg=SURF, fg=MUT,
                 font=('DejaVu Sans', 9, 'bold')).pack(anchor='w', pady=(0, 8))
        self._stat_lbls = {}
        for kind, color in TUR_RENK.items():
            row = tk.Frame(right, bg=SURF)
            row.pack(fill='x', pady=1)
            tk.Label(row, text=kind, bg=SURF, fg=color, font=('DejaVu Sans', 9)).pack(side='left')
            label = tk.Label(row, text='0', bg=SURF, fg=TXT, font=('DejaVu Sans Mono', 10))
            label.pack(side='right')
            self._stat_lbls[kind] = label
        tk.Frame(right, bg=BRD, height=1).pack(fill='x', pady=14)
        tk.Label(right, text='OTURUM BAN LİSTESİ', bg=SURF, fg=MUT,
                 font=('DejaVu Sans', 9, 'bold')).pack(anchor='w')
        self._ban_list = tk.Listbox(right, bg=CARD, fg=YLW, relief='flat', height=3, highlightthickness=0,
                                    selectbackground=BRD, font=('DejaVu Sans Mono', 9))
        self._ban_list.pack(fill='both', expand=True, pady=8)
        self._button(right, 'Manuel IP engelle', self._manuel_ban).pack(fill='x', pady=3)
        self._button(right, 'Seçili engeli kaldır', self._ban_kaldir).pack(fill='x', pady=3)
        tk.Label(right, text='Alarmlar eşik tabanlı şüphelerdir.\nOtomatik engelleme kapalı.', bg=SURF,
                 fg=MUT, justify='left', font=('DejaVu Sans', 8)).pack(anchor='w', pady=(10, 0))
        self._status = tk.Label(self.root, bg=BG, fg=MUT, anchor='w', padx=18, pady=10,
                                text='Hazır', font=('DejaVu Sans', 8))
        self._status.pack(side='bottom', fill='x', before=main)
        self._main, self._sidebar = main, sidebar
        self._vertical, self._inspector = vertical, inspector
        self._build_analysis_panels()

    def _kart(self, parent, label, value, color):
        frame = tk.Frame(parent, bg=SURF, padx=15, pady=11)
        frame.pack(side='left', fill='both', expand=True, padx=(0, 7))
        tk.Label(frame, text=label, fg=MUT, bg=SURF, font=('DejaVu Sans', 8)).pack(anchor='w')
        number = tk.Label(frame, text=value, fg=color, bg=SURF, font=('DejaVu Sans', 22, 'bold'))
        number.pack(anchor='w', pady=(4, 0))
        return number

    def _table(self, parent, columns):
        frame = tk.Frame(parent, bg=SURF)
        frame.pack(fill='both', expand=True)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show='headings', selectmode='browse')
        for key, title, width in columns:
            tree.heading(key, text=title, command=lambda column=key: self._sort_table(tree, column))
            tree.column(key, width=width, minwidth=45, stretch=key == columns[-1][0])
        ybar = ttk.Scrollbar(frame, orient='vertical', command=tree.yview)
        xbar = ttk.Scrollbar(frame, orient='horizontal', command=tree.xview)
        tree.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        tree.grid(row=0, column=0, sticky='nsew')
        ybar.grid(row=0, column=1, sticky='ns')
        xbar.grid(row=1, column=0, sticky='ew')
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return tree

    def _grafik_ciz(self):
        graph = self._graph
        graph.delete('all')
        width, height = max(graph.winfo_width(), 200), max(graph.winfo_height(), 60)
        data = list(self.trafik)
        peak = max(max(data), 1)
        graph.create_text(5, 5, text=f'{max(data):,} pkt/sn', fill=MUT, anchor='nw', font=('DejaVu Sans', 8))
        points = []
        for index, value in enumerate(data):
            points.extend((index * (width - 6) / max(len(data) - 1, 1) + 3,
                           height - 8 - value * (height - 30) / peak))
        if len(points) >= 4:
            graph.create_line(*points, fill=ACC, width=2)
        graph.create_line(0, height - 7, width, height - 7, fill=BRD)

    def _matches(self, packet):
        protocol = self._active_protocol
        return self._filter_match(packet) and (protocol == 'Tümü' or protocol in
                                               (packet['proto'], packet.get('transport'), packet.get('network')))

    def _insert_packet(self, key, packet):
        if self._matches(packet):
            fields = ('ui_id', 'ts', 'src', 'dst', 'proto', 'length', 'info')
            self._packet_tree.insert('', 'end', iid=key, values=[packet.get(f, '') for f in fields[:5]] + ['Simülasyon' if packet.get('simulated') else 'Canlı'] + [packet.get(f, '') for f in fields[5:]],
                                      tags=(packet['proto'],))

    def _filtre_uygula(self):
        try:
            predicate = compile_filter(self._filter_text.get())
        except ValueError as exc:
            self._filter_status.configure(text=str(exc), fg=RED)
            return
        self._filter_match = predicate
        self._active_protocol = self._protocol.get()
        children = self._packet_tree.get_children()
        if children:
            self._packet_tree.delete(*children)
        for key, packet in self._packets.items():
            self._insert_packet(key, packet)
        self._apply_table_order(self._packet_tree)
        self._filter_status.configure(text=f'{len(self._packet_tree.get_children())} / {len(self._packets)} paket eşleşiyor · Filtre yalnızca paket görünümünü etkiler', fg=GRN)

    def _show_details(self, text):
        self._details.configure(state='normal')
        self._details.delete('1.0', 'end')
        self._details.insert('end', text)
        self._details.configure(state='disabled')

    def _packet_selected(self, _=None):
        selection = self._packet_tree.selection()
        if not selection or selection[0] not in self._packets:
            return
        p = self._packets[selection[0]]
        raw = p.get('hex', '').split()
        lines = [' '.join(raw[n:n+16]) for n in range(0, len(raw), 16)]
        self._show_details(f"{p['proto']}  |  {p['src']}:{p.get('sport') or '—'} → {p['dst']}:{p.get('dport') or '—'}\n"
                           f"Zaman: {p['ts']}   Arayüz: {p.get('interface', '—')}   Uzunluk: {p['length']} B   Bayraklar: {p.get('flags', '—')}\n"
                           f"{p['info']}\n\nYük önizlemesi (en fazla 256 bayt):\n{p.get('payload', '')}\n\n"
                           'Ham paket (ilk 256 bayt):\n' + ('\n'.join(lines) or 'Simülasyonda ham paket yok.'))

    def _alert_selected(self, _=None):
        selection = self._alert_tree.selection()
        if not selection:
            return
        event = next((e for e in self.olaylar if str(e['id']) == selection[0]), None)
        if event:
            self._show_details(f"{event['tur']} · {event['severity']}\nKaynak: {event['ip']} → Hedef: {event.get('dst', '—')}\n"
                               f"{event['detay']}\n\nBu alarm bir hız/eşik sezgisidir; saldırı kanıtı değildir.\n"
                               'Normal yoğunluk, yeniden iletim ve ağ topolojisini inceleyin.\n'
                               f"Mod: {'Simülasyon' if event.get('simulated') else 'Canlı'}")

    def _thresholds(self):
        if self.motor and self.motor.status not in ('Durduruldu', 'Hata', 'Hazır'):
            messagebox.showinfo('Eşikler', 'Eşikleri değiştirmek için yakalamayı durdurun.', parent=self.root)
            return
        win = tk.Toplevel(self.root)
        win.title('Tespit eşikleri')
        win.configure(bg=SURF)
        win.transient(self.root)
        entries = {}
        for row, (key, label) in enumerate(THRESHOLD_LABELS.items()):
            tk.Label(win, text=label, bg=SURF, fg=TXT).grid(row=row, column=0, sticky='w', padx=16, pady=6)
            value = tk.StringVar(value=str(self.esik[key]))
            ttk.Entry(win, textvariable=value, width=12).grid(row=row, column=1, padx=16)
            entries[key] = value
        preset = tk.StringVar(value='Profil seç')
        presets = ttk.Combobox(win, textvariable=preset, state='readonly', values=['Hassas', 'Dengeli', 'Yoğun ağ'])
        presets.grid(row=len(entries), column=0, columnspan=2, pady=8)
        def apply_profile(_):
            from netshield.config import ESIKLER
            factor = {'Hassas': 0.5, 'Dengeli': 1, 'Yoğun ağ': 4}[preset.get()]
            for key, value in entries.items():
                value.set(str(max(1, int(ESIKLER[key] * factor)) if key.endswith('_per_sec') else ESIKLER[key]))
        presets.bind('<<ComboboxSelected>>', apply_profile)
        def save():
            try:
                values = {key: int(value.get()) for key, value in entries.items()}
                if any(not 1 <= value <= 1000000 for value in values.values()):
                    raise ValueError()
                if values['port_scan'] > 1024 or values['target_sources'] > 1024:
                    raise ValueError()
            except ValueError:
                messagebox.showerror('Geçersiz eşik', 'Pozitif tam sayı girin (en çok 1.000.000).\nPort ve kaynak sayısı en çok 1024 olabilir.', parent=win)
                return
            if not self._commit_preferences(thresholds=values):
                return
            self.esik.update(values)
            self._syslog('SİSTEM', 'Eşikler güncellendi; bir sonraki yakalamada uygulanacak.')
            win.destroy()
        self._button(win, 'Kaydet', save, True).grid(row=len(entries)+1, column=0, columnspan=2, pady=14)

    def _export(self):
        path = filedialog.asksaveasfilename(parent=self.root, title='Oturumu dışa aktar',
                                           defaultextension='.json', filetypes=[('JSON', '*.json')])
        if not path:
            return
        data = dict(schema_version=1, thresholds=self.esik, total_packets=self._packet_total,
                    preview_dropped=self._preview_dropped_total + self.motor.preview_dropped,
                    packets=list(self._packets.values()), alerts=self.olaylar)
        try:
            with open(path, 'w', encoding='utf-8') as output:
                json.dump(data, output, ensure_ascii=False, indent=2)
        except OSError as exc:
            messagebox.showerror('Dışa aktarma hatası', str(exc), parent=self.root)
            return
        self._syslog('SİSTEM', f'JSON kaydedildi: {path}')
