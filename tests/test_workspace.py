import json
import os
import tempfile
import time
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import patch

import ids
from netshield.core.motor import Motor
from netshield.config import ESIKLER



@unittest.skipUnless(os.environ.get('DISPLAY'), 'A display is required for Tk integration tests')
class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.settings_dir = tempfile.TemporaryDirectory()
        self.app = ids.App(self.root, autostart=False, settings_path=Path(self.settings_dir.name) / 'settings.json')
        self.app.motor = Motor(self.app.q, ESIKLER, simulation=True)
        self.errors = []
        self.root.report_callback_exception = lambda *args: self.errors.append(args)

    def tearDown(self):
        self.app.kapat()
        self.settings_dir.cleanup()
        self.assertEqual(self.errors, [])

    def wait_agent_refresh(self):
        deadline = time.monotonic() + 3
        while self.app._agent_request_id is not None or self.app._agent_refresh_pending:
            self.root.update()
            if time.monotonic() > deadline:
                self.fail('Status reader did not finish')
            time.sleep(.005)

    def test_firewall_refresh_keeps_gui_responsive_and_restores_system_rules(self):
        import threading
        entered, release = threading.Event(), threading.Event()
        def snapshot():
            entered.set()
            if not release.wait(3):
                raise TimeoutError('test worker stalled')
            return {'192.0.2.1': [['saved kernel rule']]}
        with patch.object(ids, 'is_root', return_value=True), patch.object(self.app._firewall, 'snapshot', side_effect=snapshot):
            try:
                self.app._refresh_firewall()
                self.assertTrue(entered.wait(1))
                ticks = []
                self.root.after(0, lambda: ticks.append(True))
                self.root.update()
                self.assertEqual(ticks, [True])
                release.set()
                deadline = time.monotonic() + 3
                while self.app._firewall_future is not None:
                    self.root.update()
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(.005)
                self.assertIn('192.0.2.1', self.app._ban_list.get(0))
            finally:
                release.set()

    def test_packet_selection_filter_alarm_and_export(self):
        a = self.app
        packet = dict(ts='12:00:00', src='192.168.1.20', dst='192.168.1.10',
                      sport=50000, dport=80, transport='TCP', proto='HTTP', length=90,
                      info='GET / HTTP/1.1', payload='GET /', hex='47 45 54',
                      flags='PA', simulated=True)
        a._on_packet(packet)
        a._packet_tree.selection_set('1')
        a._packet_selected()
        self.assertIn('192.168.1.20', a._details.get('1.0', 'end'))
        a._filter_text.set('port=443')
        a._filtre_uygula()
        self.assertEqual(a._packet_tree.get_children(), ())
        a._filter_text.set('port=80 proto=TCP')
        a._filtre_uygula()
        self.assertEqual(a._packet_tree.get_children(), ('1',))
        a._protocol.set('UDP')
        a._filter_text.set('port=invalid')
        a._filtre_uygula()
        self.assertEqual(a._packet_tree.get_children(), ('1',))
        self.assertEqual(a._active_protocol, 'Tümü')
        event = dict(ts='12:00:00', ip='192.168.1.20', dst='192.168.1.10',
                     tip='FLOOD', tur='SYN', detay='150 / 1 sn', severity='Yüksek', simulated=True)
        a._on_olay(event)
        a._alert_tree.selection_set('1')
        a._alert_selected()
        self.assertIn('150 / 1 sn', a._details.get('1.0', 'end'))
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / 'session.json')
            with patch('netshield.ui.workspace.filedialog.asksaveasfilename', return_value=path):
                a._export()
            data = json.loads(Path(path).read_text())
            self.assertEqual(len(data['packets']), 1)
            self.assertEqual(data['alerts'][0]['tur'], 'SYN')
        with patch.object(ids.messagebox, 'askyesno', return_value=True):
            a._sifirla()
        self.assertEqual(a._packet_tree.get_children(), ())
        self.assertEqual(a._alert_tree.get_children(), ())
        self.assertEqual(a.olaylar, [])

    def test_tracking_watchlist_and_bidirectional_follow(self):
        a = self.app
        p = dict(ts='12:00:00', src='192.168.1.10', dst='192.168.1.20',
                 sport=50000, dport=443, transport='TCP', proto='TCP', length=60, info='test')
        a._on_packet(dict(p))
        a._on_packet(dict(p, src=p['dst'], dst=p['src'], sport=443, dport=50000))
        a._on_packet(dict(p, sport=443, dport=50000))
        a._watch_ip('192.168.1.99')
        a._notebook.select(a._tracking_page)
        a._refresh_tracking()
        self.assertEqual(len(a._host_tree.get_children()), 3)
        self.assertEqual(a._watch_tree.get_children(), ('192.168.1.99',))
        self.assertEqual(len(a._flow_tree.get_children()), 2)
        key = next(key for key, flow in a._flow_rows.items() if flow['packets'] == 2)
        a._flow_tree.selection_set(key)
        a._follow_flow()
        self.assertEqual(a._packet_tree.get_children(), ('1', '2'))
        self.assertIn('192.168.1.99', json.loads(Path(a.settings_path).read_text())['watchlist'])

    def test_employee_inventory_persistence_filter_and_removal(self):
        a = self.app
        a._notebook.select(a._tracking_page)
        a._tracking_tabs.select(3)
        device = dict(id='employee1', name='Test Yazılımcı', department='Yazılım', ip='192.0.2.10', interface='lan1')
        self.assertTrue(a._save_device(device))
        self.assertEqual(a._device_tree.set('employee1', 'status'), 'Gözlenmedi')
        packet = dict(ts='12:00:00', src=device['ip'], dst='192.0.2.20', proto='TCP',
                      length=60, info='', interface='lan1', simulated=False)
        for changes in ({}, {'simulated': True}, {'interface': 'lan2'}):
            a._on_packet(dict(packet, **changes))
        a._tracking_scope.set('Canlı')
        a._change_tracking_scope()
        self.assertEqual(a._device_tree.set('employee1', 'sent'), '60')
        a._device_tree.selection_set('employee1')
        a._device_details()
        self.assertIn('Test Yazılımcı', a._device_detail.get('1.0', 'end'))
        a._follow_tracking()
        self.assertEqual(a._packet_tree.get_children(), ('1',))
        a._notebook.select(a._tracking_page)
        a._tracking_iface.set('lan2')
        a._change_tracking_scope()
        self.assertEqual(a._device_tree.set('employee1', 'status'), 'Gözlenmedi')
        a._follow_device()
        self.assertEqual(a._packet_tree.get_children(), ())
        a._notebook.select(a._tracking_page)
        a._device_search.set('bulunamayan')
        self.assertEqual(a._device_tree.get_children(), ())
        a._device_search.set('Yazılım')
        self.assertEqual(a._device_tree.get_children(), ('employee1',))
        a._device_tree.selection_set('employee1')
        self.assertEqual(json.loads(Path(a.settings_path).read_text())['devices'], [device])
        with patch('netshield.ui.inventory.messagebox.askyesno', return_value=True):
            a._remove_device()
        self.assertEqual(a.preferences['devices'], [])
        self.assertEqual(a._device_tree.get_children(), ())

    def test_saving_reveals_device_despite_search_and_inactive_tracking_page(self):
        a = self.app
        a._device_search.set('does-not-match')
        a._notebook.select(0)
        device = dict(id='new-device', name='New PC', department='Dev', ip='192.0.2.99', interface='')
        self.assertTrue(a._save_device(device))
        self.assertEqual(a._device_search.get(), '')
        self.assertEqual(a._notebook.select(), str(a._tracking_page))
        self.assertEqual(a._tracking_tabs.select(), str(a._inventory_page))
        self.assertEqual(a._device_tree.selection(), ('new-device',))
        self.assertEqual(a._agent_tree.selection(), ('new-device',))
        self.assertEqual(a._agent_tree.set('new-device', 'state'), 'Ajan verisi yok')
        self.assertIn('New PC', a._device_detail.get('1.0', 'end'))
        a._tracking_tabs.select(a._agent_page)
        self.assertTrue(a._save_device(dict(device, name='Updated PC')))
        self.assertEqual(a._tracking_tabs.select(), str(a._agent_page))
        self.assertEqual(a._agent_tree.set('new-device', 'name'), 'Updated PC')
        with patch('netshield.ui.inventory.messagebox.askyesno', return_value=True):
            a._remove_device()
        self.assertEqual(a._agent_tree.get_children(), ())

    def test_add_device_dialog_from_windows_tab_reveals_saved_record(self):
        from tkinter import ttk
        a = self.app
        a._notebook.select(a._tracking_page)
        a._tracking_tabs.select(a._agent_page)
        a._device_search.set('old-filter')
        a._edit_device()
        dialog = next(child for child in self.root.winfo_children() if isinstance(child, tk.Toplevel))
        entries = [child for child in dialog.winfo_children() if type(child) is ttk.Entry]
        for entry, value in zip(entries, ('Test PC', 'Yazılım', '192.0.2.55')):
            entry.insert(0, value)
        next(child for child in dialog.winfo_children() if isinstance(child, tk.Button) and child.cget('text') == 'Kaydet').invoke()
        self.root.update()
        self.assertFalse(dialog.winfo_exists())
        identity = a.preferences['devices'][0]['id']
        self.assertEqual(a._tracking_tabs.select(), str(a._agent_page))
        self.assertEqual(a._agent_tree.selection(), (identity,))
        self.assertEqual(a._agent_tree.set(identity, 'name'), 'Test PC')
        self.assertEqual(a._device_tree.selection(), (identity,))

    def test_failed_device_save_preserves_filters_and_existing_rows(self):
        a = self.app
        a._device_search.set('keep-this-search')
        device = dict(id='failed', name='PC', department='Dev', ip='192.0.2.99', interface='')
        with patch('netshield.ui.panels.save_settings', side_effect=OSError('disk full')), \
                patch('netshield.ui.panels.messagebox.showerror'):
            self.assertFalse(a._save_device(device))
        self.assertEqual(a._device_search.get(), 'keep-this-search')
        self.assertEqual(a.preferences['devices'], [])
        self.assertFalse(a._agent_tree.exists('failed'))

    def test_windows_status_panel_uses_device_identity_and_ignores_packet_filters(self):
        import time
        a = self.app
        device = dict(id='windows1', name='Test Windows', department='Yazılım', ip='192.0.2.10', interface='lan1')
        self.assertTrue(a._save_device(device))
        a._tracking_scope.set('Simülasyon')
        record = dict(received_at=time.time(), boot_time='2026-09-17T08:00:00+00:00', session='locked',
                      events=[dict(id='a' * 32, kind='session_lock', time='2026-09-17T09:00:00+00:00')])
        path = Path(a.settings_path).parent / 'agent-status.json'
        path.write_text(json.dumps({'windows1': record}))
        a._refresh_agent_panel()
        self.wait_agent_refresh()
        self.assertEqual(a._agent_tree.set('windows1', 'state'), 'Bağlı · kilitli')
        a._agent_tree.selection_set('windows1')
        a._show_agent_details()
        self.assertIn('Cihaz kimliği: windows1', a._agent_details.get('1.0', 'end'))
        self.assertIn('Oturum kilitlendi', a._agent_details.get('1.0', 'end'))
        self.assertIn('oturum bağlamı kaydedilmemiş', a._agent_details.get('1.0', 'end'))
        record['session_id'] = 7
        record['events'][0].update(session_id=2, boot_time='2026-09-16T08:00:00+00:00')
        path.write_text(json.dumps({'windows1': record}))
        a._refresh_agent_panel()
        self.wait_agent_refresh()
        self.assertEqual(a._agent_tree.set('windows1', 'state'), 'Bağlı · kilitli · oturum #7')
        detail = a._agent_details.get('1.0', 'end')
        self.assertIn('Son bildiren Windows oturumu: #7', detail)
        self.assertIn('gözlemci oturum #2 · açılış 2026-09-16', detail)
        record['received_at'] -= 100
        path.write_text(json.dumps({'windows1': record}))
        a._refresh_agent_panel()
        self.wait_agent_refresh()
        self.assertIn('kapanış bilinmiyor', a._agent_tree.set('windows1', 'state'))
        path.write_text('{corrupt')
        a._refresh_agent_panel()
        self.wait_agent_refresh()
        self.assertEqual(a._agent_tree.set('windows1', 'state'), 'Veri okunamadı')
        self.assertIn('okunamadı', a._agent_notice.cget('text'))

    def test_gui_callbacks_continue_during_slow_status_read(self):
        import threading
        a = self.app
        self.root.update()
        self.wait_agent_refresh()
        release, entered = threading.Event(), threading.Event()
        a._agent_reader.cached = None
        def loader(_):
            entered.set()
            release.wait(2)
            return {}, None
        try:
            with patch.object(a._agent_reader, 'loader', side_effect=loader):
                a._refresh_agent_panel()
                self.assertTrue(entered.wait(1))
                marker = []
                self.root.after(0, lambda: marker.append('responsive'))
                self.root.update()
                self.assertEqual(marker, ['responsive'])
                self.assertIsNotNone(a._agent_request_id)
                release.set()
                self.wait_agent_refresh()
        finally:
            release.set()

    def test_pairing_wizard_without_ip_creates_config_checks_status_and_revokes(self):
        from netshield.core.enrollment import read_credentials
        a = self.app
        device = dict(id='pairing-device', name='Windows PC', department='Dev', ip='', interface='')
        self.assertTrue(a._save_device(device))
        a._tracking_tabs.select(a._agent_page)
        a._agent_tree.selection_set(device['id'])
        dialog = a._pair_device()
        self.assertIsNotNone(dialog)
        def wait():
            deadline = time.monotonic() + 3
            while dialog.future is not None:
                self.root.update()
                if time.monotonic() > deadline:
                    self.fail('Pairing job did not finish')
                time.sleep(.005)
        dialog.server.set('http://not-secure')
        dialog.generate_button.invoke()
        self.assertIn('HTTPS', dialog.status.get())
        output = Path(a.settings_path).parent / 'client.json'
        dialog.server.set('https://netshield.example:8443')
        with patch('netshield.ui.pairing.filedialog.asksaveasfilename', return_value=str(output)):
            dialog.generate_button.invoke()
            wait()
        config = json.loads(output.read_text())
        self.assertEqual(config['device_id'], device['id'])
        self.assertNotIn(config['token'], dialog.status.get())
        dialog.check_button.invoke()
        wait()
        self.assertIn('bekleniyor', dialog.status.get())
        record = dict(received_at=time.time(), boot_time='2026-09-18T08:00:00+00:00', session='locked', events=[])
        (output.parent / 'agent-status.json').write_text(json.dumps({device['id']: record}))
        dialog.check_button.invoke()
        wait()
        self.assertIn('Bağlı · kilitli', dialog.status.get())
        dialog.revoke_button.invoke()
        wait()
        self.assertNotIn(device['id'], read_credentials(output.parent / 'agent-credentials.json'))
        self.assertIn('iptal edildi', dialog.status.get())
        dialog.win.destroy()

    def test_agent_selection_edits_the_visible_device_and_empty_ip_does_not_clear_filter(self):
        a = self.app
        first = dict(id='pc-a', name='A', department='Dev', ip='', interface='')
        second = dict(first, id='pc-b', name='B')
        self.assertTrue(a._save_device(first))
        self.assertTrue(a._save_device(second))
        a._tracking_tabs.select(a._agent_page)
        a._agent_tree.selection_set('pc-a')
        self.assertEqual(a._selected_device()['id'], 'pc-a')
        a._filter_text.set('port=443')
        a._follow_device()
        self.assertEqual(a._filter_text.get(), 'port=443')

    def test_multiple_interface_selection_and_status_view(self):
        a = self.app
        with patch('netshield.core.motor.get_if_list', return_value=['lan1', 'lan2']):
            a._choose_interfaces()
            dialog = next(child for child in self.root.winfo_children() if isinstance(child, tk.Toplevel))
            checks = [child for child in dialog.winfo_children() if isinstance(child, tk.Checkbutton)]
            for check in checks:
                check.select()
            save = next(child for child in dialog.winfo_children() if isinstance(child, tk.Button))
            save.invoke()
        self.assertEqual(a._selected_interfaces, ['lan1', 'lan2'])
        a.motor._interface_status('lan1', 'Canlı')
        a.motor._interface_status('lan2', 'Hata')
        a._refresh_interface_status()
        self.assertEqual(a._interfaces_tree.set('lan2', 'status'), 'Hata')
        a._interfaces_tree.selection_set('lan1')
        a._follow_interface()
        self.assertEqual(a._filter_text.get(), 'iface=lan1')

    def test_security_center_disables_exports_and_clipboard_in_enterprise_mode(self):
        from tkinter import ttk
        a = self.app
        a._security_center()
        dialog = next(child for child in self.root.winfo_children() if isinstance(child, tk.Toplevel))
        profile = next(child for child in dialog.winfo_children() if isinstance(child, ttk.Combobox))
        profile.set('Kurumsal')
        save = next(child for child in dialog.winfo_children() if isinstance(child, tk.Button) and child.cget('text') == 'Politikayı kaydet')
        save.invoke()
        self.assertEqual(a.preferences['security']['profile'], 'Kurumsal')
        with patch('netshield.ui.workspace.filedialog.asksaveasfilename') as choose, \
                patch.object(a.root, 'clipboard_append') as clipboard:
            a._export()
            a._copy_selected_packet()
            choose.assert_not_called()
            clipboard.assert_not_called()
        self.assertFalse(json.loads(Path(a.settings_path).read_text())['security']['allow_exports'])

    def test_tracking_can_exclude_demo_records(self):
        a = self.app
        packet = dict(ts='12:00:00', src='192.0.2.1', dst='192.0.2.2', sport=1000,
                      dport=80, transport='TCP', proto='TCP', length=60, info='test')
        a._on_packet(dict(packet, simulated=True))
        a._on_packet(dict(packet, src='192.0.2.3', simulated=False))
        a._notebook.select(a._tracking_page)
        a._tracking_scope.set('Canlı')
        a._change_tracking_scope()
        self.assertNotIn('192.0.2.1', a._host_tree.get_children())
        self.assertIn('192.0.2.3', a._host_tree.get_children())
        self.assertEqual(a._packet_tree.set('1', 'mode'), 'Simülasyon')
        self.assertEqual(a._packet_tree.set('2', 'mode'), 'Canlı')
        a._host_tree.selection_set('192.0.2.3')
        a._follow_host(a._host_tree)
        self.assertEqual(a._packet_tree.get_children(), ('2',))
        self.assertIn('mode=live', a._filter_text.get())

    def test_alarm_review_filters_and_hidden_record_eviction(self):
        a = self.app
        event = dict(ts='12:00:00', ip='192.0.2.1', dst='192.0.2.2', tip='FLOOD',
                     tur='SYN', severity='Yüksek', detay='test')
        a._on_olay(event)
        a._alert_tree.selection_set('1')
        a._toggle_review()
        self.assertTrue(a.olaylar[0]['reviewed'])
        a._alarm_review.set('Yeni')
        a._refresh_alerts()
        self.assertEqual(a._alert_tree.get_children(), ())
        with patch.object(ids, 'ALERT_HISTORY', 2):
            a._on_olay(event)
            a._on_olay(event)
        self.assertEqual(a._alert_tree.get_children(), ('2', '3'))
        a._alarm_level.set('Kritik')
        a._refresh_alerts()
        self.assertEqual(a._alert_tree.get_children(), ())

    def test_numeric_sort_persists_and_panels_can_be_hidden(self):
        a = self.app
        p = dict(ts='12:00:00', src='192.0.2.1', dst='192.0.2.2', transport='UDP', proto='UDP', info='test')
        for length in (9, 100, 2):
            a._on_packet(dict(p, length=length))
        a._sort_table(a._packet_tree, 'length')
        self.assertEqual(a._packet_tree.get_children(), ('2', '1', '3'))
        self.assertFalse(a._autoscroll.get())
        a._on_packet(dict(p, length=200))
        a._resort_tables()
        self.assertEqual(a._packet_tree.get_children()[0], '4')
        a._sidebar_visible.set(False)
        a._toggle_sidebar()
        self.assertNotIn(str(a._sidebar), tuple(map(str, a._main.panes())))
        a._sidebar_visible.set(True)
        a._toggle_sidebar()
        self.assertIn(str(a._sidebar), tuple(map(str, a._main.panes())))
        before = dict(a.preferences)
        with patch('netshield.ui.panels.save_settings', side_effect=OSError('read-only')), \
                patch('netshield.ui.panels.messagebox.showerror'):
            self.assertFalse(a._commit_preferences(density='Kompakt'))
        self.assertEqual(a.preferences, before)

    def test_threshold_profile_is_saved_and_applied_next_start(self):
        from tkinter import ttk
        a = self.app
        a._thresholds()
        dialog = next(child for child in self.root.winfo_children() if isinstance(child, tk.Toplevel))
        combo = next(child for child in dialog.winfo_children() if isinstance(child, ttk.Combobox))
        combo.set('Yoğun ağ')
        combo.event_generate('<<ComboboxSelected>>')
        self.root.update()
        save = next(child for child in dialog.winfo_children() if isinstance(child, tk.Button) and child.cget('text') == 'Kaydet')
        save.invoke()
        self.assertEqual(a.esik['syn_per_sec'], ESIKLER['syn_per_sec'] * 4)
        stored = json.loads(Path(a.settings_path).read_text())
        self.assertEqual(stored['thresholds']['syn_per_sec'], a.esik['syn_per_sec'])
        self.assertEqual(a.motor.esik['syn_per_sec'], ESIKLER['syn_per_sec'])

    def test_status_and_controls_fit_supported_window_sizes(self):
        self.root.deiconify()
        for geometry in ('1440x920', '1200x820'):
            self.root.geometry(geometry)
            self.root.update()
            status = self.app._status
            self.assertLessEqual(status.winfo_y() + status.winfo_height(), self.root.winfo_height())
            self.assertGreater(self.app._packet_tree.winfo_height(), 100)
            self.assertTrue(self.app._ban_list.winfo_ismapped())

    def test_demo_pause_restart_and_poll(self):
        a = self.app
        a._mode.set('Simülasyon')
        a._motor_baslat()
        first = a.motor
        a._toggle_capture()
        self.assertEqual(first.status, 'Durduruldu')
        self.assertTrue(all(not thread.is_alive() for thread in first._threads))
        a._toggle_capture()
        self.assertIsNot(a.motor, first)
        a._poll()
        self.root.update()
        self.assertEqual(a.motor.status, 'Simülasyon')


if __name__ == '__main__':
    unittest.main()
