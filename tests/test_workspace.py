import json
import os
import tempfile
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
        self.assertEqual(a._agent_tree.set('windows1', 'state'), 'Bağlı · kilitli')
        a._agent_tree.selection_set('windows1')
        a._show_agent_details()
        self.assertIn('Cihaz kimliği: windows1', a._agent_details.get('1.0', 'end'))
        self.assertIn('Oturum kilitlendi', a._agent_details.get('1.0', 'end'))
        record['received_at'] -= 100
        path.write_text(json.dumps({'windows1': record}))
        a._refresh_agent_panel()
        self.assertIn('kapanış bilinmiyor', a._agent_tree.set('windows1', 'state'))
        path.write_text('{corrupt')
        a._refresh_agent_panel()
        self.assertEqual(a._agent_tree.set('windows1', 'state'), 'Ajan verisi yok')
        self.assertIn('okunamadı', a._agent_notice.cget('text'))

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
