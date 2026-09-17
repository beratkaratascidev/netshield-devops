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
        self.app = ids.App(self.root, autostart=False)
        self.app.motor = Motor(self.app.q, ESIKLER, simulation=True)
        self.errors = []
        self.root.report_callback_exception = lambda *args: self.errors.append(args)

    def tearDown(self):
        self.app.kapat()
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
