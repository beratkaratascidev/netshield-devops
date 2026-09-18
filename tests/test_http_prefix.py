import unittest
from netshield.core.http_prefix import HTTPPrefixes


class PrefixTests(unittest.TestCase):
    def test_split_request_retransmission_overlap_and_sequence_wrap(self):
        for start in (100, 0xfffffffc):
            with self.subTest(start=start):
                tracker = HTTPPrefixes()
                self.assertFalse(tracker.feed('flow', start, b'GET / HT', 0))
                self.assertFalse(tracker.feed('flow', start, b'GET / HT', .1))
                self.assertTrue(tracker.feed('flow', (start + 6) & 0xffffffff, b'HTTP/1.1\r\n', .2))
                self.assertEqual(len(tracker.pending), 0)

    def test_gap_expiration_reset_and_other_interface_do_not_join(self):
        for key, sequence, now, reset in [('other', 8, .1, False), ('flow', 10, .1, False),
                                          ('flow', 8, 3, False), ('flow', 8, .1, True)]:
            tracker = HTTPPrefixes()
            tracker.feed('flow', 0, b'GET / HT', 0)
            self.assertFalse(tracker.feed(key, sequence, b'TP/1.1\r\n', now, reset))

    def test_storage_limits_and_non_http(self):
        tracker = HTTPPrefixes(capacity=2)
        for key in range(5):
            tracker.feed(key, 0, b'GET / HT', 0)
        self.assertEqual(len(tracker.pending), 2)
        self.assertFalse(tracker.feed('long', 0, b'GET /' + b'x' * 600, 0))
        self.assertFalse(tracker.feed('tls', 0, b'\x16\x03\x03', 0))
        self.assertEqual(len(tracker.pending), 2)
