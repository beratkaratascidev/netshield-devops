"""Bounded, short-lived HTTP/1 request-line fragments, never exported or persisted.
This is not a general TCP/HTTP decoder: gaps and oversized lines are discarded.
"""
from collections import OrderedDict
import re

HTTP_LINE = re.compile(rb'^(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) [^ \r\n]+ HTTP/1\.[01]\r\n')
METHODS = tuple(word + b' ' for word in (b'GET', b'HEAD', b'POST', b'PUT', b'DELETE', b'CONNECT', b'OPTIONS', b'TRACE', b'PATCH'))


class HTTPPrefixes:
    def __init__(self, capacity=1024, timeout=2, limit=512):
        self.pending = OrderedDict()
        self.capacity, self.timeout, self.limit = capacity, timeout, limit

    def expire(self, now):
        while self.pending and now - next(iter(self.pending.values()))[2] >= self.timeout:
            self.pending.popitem(last=False)

    def feed(self, key, sequence, payload, now, reset=False):
        self.expire(now)
        if reset:
            self.pending.pop(key, None)
        if not payload:
            return False
        payload = payload[:self.limit]
        prior = self.pending.pop(key, None)
        if prior:
            expected, prefix, _ = prior
            overlap = (expected - sequence) & 0xffffffff
            if overlap > len(payload):
                # A gap or an unrelated segment: don't invent missing bytes.
                prefix = b''
            else:
                if overlap == len(payload):
                    self.pending[key] = (expected, prefix, now)
                    return False
                payload = payload[overlap:]
                sequence = expected
        else:
            prefix = b''
        combined = (prefix + payload)[:self.limit]
        if HTTP_LINE.match(combined):
            return True
        if b'\r\n' in combined or len(combined) >= self.limit:
            return False
        if not any(method.startswith(combined) or combined.startswith(method) for method in METHODS):
            return False
        if len(self.pending) >= self.capacity:
            self.pending.popitem(last=False)
        self.pending[key] = ((sequence + len(payload)) & 0xffffffff, combined, now)
        return False
