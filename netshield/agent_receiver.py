"""Opt-in HTTPS receiver. Run separately from the packet capture application."""
import argparse
import hashlib
import hmac
import json
import secrets
import ssl
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from netshield.core.agent_status import validate_status, read_snapshot
from netshield.core.security import private_write
from netshield.core.settings import default_path, load_settings


def digest(token):
    return hashlib.sha256(token.encode('ascii')).hexdigest()


def read_credentials(path):
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict) or len(data) > 500:
        raise ValueError('Invalid credentials')
    return data


class Receiver:
    def __init__(self, settings_path):
        self.settings_path = Path(settings_path)
        self.credentials_path = self.settings_path.parent / 'agent-credentials.json'
        self.status_path = self.settings_path.parent / 'agent-status.json'
        self.records, error = read_snapshot(self.settings_path)
        if error:
            raise ValueError(error)
        self.last_write = {}

    def accept(self, identity, token, payload):
        settings, error = load_settings(self.settings_path)
        if error or identity not in {d['id'] for d in settings['devices']}:
            raise PermissionError()
        expected = read_credentials(self.credentials_path).get(identity)
        if not isinstance(expected, str) or not hmac.compare_digest(expected, digest(token)):
            raise PermissionError()
        data = validate_status(payload)
        now = time.monotonic()
        if now - self.last_write.get(identity, -100) < 2:
            return False
        previous = self.records.get(identity, {}).get('events', [])
        merged = {e['id']: e for e in previous}
        merged.update({e['id']: e for e in data['events']})
        record = dict(data, events=list(merged.values())[-100:], received_at=time.time())
        valid = {d['id'] for d in settings['devices']}
        records = {k: v for k, v in self.records.items() if k in valid}
        records[identity] = record
        private_write(self.status_path, json.dumps(records, ensure_ascii=False))
        self.records = records
        self.last_write[identity] = now
        return True


def handler_for(receiver):
    class Handler(BaseHTTPRequestHandler):
        # No request paths, identities, credentials or events in access logs.
        def log_message(self, *_):
            pass

        def setup(self):
            self.request.settimeout(5)
            super().setup()

        def do_POST(self):
            code = 400
            try:
                if not self.path.startswith('/v1/status/') or self.headers.get('Transfer-Encoding'):
                    raise ValueError()
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 32768:
                    raise ValueError()
                auth = self.headers.get('Authorization', '')
                if not auth.startswith('Bearer ') or len(auth) > 256:
                    raise PermissionError()
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError()
                accepted = receiver.accept(self.path[len('/v1/status/'):], auth[7:], json.loads(raw))
                code = 204 if accepted else 429
            except PermissionError:
                code = 403
            except (ValueError, TypeError, KeyError, UnicodeError):
                code = 400
            except OSError:
                code = 503
            self.send_response(code)
            self.send_header('Content-Length', '0')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
    return Handler


class TLSServer(HTTPServer):
    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(5)
        try:
            return self.tls.wrap_socket(sock, server_side=True), address
        except (OSError, ssl.SSLError):
            sock.close()
            raise


def main():
    parser = argparse.ArgumentParser(description='NetShield Windows agent enrollment / HTTPS receiver')
    parser.add_argument('--settings', type=Path, default=default_path())
    commands = parser.add_subparsers(dest='command', required=True)
    enroll = commands.add_parser('enroll')
    enroll.add_argument('--device-id', required=True)
    enroll.add_argument('--server', required=True, help='https://netshield.company:8443')
    enroll.add_argument('--output', type=Path, required=True)
    revoke = commands.add_parser('revoke')
    revoke.add_argument('--device-id', required=True)
    serve = commands.add_parser('serve')
    serve.add_argument('--bind', default='127.0.0.1')
    serve.add_argument('--port', type=int, default=8443)
    serve.add_argument('--cert', required=True)
    serve.add_argument('--key', required=True)
    args = parser.parse_args()
    path = args.settings.parent / 'agent-credentials.json'
    if args.command in ('enroll', 'revoke'):
        credentials = read_credentials(path)
        if args.command == 'revoke':
            credentials.pop(args.device_id, None)
        else:
            settings, error = load_settings(args.settings)
            if error or args.device_id not in {d['id'] for d in settings['devices']}:
                parser.error('Device ID must exist in the local inventory')
            url = urlsplit(args.server)
            if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
                parser.error('Server must be an HTTPS origin without credentials, path or query')
            if args.output.exists() or args.output.is_symlink():
                parser.error('Output already exists; choose a new private file')
            token = secrets.token_urlsafe(32)
            private_write(args.output, json.dumps(dict(server=args.server.rstrip('/'), device_id=args.device_id, token=token)))
            credentials[args.device_id] = digest(token)
        private_write(path, json.dumps(credentials))
        print('Enrollment updated. Protect the agent configuration; never commit it.')
        return
    receiver = Receiver(args.settings)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(args.cert, args.key)
    with TLSServer((args.bind, args.port), handler_for(receiver)) as server:
        server.tls = tls
        print(f'NetShield HTTPS receiver: {args.bind}:{args.port}; Ctrl+C to stop')
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
