"""Opt-in HTTPS receiver. Run separately from the packet capture application."""
import argparse
import asyncio
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
import hmac
import json
import ssl
import time
from pathlib import Path

from netshield.core.agent_status import validate_status
from netshield.core.agent_store import AgentStore
from netshield.core.enrollment import digest, read_credentials, enroll, revoke, credential_matches, activate_pending
from netshield.core.settings import default_path, load_settings


class ConfigurationError(RuntimeError):
    """Server-owned authorization files cannot be read or validated."""


class Receiver:
    def __init__(self, settings_path, retention_days=30):
        self.settings_path = Path(settings_path)
        self.credentials_path = self.settings_path.parent / 'agent-credentials.json'
        self.store = AgentStore(self.settings_path, retention_days)
        self.status_path = self.store.path
        self.last_write = {}
        self._lock = threading.RLock()
        self._authorization_cache = {}

    def _cached_file(self, path, loader):
        # Atomic replacement, permission changes and in-place edits all invalidate the cache.
        def fingerprint():
            st = path.stat()
            return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_uid)
        for _ in range(3):
            before = fingerprint()
            cached = self._authorization_cache.get(path)
            if cached and cached[0] == before:
                return cached[1]
            try:
                value = loader()
            except (OSError, ValueError, TypeError) as exc:
                raise ConfigurationError('Yetkilendirme yapılandırması okunamadı.') from exc
            if fingerprint() == before:
                self._authorization_cache[path] = (before, value)
                return value
        raise OSError('Ayar dosyası sürekli değişiyor; bildirim daha sonra denenecek.')

    def _valid_ids(self):
        def load():
            settings, error = load_settings(self.settings_path)
            if error:
                raise ValueError(error)
            return {d['id'] for d in settings['devices']}
        return self._cached_file(self.settings_path, load)

    def authorize(self, identity, token):
        with self._lock:
            valid = self._valid_ids()
            if identity not in valid:
                raise PermissionError()
            credentials = self._cached_file(self.credentials_path, lambda: read_credentials(self.credentials_path))
            expected = credentials.get(identity)
            if not credential_matches(expected, token):
                raise PermissionError()
            return valid

    def accept(self, identity, token, payload):
        with self._lock:
            valid = self.authorize(identity, token)
            data = validate_status(payload)
            now = time.monotonic()
            if now - self.last_write.get(identity, -100) < 2:
                return False
            self.store.accept(identity, data, valid)
            credentials = self._cached_file(self.credentials_path, lambda: read_credentials(self.credentials_path))
            candidate = credentials.get(identity)
            if isinstance(candidate, dict) and hmac.compare_digest(candidate['pending'], digest(token)):
                activate_pending(self.settings_path, identity, token)
            self.last_write = {key: value for key, value in self.last_write.items() if key in valid}
            self.last_write[identity] = now
            return True

    def maintain(self):
        with self._lock:
            if not self.settings_path.is_file():
                raise FileNotFoundError('Ayar dosyası bulunamadı; otomatik silme durduruldu.')
            self.store.maintain(self._valid_ids())


def create_app(receiver, max_inflight=128, body_timeout=5):
    """Bounded admission plus one database worker; slow uploads never hold the writer."""
    from aiohttp import web
    if not 1 <= max_inflight <= 1024 or body_timeout <= 0:
        raise ValueError('Invalid server limits')
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='netshield-db')
    active = 0
    maintenance_ok = True

    async def run(function, *args):
        return await asyncio.get_running_loop().run_in_executor(executor, function, *args)

    def response(status, code, **extra):
        headers = {'Cache-Control': 'no-store'}
        if status in (429, 503):
            headers['Retry-After'] = '5'
        return web.json_response(dict(code=code, **extra), status=status, headers=headers)

    async def receive(request):
        nonlocal active, maintenance_ok
        if active >= max_inflight:
            return response(503, 'receiver_busy')
        active += 1
        try:
            if request.headers.get('Content-Encoding') or request.headers.get('Transfer-Encoding'):
                return response(400, 'unsupported_encoding')
            if request.content_length is None or not 0 < request.content_length <= 32768:
                return response(413, 'invalid_body_size')
            if request.content_type != 'application/json':
                return response(415, 'json_required')
            authorizations = request.headers.getall('Authorization', [])
            if len(authorizations) != 1:
                return response(403, 'invalid_credentials')
            auth = authorizations[0]
            if not auth.startswith('Bearer ') or len(auth) > 256:
                return response(403, 'invalid_credentials')
            identity, token = request.match_info['identity'], auth[7:]
            await run(receiver.authorize, identity, token)
            raw = await asyncio.wait_for(request.read(), body_timeout)
            data = json.loads(raw)
            accepted = await run(receiver.accept, identity, token, data)
            if not accepted:
                return response(429, 'retry_later')
            maintenance_ok = True
            if request.match_info['version'] == '1':
                return web.Response(status=204, headers={'Cache-Control': 'no-store'})
            return response(200, 'accepted', protocol=2, accepted_event_ids=[e['id'] for e in data['events']])
        except PermissionError:
            return response(403, 'invalid_credentials')
        except ConfigurationError:
            maintenance_ok = False
            return response(503, 'configuration_unavailable')
        except (asyncio.TimeoutError, ConnectionError):
            return response(408, 'body_timeout')
        except web.HTTPRequestEntityTooLarge:
            return response(413, 'invalid_body_size')
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            return response(400, 'invalid_payload')
        except (OSError, sqlite3.Error):
            maintenance_ok = False
            return response(503, 'storage_unavailable')
        finally:
            active -= 1

    async def health(request):
        # No identities, events, configuration paths, tokens or credentials exposed.
        return response(200 if maintenance_ok else 503, 'ready' if maintenance_ok else 'storage_unavailable', protocols=[1, 2])

    async def maintain():
        nonlocal maintenance_ok
        while True:
            try:
                await run(receiver.maintain)
                maintenance_ok = True
            except (OSError, ValueError, TypeError, ConfigurationError, sqlite3.Error):
                maintenance_ok = False
            await asyncio.sleep(60)

    async def lifecycle(app):
        task = asyncio.create_task(maintain())
        try:
            yield
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            # Workers finish committed requests before exit. This runs outside the event loop.
            await asyncio.to_thread(executor.shutdown, wait=True, cancel_futures=True)

    app = web.Application(client_max_size=32768, handler_args={
        'auto_decompress': False, 'max_line_size': 8190, 'max_field_size': 8190,
        'keepalive_timeout': 10})
    app.cleanup_ctx.append(lifecycle)
    app.router.add_post('/v{version:1|2}/status/{identity:[a-zA-Z0-9_-]{1,64}}', receive)
    app.router.add_get('/healthz', health)
    return app


def main():
    parser = argparse.ArgumentParser(description='NetShield Windows agent enrollment / HTTPS receiver')
    parser.add_argument('--settings', type=Path, default=default_path())
    commands = parser.add_subparsers(dest='command', required=True)
    enroll_parser = commands.add_parser('enroll')
    enroll_parser.add_argument('--device-id', required=True)
    enroll_parser.add_argument('--server', required=True, help='https://netshield.company:8443')
    enroll_parser.add_argument('--output', type=Path, required=True)
    revoke_parser = commands.add_parser('revoke')
    revoke_parser.add_argument('--device-id', required=True)
    serve = commands.add_parser('serve')
    serve.add_argument('--bind', default='127.0.0.1')
    serve.add_argument('--port', type=int, default=8443)
    serve.add_argument('--cert', required=True)
    serve.add_argument('--key', required=True)
    serve.add_argument('--retention-days', type=int, default=30)
    serve.add_argument('--max-inflight', type=int, default=128)
    args = parser.parse_args()
    if args.command in ('enroll', 'revoke'):
        try:
            if args.command == 'enroll':
                enroll(args.settings, args.device_id, args.server, args.output)
            else:
                revoke(args.settings, args.device_id)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        print('Enrollment updated. Protect the agent configuration; never commit it.')
        return
    try:
        from aiohttp import web
    except ImportError:
        parser.error('HTTPS alıcısı için requirements-receiver.txt bağımlılıklarını kurun.')
    receiver = Receiver(args.settings, retention_days=args.retention_days)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(args.cert, args.key)
    app = create_app(receiver, max_inflight=args.max_inflight)
    web.run_app(app, host=args.bind, port=args.port, ssl_context=tls, access_log=None,
                handler_cancellation=False, shutdown_timeout=10)


if __name__ == '__main__':
    main()
