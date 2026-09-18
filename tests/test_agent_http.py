import asyncio
import json
import shutil
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    import aiohttp
    from aiohttp import web
except ImportError:
    aiohttp = None

from netshield.agent_receiver import Receiver, create_app, digest
from netshield.core.agent_status import read_snapshot
from netshield.core.settings import save_settings


def payload():
    return dict(boot_time='2026-09-17T08:00:00Z', session='unknown', events=[
        dict(id='a' * 32, kind='agent_started', time='2026-09-17T08:01:00Z')])


@unittest.skipUnless(aiohttp and shutil.which('openssl'), 'Install requirements-receiver.txt and openssl')
class HTTPTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.settings = Path(folder.name) / 'settings.json'
        save_settings(self.settings, dict(devices=[dict(id='pc1', name='Test', department='Dev', ip='192.0.2.1', interface='')]))
        (self.settings.parent / 'agent-credentials.json').write_text(json.dumps({'pc1': digest('secret')}))
        self.receiver = Receiver(self.settings)
        cert, key = self.settings.parent / 'cert.pem', self.settings.parent / 'key.pem'
        await asyncio.to_thread(subprocess.run, ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
            '-keyout', str(key), '-out', str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(cert, key)
        self.context = ssl.create_default_context(cafile=str(cert))
        self.runner = web.AppRunner(create_app(self.receiver, max_inflight=2, body_timeout=0.3), access_log=None)
        await self.runner.setup()
        self.addAsyncCleanup(self.runner.cleanup)
        site = web.TCPSite(self.runner, '127.0.0.1', 0, ssl_context=tls)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]
        self.base = f'https://127.0.0.1:{self.port}'
        self.client = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=self.context))
        self.addAsyncCleanup(self.client.close)
        self.headers = {'Authorization': 'Bearer secret'}

    async def test_tls_auth_and_legacy_compatibility(self):
        loop = asyncio.get_running_loop()
        previous = loop.get_exception_handler()
        def expected_reset(loop, context):
            if isinstance(context.get('exception'), ConnectionResetError) and context.get('message') == 'Error on transport creation for incoming connection':
                return
            loop.default_exception_handler(context)
        loop.set_exception_handler(expected_reset)
        self.addCleanup(loop.set_exception_handler, previous)
        async with aiohttp.ClientSession() as untrusted:
            with self.assertRaises(aiohttp.ClientConnectorCertificateError):
                await untrusted.post(self.base + '/v1/status/pc1', json=payload(), headers=self.headers)
        async with self.client.post(self.base + '/v1/status/pc1', json=payload(), headers={'Authorization': 'Bearer wrong'}) as r:
            self.assertEqual(r.status, 403)
        async with self.client.post(self.base + '/v1/status/pc1', json=payload(), headers=self.headers) as r:
            self.assertEqual(r.status, 204)
        self.assertEqual(len(read_snapshot(self.settings)[0]['pc1']['events']), 1)

    async def test_ack_after_commit_and_error_without_ack(self):
        with patch.object(self.receiver.store, 'accept', side_effect=sqlite3.OperationalError('disk full')):
            async with self.client.post(self.base + '/v2/status/pc1', json=payload(), headers=self.headers) as r:
                self.assertEqual(r.status, 503)
                self.assertNotIn('accepted_event_ids', await r.json())
            async with self.client.get(self.base + '/healthz') as r:
                self.assertEqual(r.status, 503)
        async with self.client.post(self.base + '/v2/status/pc1', json=payload(), headers=self.headers) as r:
            self.assertEqual(r.status, 200)
            self.assertEqual((await r.json())['accepted_event_ids'], ['a' * 32])
            self.assertEqual(len(read_snapshot(self.settings)[0]['pc1']['events']), 1)
        async with self.client.get(self.base + '/healthz') as r:
            self.assertEqual(r.status, 200)

    async def test_slow_upload_does_not_block_other_requests(self):
        authorized = threading.Event()
        original = self.receiver.authorize
        def authorize(*args):
            result = original(*args)
            authorized.set()
            return result
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port, ssl=self.context)
        try:
            with patch.object(self.receiver, 'authorize', side_effect=authorize):
                writer.write(b'POST /v1/status/pc1 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{')
                await writer.drain()
                self.assertTrue(await asyncio.to_thread(authorized.wait, 2))
                async with self.client.post(self.base + '/v2/status/pc1', json=payload(), headers=self.headers) as r:
                    self.assertEqual(r.status, 200)
                header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 2)
                self.assertIn(b'408', header.split(b'\r\n')[0])
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_admission_limit_rejects_excess_requests_without_writer_growth(self):
        entered = threading.Event()
        original = self.receiver.authorize
        count = 0
        def authorize(*args):
            nonlocal count
            result = original(*args)
            count += 1
            if count == 2:
                entered.set()
            return result
        writers = []
        try:
            with patch.object(self.receiver, 'authorize', side_effect=authorize):
                for _ in range(2):
                    _, writer = await asyncio.open_connection('127.0.0.1', self.port, ssl=self.context)
                    writers.append(writer)
                    writer.write(b'POST /v1/status/pc1 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{')
                    await writer.drain()
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                async with self.client.post(self.base + '/v2/status/pc1', json=payload(), headers=self.headers) as response:
                    self.assertEqual(response.status, 503)
                    self.assertEqual((await response.json())['code'], 'receiver_busy')
                async with self.client.get(self.base + '/healthz') as response:
                    self.assertEqual(response.status, 200)
        finally:
            for writer in writers:
                writer.close()
                await writer.wait_closed()

    async def test_broken_server_configuration_does_not_blame_client_payload(self):
        self.settings.write_text('{corrupt')
        async with self.client.post(self.base + '/v2/status/pc1', json=payload(), headers=self.headers) as r:
            self.assertEqual(r.status, 503)
            self.assertEqual((await r.json())['code'], 'configuration_unavailable')
        self.assertEqual(read_snapshot(self.settings)[0], {})

    async def test_bad_encoding_oversized_payload_and_health(self):
        async with self.client.post(self.base + '/v2/status/pc1', data='x' * 32769,
                                    headers={**self.headers, 'Content-Type': 'application/json'}) as r:
            self.assertEqual(r.status, 413)
        async with self.client.post(self.base + '/v2/status/pc1', json=payload(),
                                    headers={**self.headers, 'Content-Encoding': 'gzip'}) as r:
            self.assertEqual(r.status, 400)
        async with self.client.get(self.base + '/healthz') as r:
            self.assertEqual(r.status, 200)
            text = await r.text()
            self.assertNotIn('secret', text)
            self.assertNotIn('pc1', text)
