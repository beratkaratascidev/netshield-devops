"""Reproducible loopback HTTPS load probe. Only temporary synthetic identities/data."""
import argparse
import asyncio
import json
import math
import resource
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aiohttp import ClientSession, TCPConnector, web
from netshield.agent_receiver import Receiver, create_app, digest
from netshield.core.agent_status import read_snapshot
from netshield.core.settings import save_settings


async def measure(count, events_per_request):
    with tempfile.TemporaryDirectory(prefix='netshield-load-') as folder:
        directory = Path(folder)
        settings = directory / 'settings.json'
        devices = [dict(id=f'pc{i}', name=f'Synthetic {i}', department='Test',
                        ip=f'10.0.{i // 254}.{i % 254 + 1}', interface='') for i in range(count)]
        save_settings(settings, {'devices': devices})
        (directory / 'agent-credentials.json').write_text(json.dumps({d['id']: digest('synthetic-token') for d in devices}))
        cert, key = directory / 'cert.pem', directory / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1',
                        '-keyout', str(key), '-out', str(cert)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        receiver = Receiver(settings)
        runner = web.AppRunner(create_app(receiver), access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, '127.0.0.1', 0, ssl_context=tls)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        context = ssl.create_default_context(cafile=str(cert))
        durations, statuses = [], []
        slots = asyncio.Semaphore(64)
        process_start, wall_start = time.process_time(), time.perf_counter()
        try:
            async with ClientSession(connector=TCPConnector(ssl=context, limit=64)) as client:
                async def send(device):
                    started = time.perf_counter()
                    body = dict(boot_time='2026-09-18T08:00:00Z', session='unknown', events=[
                        dict(id=f'{i:032x}', kind='agent_started', time='2026-09-18T08:01:00Z')
                        for i in range(events_per_request)])
                    async with slots:
                        async with client.post(f'https://127.0.0.1:{port}/v2/status/{device["id"]}', json=body,
                                               headers={'Authorization': 'Bearer synthetic-token'}) as response:
                            result = await response.json()
                            statuses.append(response.status)
                            if response.status == 200 and len(result['accepted_event_ids']) != events_per_request:
                                raise AssertionError('Incomplete ACK')
                    durations.append(time.perf_counter() - started)
                await asyncio.gather(*(send(d) for d in devices))
            wall, cpu = time.perf_counter() - wall_start, time.process_time() - process_start
            records, error = read_snapshot(settings)
            expected = count * events_per_request
            actual = sum(len(r['events']) for r in records.values())
            if error or len(records) != count or actual != expected or any(status != 200 for status in statuses):
                raise AssertionError('Records lost or requests rejected')
            sizes = sum(p.stat().st_size for p in directory.glob('agent-status.sqlite3*'))
            return dict(devices=count, events_per_request=events_per_request, concurrency=64,
                        accepted=len(statuses), stored_events=actual, elapsed_seconds=round(wall, 3),
                        p95_seconds=round(sorted(durations)[math.ceil(len(durations) * .95) - 1], 3),
                        cpu_seconds=round(cpu, 3), process_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                        database_bytes=sizes)
        finally:
            await runner.cleanup()


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    results = []
    for count in (10, 100, 500):
        for events in (1, 100):
            result = await measure(count, events)
            results.append(result)
            print(json.dumps(result), flush=True)
    if args.output:
        args.output.write_text(json.dumps({'scope': 'Single-host loopback HTTPS, synthetic data; not Windows or sustained production load',
                                          'results': results}, indent=2) + '\n')


if __name__ == '__main__':
    asyncio.run(main())
