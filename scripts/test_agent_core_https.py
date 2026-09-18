"""Exercise the real C# transport against the real Python receiver on loopback TLS.
The test-only C# protector is not a Windows DPAPI validation.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aiohttp import web
from netshield.agent_receiver import Receiver, create_app, digest
from netshield.core.agent_status import read_snapshot, status_label
from netshield.core.settings import save_settings


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dotnet', required=True)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1] / 'agents/windows/Core.Tests/Core.Tests.csproj'
    with tempfile.TemporaryDirectory(prefix='netshield-core-https-') as folder:
        directory = Path(folder)
        settings = directory / 'settings.json'
        save_settings(settings, {'devices': [dict(id='pc1', name='Synthetic', department='Test', ip='', interface='')]})
        token = 'a' * 43
        (directory / 'agent-credentials.json').write_text(json.dumps({'pc1': digest(token)}))
        cert, key = directory / 'cert.pem', directory / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1',
                        '-keyout', str(key), '-out', str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        runner = web.AppRunner(create_app(Receiver(settings)), access_log=None)
        await runner.setup()
        try:
            site = web.TCPSite(runner, '127.0.0.1', 0, ssl_context=tls)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            config, state = directory / 'config.json', directory / 'state.dat'
            config.write_text(json.dumps(dict(server=f'https://127.0.0.1:{port}', device_id='pc1', token=token)))
            environment = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1')
            for trusted in (False, True):
                if trusted:
                    environment['SSL_CERT_FILE'] = str(cert)
                else:
                    environment.pop('SSL_CERT_FILE', None)
                process = await asyncio.create_subprocess_exec(args.dotnet, 'run', '--project', str(project), '--no-build',
                    '--', str(config), str(state), env=environment, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
                output = stdout.decode()
                if trusted:
                    assert process.returncode == 0 and 'RESULT accepted pending=0' in output, (output, stderr.decode())
                else:
                    assert process.returncode == 2 and 'RESULT tls_error pending=1' in output, (output, stderr.decode())
                print(output.strip())
            records, error = read_snapshot(settings)
            assert error is None and len(records['pc1']['events']) == 2
            assert records['pc1']['agent_state'] == 'running'
            assert 'Bağlı' in status_label(records['pc1'])
            print('PASS real C# -> HTTPS -> Python -> SQLite -> dashboard snapshot; untrusted TLS preserved queue, trusted retry delivered both events')
        finally:
            await runner.cleanup()


if __name__ == '__main__':
    asyncio.run(main())
