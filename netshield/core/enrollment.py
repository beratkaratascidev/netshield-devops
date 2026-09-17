"""Local, explicit device pairing shared by GUI and CLI. Never sends data."""
import hashlib
import json
import os
import re
import secrets
import stat
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from netshield.core.security import private_write
from netshield.core.settings import load_settings


def digest(token):
    return hashlib.sha256(token.encode('ascii')).hexdigest()


def read_credentials(path):
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0))
    except FileNotFoundError:
        return {}
    with os.fdopen(fd, encoding='utf-8') as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 131072:
            raise ValueError('Geçersiz eşleştirme deposu.')
        data = json.load(source)
    if not isinstance(data, dict) or len(data) > 500:
        raise ValueError('Geçersiz eşleştirme deposu.')
    if any(not isinstance(k, str) or not isinstance(v, str) or not re.fullmatch(r'[0-9a-f]{64}', v) for k, v in data.items()):
        raise ValueError('Geçersiz anahtar özeti.')
    return data


def server_origin(value):
    if not isinstance(value, str) or not value or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError('Sunucu adresi https://sunucu:8443 biçiminde olmalı.')
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.password is not None
            or '?' in value or '#' in value or parsed.path not in ('', '/') or parsed.port == 0):
        raise ValueError('HTTPS sunucu adresi kullanıcı bilgisi, yol veya sorgu içermemeli.')
    # Accessing port also validates the numeric range, before any credential is created.
    _ = parsed.port
    return value.rstrip('/')


@contextmanager
def enrollment_lock(directory):
    """OS lock, not a stale lock-file marker; releases automatically after a crash."""
    path = Path(directory) / '.agent-enrollment.lock'
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    acquired = False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('Geçersiz eşleştirme kilidi.')
        if os.fstat(fd).st_size == 0:
            os.write(fd, b'0')
        deadline = time.monotonic() + 2
        while not acquired:
            try:
                if os.name == 'posix':
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                acquired = True
            except (BlockingIOError, PermissionError):
                if time.monotonic() >= deadline:
                    raise OSError('Başka bir eşleştirme işlemi sürüyor; tekrar deneyin.')
                time.sleep(.02)
        yield
    finally:
        if acquired:
            if os.name == 'posix':
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
            else:
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        os.close(fd)


def enroll(settings_path, identity, server, output):
    settings_path, output = Path(settings_path), Path(output)
    server = server_origin(server)
    if not isinstance(identity, str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', identity):
        raise ValueError('Geçersiz cihaz kimliği.')
    credentials_path = settings_path.parent / 'agent-credentials.json'
    protected = {settings_path.resolve(), credentials_path.resolve(),
                 (settings_path.parent / '.agent-enrollment.lock').resolve()}
    if output.resolve() in protected or output.name.startswith('agent-status.'):
        raise ValueError('Yapılandırma için uygulama veri dosyasını seçmeyin.')
    with enrollment_lock(settings_path.parent):
        settings, error = load_settings(settings_path)
        if error or identity not in {d['id'] for d in settings['devices']}:
            raise ValueError('Cihaz envanterde bulunamadı; önce kaydedin.')
        credentials = read_credentials(credentials_path)
        token = secrets.token_urlsafe(32)
        # O_EXCL prevents overwriting even if another process creates the selected path.
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump(dict(server=server, device_id=identity, token=token), stream)
                stream.flush()
                os.fsync(stream.fileno())
            credentials[identity] = digest(token)
            private_write(credentials_path, json.dumps(credentials))
        except BaseException:
            output.unlink(missing_ok=True)
            raise
    return output


def revoke(settings_path, identity):
    path = Path(settings_path).parent / 'agent-credentials.json'
    with enrollment_lock(path.parent):
        credentials = read_credentials(path)
        credentials.pop(identity, None)
        private_write(path, json.dumps(credentials))
