"""Bounded local administrative journal. No tokens, free text or packet data."""
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
import os
from pathlib import Path
import re
import time
import uuid

from netshield.core.agent_store import connection

ACTIONS = {'settings_save', 'device_add', 'device_edit', 'device_remove',
           'credential_enroll', 'credential_revoke', 'credential_activate'}
LIMIT = 10000


def audit_path(settings_path):
    return Path(settings_path).parent / 'admin-audit.sqlite3'


def initialize(settings_path):
    path = audit_path(settings_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(fd)
    with connection(path) as conn:
        version = conn.execute('PRAGMA user_version').fetchone()[0]
        if version not in (0, 1):
            raise ValueError('Desteklenmeyen denetim kaydı sürümü.')
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('CREATE TABLE IF NOT EXISTS audit (id TEXT PRIMARY KEY, started REAL NOT NULL, finished REAL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, outcome TEXT NOT NULL)')
        conn.execute('CREATE INDEX IF NOT EXISTS audit_time ON audit(started)')
        conn.execute('PRAGMA user_version=1')
    return path


@contextmanager
def operation(settings_path, changes):
    changes = list(changes)
    if not changes or len(changes) > 1001:
        raise ValueError('Geçersiz denetim işlem sayısı.')
    for action, target in changes:
        if action not in ACTIONS or not isinstance(target, str) or not re.fullmatch(r'[a-zA-Z0-9_-]{0,64}', target):
            raise ValueError('Geçersiz denetim alanı.')
    path = initialize(settings_path)
    now = time.time()
    actor = f'uid:{os.getuid()}' if hasattr(os, 'getuid') else 'windows-identity-unverified'
    ids = [uuid.uuid4().hex for _ in changes]
    with connection(path) as conn:
        conn.execute('BEGIN IMMEDIATE')
        try:
            conn.execute('DELETE FROM audit WHERE started < ?', (now - 90 * 86400,))
            conn.execute('DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY started DESC, rowid DESC LIMIT ?)', (LIMIT - len(changes),))
            conn.executemany('INSERT INTO audit VALUES (?, ?, NULL, ?, ?, ?, ?)',
                             [(identity, now, actor, action, target, 'started') for identity, (action, target) in zip(ids, changes)])
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
    def finish(outcome):
        with connection(path) as conn:
            conn.execute('BEGIN IMMEDIATE')
            try:
                conn.executemany('UPDATE audit SET finished=?, outcome=? WHERE id=?', [(time.time(), outcome, identity) for identity in ids])
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
    try:
        yield
    except BaseException:
        try:
            finish('failed')
        except Exception:
            # Preserve the original operation failure; started means outcome unknown.
            pass
        raise
    else:
        try:
            finish('succeeded')
        except Exception as exc:
            raise OSError('İşlem uygulandı ancak denetim sonuç kaydı yazılamadı; yeniden denemeden önce mevcut durumu kontrol edin.') from exc


def audited(action):
    def decorate(function):
        @wraps(function)
        def wrapped(settings_path, identity, *args, **kwargs):
            with operation(settings_path, [(action, identity)]):
                return function(settings_path, identity, *args, **kwargs)
        return wrapped
    return decorate


def read_recent(settings_path, limit=100):
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError('Geçersiz denetim okuma sınırı.')
    path = audit_path(settings_path)
    if not path.exists() and not path.is_symlink():
        return []
    with connection(path, readonly=True) as conn:
        if conn.execute('PRAGMA user_version').fetchone()[0] != 1:
            raise ValueError('Desteklenmeyen denetim kaydı sürümü.')
        # A single operation intentionally shares one timestamp. rowid preserves
        # insertion order within that timestamp, unlike a random UUID.
        return [dict(row) for row in conn.execute('SELECT * FROM audit ORDER BY started DESC, rowid DESC LIMIT ?', (limit,))]


class AuditReader:
    """Single-flight audit reader so SQLite access never blocks Tk callbacks."""
    def __init__(self, settings_path, loader=read_recent):
        self.settings_path = settings_path
        self.loader = loader
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='netshield-audit')
        self.future = None
        self.closed = False
        self.cached = None
        self.signature = None

    def _signature(self):
        directory = Path(self.settings_path).parent
        signatures = []
        for name in ('admin-audit.sqlite3', 'admin-audit.sqlite3-wal', 'admin-audit.sqlite3-shm'):
            try:
                st = (directory / name).lstat()
                signatures.append((st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_uid))
            except FileNotFoundError:
                signatures.append(None)
        return tuple(signatures)

    def _read(self):
        try:
            before = self._signature()
            if self.cached is not None and before == self.signature:
                return self.cached
            records = self.loader(self.settings_path)
            after = self._signature()
            result = (records, None)
            if before == after:
                self.signature, self.cached = after, result
            else:
                self.signature, self.cached = None, None
            return result
        except Exception as exc:
            return [], f'Denetim günlüğü okunamadı: {type(exc).__name__}'

    def request(self):
        if self.closed or self.future is not None:
            return False
        self.future = self.executor.submit(self._read)
        return True

    def poll(self):
        if self.future is None or not self.future.done():
            return None
        result = self.future.result()
        self.future = None
        return result

    def close(self):
        self.closed = True
        self.executor.shutdown(wait=False, cancel_futures=True)
