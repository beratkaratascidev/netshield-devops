"""Transactional local agent data. No credentials, packet contents or outbound IO."""
import os
import json
import sqlite3
import stat
import time
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 3
DISPLAY_EVENTS = 100
MAX_EVENTS = 1000
DEFAULT_RETENTION_DAYS = 30


def database_path(settings_path):
    return Path(settings_path).parent / 'agent-status.sqlite3'


def _check_path(path):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError('Ajan veritabanı normal bir dosya olmalı.')
    if os.name == 'posix' and (metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077):
        raise ValueError('Ajan veritabanı bu kullanıcıya ait ve 0600 izinli olmalı.')


@contextmanager
def connection(path, readonly=False):
    path = Path(path)
    _check_path(path)
    conn = sqlite3.connect(path.resolve().as_uri() + ('?mode=ro' if readonly else '?mode=rw'),
                           uri=True, timeout=2, isolation_level=None)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys=ON')
        if readonly:
            conn.execute('PRAGMA query_only=ON')
        else:
            conn.execute('PRAGMA synchronous=FULL')
        yield conn
    finally:
        conn.close()


def _version(conn, allow_legacy=False):
    if conn.execute('PRAGMA user_version').fetchone()[0] not in ((1, 2, SCHEMA_VERSION) if allow_legacy else (SCHEMA_VERSION,)):
        raise ValueError('Desteklenmeyen ajan veritabanı sürümü.')


class AgentStore:
    def __init__(self, settings_path, retention_days=DEFAULT_RETENTION_DAYS):
        if type(retention_days) is not int or not 1 <= retention_days <= 365:
            raise ValueError('Saklama süresi 1–365 gün olmalı.')
        self.retention_days = retention_days
        self.path = database_path(settings_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        with connection(self.path) as conn:
            version = conn.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0, 1, 2, SCHEMA_VERSION):
                raise ValueError('Desteklenmeyen ajan veritabanı sürümü.')
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA secure_delete=ON')
            conn.execute('BEGIN IMMEDIATE')
            try:
                conn.execute('CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
                conn.execute('''CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY, boot_time TEXT NOT NULL, session TEXT NOT NULL,
                    received_at REAL NOT NULL, details TEXT NOT NULL DEFAULT '{}')''')
                if 'details' not in {row[1] for row in conn.execute('PRAGMA table_info(devices)')}:
                    conn.execute("ALTER TABLE devices ADD COLUMN details TEXT NOT NULL DEFAULT '{}'")
                conn.execute('''CREATE TABLE IF NOT EXISTS events (
                    position INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                    event_id TEXT NOT NULL, kind TEXT NOT NULL, source_time TEXT NOT NULL,
                    received_at REAL NOT NULL, details TEXT NOT NULL DEFAULT '{}', UNIQUE(device_id, event_id))''')
                if 'details' not in {row[1] for row in conn.execute('PRAGMA table_info(events)')}:
                    conn.execute("ALTER TABLE events ADD COLUMN details TEXT NOT NULL DEFAULT '{}'")
                conn.execute('CREATE INDEX IF NOT EXISTS events_device_position ON events(device_id, position DESC)')
                conn.execute('CREATE INDEX IF NOT EXISTS events_received ON events(received_at)')
                if not conn.execute("SELECT 1 FROM metadata WHERE key='legacy_imported'").fetchone():
                    from netshield.core.agent_status import read_legacy_snapshot, validate_status
                    legacy, error = read_legacy_snapshot(settings_path)
                    if error:
                        raise ValueError(error)
                    for identity, record in legacy.items():
                        normalized = validate_status({k: v for k, v in record.items() if k != 'received_at'})
                        self._put(conn, identity, normalized, record['received_at'])
                    conn.execute("INSERT INTO metadata VALUES ('legacy_imported', '1')")
                conn.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
                conn.commit()
            except BaseException:
                conn.rollback()
                raise

    @staticmethod
    def _put(conn, identity, data, received_at):
        extra = {key: data[key] for key in ('agent_state', 'dropped_events', 'pending_events', 'session_id') if key in data}
        conn.execute('''INSERT INTO devices (id, boot_time, session, received_at, details) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET boot_time=excluded.boot_time,
            session=excluded.session, received_at=excluded.received_at, details=excluded.details''',
                     (identity, data['boot_time'], data['session'], received_at, json.dumps(extra)))
        for event in data['events']:
            context = {key: event[key] for key in ('session_id', 'boot_time') if key in event}
            previous = conn.execute('SELECT kind, source_time, details FROM events WHERE device_id=? AND event_id=?',
                                    (identity, event['id'])).fetchone()
            if previous and (previous['kind'], previous['source_time'], json.loads(previous['details'])) != (event['kind'], event['time'], context):
                raise ValueError('Aynı olay kimliği farklı içerikle kullanılamaz.')
            conn.execute('''INSERT OR IGNORE INTO events
                (device_id,event_id,kind,source_time,received_at,details) VALUES (?,?,?,?,?,?)''',
                         (identity, event['id'], event['kind'], event['time'], received_at, json.dumps(context)))
        conn.execute('''DELETE FROM events WHERE device_id=? AND position NOT IN (
            SELECT position FROM events WHERE device_id=? ORDER BY position DESC LIMIT ?)''',
                     (identity, identity, MAX_EVENTS))

    def accept(self, identity, data, valid_ids, received_at=None):
        from netshield.core.agent_status import validate_status
        data = validate_status(data)
        now = time.time() if received_at is None else received_at
        if identity not in valid_ids:
            raise PermissionError()
        with connection(self.path) as conn:
            _version(conn)
            conn.execute('BEGIN IMMEDIATE')
            try:
                self._prune(conn, valid_ids, now)
                self._put(conn, identity, data, now)
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
        # Return ACK only after commit; re-delivery uses UNIQUE(device_id,event_id).
        return [event['id'] for event in data['events']]

    def _prune(self, conn, valid_ids, now):
        valid = set(valid_ids)
        for row in conn.execute('SELECT id FROM devices').fetchall():
            if row['id'] not in valid:
                conn.execute('DELETE FROM devices WHERE id=?', (row['id'],))
        cutoff = now - self.retention_days * 86400
        conn.execute('DELETE FROM events WHERE received_at < ?', (cutoff,))
        conn.execute('DELETE FROM devices WHERE received_at < ?', (cutoff,))

    def maintain(self, valid_ids, now=None):
        with connection(self.path) as conn:
            _version(conn)
            conn.execute('BEGIN IMMEDIATE')
            try:
                self._prune(conn, valid_ids, time.time() if now is None else now)
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
            conn.execute('PRAGMA wal_checkpoint(PASSIVE)')


def read_database(settings_path):
    with connection(database_path(settings_path), readonly=True) as conn:
        _version(conn, allow_legacy=True)
        conn.execute('BEGIN')
        try:
            rows = conn.execute('SELECT * FROM devices LIMIT 501').fetchall()
            if len(rows) > 500:
                raise ValueError('Ajan cihaz sınırı aşıldı.')
            result = {}
            event_details = 'details' in {row[1] for row in conn.execute('PRAGMA table_info(events)')}
            for row in rows:
                events = conn.execute(f'''SELECT event_id, kind, source_time, {"details" if event_details else "'{}'"} AS details FROM events
                    WHERE device_id=? ORDER BY position DESC LIMIT ?''', (row['id'], DISPLAY_EVENTS)).fetchall()
                extra = json.loads(row['details']) if 'details' in row.keys() else {}
                if not isinstance(extra, dict) or set(extra) - {'agent_state', 'dropped_events', 'pending_events', 'session_id'}:
                    raise ValueError('Invalid stored agent diagnostics')
                history = []
                for event in reversed(events):
                    context = json.loads(event['details'])
                    if not isinstance(context, dict) or set(context) not in (set(), {'session_id', 'boot_time'}):
                        raise ValueError('Invalid stored event context')
                    history.append(dict(id=event['event_id'], kind=event['kind'], time=event['source_time'], **context))
                result[row['id']] = dict(boot_time=row['boot_time'], session=row['session'], received_at=row['received_at'],
                    events=history, **extra)
            conn.commit()
            return result
        except BaseException:
            conn.rollback()
            raise
