"""Local, credential-free recovery archives. Restore only to a new directory."""
import argparse
import json
import math
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import zipfile
from contextlib import closing

from netshield.core.agent_status import validate_status
from netshield.core.agent_store import AgentStore, connection, database_path, read_database
from netshield.core.settings import load_settings, save_settings, validate_settings
from netshield.core.security import effective_policy, load_managed_policy

LIMIT = 128 * 1024 * 1024
MEMBERS = {'settings.json', 'agent-status.sqlite3', 'manifest.json'}


def validate_snapshot(settings):
    preferences, error = load_settings(settings)
    if error or not Path(settings).is_file():
        raise ValueError(error or 'Yedek ayar dosyası eksik.')
    with connection(database_path(settings), readonly=True) as conn:
        if conn.execute('PRAGMA integrity_check').fetchone()[0] != 'ok' or conn.execute('PRAGMA foreign_key_check').fetchone():
            raise ValueError('Veritabanı bütünlük kontrolü başarısız.')
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if tables != {'metadata', 'devices', 'events', 'sqlite_sequence'}:
            raise ValueError('Beklenmeyen yedek tabloları.')
        version = conn.execute('PRAGMA user_version').fetchone()[0]
        expected = {
            'devices': {'id', 'boot_time', 'session', 'received_at'} | ({'details'} if version >= 2 else set()),
            'events': {'position', 'device_id', 'event_id', 'kind', 'source_time', 'received_at'} | ({'details'} if version >= 3 else set()),
            'metadata': {'key', 'value'},
        }
        for table, fields in expected.items():
            if {row[1] for row in conn.execute(f'PRAGMA table_info({table})')} != fields:
                raise ValueError('Beklenmeyen yedek sütunları.')
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view')").fetchone():
            raise ValueError('Yedek tetikleyici veya görünüm içeremez.')
        if [tuple(row) for row in conn.execute('SELECT key,value FROM metadata')] != [('legacy_imported', '1')]:
            raise ValueError('Beklenmeyen yedek metadata alanı.')
        if conn.execute('SELECT 1 FROM events GROUP BY device_id HAVING COUNT(*) > 1000').fetchone():
            raise ValueError('Olay saklama sınırı aşılmış.')
    for record in read_database(settings, event_limit=1000).values():
        seen = record['received_at']
        if type(seen) not in (int, float) or not math.isfinite(seen) or not 0 <= seen <= 253402214400:
            raise ValueError('Geçersiz alım zamanı.')
        base = {k: v for k, v in record.items() if k not in ('received_at', 'events')}
        events = record['events']
        for offset in range(0, max(1, len(events)), 100):
            validate_status(dict(base, events=events[offset:offset + 100]))
    return preferences


def create_backup(settings, output):
    settings, output = Path(settings), Path(output)
    original = settings.read_bytes()
    preferences = validate_settings(json.loads(original))
    policy, error = load_managed_policy()
    if not effective_policy(preferences['security'], policy)['allow_exports']:
        raise PermissionError('Güvenlik politikası yedek dışa aktarımına izin vermiyor.')
    with tempfile.TemporaryDirectory(prefix='.netshield-backup-', dir=output.parent) as folder:
        stage = Path(folder)
        staged_settings = stage / 'settings.json'
        save_settings(staged_settings, preferences)
        db = database_path(settings)
        if db.exists() or db.is_symlink():
            staged_db = database_path(staged_settings)
            staged_db.touch(mode=0o600)
            with connection(db, readonly=True) as source, closing(sqlite3.connect(staged_db)) as target:
                source.backup(target)
        else:
            if (settings.parent / 'agent-status.json').exists():
                raise ValueError('Önce alıcıyı başlatıp eski JSON deposunu yükseltin.')
            AgentStore(staged_settings)
        validate_snapshot(staged_settings)
        if settings.read_bytes() != original:
            raise ValueError('Yedek sırasında ayarlar değişti; tekrar deneyin.')
        if database_path(staged_settings).stat().st_size > LIMIT - staged_settings.stat().st_size - 1024:
            raise ValueError('Yedek 128 MiB sınırını aşıyor.')
        archive = stage / 'backup.zip'
        archive.touch(mode=0o600)
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as bundle:
            bundle.writestr('manifest.json', json.dumps({'format': 1, 'credentials': False}))
            bundle.write(staged_settings, 'settings.json')
            bundle.write(database_path(staged_settings), 'agent-status.sqlite3')
        with archive.open('rb') as stream:
            os.fsync(stream.fileno())
        os.link(archive, output)  # Atomic publication, refuses an existing destination.
    return output


def restore_backup(archive, destination):
    archive, destination = Path(archive), Path(destination)
    if archive.stat().st_size > LIMIT:
        raise ValueError('Yedek 128 MiB sınırını aşıyor.')
    with tempfile.TemporaryDirectory(prefix='.netshield-restore-', dir=destination.parent) as folder:
        stage = Path(folder)
        with zipfile.ZipFile(archive) as bundle:
            entries = bundle.infolist()
            if len(entries) != 3 or {e.filename for e in entries} != MEMBERS or sum(e.file_size for e in entries) > LIMIT:
                raise ValueError('Geçersiz yedek içeriği veya boyutu.')
            manifest = bundle.getinfo('manifest.json')
            if manifest.file_size > 1024 or bundle.getinfo('settings.json').file_size > 1024 * 1024:
                raise ValueError('Yedek yapılandırma sınırı aşıldı.')
            if json.loads(bundle.read(manifest)) != {'format': 1, 'credentials': False}:
                raise ValueError('Desteklenmeyen yedek sürümü.')
            for name in ('settings.json', 'agent-status.sqlite3'):
                fd = os.open(stage / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as target, bundle.open(name) as source:
                    shutil.copyfileobj(source, target)
        validate_snapshot(stage / 'settings.json')
        # Upgrade old supported schemas before publishing the new recovery directory.
        AgentStore(stage / 'settings.json')
        with connection(stage / 'agent-status.sqlite3') as conn:
            conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        destination.mkdir(mode=0o700)  # Never overwrite a live installation or existing folder.
        try:
            for name in ('settings.json', 'agent-status.sqlite3'):
                os.replace(stage / name, destination / name)
        except BaseException:
            shutil.rmtree(destination)
            raise
    return destination


def main():
    parser = argparse.ArgumentParser(description='Yerel yedekleme; anahtarlar dahil edilmez, geri yüklemede yeniden eşleştirme gerekir.')
    sub = parser.add_subparsers(dest='action', required=True)
    create = sub.add_parser('create')
    create.add_argument('--settings', type=Path, required=True)
    create.add_argument('--output', type=Path, required=True)
    restore = sub.add_parser('restore')
    restore.add_argument('--archive', type=Path, required=True)
    restore.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = create_backup(args.settings, args.output) if args.action == 'create' else restore_backup(args.archive, args.destination)
    except (OSError, ValueError, sqlite3.Error, zipfile.BadZipFile) as exc:
        parser.exit(1, f'İşlem tamamlanamadı: {exc}\n')
    print(result)


if __name__ == '__main__':
    main()
