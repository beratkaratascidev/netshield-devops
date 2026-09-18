"""Strict status protocol shared by the receiver and local dashboard."""
import json
import os
import stat
import math
import time
import sqlite3
from datetime import datetime
from pathlib import Path

EVENTS = {'agent_started', 'agent_stopped', 'session_lock', 'session_unlock', 'suspend', 'resume', 'session_logoff'}


def timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError('Invalid timestamp')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Timezone required')
    return parsed.isoformat()


def validate_status(data):
    required = {'boot_time', 'session', 'events'}
    optional = {'agent_state', 'dropped_events', 'pending_events'}
    if not isinstance(data, dict) or not required <= set(data) or set(data) - required - optional:
        raise ValueError('Invalid status fields')
    if data['session'] not in ('unknown', 'locked', 'unlocked'):
        raise ValueError('Invalid session')
    if not isinstance(data['events'], list) or len(data['events']) > 100:
        raise ValueError('Too many events')
    events = []
    for event in data['events']:
        if not isinstance(event, dict) or set(event) != {'id', 'kind', 'time'}:
            raise ValueError('Invalid event')
        if not isinstance(event['id'], str) or len(event['id']) != 32 or any(c not in '0123456789abcdef' for c in event['id']):
            raise ValueError('Invalid event ID')
        if event['kind'] not in EVENTS:
            raise ValueError('Invalid event kind')
        events.append(dict(id=event['id'], kind=event['kind'], time=timestamp(event['time'])))
    extra = {k: data[k] for k in optional if k in data}
    if 'agent_state' in extra and extra['agent_state'] not in ('running', 'stopped'):
        raise ValueError('Invalid agent state')
    for key in ('dropped_events', 'pending_events'):
        if key in extra and (type(extra[key]) is not int or not 0 <= extra[key] <= 9007199254740991):
            raise ValueError('Invalid queue counter')
    return dict(boot_time=timestamp(data['boot_time']), session=data['session'], events=events, **extra)


def read_legacy_snapshot(settings_path):
    path = Path(settings_path).parent / 'agent-status.json'
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, encoding='utf-8') as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 8 * 1024 * 1024:
                raise ValueError('Durum dosyası en fazla 8 MiB boyutunda normal bir dosya olmalı.')
            raw = source.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError('Status file too large')
        data = json.loads(raw)
        if not isinstance(data, dict) or len(data) > 500:
            raise ValueError('Invalid status snapshot')
        for identity, record in data.items():
            if not isinstance(identity, str) or not isinstance(record, dict):
                raise ValueError('Invalid device')
            seen = record['received_at']
            if type(seen) not in (int, float) or not math.isfinite(seen) or not 0 <= seen <= 253402214400:
                raise ValueError('Invalid receive time')
            validate_status({k: v for k, v in record.items() if k != 'received_at'})
        return data, None
    except FileNotFoundError:
        return {}, None
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return {}, f'Ajan durumu okunamadı: {exc}'


def read_snapshot(settings_path):
    from netshield.core.agent_store import database_path, read_database
    path = database_path(settings_path)
    if not path.exists() and not path.is_symlink():
        return read_legacy_snapshot(settings_path)
    try:
        records = read_database(settings_path)
        for record in records.values():
            validate_status({k: v for k, v in record.items() if k != 'received_at'})
            seen = record['received_at']
            if type(seen) not in (int, float) or not math.isfinite(seen) or not 0 <= seen <= 253402214400:
                raise ValueError('Invalid receive time')
        return records, None
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error) as exc:
        return {}, f'Ajan durumu okunamadı: {exc}'


def status_label(record, now=None):
    if not record:
        return 'Ajan verisi yok'
    age = (time.time() if now is None else now) - record['received_at']
    if age < 0 or age > 90:
        return 'Bağlantı kesildi / kapanış bilinmiyor'
    if record.get('agent_state') == 'stopped' or ('agent_state' not in record and record['events'] and record['events'][-1]['kind'] == 'agent_stopped'):
        return 'Ajan durduruldu'
    return {'locked': 'Bağlı · kilitli', 'unlocked': 'Bağlı · kilit açık', 'unknown': 'Bağlı · oturum bilinmiyor'}[record['session']]
