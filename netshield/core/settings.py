"""Validated user preferences, written atomically without traffic data."""
import json
import os
import tempfile
import ipaddress
from pathlib import Path
from netshield.core.inventory import validate_devices
from netshield.config import ESIKLER
from netshield.core.security import validate_security


def default_path():
    return Path(os.environ.get('XDG_CONFIG_HOME', Path.home() / '.config')) / 'netshield' / 'settings.json'


def validate_settings(data):
    if not isinstance(data, dict):
        raise ValueError('Ayar dosyası bir JSON nesnesi olmalı.')
    thresholds = {**ESIKLER, **data.get('thresholds', {})}
    for key in ESIKLER:
        value = thresholds[key]
        maximum = 1024 if key in ('port_scan', 'target_sources') else 1000000
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f'Geçersiz eşik: {key}')
    density = data.get('density', 'Rahat')
    if density not in ('Rahat', 'Kompakt'):
        raise ValueError('Geçersiz tablo yoğunluğu.')
    watchlist = data.get('watchlist', [])
    if not isinstance(watchlist, list) or len(watchlist) > 100 or any(not isinstance(ip, str) for ip in watchlist):
        raise ValueError('En fazla 100 adres takip edilebilir.')
    watched = list(dict.fromkeys(str(ipaddress.ip_address(ip)) for ip in watchlist))
    return dict(version=1, thresholds={k: thresholds[k] for k in ESIKLER},
                density=density, watchlist=watched, devices=validate_devices(data.get('devices', [])), security=validate_security(data.get('security', {})))


def load_settings(path):
    try:
        with Path(path).open(encoding='utf-8') as source:
            return validate_settings(json.load(source)), None
    except FileNotFoundError:
        return validate_settings({}), None
    except (OSError, ValueError, TypeError) as exc:
        return validate_settings({'security': {'profile': 'Kurumsal'}}), f'Ayarlar okunamadı; kısıtlı güvenlik profili kullanılıyor: {exc}'


def _save_settings(path, data):
    data = validate_settings(data)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix='.settings-', delete=False) as output:
            temporary = Path(output.name)
            json.dump(data, output, ensure_ascii=False, indent=2)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def save_settings(path, data):
    from netshield.core.audit import operation
    data = validate_settings(data)
    previous, error = load_settings(path)
    old = {d['id']: d for d in previous['devices']} if error is None else {}
    new = {d['id']: d for d in data['devices']}
    changes = [('settings_save', '')]
    changes += [('device_remove', identity) for identity in sorted(old.keys() - new.keys())]
    for identity, device in new.items():
        if identity not in old:
            changes.append(('device_add', identity))
        elif device != old[identity]:
            changes.append(('device_edit', identity))
    with operation(path, changes):
        _save_settings(path, data)
