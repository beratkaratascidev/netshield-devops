"""Local privacy policy. This is an application boundary, not an OS sandbox."""
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import stat
import tempfile
from pathlib import Path
from html import escape

MANAGED_PATH = Path('/etc/netshield/policy.json')
RESTRICTIONS = ('allow_exports', 'allow_clipboard', 'allow_firewall')


def validate_security(value):
    if not isinstance(value, dict):
        raise ValueError('Güvenlik ayarları nesne olmalı.')
    profile = value.get('profile', 'Bireysel')
    if profile not in ('Bireysel', 'Kurumsal'):
        raise ValueError('Geçersiz güvenlik profili.')
    result = dict(profile=profile)
    for key, default in (('allow_exports', True), ('allow_clipboard', False), ('allow_firewall', False)):
        flag = value.get(key, default)
        if type(flag) is not bool:
            raise ValueError(f'Geçersiz güvenlik seçeneği: {key}')
        result[key] = flag if profile == 'Bireysel' else False
    return result


def load_managed_policy(path=MANAGED_PATH):
    """Only root-owned, non-writable-by-others policy files are trusted on POSIX."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(fd, encoding='utf-8') as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError('Politika normal bir dosya olmalı.')
            if os.name == 'posix' and (metadata.st_uid != 0 or metadata.st_mode & 0o022):
                raise ValueError('Politika root sahipliğinde olmalı; grup/diğer kullanıcılar yazamamalı.')
            if metadata.st_size > 16384:
                raise ValueError('Politika dosyası 16 KiB sınırını aşıyor.')
            policy = json.load(source)
        if not isinstance(policy, dict) or set(policy) - set(RESTRICTIONS):
            raise ValueError('Bilinmeyen politika alanı.')
        if any(type(value) is not bool for value in policy.values()):
            raise ValueError('Politika değerleri true/false olmalı.')
        return policy, None
    except FileNotFoundError:
        if os.path.lexists(path):
            return dict.fromkeys(RESTRICTIONS, False), 'Yönetici politikası bağlantısı geçersiz; işlemler kapalı.'
        return {}, None
    except (OSError, ValueError, TypeError) as exc:
        return dict.fromkeys(RESTRICTIONS, False), f'Yönetici politikası okunamadı; dışa aktarım, pano ve firewall kapalı: {exc}'


def effective_policy(preferences, managed):
    result = validate_security(preferences)
    for key in RESTRICTIONS:
        result[key] = result[key] and managed.get(key, True)
    return result


def private_write(path, contents):
    """Replace a selected file atomically with mode 0600; never follow its symlink."""
    path = Path(path)
    if path.is_symlink():
        raise OSError('Sembolik bağlantıya kayıt yapılmaz.')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix='.netshield-', delete=False) as output:
            temporary = Path(output.name)
            os.chmod(temporary, 0o600)
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class PrivateSnapshot:
    """Allowlisted export; fresh keyed aliases per export, no reversible key stored."""
    def __init__(self):
        self._key = secrets.token_bytes(32)

    def address(self, value):
        try:
            canonical = str(ipaddress.ip_address(value))
        except ValueError:
            return 'Çoklu / belirtilmedi'
        return 'host-' + hmac.new(self._key, canonical.encode(), hashlib.sha256).hexdigest()[:16]

    def packet(self, packet):
        return {**{key: packet.get(key) for key in
                   ('ts', 'sport', 'dport', 'proto', 'transport', 'length', 'flags', 'simulated')},
                'src': self.address(packet.get('src')), 'dst': self.address(packet.get('dst'))}

    def alert(self, event):
        return {**{key: event.get(key) for key in
                   ('ts', 'tur', 'count', 'threshold', 'window', 'severity', 'reviewed', 'simulated')},
                'ip': self.address(event.get('ip')), 'dst': self.address(event.get('dst'))}

    def session(self, packets, alerts, total):
        return dict(schema_version=2, privacy='IP takma kimliği; içerik ve serbest metin yok',
                    total_packets=total, packets=[self.packet(p) for p in packets],
                    alerts=[self.alert(e) for e in alerts])


def render_report(snapshot):
    def cell(value):
        return escape('—' if value is None else str(value), quote=True)
    columns = ('ts', 'tur', 'ip', 'dst', 'severity', 'count', 'threshold', 'window', 'reviewed')
    rows = ''.join('<tr>' + ''.join(f'<td>{cell(event.get(key))}</td>' for key in columns) + '</tr>'
                   for event in snapshot['alerts'])
    return '''<!doctype html><html lang="tr"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>NetShield · Yerel güvenlik raporu</title>
<style>body{background:#101722;color:#dce6f2;font:14px sans-serif;padding:30px}h1{color:#65b7ff}
table{border-collapse:collapse;width:100%}td,th{padding:10px;text-align:left;border-bottom:1px solid #2c3c51}th{color:#94a6bc}</style>
</head><body><h1>NetShield · Yerel güvenlik raporu</h1>
<p>IP adresleri bu dosyaya özel takma kimliklerle gösterilir. Paket yükü ve URL içermez.
Bu işlem ağ üzerinden rapor göndermez; dosyayı paylaşma sorumluluğu kullanıcıdadır.</p>
<table><tr><th>Saat</th><th>Tespit</th><th>Kaynak</th><th>Hedef</th><th>Önem</th><th>Ölçüm</th><th>Eşik</th><th>Pencere</th><th>İncelendi</th></tr>''' + rows + '</table></body></html>'
