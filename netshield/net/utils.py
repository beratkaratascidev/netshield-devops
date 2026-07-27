"""NetShield ağ ve sistem yardımcı fonksiyonları."""

import ipaddress
import json
import os
import threading
import urllib.request

from netshield.config import GEO_URL


_geo_cache: dict[str, dict[str, str]] = {}
_geo_lock = threading.Lock()


def is_root() -> bool:
    """Programın root yetkisiyle çalışıp çalışmadığını döndürür."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def is_private(ip: str) -> bool:
    """IP adresinin özel veya yerel bir adres olup olmadığını denetler."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def geo_lookup(ip: str, q) -> None:
    """IP adresinin GEO bilgisini bulup GUI kuyruğuna gönderir."""
    with _geo_lock:
        cached = _geo_cache.get(ip)

    if cached is not None:
        q.put(("GEO", ip, cached))
        return

    if is_private(ip):
        geo = {
            "country": "Yerel Ağ",
            "city": "-",
            "isp": "-",
        }
    else:
        try:
            url = GEO_URL.format(ip=ip)

            with urllib.request.urlopen(url, timeout=4) as response:
                data = json.loads(
                    response.read().decode("utf-8")
                )

            if data.get("status") == "success":
                geo = {
                    "country": data.get("country", "?"),
                    "city": data.get("city", "?"),
                    "isp": data.get("isp", "?"),
                }
            else:
                geo = {
                    "country": "?",
                    "city": "-",
                    "isp": "-",
                }

        except Exception:
            geo = {
                "country": "Zaman aşımı",
                "city": "-",
                "isp": "-",
            }

    with _geo_lock:
        _geo_cache[ip] = geo

    q.put(("GEO", ip, geo))
