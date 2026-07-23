import os
import ipaddress


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
