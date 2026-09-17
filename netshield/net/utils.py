"""Local-only network and system helpers. No remote lookup clients."""
import ipaddress
import os


def is_root():
    return hasattr(os, 'geteuid') and os.geteuid() == 0


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
