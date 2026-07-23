def is_private(ip):
    return ip.startswith(
        ("10.", "192.168.", "127.", "172.16.", "::1", "fe80", "0.")
    )