"""Reconcile only NetShield-owned INPUT rules; the kernel is the source of truth."""
import ipaddress
import re
import shlex
import subprocess

TAG = 'netshield-managed-v1'
OWNED = re.compile(r'netshield-(?:managed-v1|[0-9a-f]{16})\Z')


def parse_rules(output):
    result = {}
    for line in output.splitlines():
        try:
            parts = shlex.split(line)
            if len(parts) != 10 or parts[:3] != ['-A', 'INPUT', '-s']:
                continue
            if parts[4:7] != ['-m', 'comment', '--comment'] or parts[8:] != ['-j', 'DROP']:
                continue
            if not OWNED.fullmatch(parts[7]):
                continue
            network = ipaddress.IPv4Network(parts[3])
            if network.prefixlen != 32:
                continue
            result.setdefault(str(network.network_address), []).append(parts[2:])
        except ValueError:
            continue
    return result


class Firewall:
    def __init__(self, run=None):
        self.run = run or subprocess.run

    def command(self, *args):
        return self.run(['/usr/sbin/iptables', '-w', '3', *args], check=True,
                        timeout=5, capture_output=True, text=True).stdout

    def snapshot(self):
        return parse_rules(self.command('-S', 'INPUT'))

    def add(self, address):
        address = str(ipaddress.IPv4Address(address))
        if address not in self.snapshot():
            self.command('-I', 'INPUT', '1', '-s', address, '-m', 'comment', '--comment', TAG, '-j', 'DROP')
        return self.snapshot()

    def remove(self, address):
        address = str(ipaddress.IPv4Address(address))
        # Re-read rather than trusting stale UI state or caller-supplied command arguments.
        for rule in self.snapshot().get(address, []):
            self.command('-D', 'INPUT', *rule)
        return self.snapshot()
