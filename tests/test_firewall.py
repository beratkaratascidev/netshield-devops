import unittest
from types import SimpleNamespace
from netshield.core.firewall import Firewall, parse_rules


class FirewallTests(unittest.TestCase):
    def test_only_exact_owned_single_host_drop_rules_are_recovered(self):
        line = '-A INPUT -s 192.0.2.1/32 -m comment --comment netshield-0123456789abcdef -j DROP'
        other = [line.replace('netshield-0123456789abcdef', 'administrator'),
                 line.replace('/32', '/24'), line.replace('INPUT', 'FORWARD'),
                 line.replace('DROP', 'ACCEPT'), line + ' -p tcp']
        rules = parse_rules('\n'.join([line, line, *other]))
        self.assertEqual(set(rules), {'192.0.2.1'})
        self.assertEqual(len(rules['192.0.2.1']), 2)

    def test_restart_recovers_old_rules_and_removes_duplicates_only(self):
        lines = ['-A INPUT -s 192.0.2.1/32 -m comment --comment netshield-0123456789abcdef -j DROP'] * 2
        foreign = '-A INPUT -s 192.0.2.1/32 -m comment --comment administrator -j DROP'
        lines.append(foreign)
        def run(command, **kwargs):
            self.assertEqual(kwargs['timeout'], 5)
            args = command[3:]
            if args[:2] == ['-D', 'INPUT']:
                lines.remove(' '.join(['-A', 'INPUT', *args[2:]]))
            return SimpleNamespace(stdout='\n'.join(lines))
        self.assertIn('192.0.2.1', Firewall(run).snapshot())
        self.assertEqual(Firewall(run).remove('192.0.2.1'), {})
        self.assertEqual(lines, [foreign])

    def test_existing_rule_is_not_added_again(self):
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(stdout='-A INPUT -s 192.0.2.1/32 -m comment --comment netshield-managed-v1 -j DROP')
        Firewall(run).add('192.0.2.1')
        self.assertTrue(all('-I' not in call for call in calls))
