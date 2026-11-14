import json
import unittest
import host_checks as h
from security_auditor import Finding


class FirewallTests(unittest.TestCase):
    def nft(self, payload, code=0):
        return h.firewall_extensions(lambda args: (code, json.dumps(payload), 'denied' if code else ''), lambda name: name if name == 'nft' else None, Finding)[0]

    def test_nft_dual_stack_and_partial_coverage(self):
        for family, expected in [('inet', 'PASS'), ('ip', 'WARN'), ('ip6', 'WARN'), ('bridge', 'WARN')]:
            self.assertEqual(self.nft({'nftables': [{'chain': {'family': family, 'hook': 'input', 'policy': 'drop', 'name': 'input'}}]}).status, expected)

    def test_nft_unknown_empty_and_failed_never_pass(self):
        for payload in [{}, {'nftables': []}, {'nftables': None}, {'nftables': [{'chain': []}]}, {'nftables': [{'chain': {'family': 'inet', 'hook': 'input', 'policy': 'accept'}}]}]:
            self.assertEqual(self.nft(payload).status, 'WARN')
        self.assertEqual(self.nft({'nftables': []}, 1).status, 'WARN')

    def test_firewalld_targets_and_query_errors(self):
        for target, expected in [('DROP', 'PASS'), ('REJECT', 'PASS'), ('ACCEPT', 'WARN'), ('default', 'WARN')]:
            def run(args):
                return (0, 'running', '') if '--state' in args else ((0, 'public\n  interfaces: eth0', '') if '--get-active-zones' in args else (0, target, ''))
            result = h.firewall_extensions(run, lambda name: name if name == 'firewall-cmd' else None, Finding)[1]
            self.assertEqual(result.status, expected)

    def test_ipv6_policy_and_errors(self):
        for code, value, expected in [(0, '-P INPUT DROP', 'PASS'), (0, '-P INPUT ACCEPT', 'WARN'), (1, '-P INPUT DROP', 'WARN'), (0, '-P INPUT DROP\n-P INPUT DROP', 'WARN')]:
            result = h.firewall_extensions(lambda args: (code, value, ''), lambda name: name if name == 'ip6tables' else None, Finding)[-1]
            self.assertEqual(result.status, expected)

    def test_all_backends_are_consulted_without_mutation(self):
        calls = []
        def run(args):
            calls.append(args)
            return 1, '', 'denied'
        result = h.firewall_extensions(run, lambda name: name, Finding, True)
        self.assertEqual(len(result), 4)
        self.assertEqual({args[0] for args in calls}, {'nft', 'firewall-cmd', 'iptables', 'ip6tables'})
        self.assertTrue(all(f.status == 'WARN' for f in result))


class ServicesTests(unittest.TestCase):
    def probe(self, active=None, enabled=None, processes='systemd\nsshd', ports='', error=None):
        def run(args):
            if args[0] == error:
                return 1, '', 'denied'
            if args[0] == 'ss':return 0, ports, ''
            if args[0] == 'ps':return 0, processes, ''
            unit = args[2]
            return 0, f'LoadState=loaded\nActiveState={"active" if unit == active else "inactive"}\nUnitFileState={"enabled" if unit == enabled else "disabled"}', ''
        return h.services(run, lambda name: name, Finding)

    def test_clean_supported_probes_pass_with_unique_ids(self):
        result = self.probe()
        self.assertTrue(all(f.status == 'PASS' for f in result))
        self.assertEqual(len({f.id for f in result}), 5)

    def test_service_variant_active_even_when_primary_socket_inactive(self):
        self.assertEqual(self.probe(active='telnetd.service')[0].status, 'FAIL')

    def test_process_outside_systemd_is_detected(self):
        self.assertEqual(self.probe(processes='systemd\nin.telnetd')[0].status, 'FAIL')

    def test_enabled_inactive_warns(self):
        self.assertEqual(self.probe(enabled='tftpd.service')[3].status, 'WARN')

    def test_port_is_warning_not_proof_of_protocol(self):
        result = self.probe(ports='tcp LISTEN 0 128 [::]:23 [::]:*')
        self.assertEqual(result[0].status, 'WARN')
        self.assertEqual(result[1].status, 'PASS')

    def test_missing_or_failed_visibility_cannot_pass(self):
        for error in ['ss', 'ps', 'systemctl']:
            self.assertTrue(all(f.status == 'WARN' for f in self.probe(error=error)))
        self.assertTrue(all(f.status == 'WARN' for f in h.services(lambda args: (0, '', ''), lambda name: None, Finding)))

    def test_malformed_listeners_are_inconclusive(self):
        self.assertTrue(all(f.status == 'WARN' for f in self.probe(ports='malformed')))
        with self.assertRaises(ValueError):h.parse_listeners('tcp LISTEN 0 0 invalid *:*')


if __name__ == '__main__':unittest.main()
