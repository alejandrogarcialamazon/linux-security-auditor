"""SSH contexts, advisory authentication interpretation and real -T fixtures."""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import security_auditor as a


SAFE = {
    'permitrootlogin': 'no', 'passwordauthentication': 'no',
    'kbdinteractiveauthentication': 'no', 'pubkeyauthentication': 'yes',
    'usepam': 'yes', 'authenticationmethods': 'any',
}


class ContextTests(unittest.TestCase):
    def test_normalizes_field_order_ips_and_port(self):
        one = a.parse_ssh_context('user=root,addr=::1,lport=0022,host=localhost')
        two = a.parse_ssh_context('host=localhost,lport=22,addr=0:0:0:0:0:0:0:1,user=root')
        self.assertEqual(one, two)
        self.assertEqual(a.ssh_context_spec(one), 'addr=::1,host=localhost,lport=22,user=root')

    def test_rejects_incomplete_unknown_duplicate_and_injected_fields(self):
        invalid = ['user=root', 'addr=127.0.0.1', 'user=root,addr=invalid', 'user=root,addr=127.0.0.1,port=22',
                   'user=root,user=other,addr=127.0.0.1', 'user=root,addr=127.0.0.1,lport=0',
                   'user=root,addr=127.0.0.1,lport=65536', 'user=root,addr=127.0.0.1,lport=no',
                   'user=,addr=127.0.0.1', 'user=root\nother,addr=127.0.0.1', 'user=root,addr=127.0.0.1,']
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                a.parse_ssh_context(value)
        with self.assertRaises(ValueError):
            a.normalize_ssh_context({'user': 'root,host=evil', 'addr': '127.0.0.1'})

    def test_query_passes_one_literal_context_argument(self):
        context = a.parse_ssh_context('user=root,addr=127.0.0.1')
        with patch.object(a.shutil, 'which', return_value='/test/sshd'), patch.object(Path, 'exists', return_value=True), patch.object(
            a, 'command', return_value=(0, 'permitrootlogin no\npasswordauthentication no', '')
        ) as command:
            settings, error = a.ssh_effective_settings(context, Path('/tmp/custom.conf'))
        self.assertFalse(error)
        self.assertEqual(settings['permitrootlogin'], 'no')
        self.assertEqual(command.call_args.args[0], ['/test/sshd', '-T', '-f', '/tmp/custom.conf', '-C', 'addr=127.0.0.1,user=root'])

    def test_invalid_api_context_does_not_execute(self):
        with patch.object(a.shutil, 'which', return_value='/test/sshd'), patch.object(Path, 'exists', return_value=True), patch.object(a, 'command') as command:
            settings, error = a.ssh_effective_settings({'user': 'root'})
        self.assertEqual(settings, {})
        self.assertIn('Contexto SSH inválido', error)
        command.assert_not_called()

    def test_alias_is_explained_and_still_fails_no_root_policy(self):
        for value in ['without-password', 'prohibit-password', 'forced-commands-only', 'yes']:
            with patch.object(a, 'ssh_effective_settings', return_value=(SAFE | {'permitrootlogin': value}, '')):
                finding = a.audit_ssh()[0]
            self.assertEqual(finding.status, 'FAIL')
            self.assertIn('contexto=global', finding.evidence)
            self.assertGreater(len(finding.evidence), len('permitrootlogin=' + value))
        with patch.object(a, 'ssh_effective_settings', return_value=(SAFE | {'permitrootlogin': 'without-password'}, '')):
            self.assertIn('alias de prohibit-password', a.audit_ssh()[0].evidence)

    def test_context_ids_are_stable_unique_and_grouped_by_family(self):
        one = a.parse_ssh_context('user=root,addr=127.0.0.1')
        duplicate = a.parse_ssh_context('addr=127.0.0.1,user=root')
        other = a.parse_ssh_context('user=root,addr=127.0.0.2')
        with patch.object(a, 'ssh_effective_settings', return_value=(SAFE | {'permitrootlogin': 'yes'}, '')):
            first = a.audit_ssh([one, duplicate, other])
            second = a.audit_ssh([other, one])
        self.assertEqual(len(first), 9)
        self.assertEqual(len({f.id for f in first}), 9)
        self.assertEqual({f.id for f in first}, {f.id for f in second})
        self.assertEqual(a.report_data(first)['scope']['control_families'], 3)
        self.assertTrue(all(not f.remediable for f in first if f.context))
        self.assertEqual(first[3].context, one)
        self.assertEqual(first[3].source, '/etc/ssh/sshd_config')

    def test_global_and_context_can_have_different_outcomes(self):
        def query(context=None, config=None):
            return SAFE | ({'permitrootlogin': 'yes'} if context else {}), ''
        with patch.object(a, 'ssh_effective_settings', side_effect=query):
            findings = a.audit_ssh([a.parse_ssh_context('user=root,addr=127.0.0.1')])
        self.assertEqual(findings[0].status, 'PASS')
        self.assertEqual(findings[3].status, 'FAIL')
        self.assertFalse(findings[3].remediable)

    def test_custom_config_is_never_automatically_remediable(self):
        with patch.object(a, 'ssh_effective_settings', return_value=(SAFE | {'permitrootlogin': 'yes'}, '')):
            results = a.audit_ssh(config=Path('/tmp/custom.conf'))
        self.assertTrue(all(not f.remediable for f in results))
        self.assertTrue(all(f.source == '/tmp/custom.conf' for f in results))

    def test_unknown_context_result_never_inherits_global_pass(self):
        def query(context=None, config=None):
            return ({}, 'Permission denied') if context else (SAFE, '')
        with patch.object(a, 'ssh_effective_settings', side_effect=query):
            results = a.audit_ssh([a.parse_ssh_context('user=root,addr=127.0.0.1')])
        self.assertEqual([f.status for f in results[:3]], ['PASS'] * 3)
        self.assertEqual([f.status for f in results[3:]], ['WARN'] * 3)

    def test_cli_refuses_remediation_with_custom_scope(self):
        for extra in [['--ssh-context', 'user=root,addr=127.0.0.1'], ['--ssh-config', '/tmp/test']]:
            result = subprocess.run([sys.executable, 'security_auditor.py', '--remediate', 'permissions', '--yes', *extra], text=True, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('opciones son de auditoría', result.stderr)

    def test_limit_is_enforced(self):
        context = a.parse_ssh_context('user=root,addr=127.0.0.1')
        with self.assertRaises(ValueError):
            a.audit_ssh([context] * 17)

    def test_cli_rejects_too_many_contexts(self):
        args = [sys.executable, 'security_auditor.py']
        for _ in range(17):
            args.extend(['--ssh-context', 'user=root,addr=127.0.0.1'])
        result = subprocess.run(args, text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('máximo 16', result.stderr)

    def test_cli_forwards_scope_and_keeps_failure_exit_code(self):
        context = a.parse_ssh_context('user=root,addr=127.0.0.1')
        with patch.object(sys, 'argv', ['security_auditor.py', '--ssh-config', '/tmp/fixture.conf', '--ssh-context', 'user=root,addr=127.0.0.1']), patch.object(
            a, 'audit', return_value=[a.Finding('CIS-LITE-003', 'test', 'FAIL', 'high', 'fixture', 'Review')]
        ) as audit, patch('builtins.print'):
            self.assertEqual(a.main(), 1)
            audit.assert_called_once_with([context], Path('/tmp/fixture.conf'))

    def test_json_preserves_context_and_source(self):
        context = a.parse_ssh_context('user=root,addr=127.0.0.1')
        with patch.object(a, 'ssh_effective_settings', return_value=(SAFE, '')):
            data = json.loads(json.dumps(a.report_data(a.audit_ssh([context]))))
        self.assertEqual(data['findings'][3]['context'], context)
        self.assertEqual(data['findings'][3]['source'], '/etc/ssh/sshd_config')


class AuthenticationTests(unittest.TestCase):
    def test_common_routes_and_multiple_methods(self):
        cases = [
            ({}, 'PASS'),
            ({'passwordauthentication': 'yes'}, 'WARN'),
            ({'kbdinteractiveauthentication': 'yes'}, 'WARN'),
            ({'pubkeyauthentication': 'no'}, 'WARN'),
            ({'authenticationmethods': 'publickey'}, 'PASS'),
            ({'authenticationmethods': 'publickey,password', 'passwordauthentication': 'yes'}, 'INFO'),
            ({'authenticationmethods': 'publickey,keyboard-interactive:pam', 'kbdinteractiveauthentication': 'yes'}, 'INFO'),
            ({'authenticationmethods': 'publickey,publickey'}, 'INFO'),
            ({'authenticationmethods': 'publickey password', 'passwordauthentication': 'yes'}, 'WARN'),
            ({'authenticationmethods': 'publickey,password'}, 'WARN'),
            ({'authenticationmethods': 'unknown'}, 'WARN'),
            ({'authenticationmethods': ''}, 'WARN'),
            ({'authenticationmethods': 'publickey,'}, 'WARN'),
            ({'authenticationmethods': 'gssapi-with-mic'}, 'INFO'),
        ]
        for changed, expected in cases:
            with self.subTest(changed=changed):
                result = a.ssh_authentication_finding(SAFE | changed)
                self.assertEqual(result.status, expected)
                self.assertFalse(result.remediable)
                if expected == 'INFO':
                    self.assertIn('no demuestra', result.evidence)

    def test_missing_values_remain_inconclusive(self):
        for key in SAFE:
            if key == 'permitrootlogin':
                continue
            settings = dict(SAFE)
            del settings[key]
            self.assertEqual(a.ssh_authentication_finding(settings).status, 'WARN')

    def test_parses_all_selected_values_and_rejects_duplicate(self):
        output = '\n'.join(f'{key}\t{value}' for key, value in SAFE.items())
        with patch.object(a.shutil, 'which', return_value='/test/sshd'), patch.object(Path, 'exists', return_value=True), patch.object(
            a, 'command', return_value=(0, output, '')
        ):
            self.assertEqual(a.ssh_effective_settings(), (SAFE, ''))
        with patch.object(a.shutil, 'which', return_value='/test/sshd'), patch.object(Path, 'exists', return_value=True), patch.object(
            a, 'command', return_value=(0, output + '\nusepam no', '')
        ):
            self.assertTrue(a.ssh_effective_settings()[1])


@unittest.skipUnless(shutil.which('sshd') and shutil.which('ssh-keygen'), 'OpenSSH server/keygen no disponible')
class RealOpenSSHTests(unittest.TestCase):
    def test_real_include_match_global_and_two_connection_contexts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / 'fixture_host_key'
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True, capture_output=True)
            include = root / 'included.conf'
            include.write_text('Match User root Address 127.0.0.1\n PermitRootLogin yes\n PasswordAuthentication yes\n')
            config = root / 'sshd_config'
            config.write_text(f'HostKey {key}\nUsePAM no\nPermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nInclude {include}\n')
            snapshots = {p.name: p.read_bytes() for p in root.iterdir()}
            contexts = [a.parse_ssh_context('user=root,addr=127.0.0.1,host=localhost'), a.parse_ssh_context('user=root,addr=127.0.0.2,host=localhost')]
            results = a.audit_ssh(contexts, config)
            self.assertEqual([results[i].status for i in (0, 3, 6)], ['PASS', 'FAIL', 'PASS'], [f.evidence for f in results])
            self.assertTrue(all(not f.remediable for f in results))
            self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, snapshots)

    def test_real_invalid_config_is_warn_without_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'invalid.conf'
            config.write_text('InvalidFixtureDirective yes\n')
            results = a.audit_ssh(config=config)
            self.assertEqual([f.status for f in results], ['WARN'] * 3)
            self.assertEqual(config.read_text(), 'InvalidFixtureDirective yes\n')


if __name__ == '__main__':
    unittest.main()
