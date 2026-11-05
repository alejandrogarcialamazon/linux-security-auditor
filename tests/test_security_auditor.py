import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import security_auditor as auditor


class AuditorTests(unittest.TestCase):
    def test_command_timeout_is_reported(self):
        with patch.object(auditor.subprocess, 'run', side_effect=subprocess.TimeoutExpired('test', 12)):
            code, out, err = auditor.command(['test'])
        self.assertEqual(code, 127)
        self.assertEqual(out, '')
        self.assertTrue(err)

    def test_ufw_permission_error_is_unknown(self):
        with patch.object(auditor.shutil, 'which', return_value='/usr/sbin/ufw'), patch.object(
            auditor, 'command', return_value=(1, '', 'Permission denied')
        ):
            self.assertEqual(auditor.audit_firewall()[0].status, 'WARN')

    def test_ufw_active_and_inactive(self):
        for output, expected in [('Status: active', 'PASS'), ('Status: inactive', 'FAIL')]:
            with self.subTest(output=output), patch.object(auditor.shutil, 'which', return_value='ufw'), patch.object(
                auditor, 'command', return_value=(0, output, '')
            ):
                self.assertEqual(auditor.audit_firewall()[0].status, expected)

    def test_global_directive_preserves_match_and_is_idempotent(self):
        source = '# comment\nInclude /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nMatch User backup\n PermitRootLogin prohibit-password\n'
        result = auditor.replace_or_append_directive(source, 'PermitRootLogin', 'no')
        self.assertTrue(result.startswith('PermitRootLogin no\n'))
        self.assertNotIn('\nPermitRootLogin yes', result)
        self.assertIn('Match User backup\n PermitRootLogin prohibit-password\n', result)
        self.assertEqual(result, auditor.replace_or_append_directive(result, 'PermitRootLogin', 'no'))

    def test_remediation_requires_root(self):
        with patch.object(auditor.os, 'geteuid', return_value=1000):
            with self.assertRaises(PermissionError):
                auditor.remediate_permissions()

    def run_ssh_remediation(self, source, validation=(0, '', ''), effective=None):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'sshd_config'
            config.write_text(source)
            with patch.object(auditor, 'require_root'), patch.object(auditor, 'Path', return_value=config), patch.object(
                auditor.shutil, 'which', return_value='/test/sshd'
            ), patch.object(auditor, 'command', return_value=validation), patch.object(
                auditor, 'ssh_effective_settings', return_value=effective or ({'permitrootlogin': 'no'}, '')
            ):
                try:
                    result = auditor.remediate_ssh_root_login()
                except RuntimeError as exc:
                    result = exc
            return result, config.read_text(), [(p.stat().st_mode & 0o777, p.read_text()) for p in Path(directory).glob('*.bak')]

    def test_ssh_validation_failure_restores_original(self):
        source = 'PermitRootLogin yes\n'
        result, content, backups = self.run_ssh_remediation(source, (1, '', 'invalid'))
        self.assertIsInstance(result, RuntimeError)
        self.assertEqual(content, source)
        self.assertEqual(backups, [(0o600, source)])

    def test_ssh_effective_failure_restores_original(self):
        source = 'PermitRootLogin yes\n'
        result, content, _ = self.run_ssh_remediation(source, effective=({'permitrootlogin': 'yes'}, ''))
        self.assertIsInstance(result, RuntimeError)
        self.assertEqual(content, source)

    def test_ssh_success(self):
        result, content, _ = self.run_ssh_remediation('PermitRootLogin yes\n')
        self.assertIsInstance(result, str)
        self.assertEqual(content, 'PermitRootLogin no\n')
        self.assertIn('Recargue SSH manualmente', result)

    def test_ssh_complex_config_refused_before_write(self):
        for source in ['Include /etc/ssh/conf.d/*\n', 'Match User root\n PermitRootLogin yes\n']:
            result, content, backups = self.run_ssh_remediation(source)
            self.assertIsInstance(result, RuntimeError)
            self.assertEqual(content, source)
            self.assertEqual(backups, [])

    def test_report_roundtrip_and_markdown_escaping(self):
        finding = auditor.Finding('TEST', 'Title|line', 'FAIL', 'high', 'one\ntwo', 'Fix')
        data = auditor.report_data([finding])
        self.assertEqual(data['summary'], {'PASS': 0, 'FAIL': 1, 'WARN': 0, 'INFO': 0})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'nested' / 'report.json'
            auditor.write_report(data, path, 'json')
            self.assertEqual(json.loads(path.read_text()), data)
        self.assertIn('Title\\|line', auditor.markdown_report(data))
        self.assertIn('one two', auditor.markdown_report(data))

    def test_cli_refuses_unconfirmed_remediation(self):
        result = subprocess.run([sys.executable, 'security_auditor.py', '--remediate', 'permissions'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('requiere --yes', result.stderr)

    def test_cli_exit_codes(self):
        for status, expected in [('PASS', 0), ('FAIL', 1)]:
            with self.subTest(status=status), patch.object(sys, 'argv', ['security_auditor.py']), patch.object(
                auditor, 'audit', return_value=[auditor.Finding('T', 'test', status, 'low', '', '')]
            ), patch('builtins.print'):
                self.assertEqual(auditor.main(), expected)


if __name__ == '__main__':
    unittest.main()
