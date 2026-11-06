"""Classify incomplete evidence without changing the real host."""
import os
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import security_auditor as auditor


class CommandTests(unittest.TestCase):
    def test_locale_is_fixed_without_mutating_parent_environment(self):
        with patch.dict(os.environ, {'LANG': 'es_AR.UTF-8', 'LC_ALL': 'es_AR.UTF-8', 'LANGUAGE': 'es', 'PATH': '/test'}), patch.object(
            auditor.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=' active\n', stderr='')
        ) as run:
            self.assertEqual(auditor.command(['test']), (0, 'active', ''))
            options = run.call_args.kwargs
            self.assertEqual([options['env'][k] for k in ['LANG', 'LC_ALL', 'LANGUAGE']], ['C'] * 3)
            self.assertEqual(options['env']['PATH'], '/test')
            self.assertEqual(os.environ['LANG'], 'es_AR.UTF-8')
            self.assertFalse(options.get('shell', False))
            self.assertEqual(options['timeout'], 12)
            self.assertEqual(options['errors'], 'replace')

    def test_os_errors_and_timeout_are_distinct(self):
        for error, code in [(FileNotFoundError('absent'), 127), (PermissionError('denied'), 127), (subprocess.TimeoutExpired('test', 12), 124)]:
            with self.subTest(error=error), patch.object(auditor.subprocess, 'run', side_effect=error):
                result = auditor.command(['test'])
                self.assertEqual(result[0], code)
                self.assertEqual(result[1], '')
                self.assertTrue(result[2])


class SSHClassificationTests(unittest.TestCase):
    def test_known_and_unknown_root_values(self):
        for value, status in [('no', 'PASS'), ('yes', 'FAIL'), ('without-password', 'FAIL'), ('prohibit-password', 'FAIL'), ('forced-commands-only', 'FAIL'), ('', 'WARN'), ('unexpected', 'WARN'), (None, 'WARN')]:
            settings = {'passwordauthentication': 'no'}
            if value is not None:
                settings['permitrootlogin'] = value
            with self.subTest(value=value), patch.object(auditor, 'ssh_effective_settings', return_value=(settings, '')):
                result = auditor.audit_ssh()[0]
            self.assertEqual(result.status, status)
            self.assertEqual(result.remediable, status == 'FAIL')

    def test_unknown_password_value_explains_incomplete_evidence(self):
        with patch.object(auditor, 'ssh_effective_settings', return_value=({'permitrootlogin': 'no'}, '')):
            result = auditor.audit_ssh()[1]
        self.assertEqual(result.status, 'WARN')
        self.assertIn('valor válido', result.recommendation)
        self.assertFalse(result.remediable)

    def test_command_error_marks_both_controls_warn(self):
        for error in ['Permission denied', 'Timed out', 'No configuration', 'Malformed output']:
            with patch.object(auditor, 'ssh_effective_settings', return_value=({}, error)):
                results = auditor.audit_ssh()
            self.assertEqual([item.id for item in results], ['CIS-LITE-003', 'CIS-LITE-004', 'CIS-LITE-007'])
            self.assertEqual([item.status for item in results], ['WARN', 'WARN', 'WARN'])
            self.assertFalse(any(item.remediable for item in results))

    def query(self, response):
        with patch.object(auditor.shutil, 'which', return_value='/test/sshd'), patch.object(
            auditor.Path, 'exists', return_value=True
        ), patch.object(auditor, 'command', return_value=response):
            return auditor.ssh_effective_settings()

    def test_effective_output_parsing(self):
        settings, error = self.query((0, 'port 22\npermitrootlogin no\npasswordauthentication yes\n', ''))
        self.assertEqual(settings, {'permitrootlogin': 'no', 'passwordauthentication': 'yes'})
        self.assertFalse(error)

    def test_empty_unrecognized_duplicate_and_failed_output(self):
        for response in [(0, '', ''), (0, 'unexpected output', ''), (0, 'permitrootlogin no\npermitrootlogin yes', ''), (1, 'permitrootlogin no', 'Permission denied'), (124, '', 'Timeout')]:
            with self.subTest(response=response):
                settings, error = self.query(response)
                self.assertEqual(settings, {})
                self.assertTrue(error)

    def test_config_permission_error_is_captured(self):
        with patch.object(auditor.shutil, 'which', return_value='/test/sshd'), patch.object(
            auditor.Path, 'exists', side_effect=PermissionError('denied')
        ):
            settings, error = auditor.ssh_effective_settings()
        self.assertEqual(settings, {})
        self.assertIn('denied', error)

    def test_missing_executable_is_inconclusive(self):
        with patch.object(auditor.shutil, 'which', return_value=None):
            settings, error = auditor.ssh_effective_settings()
        self.assertEqual(settings, {})
        self.assertTrue(error)


class ServiceClassificationTests(unittest.TestCase):
    def test_exit_code_and_output_must_agree(self):
        cases = [
            ((0, 'active', ''), True), ((3, 'inactive', ''), False), ((3, 'failed', ''), False),
            ((0, '', ''), None), ((0, 'unexpected', ''), None), ((3, '', ''), None),
            ((4, 'unknown', ''), None), ((4, 'inactive', ''), None), ((3, 'activating', ''), None),
            ((3, 'deactivating', ''), None), ((1, '', 'Permission denied'), None),
            ((124, '', 'Timeout'), None), ((127, '', 'not found'), None), ((1, 'active', ''), None),
        ]
        for response, expected in cases:
            with self.subTest(response=response), patch.object(auditor.shutil, 'which', return_value='systemctl'), patch.object(
                auditor, 'command', return_value=response
            ):
                self.assertIs(auditor.service_is_active('test')[0], expected)

    def test_unavailable_systemctl_generates_warn_for_each_control(self):
        with patch.object(auditor.shutil, 'which', return_value=None):
            results = auditor.audit_services()
        self.assertEqual(len(results), 5)
        self.assertTrue(all(item.status == 'WARN' for item in results))
        self.assertTrue(all(not item.remediable for item in results))

    def test_unknown_state_is_not_pass_or_info(self):
        with patch.object(auditor, 'service_is_active', return_value=(None, 'unknown')):
            results = auditor.audit_services()
        self.assertTrue(all(item.status == 'WARN' for item in results))


class FirewallClassificationTests(unittest.TestCase):
    def test_ufw_requires_single_recognized_status_and_success(self):
        cases = [
            ((0, 'Status: active\nRules follow', ''), 'PASS'),
            ((0, 'Status: inactive', ''), 'FAIL'),
            ((0, '', ''), 'WARN'), ((0, 'Estado: activo', ''), 'WARN'),
            ((0, 'Diagnostic: Status: active', ''), 'WARN'),
            ((0, 'Status: active\nStatus: inactive', ''), 'WARN'),
            ((0, 'Status: active\nStatus: unexpected', ''), 'WARN'),
            ((0, 'Status: active\nStatus: active', ''), 'WARN'),
            ((1, 'Status: inactive', 'Permission denied'), 'WARN'),
            ((1, 'Status: active', 'error'), 'WARN'), ((124, '', 'Timeout'), 'WARN'),
        ]
        for response, expected in cases:
            with self.subTest(response=response), patch.object(auditor.shutil, 'which', return_value='ufw'), patch.object(
                auditor, 'command', return_value=response
            ):
                self.assertEqual(auditor.audit_firewall()[0].status, expected)

    def test_iptables_requires_single_valid_drop_policy_and_success(self):
        cases = [
            ((0, '-P INPUT DROP\n-P OUTPUT ACCEPT', ''), 'PASS'),
            ((0, '  -P   INPUT   DROP ', ''), 'PASS'),
            ((0, '-P INPUT ACCEPT', ''), 'WARN'), ((0, '-P INPUT REJECT', ''), 'WARN'),
            ((0, '-P INPUT DROP\n-P INPUT ACCEPT', ''), 'WARN'),
            ((0, '-P INPUT DROP extra', ''), 'WARN'), ((0, '-P OUTPUT DROP', ''), 'WARN'),
            ((0, '', ''), 'WARN'), ((1, '-P INPUT DROP', 'error'), 'WARN'),
            ((124, '', 'Timeout'), 'WARN'),
        ]
        for response, expected in cases:
            with self.subTest(response=response), patch.object(auditor.shutil, 'which', side_effect=[None, 'iptables']), patch.object(
                auditor, 'command', return_value=response
            ):
                self.assertEqual(auditor.audit_firewall()[0].status, expected)

    def test_no_supported_firewall_is_warn(self):
        with patch.object(auditor.shutil, 'which', return_value=None):
            self.assertEqual(auditor.audit_firewall()[0].status, 'WARN')


class InconclusiveReportTests(unittest.TestCase):
    def test_valid_lab_report_keeps_original_findings(self):
        info = SimpleNamespace(st_mode=0o100640, st_uid=0, st_gid=0)
        with patch.object(auditor.Path, 'lstat', return_value=info), patch.object(
            auditor, 'ssh_effective_settings', return_value=({'permitrootlogin': 'without-password', 'passwordauthentication': 'yes'}, '')
        ), patch.object(auditor, 'service_is_active', return_value=(False, 'inactive')), patch.object(
            auditor.shutil, 'which', return_value='ufw'
        ), patch.object(auditor, 'command', return_value=(0, 'Status: inactive', '')):
            data = auditor.report_data(auditor.audit())
        self.assertEqual(data['summary'], {'PASS': 7, 'FAIL': 2, 'WARN': 2, 'INFO': 0})
        self.assertEqual([item['id'] for item in data['findings'] if item['status'] == 'FAIL'], ['CIS-LITE-003', 'CIS-LITE-006'])

    def test_completely_inconclusive_audit_does_not_contain_pass_or_fail(self):
        with patch.object(auditor.shutil, 'which', return_value=None), patch.object(
            auditor.Path, 'lstat', side_effect=PermissionError('denied')
        ):
            data = auditor.report_data(auditor.audit())
        self.assertEqual(data['summary'], {'PASS': 0, 'FAIL': 0, 'WARN': 11, 'INFO': 0})
        self.assertFalse(any(item['remediable'] for item in data['findings']))

    def test_warn_only_retains_compatible_zero_exit_code(self):
        with patch.object(auditor.sys, 'argv', ['security_auditor.py']), patch.object(
            auditor, 'audit', return_value=[auditor.Finding('T', 'test', 'WARN', 'medium', 'unknown', 'Review')]
        ), patch('builtins.print'):
            self.assertEqual(auditor.main(), 0)

    def test_remediation_error_keeps_exit_code_two(self):
        with patch.object(auditor.sys, 'argv', ['security_auditor.py', '--remediate', 'permissions', '--yes']), patch.object(
            auditor, 'remediate_permissions', side_effect=PermissionError('denied')
        ), patch('builtins.print'):
            self.assertEqual(auditor.main(), 2)


if __name__ == '__main__':
    unittest.main()
