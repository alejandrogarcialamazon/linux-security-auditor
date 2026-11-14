import io
import json
import os
import stat
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import remediation_plan as p
import security_auditor as a


class PermissionPlanTests(unittest.TestCase):
    def metadata(self, mode=0o660, uid=0):
        return SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=uid, st_gid=0, st_dev=1, st_ino=2)

    def test_exact_diff_never_expands_mode_or_changes_group(self):
        with patch.object(Path, 'lstat', return_value=self.metadata()), patch.object(os, 'chmod') as chmod, patch.object(os, 'chown') as chown:
            result = p.permissions([(Path('/fixture/shadow'), 'TEST', 'test')], a.allowed_account_mode)
        self.assertEqual(result['status'], 'planned')
        self.assertEqual(result['operations'][0]['before']['mode'], '0660')
        self.assertEqual(result['operations'][0]['after'], {'uid': 0, 'gid': 0, 'mode': '0640'})
        self.assertFalse(result['applied'])
        chmod.assert_not_called();chown.assert_not_called()

    def test_restrictive_mode_is_noop(self):
        with patch.object(Path, 'lstat', return_value=self.metadata(0o400)):
            result = p.permissions([(Path('/fixture/shadow'), 'TEST', 'test')], a.allowed_account_mode)
        self.assertEqual(result['status'], 'no_changes')
        self.assertEqual(result['operations'], [])

    def test_wrong_owner_is_planned_without_adding_permissions(self):
        with patch.object(Path, 'lstat', return_value=self.metadata(0o400, uid=1000)):
            result = p.permissions([(Path('/fixture/shadow'), 'TEST', 'test')], a.allowed_account_mode)
        self.assertEqual(result['operations'][0]['after'], {'uid': 0, 'gid': 0, 'mode': '0400'})

    def test_missing_or_nonregular_file_blocks_entire_plan(self):
        for error in [PermissionError('denied'), FileNotFoundError('missing')]:
            with patch.object(Path, 'lstat', side_effect=error):
                result = p.permissions(a.ACCOUNT_FILES, a.allowed_account_mode)
            self.assertEqual(result['status'], 'blocked')
            self.assertEqual(len(result['blockers']), 2)
        with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFLNK | 0o777)):
            self.assertEqual(p.permissions(a.ACCOUNT_FILES, a.allowed_account_mode)['status'], 'blocked')

    def test_report_does_not_offer_batch_fix_when_other_file_is_unavailable(self):
        with patch.object(Path, 'lstat', side_effect=[self.metadata(uid=1000), FileNotFoundError('missing')]):
            self.assertFalse(any(f.remediable for f in a.audit_file_permissions()))


class SSHPlanTests(unittest.TestCase):
    def test_real_temporary_config_is_unchanged_and_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'sshd_config'
            content = 'PermitRootLogin yes\n# PRIVATE_FIXTURE_VALUE_DO_NOT_EXPOSE\n'
            config.write_text(content)
            def capability(path):return p.ssh_capability(path, lambda name: '/test/sshd')
            result = p.ssh(config, capability, a.replace_or_append_directive)
            self.assertEqual(result['status'], 'planned')
            self.assertNotIn('PRIVATE_FIXTURE', json.dumps(result))
            self.assertEqual(config.read_text(), content)
            self.assertEqual(list(Path(directory).iterdir()), [config])

    def test_match_include_missing_binary_and_symlink_are_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'sshd_config'
            for content in ['Match User root\n PermitRootLogin yes\n', 'Include /fixture/*\n']:
                config.write_text(content)
                self.assertFalse(p.ssh_capability(config, lambda name: 'sshd')[0])
            config.write_text('PermitRootLogin yes\n')
            self.assertFalse(p.ssh_capability(config, lambda name: None)[0])
            link = Path(directory) / 'link'
            link.symlink_to(config)
            self.assertFalse(p.ssh_capability(link, lambda name: 'sshd')[0])

    def test_ready_config_and_no_changes(self):
        capability = lambda path: (True, '', 'PermitRootLogin no\n')
        result = p.ssh(Path('/fixture/config'), capability, a.replace_or_append_directive)
        self.assertEqual(result['status'], 'no_changes')
        self.assertTrue(any('sshd -t' in item for item in result['requirements']))

    def test_blocked_plan_has_no_operations(self):
        result = p.ssh(Path('/fixture/config'), lambda path: (False, 'unavailable', ''), a.replace_or_append_directive)
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(result['operations'], [])

    def test_unreadable_or_invalid_encoding_is_blocked(self):
        with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFREG)), patch.object(Path, 'open', side_effect=PermissionError('denied')):
            self.assertFalse(p.ssh_capability(Path('/fixture/config'), lambda name: 'sshd')[0])

    def test_remediability_agrees_with_capability(self):
        with patch.object(a, 'ssh_effective_settings', return_value=({'permitrootlogin': 'yes', 'passwordauthentication': 'no'}, '')), patch.object(
            a, 'ssh_remediation_capability', return_value=(False, 'Include', '')
        ):
            self.assertFalse(a.audit_ssh()[0].remediable)


class CLIPlanTests(unittest.TestCase):
    def invoke(self, args, plan):
        with patch.object(a.sys, 'argv', ['security_auditor.py', *args]), patch.object(a, 'plan_remediation', return_value=plan), patch.object(
            a, 'remediate_permissions'
        ) as apply, patch.object(a, 'require_root') as root, patch('sys.stdout', new_callable=io.StringIO) as stream:
            status = a.main()
            apply.assert_not_called();root.assert_not_called()
            return status, stream.getvalue()

    def test_dry_run_does_not_require_confirmation_or_root(self):
        result = p.base('permissions');result['status'] = 'planned'
        status, output = self.invoke(['--remediate', 'permissions', '--dry-run'], result)
        self.assertEqual(status, 0)
        self.assertFalse(json.loads(output)['applied'])

    def test_yes_cannot_turn_dry_run_into_application(self):
        status, _ = self.invoke(['--remediate', 'permissions', '--dry-run', '--yes'], p.base('permissions'))
        self.assertEqual(status, 0)

    def test_blocked_exit_is_two_and_markdown_is_available(self):
        result = p.base('permissions');result['status'] = 'blocked'
        status, output = self.invoke(['--remediate', 'permissions', '--dry-run', '--format', 'markdown'], result)
        self.assertEqual(status, 2)
        self.assertIn('sin aplicar', output)

    def test_output_is_only_explicit_report_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'nested' / 'plan.json'
            status, _ = self.invoke(['--remediate', 'permissions', '--dry-run', '--output', str(path)], p.base('permissions'))
            self.assertEqual(status, 0)
            self.assertTrue(json.loads(path.read_text())['dry_run'])

    def test_cli_requires_explicit_control_and_rejects_custom_ssh_scope(self):
        for args in [['--dry-run'], ['--remediate', 'ssh-root-login', '--dry-run', '--ssh-config', '/fixture/config']]:
            result = subprocess.run([sys.executable, 'security_auditor.py', *args], text=True, capture_output=True)
            self.assertEqual(result.returncode, 2)

    def test_unchanged_ssh_still_requires_validation(self):
        with patch.object(a, 'require_root'), patch.object(a.shutil, 'which', return_value='sshd'), patch.object(
            a, 'ssh_remediation_capability', return_value=(True, '', 'PermitRootLogin no\n')
        ), patch.object(a, 'command', return_value=(1, '', 'invalid')), patch.object(
            a, 'ssh_effective_settings', return_value=({'permitrootlogin': 'no'}, '')
        ):
            with self.assertRaisesRegex(RuntimeError, 'validar SSH'):
                a.remediate_ssh_root_login()


if __name__ == '__main__':unittest.main()
