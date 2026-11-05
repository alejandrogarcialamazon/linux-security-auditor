"""Account permission regressions; only temporary files and mocked ownership."""
import errno
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import security_auditor as auditor


def metadata(mode=0o640, uid=0, gid=42, kind=stat.S_IFREG):
    return SimpleNamespace(st_mode=kind | mode, st_uid=uid, st_gid=gid)


class AccountAuditTests(unittest.TestCase):
    def audit_one(self, name, info, group='shadow'):
        path = Path('/test') / name
        with patch.object(auditor, 'ACCOUNT_FILES', [(path, 'TEST', name)]), patch.object(
            Path, 'lstat', return_value=info
        ) as read, patch.object(auditor.grp, 'getgrgid', return_value=SimpleNamespace(gr_name=group)):
            result = auditor.audit_file_permissions()[0]
        self.assertEqual(read.call_count, 1)
        return result

    def test_all_permission_bits_against_maximum(self):
        for name, maximum in [('passwd', 0o644), ('shadow', 0o640)]:
            path = Path('/test') / name
            with patch.object(auditor, 'ACCOUNT_FILES', [(path, 'TEST', name)]), patch.object(
                auditor.grp, 'getgrgid', return_value=SimpleNamespace(gr_name='shadow')
            ), patch.object(Path, 'lstat') as read:
                for mode in range(0o10000):
                    read.return_value = metadata(mode)
                    result = auditor.audit_file_permissions()[0]
                    expected = 'FAIL' if mode & ~maximum else 'PASS'
                    self.assertEqual(result.status, expected, f'{name}: {mode:04o}')
                    self.assertEqual(result.remediable, expected == 'FAIL')

    def test_shadow_group_write_is_fail(self):
        self.assertEqual(self.audit_one('shadow', metadata(0o660)).status, 'FAIL')

    def test_restrictive_modes_pass_without_chmod_recommendation(self):
        for name in ['passwd', 'shadow']:
            for mode in [0o000, 0o400, 0o600]:
                result = self.audit_one(name, metadata(mode))
                self.assertEqual(result.status, 'PASS')
                self.assertEqual(result.recommendation, 'Sin cambios necesarios.')

    def test_wrong_owner_is_fail(self):
        self.assertEqual(self.audit_one('passwd', metadata(0o644, uid=1000)).status, 'FAIL')

    def test_shadow_unrelated_group_read_is_fail(self):
        result = self.audit_one('shadow', metadata(), group='users')
        self.assertEqual(result.status, 'FAIL')
        self.assertIn('0600', result.recommendation)

    def test_unrelated_group_without_access_is_accepted(self):
        self.assertEqual(self.audit_one('shadow', metadata(0o600), group='users').status, 'PASS')

    def test_root_group_is_trusted(self):
        self.assertEqual(self.audit_one('shadow', metadata(gid=0), group='users').status, 'PASS')

    def test_unknown_group_is_not_trusted(self):
        with patch.object(auditor.grp, 'getgrgid', side_effect=KeyError(1234)):
            self.assertEqual(auditor.allowed_account_mode(Path('/test/shadow'), metadata()), 0o600)

    def test_nss_failure_is_warn(self):
        with patch.object(Path, 'lstat', return_value=metadata()), patch.object(
            auditor.grp, 'getgrgid', side_effect=OSError('NSS unavailable')
        ):
            result = auditor.audit_file_permissions()[1]
        self.assertEqual(result.status, 'WARN')
        self.assertFalse(result.remediable)

    def test_missing_or_inaccessible_files_are_warn(self):
        for error in [FileNotFoundError('missing'), PermissionError('denied'), OSError('I/O')]:
            with patch.object(Path, 'lstat', side_effect=error):
                findings = auditor.audit_file_permissions()
            self.assertEqual([item.status for item in findings], ['WARN', 'WARN'])
            self.assertFalse(any(item.remediable for item in findings))

    def test_nonregular_files_are_not_remediable(self):
        for kind in [stat.S_IFLNK, stat.S_IFDIR, stat.S_IFIFO, stat.S_IFSOCK]:
            result = self.audit_one('shadow', metadata(kind=kind))
            self.assertEqual(result.status, 'WARN')
            self.assertFalse(result.remediable)


class PermissionRemediationTests(unittest.TestCase):
    def files(self, directory):
        return [(Path(directory) / name, 'TEST', name) for name in ['passwd', 'shadow']]

    def test_real_temporary_modes_never_expand_and_are_idempotent(self):
        real_fstat = os.fstat
        def as_root(fd):
            info = real_fstat(fd)
            return metadata(stat.S_IMODE(info.st_mode), uid=0, gid=0)
        for modes, expected in [((0o400, 0o400), (0o400, 0o400)), ((0o666, 0o660), (0o644, 0o640)), ((0o644, 0o600), (0o644, 0o600)), ((0o755, 0o7640), (0o644, 0o640))]:
            with self.subTest(modes=modes), tempfile.TemporaryDirectory() as directory:
                files = self.files(directory)
                for (path, _, _), mode in zip(files, modes):
                    path.write_text('synthetic fixture\n')
                    path.chmod(mode)
                with patch.object(auditor, 'ACCOUNT_FILES', files), patch.object(auditor, 'require_root'), patch.object(
                    auditor.os, 'fstat', side_effect=as_root
                ), patch.object(auditor.os, 'fchown') as chown:
                    auditor.remediate_permissions()
                    with patch.object(auditor.os, 'fchmod', wraps=os.fchmod) as chmod:
                        self.assertIn('Sin cambios', auditor.remediate_permissions())
                        chmod.assert_not_called()
                    chown.assert_not_called()
                self.assertEqual(tuple(stat.S_IMODE(path.stat().st_mode) for path, _, _ in files), expected)
                for path, _, _ in files:
                    self.assertEqual(path.read_text(), 'synthetic fixture\n')

    def test_symlink_preflight_refuses_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            files = self.files(directory)
            files[0][0].write_text('fixture')
            files[0][0].chmod(0o666)
            files[1][0].symlink_to(files[0][0])
            with patch.object(auditor, 'ACCOUNT_FILES', files), patch.object(auditor, 'require_root'), patch.object(
                auditor.os, 'fchmod'
            ) as chmod, patch.object(auditor.os, 'fchown') as chown:
                with self.assertRaises(OSError) as error:
                    auditor.remediate_permissions()
                self.assertEqual(error.exception.errno, errno.ELOOP)
                chmod.assert_not_called()
                chown.assert_not_called()
            self.assertEqual(stat.S_IMODE(files[0][0].stat().st_mode), 0o666)

    def test_missing_second_file_aborts_before_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            files = self.files(directory)
            files[0][0].write_text('fixture')
            with patch.object(auditor, 'ACCOUNT_FILES', files), patch.object(auditor, 'require_root'), patch.object(
                auditor.os, 'fchmod'
            ) as chmod, patch.object(auditor.os, 'fchown') as chown:
                with self.assertRaises(FileNotFoundError):
                    auditor.remediate_permissions()
                chmod.assert_not_called()
                chown.assert_not_called()

    def test_owner_only_fix_preserves_group_and_mode(self):
        info = metadata(0o400, uid=1000, gid=456)
        def change_owner(fd, uid, gid):
            self.assertEqual((fd, uid, gid), (99, 0, -1))
            info.st_uid = uid
        with patch.object(auditor, 'ACCOUNT_FILES', [(Path('/test/shadow'), 'TEST', 'shadow')]), patch.object(
            auditor, 'require_root'
        ), patch.object(auditor.os, 'open', return_value=99), patch.object(auditor.os, 'close') as close, patch.object(
            auditor.os, 'fstat', return_value=info
        ), patch.object(auditor.os, 'fchown', side_effect=change_owner), patch.object(auditor.os, 'fchmod') as chmod:
            auditor.remediate_permissions()
            chmod.assert_not_called()
            close.assert_called_once_with(99)

    def test_failed_change_is_reported_and_descriptor_closed(self):
        with patch.object(auditor, 'ACCOUNT_FILES', [(Path('/test/passwd'), 'TEST', 'passwd')]), patch.object(
            auditor, 'require_root'
        ), patch.object(auditor.os, 'open', return_value=99), patch.object(auditor.os, 'close') as close, patch.object(
            auditor.os, 'fstat', return_value=metadata(0o666, gid=0)
        ), patch.object(auditor.os, 'fchmod', side_effect=PermissionError('denied')):
            with self.assertRaisesRegex(RuntimeError, 'no hay rollback'):
                auditor.remediate_permissions()
            close.assert_called_once_with(99)

    def test_untrusted_group_read_is_removed_without_changing_group(self):
        info = metadata(0o640, gid=456)
        def change_mode(fd, mode):
            info.st_mode = stat.S_IFREG | mode
        with patch.object(auditor, 'ACCOUNT_FILES', [(Path('/test/shadow'), 'TEST', 'shadow')]), patch.object(
            auditor, 'require_root'
        ), patch.object(auditor.os, 'open', return_value=99), patch.object(auditor.os, 'close'), patch.object(
            auditor.os, 'fstat', return_value=info
        ), patch.object(auditor.grp, 'getgrgid', return_value=SimpleNamespace(gr_name='users')), patch.object(
            auditor.os, 'fchmod', side_effect=change_mode
        ) as chmod, patch.object(auditor.os, 'fchown') as chown:
            auditor.remediate_permissions()
            chmod.assert_called_once_with(99, 0o600)
            chown.assert_not_called()
            self.assertEqual(info.st_gid, 456)

    def test_nss_failure_preflight_aborts_without_mutation(self):
        with patch.object(auditor, 'ACCOUNT_FILES', [(Path('/test/shadow'), 'TEST', 'shadow')]), patch.object(
            auditor, 'require_root'
        ), patch.object(auditor.os, 'open', return_value=99), patch.object(auditor.os, 'close') as close, patch.object(
            auditor.os, 'fstat', return_value=metadata()
        ), patch.object(auditor.grp, 'getgrgid', side_effect=OSError('NSS unavailable')), patch.object(
            auditor.os, 'fchmod'
        ) as chmod, patch.object(auditor.os, 'fchown') as chown:
            with self.assertRaises(OSError):
                auditor.remediate_permissions()
            chmod.assert_not_called()
            chown.assert_not_called()
            close.assert_called_once_with(99)

    def test_failed_postcondition_does_not_report_success(self):
        with patch.object(auditor, 'ACCOUNT_FILES', [(Path('/test/passwd'), 'TEST', 'passwd')]), patch.object(
            auditor, 'require_root'
        ), patch.object(auditor.os, 'open', return_value=99), patch.object(auditor.os, 'close'), patch.object(
            auditor.os, 'fstat', return_value=metadata(0o666, gid=0)
        ), patch.object(auditor.os, 'fchmod'):
            with self.assertRaisesRegex(RuntimeError, 'verificación'):
                auditor.remediate_permissions()

    def test_nonregular_preflight_refused(self):
        with patch.object(auditor, 'ACCOUNT_FILES', [(Path('/test/shadow'), 'TEST', 'shadow')]), patch.object(
            auditor, 'require_root'
        ), patch.object(auditor.os, 'open', return_value=99), patch.object(auditor.os, 'close'), patch.object(
            auditor.os, 'fstat', return_value=metadata(kind=stat.S_IFIFO)
        ), patch.object(auditor.os, 'fchmod') as chmod:
            with self.assertRaisesRegex(RuntimeError, 'no es un archivo regular'):
                auditor.remediate_permissions()
            chmod.assert_not_called()


if __name__ == '__main__':
    unittest.main()
