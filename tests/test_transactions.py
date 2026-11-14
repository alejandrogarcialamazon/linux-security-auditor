import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import fcntl
import remediation_transaction as t


class PermissionTransactions(unittest.TestCase):
    def setup_files(self, directory):
        files = []
        for name in ['passwd', 'shadow']:
            path = Path(directory) / name
            path.write_text('fixture\n');path.chmod(0o666)
            files.append((path, 'FIXTURE', name))
        return files

    def apply(self, files, journal=None):
        return t.fix_permissions(files, lambda path, info: 0o644, journal, owner_uid=os.geteuid())

    def test_real_modes_and_idempotence(self):
        with tempfile.TemporaryDirectory() as root:
            files = self.setup_files(root)
            result = self.apply(files, Path(root) / 'journal.json')
            self.assertEqual(result['status'], 'applied')
            self.assertEqual([stat.S_IMODE(path.stat().st_mode) for path, _, _ in files], [0o644] * 2)
            self.assertEqual(self.apply(files)['status'], 'no_changes')
            self.assertEqual((Path(root) / 'journal.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads((Path(root) / 'journal.json').read_text())['status'], 'applied')

    def test_failure_on_second_file_restores_first(self):
        with tempfile.TemporaryDirectory() as root:
            files = self.setup_files(root);original = os.fchmod;count = 0
            def fail_once(fd, mode):
                nonlocal count
                count += 1
                if count == 2:raise PermissionError('injected')
                return original(fd, mode)
            with patch.object(os, 'fchmod', side_effect=fail_once), self.assertRaises(t.TransactionError) as failure:
                self.apply(files)
            self.assertEqual(failure.exception.record['status'], 'rolled_back')
            self.assertEqual([stat.S_IMODE(path.stat().st_mode) for path, _, _ in files], [0o666] * 2)

    def test_failed_rollback_is_explicit(self):
        with tempfile.TemporaryDirectory() as root:
            files = self.setup_files(root);original = os.fchmod;count = 0
            def failure(fd, mode):
                nonlocal count
                count += 1
                if count in {2, 3}:raise PermissionError('injected')
                return original(fd, mode)
            with patch.object(os, 'fchmod', side_effect=failure), self.assertRaises(t.TransactionError) as error:
                self.apply(files)
            self.assertEqual(error.exception.record['status'], 'rollback_failed')
            self.assertIsNone(error.exception.record['applied'])

    def test_lock_conflict_prevents_changes(self):
        with tempfile.TemporaryDirectory() as root:
            files = self.setup_files(root)
            with files[0][0].open('r') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):self.apply(files)
            self.assertEqual(files[0][0].stat().st_mode & 0o777, 0o666)

    def test_journal_never_overwrites_existing_file_or_target(self):
        with tempfile.TemporaryDirectory() as root:
            files = self.setup_files(root)
            for target in [files[0][0], files[1][0]]:
                with self.assertRaises(FileExistsError):self.apply(files, target)
                self.assertEqual(target.read_text(), 'fixture\n')
                self.assertEqual(target.stat().st_mode & 0o777, 0o666)

    def test_failed_journal_after_application_rolls_back(self):
        with tempfile.TemporaryDirectory() as root:
            files = self.setup_files(root);original = t.Journal.write
            def write(journal, record):
                if record['status'] == 'applied':raise OSError('journal unavailable')
                return original(journal, record)
            with patch.object(t.Journal, 'write', new=write), self.assertRaises(t.TransactionError):
                self.apply(files, Path(root) / 'journal.json')
            self.assertEqual([path.stat().st_mode & 0o777 for path, _, _ in files], [0o666] * 2)
            self.assertEqual(json.loads((Path(root) / 'journal.json').read_text())['status'], 'rolled_back')

    def test_replaced_journal_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'journal.json'
            journal = t.Journal(path)
            external = Path(root) / 'external'
            external.write_text('EXTERNAL RECORD')
            os.replace(external, path)
            with self.assertRaises(RuntimeError):journal.write({'status': 'preflight'})
            self.assertEqual(path.read_text(), 'EXTERNAL RECORD')


class SSHTransactions(unittest.TestCase):
    def fixture(self, directory):
        config = Path(directory) / 'sshd_config'
        config.write_text('PermitRootLogin yes\n');config.chmod(0o640)
        return config

    def apply(self, config, validate=lambda path: None, journal=None):
        return t.fix_ssh(config, config.read_text(), 'PermitRootLogin no\n', validate, lambda path: 'no', journal)

    def test_atomic_update_metadata_backup_and_second_noop(self):
        with tempfile.TemporaryDirectory() as root:
            config = self.fixture(root);before = t.snapshot(config.stat())
            result = self.apply(config, journal=Path(root) / 'journal.json')
            self.assertEqual(config.read_text(), 'PermitRootLogin no\n')
            self.assertEqual(t.snapshot(config.stat()), before)
            backup = Path(result['backup'])
            self.assertEqual(backup.read_text(), 'PermitRootLogin yes\n')
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            identity = config.stat().st_ino
            self.assertEqual(self.apply(config)['status'], 'no_changes')
            self.assertEqual(config.stat().st_ino, identity)
            self.assertEqual(len(list(Path(root).glob('*.bak'))), 1)

    def test_invalid_candidate_is_rejected_without_backup_or_replace(self):
        with tempfile.TemporaryDirectory() as root:
            config = self.fixture(root);identity = config.stat().st_ino
            def invalid(path):raise RuntimeError('invalid fixture')
            with self.assertRaises(t.TransactionError) as failure:self.apply(config, invalid)
            self.assertEqual(failure.exception.record['status'], 'rejected')
            self.assertEqual(config.read_text(), 'PermitRootLogin yes\n')
            self.assertEqual(config.stat().st_ino, identity)
            self.assertEqual(list(Path(root).glob('*.bak')), [])
            self.assertEqual(list(Path(root).glob('.security-auditor-*')), [])

    def test_post_validation_failure_restores_original(self):
        with tempfile.TemporaryDirectory() as root:
            config = self.fixture(root)
            def validate(path):
                if path == config and path.read_text() == 'PermitRootLogin no\n':raise RuntimeError('post-check failed')
            with self.assertRaises(t.TransactionError) as failure:self.apply(config, validate)
            self.assertEqual(failure.exception.record['status'], 'rolled_back')
            self.assertEqual(config.read_text(), 'PermitRootLogin yes\n')
            self.assertEqual(config.stat().st_mode & 0o777, 0o640)

    def test_concurrent_replacement_is_not_overwritten_by_rollback(self):
        with tempfile.TemporaryDirectory() as root:
            config = self.fixture(root)
            def validate(path):
                if path == config:
                    replacement = Path(root) / 'external'
                    replacement.write_text('EXTERNAL EDIT\n');os.replace(replacement, config)
                    raise RuntimeError('external replacement')
            with self.assertRaises(t.TransactionError) as failure:self.apply(config, validate)
            self.assertEqual(failure.exception.record['status'], 'rollback_failed')
            self.assertEqual(config.read_text(), 'EXTERNAL EDIT\n')

    def test_journal_is_private_and_contains_no_config_content(self):
        with tempfile.TemporaryDirectory() as root:
            config = self.fixture(root);journal = Path(root) / 'journal.json'
            self.apply(config, journal=journal)
            value = journal.read_text()
            self.assertNotIn('PermitRootLogin yes', value)
            self.assertEqual(json.loads(value)['status'], 'applied')

    def test_rollback_preserves_original_line_endings(self):
        with tempfile.TemporaryDirectory() as root:
            config = self.fixture(root)
            original = 'PermitRootLogin yes\r\n# fixture\r\n'
            config.write_bytes(original.encode())
            updated = 'PermitRootLogin no\n# fixture\r\n'
            def validate(path):
                if path == config and path.read_bytes() == updated.encode():raise RuntimeError('post-check')
            with self.assertRaises(t.TransactionError):
                t.fix_ssh(config, original, updated, validate, lambda path: 'no')
            self.assertEqual(config.read_bytes(), original.encode())


if __name__ == '__main__':unittest.main()
