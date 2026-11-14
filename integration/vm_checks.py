#!/usr/bin/env python3
"""Exercise disposable fixtures only; no production paths are remediated."""
import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import security_auditor as a
import remediation_transaction as transaction


def permissions_workflow():
    if os.geteuid() != 0:
        raise RuntimeError('El flujo de permisos requiere UID 0 aislado o una VM descartable.')
    with tempfile.TemporaryDirectory(prefix='auditor-permission-fixtures-') as directory:
        root = Path(directory).resolve()
        paths = [root / 'passwd', root / 'shadow']
        files = [(path, f'CIS-LITE-00{index + 1}', 'Fixture') for index, path in enumerate(paths)]
        for path in paths:
            assert path.parent == root
            path.write_text('SYNTHETIC FIXTURE ONLY\n');path.chmod(0o666)
        with patch.object(a, 'ACCOUNT_FILES', files):
            assert all(f.status == 'FAIL' for f in a.audit_file_permissions())
            assert a.plan_remediation('permissions')['status'] == 'planned'
            result = json.loads(a.remediate_permissions(root / 'applied.json'))
            assert result['status'] == 'applied'
            assert all(f.status == 'PASS' for f in a.audit_file_permissions())
            identities = [(p.stat().st_ino, p.stat().st_mtime_ns, p.stat().st_mode) for p in paths]
            assert 'Sin cambios' in a.remediate_permissions()
            assert identities == [(p.stat().st_ino, p.stat().st_mtime_ns, p.stat().st_mode) for p in paths]
            for path in paths:path.chmod(0o666)
            real_chmod = os.fchmod
            calls = 0
            def fail_second(fd, mode):
                nonlocal calls
                calls += 1
                if calls == 2:raise PermissionError('injected fixture failure')
                return real_chmod(fd, mode)
            with patch.object(os, 'fchmod', side_effect=fail_second):
                try:a.remediate_permissions(root / 'rollback.json')
                except transaction.TransactionError as exc:assert exc.record['status'] == 'rolled_back'
                else:raise AssertionError('La inyección no provocó fallo')
            assert all(stat.S_IMODE(path.stat().st_mode) == 0o666 for path in paths)
        return {'permissions': 'audit-plan-apply-audit-idempotence-rollback passed', 'isolated_uid': os.geteuid()}


def ssh_workflow():
    sshd, keygen = shutil.which('sshd'), shutil.which('ssh-keygen')
    if not sshd or not keygen:
        return {'ssh': 'skipped', 'reason': 'OpenSSH server/keygen no disponible'}
    with tempfile.TemporaryDirectory(prefix='auditor-ssh-fixtures-') as directory:
        root = Path(directory).resolve()
        key = root / 'fixture_key'
        subprocess.run([keygen, '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True, capture_output=True)
        config = root / 'sshd_config'
        original = f'HostKey {key}\nUsePAM no\nPermitRootLogin yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n'
        config.write_text(original);config.chmod(0o640)
        updated = a.replace_or_append_directive(original, 'PermitRootLogin', 'no')
        def validate(path):
            code, out, err = a.command([sshd, '-t', '-f', str(path)])
            if code:raise RuntimeError(err or out)
        def effective(path):
            settings, error = a.ssh_effective_settings(config=path)
            if error:raise RuntimeError(error)
            return settings.get('permitrootlogin')
        assert effective(config) == 'yes'
        result = transaction.fix_ssh(config, original, updated, validate, effective, root / 'ssh.json')
        assert result['status'] == 'applied' and effective(config) == 'no'
        identity = config.stat().st_ino
        assert transaction.fix_ssh(config, updated, updated, validate, effective)['status'] == 'no_changes'
        assert config.stat().st_ino == identity
        config.write_text(original)
        def post_check(path):
            validate(path)
            if path == config and path.read_text() == updated:raise RuntimeError('injected post-validation failure')
        try:transaction.fix_ssh(config, original, updated, post_check, effective)
        except transaction.TransactionError as exc:assert exc.record['status'] == 'rolled_back'
        else:raise AssertionError('Faltó la restauración SSH')
        assert config.read_text() == original and effective(config) == 'yes'
        return {'ssh': 'real sshd -t/-T, atomic update, idempotence and rollback passed'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures-only', action='store_true', required=True)
    parser.add_argument('--permissions-inside', action='store_true')
    args = parser.parse_args()
    if args.permissions_inside:
        print(json.dumps(permissions_workflow()))
        return 0
    result = ssh_workflow()
    if os.geteuid() == 0:
        result.update(permissions_workflow())
    else:
        environment = os.environ.copy()
        environment.update(LC_ALL='C', LANG='C', LANGUAGE='C')
        if not shutil.which('unshare'):
            print(json.dumps(result | {'permissions': 'skipped; unshare unavailable'}))
            return 77
        probe = subprocess.run(['unshare', '-Ur', sys.executable, str(Path(__file__).resolve()), '--fixtures-only', '--permissions-inside'], text=True, capture_output=True, env=environment)
        if probe.returncode:
            if 'Operation not permitted' in probe.stderr or 'unshare failed' in probe.stderr:
                print(json.dumps(result | {'permissions': 'skipped; user namespace unavailable'}))
                return 77
            raise RuntimeError(probe.stderr or probe.stdout)
        result.update(json.loads(probe.stdout))
    print(json.dumps(result))
    return 0


if __name__ == '__main__':raise SystemExit(main())
