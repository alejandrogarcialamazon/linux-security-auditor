#!/usr/bin/env python3
"""Upload a bounded source bundle to a temporary directory and audit via SSH."""
import argparse
import io
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile

MODULES = ('security_auditor.py', 'host_checks.py', 'remediation_plan.py', 'remediation_transaction.py', 'audit_policy.py', 'extended_controls.py', 'report_analysis.py')
REMOTE = '''import sys, tarfile, tempfile, subprocess, pathlib
with tempfile.TemporaryDirectory(prefix="linux-auditor-") as directory:
    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|*") as archive:
        for member in archive:
            if member.name not in MODULES or not member.isfile():
                raise ValueError("Unexpected archive entry")
            pathlib.Path(directory, member.name).write_bytes(archive.extractfile(member).read())
    result = subprocess.run([sys.executable, "security_auditor.py", "--format", FORMAT, "--profile", PROFILE] + (["--extended"] if EXTENDED else []), cwd=directory)
    raise SystemExit(result.returncode)
'''


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('host')
    parser.add_argument('--user', required=True)
    parser.add_argument('--identity', type=Path)
    parser.add_argument('--format', choices=('json', 'markdown'), default='json')
    parser.add_argument('--profile', choices=('servidor', 'laboratorio', 'expuesto'), default='servidor')
    parser.add_argument('--extended', action='store_true')
    args = parser.parse_args(argv)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', args.host) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*', args.user):
        parser.error('Host o usuario inválido')
    return args


def main(argv=None):
    args = arguments(argv)
    root = Path(__file__).resolve().parents[1]
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as tar:
        for name in MODULES:
            tar.add(root / name, arcname=name, recursive=False)
    code = f'MODULES={MODULES!r}\nFORMAT={args.format!r}\nPROFILE={args.profile!r}\nEXTENDED={args.extended!r}\n' + REMOTE
    command = ['ssh', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=8']
    if args.identity:
        command += ['-i', str(args.identity)]
    command += [args.user + '@' + args.host, 'python3 -c ' + shlex.quote(code)]
    try:
        return subprocess.run(command, input=archive.getvalue(), timeout=180).returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f'Error SSH: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
