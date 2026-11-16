#!/usr/bin/env python3
"""Build a reproducible stdlib zipapp, or verify its SHA-256 manifest."""
import argparse
import hashlib
import io
from pathlib import Path
import re
import zipfile

MODULES = ('security_auditor.py', 'host_checks.py', 'remediation_plan.py', 'remediation_transaction.py', 'audit_policy.py', 'extended_controls.py', 'report_analysis.py', 'auditor_version.py')
ARTIFACT = 'linux-security-auditor.pyz'


def build(source, destination):
    source, destination = Path(source), Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    buffer = io.BytesIO(b'#!/usr/bin/env python3\n')
    with zipfile.ZipFile(buffer, 'a', compression=zipfile.ZIP_DEFLATED) as archive:
        entries = {name: (source / name).read_bytes() for name in MODULES}
        entries['__main__.py'] = b'from security_auditor import main\nraise SystemExit(main())\n'
        for name, content in sorted(entries.items()):
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    payload = buffer.getvalue()
    artifact = destination / ARTIFACT
    manifest = destination / 'SHA256SUMS'
    # Refuse links so an output directory cannot redirect writes elsewhere.
    if artifact.is_symlink() or manifest.is_symlink():
        raise ValueError('No se admiten destinos simbólicos')
    artifact.write_bytes(payload)
    artifact.chmod(0o755)
    manifest.write_text(hashlib.sha256(payload).hexdigest() + '  ' + ARTIFACT + '\n', encoding='ascii')
    return artifact


def verify(directory):
    directory = Path(directory)
    manifest = directory / 'SHA256SUMS'
    artifact = directory / ARTIFACT
    if manifest.is_symlink() or artifact.is_symlink():
        raise ValueError('No se admiten enlaces simbólicos')
    content = manifest.read_text(encoding='ascii')
    match = re.fullmatch(r'([0-9a-f]{64})  ' + re.escape(ARTIFACT) + r'\n', content)
    if not match:
        raise ValueError('Manifiesto inválido')
    digest = hashlib.sha256()
    with artifact.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            digest.update(chunk)
    if digest.hexdigest() != match[1]:
        raise ValueError('La suma SHA-256 no coincide')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('reports/distribution'))
    parser.add_argument('--verify', type=Path, metavar='DIRECTORY')
    args = parser.parse_args()
    try:
        if args.verify:
            verify(args.verify)
            print('Integridad SHA-256 verificada')
        else:
            print(build(Path(__file__).resolve().parents[1], args.output))
    except (OSError, ValueError, UnicodeError) as exc:
        parser.exit(2, f'Error de distribución: {exc}\n')


if __name__ == '__main__':
    main()
