"""Optional read-only account, sudoers metadata and clock probes."""
from pathlib import Path
import stat


def audit(run, finding, passwd=Path('/etc/passwd'), sudoers=Path('/etc/sudoers')):
    result = []
    try:
        rows = [line.split(':') for line in passwd.read_text().splitlines() if line and not line.startswith('#')]
        if any(len(row) != 7 or not row[2].isdigit() for row in rows):
            raise ValueError('Formato passwd inesperado')
        extra = [row[0] for row in rows if int(row[2]) == 0 and row[0] != 'root']
        status, evidence = ('FAIL', 'Cuentas UID 0 adicionales: ' + ', '.join(extra)) if extra else ('PASS', 'Sin cuentas UID 0 adicionales en el archivo local')
    except (OSError, ValueError):
        status, evidence = 'WARN', 'No se pudo interpretar el archivo local de cuentas'
    result.append(finding('CIS-LITE-008', 'Cuentas UID 0 locales', status, 'high', evidence, 'Revise las cuentas administrativas; no las elimine automáticamente.', expected='Sólo root con UID 0 en /etc/passwd; no cubre NSS externo.'))
    try:
        metadata = sudoers.lstat()
        valid = stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_gid == 0 and not (stat.S_IMODE(metadata.st_mode) & ~0o440)
        status, evidence = ('PASS' if valid else 'FAIL'), f'uid={metadata.st_uid}, gid={metadata.st_gid}, modo={stat.S_IMODE(metadata.st_mode):04o}'
    except OSError:
        status, evidence = 'WARN', 'Metadatos de sudoers no disponibles'
    result.append(finding('CIS-LITE-009', 'Metadatos del sudoers principal', status, 'high', evidence, 'Revise propietario y permisos con visudo; no se evalúan reglas ni includes.', expected='Archivo regular root:root, permisos contenidos en 0440.'))
    code, out, err = run(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value'])
    value = out.strip()
    status = ('PASS' if value == 'yes' else 'FAIL') if code == 0 and value in {'yes', 'no'} else 'WARN'
    result.append(finding('CIS-LITE-010', 'Sincronización del reloj', status, 'medium', f'NTPSynchronized={value if value in {"yes", "no"} else "desconocido"}; código={code}', 'Revise el servicio de sincronización y sus fuentes.', expected='timedatectl informa NTPSynchronized=yes; no certifica las fuentes NTP.'))
    return result
