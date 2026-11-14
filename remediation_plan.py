"""Pure planning: inspect metadata/configuration, never mutate system settings."""
import stat


def ssh_capability(config, which):
    try:
        if not which('sshd'):
            return False, 'sshd no disponible', ''
        if not stat.S_ISREG(config.lstat().st_mode):
            return False, 'La configuración SSH no es un archivo regular o es un enlace.', ''
        with config.open('r', encoding='utf-8', newline='') as stream:content = stream.read()
        if any(line.split()[0].lower() in {'match', 'include'} for line in content.splitlines() if line.strip() and not line.lstrip().startswith('#')):
            return False, 'Match/Include requiere revisión manual; no se ofrece corrección automática.', ''
        return True, '', content
    except (OSError, UnicodeError) as exc:
        return False, f'No se pudo inspeccionar la configuración SSH: {exc}', ''


def base(control):
    return {'dry_run': True, 'control': control, 'status': 'no_changes', 'operations': [],
            'blockers': [], 'requirements': ['Aplicación separada como root con --yes.', 'Revisar evidencia y acceso alternativo antes de aplicar.'],
            'recovery': [], 'applied': False}


def permissions(files, allowed_mode):
    plan = base('permissions')
    for path, check_id, _ in files:
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError('archivo no regular o enlace')
            current = stat.S_IMODE(info.st_mode)
            target = current & allowed_mode(path, info)
            if current != target or info.st_uid != 0:
                before = {'uid': info.st_uid, 'gid': info.st_gid, 'mode': f'{current:04o}'}
                after = {'uid': 0, 'gid': info.st_gid, 'mode': f'{target:04o}'}
                plan['operations'].append({'control': check_id, 'path': str(path), 'before': before, 'after': after,
                    'identity': {'device': getattr(info, 'st_dev', None), 'inode': getattr(info, 'st_ino', None)},
                    'reason': 'Quitar permisos excedentes y corregir propietario sin ampliar permisos ni cambiar el grupo.'})
                plan['recovery'].append(f'{path}: conservar este registro de metadatos; restaurar UID/GID/modo anteriores sólo tras verificar identidad del archivo.')
        except (OSError, ValueError) as exc:
            plan['blockers'].append(f'{path}: {exc}')
    plan['status'] = 'blocked' if plan['blockers'] else ('planned' if plan['operations'] else 'no_changes')
    plan['requirements'].append('Se intenta restaurar metadatos ante fallos; no hay atomicidad entre archivos ni garantía ante corte de energía. Revise cualquier rollback incompleto.')
    return plan


def ssh(config, capability, replace):
    plan = base('ssh-root-login')
    allowed, reason, content = capability(config)
    if not allowed:
        plan.update(status='blocked', blockers=[reason])
        return plan
    updated = replace(content, 'PermitRootLogin', 'no')
    if updated != content:
        known = {'yes', 'no', 'without-password', 'prohibit-password', 'forced-commands-only'}
        observed = []
        for line in content.splitlines():
            parts = line.split()
            if parts and parts[0].lower() == 'permitrootlogin':
                observed.append(parts[1] if len(parts) > 1 and parts[1] in known else 'valor no reconocido')
        plan['operations'].append({'path': str(config), 'before': {'PermitRootLogin': observed or ['sin directiva explícita']},
            'after': {'PermitRootLogin': 'no', 'placement': 'al principio'},
            'reason': 'Prohibir acceso directo de root; conservar el resto del archivo sin exponer su contenido en el plan.'})
        plan['status'] = 'planned'
        plan['recovery'] = ['La aplicación crea respaldo privado 0600 con marca temporal; restaurarlo si corresponde y validar sshd -t antes de cualquier recarga manual.']
    plan['requirements'] += ['Validación sshd -t y valor efectivo durante la aplicación; no se certifica la sintaxis sólo por planificar.',
                             'Consola o segunda sesión y cuenta administrativa alternativa verificadas por el operador.',
                             'No se recarga SSH automáticamente; comprobar una nueva conexión antes de cerrar la sesión existente.']
    return plan


def markdown(plan):
    import json
    return '# Plan de remediación (sin aplicar)\n\n```json\n' + json.dumps(plan, ensure_ascii=False, indent=2) + '\n```\n'
