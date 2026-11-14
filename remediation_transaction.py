"""Recoverable operations on explicit files, with cooperative locks and verification."""
import fcntl
import hashlib
import json
import os
import shutil
import stat
import tempfile
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from pathlib import Path


class TransactionError(RuntimeError):
    def __init__(self, message, record):
        self.record = record
        super().__init__(message + '; registro=' + json.dumps(record, ensure_ascii=False))


def snapshot(info):
    return {'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode)}


def read_exact(path):
    with path.open('r', encoding='utf-8', newline='') as stream:return stream.read()


def verify_path_identity(path, info):
    actual = path.lstat()
    if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino):
        raise RuntimeError(f'Cambió la identidad del archivo {path}')


class Journal:
    """Reserve a new path; never overwrite an unrelated pre-existing file."""
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:self.identity = os.fstat(fd)
        finally:os.close(fd)

    def write(self, record):
        actual = self.path.lstat()
        if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != (self.identity.st_dev, self.identity.st_ino):
            raise RuntimeError('El registro fue reemplazado por otro proceso.')
        fd, temporary = tempfile.mkstemp(prefix='.auditor-journal-', dir=self.path.parent)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump(record, stream, ensure_ascii=False, indent=2)
                stream.write('\n');stream.flush();os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            self.identity = self.path.lstat()
            sync_directory(self.path.parent)
        finally:
            if os.path.exists(temporary):os.unlink(temporary)


def save_record(path, record):
    if path is not None:
        (path if isinstance(path, Journal) else Journal(path)).write(record)


def fix_permissions(files, allowed_mode, journal=None, owner_uid=0):
    record = {'schema_version': 1, 'started_at': datetime.now(timezone.utc).isoformat(), 'control': 'permissions', 'status': 'preflight', 'files': [], 'changed': False, 'applied': False, 'rollback_errors': []}
    with ExitStack() as stack:
        planned = []
        for path, _, _ in files:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):raise RuntimeError(f'{path} no es un archivo regular')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            verify_path_identity(path, info)
            before = snapshot(info)
            target = before['mode'] & allowed_mode(path, info)
            planned.append((path, fd, info, before, target))
            record['files'].append({'path': str(path), 'before': before, 'after': {'uid': owner_uid, 'gid': before['gid'], 'mode': target}, 'identity': {'device': getattr(info, 'st_dev', None), 'inode': getattr(info, 'st_ino', None)}})
        journal = Journal(journal) if journal is not None else None
        save_record(journal, record)
        touched = []
        try:
            for path, fd, info, before, target in planned:
                verify_path_identity(path, info)
                if snapshot(os.fstat(fd)) != before:raise RuntimeError(f'Metadatos concurrentes en {path}')
                if before['uid'] == owner_uid and before['mode'] == target:continue
                touched.append((path, fd, info, before))
                if before['uid'] != owner_uid:os.fchown(fd, owner_uid, -1)
                if stat.S_IMODE(os.fstat(fd).st_mode) != target:os.fchmod(fd, target)
                if snapshot(os.fstat(fd)) != {'uid': owner_uid, 'gid': before['gid'], 'mode': target}:
                    raise RuntimeError(f'Falló la verificación de {path}')
                verify_path_identity(path, info)
                os.fsync(fd)
            record.update(status='applied' if touched else 'no_changes', changed=bool(touched), applied=bool(touched))
            record['finished_at'] = datetime.now(timezone.utc).isoformat()
            save_record(journal, record)
        except Exception as exc:
            for path, fd, info, before in reversed(touched):
                try:
                    actual = snapshot(os.fstat(fd))
                    if (actual['uid'], actual['gid']) != (before['uid'], before['gid']):
                        os.fchown(fd, before['uid'], before['gid'])
                    if stat.S_IMODE(os.fstat(fd).st_mode) != before['mode']:os.fchmod(fd, before['mode'])
                    if snapshot(os.fstat(fd)) != before:raise RuntimeError('metadatos no restaurados')
                    verify_path_identity(path, info)
                    os.fsync(fd)
                except Exception as error:record['rollback_errors'].append(f'{path}: {error}')
            record.update(status='rollback_failed' if record['rollback_errors'] else 'rolled_back', changed=bool(touched), applied=None if record['rollback_errors'] else False, error=str(exc))
            record['finished_at'] = datetime.now(timezone.utc).isoformat()
            try:save_record(journal, record)
            except Exception as error:record['journal_error'] = str(error)
            raise TransactionError('Falló la operación; restauración ' + ('incompleta' if record['rollback_errors'] else 'verificada'), record) from exc
    return record


@contextmanager
def ssh_lock(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise RuntimeError('Lock SSH inseguro')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:os.close(fd)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def candidate_file(config, content, info):
    fd, name = tempfile.mkstemp(prefix='.security-auditor-', dir=config.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(content);stream.flush()
            os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
            # copy stat/xattrs before publishing, while the original path is pinned
            shutil.copystat(config, name, follow_symlinks=False)
            os.fsync(stream.fileno())
        return Path(name)
    except Exception:
        os.unlink(name)
        raise


def fix_ssh(config, original, updated, validate, effective, journal=None):
    record = {'schema_version': 1, 'started_at': datetime.now(timezone.utc).isoformat(), 'control': 'ssh-root-login', 'status': 'preflight', 'path': str(config), 'changed': False, 'applied': False, 'rollback_errors': []}
    with ssh_lock(config.with_name(config.name + '.security-auditor.lock')):
        info = config.lstat()
        verify_path_identity(config, info)
        if read_exact(config) != original:raise RuntimeError('La configuración cambió desde la inspección.')
        record['before'] = snapshot(info)
        record['before_sha256'] = hashlib.sha256(original.encode()).hexdigest()
        record['after_sha256'] = hashlib.sha256(updated.encode()).hexdigest()
        journal = Journal(journal) if journal is not None else None
        if original == updated:
            validate(config)
            if effective(config) != 'no':raise RuntimeError('No se pudo validar el valor efectivo sin cambios.')
            record['status'] = 'no_changes';record['finished_at'] = datetime.now(timezone.utc).isoformat();save_record(journal, record)
            return record
        candidate = candidate_file(config, updated, info)
        backup = None
        installed = False
        installed_info = None
        try:
            validate(candidate)
            if effective(candidate) != 'no':raise RuntimeError('El candidato no tiene PermitRootLogin no efectivo.')
            verify_path_identity(config, info)
            if read_exact(config) != original or snapshot(config.stat()) != snapshot(info):raise RuntimeError('Edición concurrente de SSH.')
            backup = config.with_name(config.name + '.security-auditor-' + datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f') + '.bak')
            fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write(original);stream.flush();os.fsync(stream.fileno())
            sync_directory(config.parent)
            record['backup'] = str(backup)
            save_record(journal, record)
            os.replace(candidate, config);installed = True
            installed_info = config.lstat()
            record['after_identity'] = {'device': installed_info.st_dev, 'inode': installed_info.st_ino}
            sync_directory(config.parent)
            validate(config)
            if effective(config) != 'no':raise RuntimeError('Falló la verificación efectiva posterior.')
            if snapshot(config.stat()) != snapshot(info):raise RuntimeError('No se conservaron UID/GID/modo de SSH.')
            if read_exact(config) != updated:raise RuntimeError('Edición concurrente después de publicar el candidato.')
            record.update(status='applied', changed=True, applied=True)
            record['finished_at'] = datetime.now(timezone.utc).isoformat()
            save_record(journal, record)
        except Exception as exc:
            if installed:
                try:
                    verify_path_identity(config, installed_info)
                    if read_exact(config) != updated:raise RuntimeError('Cambio externo: no se sobrescribe la configuración concurrente.')
                    restore = candidate_file(config, original, info)
                    os.replace(restore, config);sync_directory(config.parent)
                    validate(config)
                    if read_exact(config) != original or snapshot(config.stat()) != snapshot(info):
                        raise RuntimeError('Restauración de contenido/metadatos incompleta')
                except Exception as error:record['rollback_errors'].append(str(error))
            record.update(status=('rollback_failed' if record['rollback_errors'] else 'rolled_back') if installed else 'rejected', changed=installed, applied=None if record['rollback_errors'] else False, error=str(exc))
            record['finished_at'] = datetime.now(timezone.utc).isoformat()
            try:save_record(journal, record)
            except Exception as error:record['journal_error'] = str(error)
            raise TransactionError('Falló SSH; restauración ' + ('incompleta' if record['rollback_errors'] else 'verificada o sin aplicar'), record) from exc
        finally:
            if candidate.exists():candidate.unlink()
    return record
