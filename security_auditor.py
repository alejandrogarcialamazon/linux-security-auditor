#!/usr/bin/env python3
"""Auditor de endurecimiento ligero para hosts Linux.

No sustituye una evaluación CIS certificada. Ejecutar como root mejora la
visibilidad, pero el modo de auditoría no modifica el sistema.
"""

from __future__ import annotations

import argparse
import grp
import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


@dataclass
class Finding:
    id: str
    title: str
    status: str  # PASS, FAIL, WARN, INFO
    severity: str
    evidence: str
    recommendation: str
    remediable: bool = False
    expected: str = ""
    risk: str = ""

    def __post_init__(self) -> None:
        family = "CIS-LITE-005" if self.id.startswith("CIS-LITE-005-") else self.id
        details = {
            "CIS-LITE-001": ("Archivo regular, UID 0 y permisos contenidos en 0644.", "Alteración de las cuentas del sistema."),
            "CIS-LITE-002": ("Archivo regular, UID 0; máximo 0640 para grupo root/shadow, o 0600 para otro grupo.", "Exposición o alteración de hashes de contraseñas."),
            "CIS-LITE-003": ("PermitRootLogin no en el contexto evaluado.", "Acceso administrativo directo con la cuenta root."),
            "CIS-LITE-004": ("PasswordAuthentication no, según la política de acceso por llave.", "Intentos de autenticación mediante contraseñas."),
            "CIS-LITE-005": ("La unidad consultada no debe estar activa.", "Exposición de servicios heredados o innecesarios."),
            "CIS-LITE-006": ("Firewall soportado consultable y criterio restrictivo comprobado.", "Exposición de servicios sin el filtrado previsto."),
        }
        expected, risk = details.get(family, ("Consultar la definición del control.", "Evaluar el impacto del incumplimiento."))
        self.expected = self.expected or expected
        self.risk = self.risk or risk
        if self.status == "PASS":
            self.recommendation = "Sin cambios necesarios."


def command(args: list[str]) -> tuple[int, str, str]:
    """Run a command without a shell and return decoded output."""
    environment = os.environ.copy()
    environment.update(LC_ALL="C", LANG="C", LANGUAGE="C")
    try:
        result = subprocess.run(args, text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=12, check=False, env=environment)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "Tiempo de espera agotado (12 segundos); comprobación inconclusa."
    except OSError as exc:
        return 127, "", f"No se pudo ejecutar el comando: {exc}"


ACCOUNT_FILES = (
    (Path("/etc/passwd"), "CIS-LITE-001", "Permisos de /etc/passwd"),
    (Path("/etc/shadow"), "CIS-LITE-002", "Permisos de /etc/shadow"),
)


def allowed_account_mode(path: Path, metadata: os.stat_result) -> int:
    """Maximum mode, never a target to which restrictive modes are expanded.

    shadow may be group-readable only by GID 0 or the local NSS group `shadow`.
    An unrelated/unknown group is preserved, but must have no access.
    """
    if path.name == "passwd":
        return 0o644
    if not metadata.st_mode & 0o040 or metadata.st_gid == 0:
        return 0o640
    try:
        trusted = grp.getgrgid(metadata.st_gid).gr_name == "shadow"
    except KeyError:
        trusted = False
    return 0o640 if trusted else 0o600


def audit_file_permissions() -> list[Finding]:
    findings: list[Finding] = []
    for path, check_id, title in ACCOUNT_FILES:
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                findings.append(Finding(check_id, title, "WARN", "high", f"{path} no es un archivo regular (o es un enlace).", "Revise el tipo de archivo manualmente."))
                continue
            allowed = allowed_account_mode(path, metadata)
        except OSError as exc:
            findings.append(Finding(check_id, title, "WARN", "medium", f"No se pudieron evaluar metadatos/grupo de {path}: {exc}", "Revise existencia, acceso a metadatos y resolución del grupo; vuelva a auditar."))
            continue
        mode = stat.S_IMODE(metadata.st_mode)
        status = "FAIL" if metadata.st_uid != 0 or mode & ~allowed else "PASS"
        target = mode & allowed
        evidence = f"modo={mode:04o}, uid={metadata.st_uid}, gid={metadata.st_gid}; máximo permitido={allowed:04o}"
        recommendation = (
            f"Asegure propietario root y quite permisos excedentes (modo resultante {target:04o}); conserve el grupo."
            if status == "FAIL" else "Sin cambios necesarios."
        )
        findings.append(Finding(
            check_id, title, status, "high", evidence,
            recommendation,
            remediable=status == "FAIL",
        ))
    return findings


def ssh_effective_settings() -> tuple[dict[str, str], str]:
    sshd = shutil.which("sshd")
    config = Path("/etc/ssh/sshd_config")
    try:
        available = bool(sshd) and config.exists()
    except OSError as exc:
        return {}, f"No se pudo comprobar el archivo de configuración SSH: {exc}"
    if not available:
        return {}, "sshd o /etc/ssh/sshd_config no está disponible"
    code, stdout, stderr = command([sshd, "-T", "-f", str(config)])
    if code != 0:
        return {}, f"sshd -T falló (código {code}): {stderr or stdout or 'sin detalles'}"
    settings: dict[str, str] = {}
    for line in stdout.splitlines():
        key, _, value = line.partition(" ")
        if key in {"permitrootlogin", "passwordauthentication"}:
            if key in settings:
                return {}, f"sshd -T devolvió un parámetro duplicado: {key}"
            settings[key] = value.strip().lower()
    return (settings, "") if settings else ({}, "sshd -T no devolvió parámetros reconocidos.")


def audit_ssh() -> list[Finding]:
    settings, error = ssh_effective_settings()
    if error:
        return [Finding(check_id, title, "WARN", "medium", error, "Revise disponibilidad, permisos y configuración de sshd; vuelva a auditar.") for check_id, title in (
            ("CIS-LITE-003", "SSH: acceso directo de root"),
            ("CIS-LITE-004", "SSH: autenticación por contraseña"),
        )]

    findings: list[Finding] = []
    root_login = settings.get("permitrootlogin", "unknown")
    root_known = root_login in {"yes", "no", "prohibit-password", "without-password", "forced-commands-only"}
    findings.append(Finding(
        "CIS-LITE-003", "SSH: acceso directo de root",
        ("PASS" if root_login == "no" else "FAIL") if root_known else "WARN", "high",
        f"permitrootlogin={root_login}",
        "Defina PermitRootLogin no." if root_known else "No se obtuvo un valor válido; revise sshd -T antes de corregir.",
        remediable=root_known and root_login != "no",
    ))
    password_auth = settings.get("passwordauthentication", "unknown")
    # Password auth can be required by an organization's access model, therefore
    # this remains advisory and is intentionally not auto-remediated.
    findings.append(Finding(
        "CIS-LITE-004", "SSH: autenticación por contraseña",
        "PASS" if password_auth == "no" else "WARN", "medium",
        f"passwordauthentication={password_auth}",
        "No se obtuvo un valor válido; revise sshd -T antes de corregir." if password_auth not in {"yes", "no"} else "Tras verificar acceso por llave para una cuenta administrativa, defina PasswordAuthentication no.",
    ))
    return findings


def service_is_active(name: str) -> tuple[bool | None, str]:
    if not shutil.which("systemctl"):
        return None, "systemctl no está disponible"
    code, stdout, stderr = command(["systemctl", "is-active", name])
    if code == 0 and stdout == "active":
        return True, stdout
    if code == 3 and stdout in {"inactive", "failed"}:
        return False, stdout
    return None, f"Estado no concluyente (código {code}): {stderr or stdout or 'sin salida'}"


def audit_services() -> list[Finding]:
    legacy = {
        "telnet.socket": "Telnet transmite credenciales sin cifrado",
        "rsh.socket": "rsh no proporciona autenticación ni cifrado modernos",
        "rexec.socket": "rexec es un servicio remoto obsoleto",
        "tftp.socket": "TFTP no proporciona autenticación",
        "xinetd.service": "xinetd suele exponer servicios heredados",
    }
    findings: list[Finding] = []
    for unit, reason in legacy.items():
        check_id = f"CIS-LITE-005-{unit.split('.')[0].upper()}"
        active, evidence = service_is_active(unit)
        if active is None:
            findings.append(Finding(check_id, f"Servicio {unit}", "WARN", "medium", evidence, "No se pudo comprobar el estado; revise systemd, permisos y nombre de unidad."))
        elif active:
            findings.append(Finding(check_id, f"Servicio {unit}", "FAIL", "medium", reason, f"Deshabilite el servicio si no existe una necesidad documentada: systemctl disable --now {unit}"))
        else:
            findings.append(Finding(check_id, f"Servicio {unit}", "PASS", "low", evidence, "Sin cambios necesarios."))
    return findings


def audit_firewall() -> list[Finding]:
    findings: list[Finding] = []
    ufw = shutil.which("ufw")
    if ufw:
        code, stdout, stderr = command([ufw, "status"])
        statuses = [line.strip() for line in stdout.splitlines() if line.strip().startswith("Status:")]
        status = "WARN"
        if code == 0 and len(statuses) == 1 and statuses[0] in {"Status: active", "Status: inactive"}:
            status = "PASS" if statuses[0] == "Status: active" else "FAIL"
        findings.append(Finding(
            "CIS-LITE-006", "Firewall UFW",
            status, "high", f"código={code}; {stdout or stderr or 'Sin salida'}",
            "No se pudo interpretar o ejecutar ufw status; revise el diagnóstico antes de cambiar reglas." if status == "WARN" else "Defina reglas explícitas de acceso administrativo y active UFW.",
            expected="Consulta UFW correcta y un único Status: active.",
        ))
        return findings

    iptables = shutil.which("iptables")
    if iptables:
        code, stdout, stderr = command([iptables, "-S"])
        policies = [line.split() for line in stdout.splitlines() if line.split()[:2] == ["-P", "INPUT"]]
        # Only DROP is a recognized restrictive built-in policy. REJECT is a
        # rule target, not a valid default policy. ACCEPT alone says too little
        # about filtering rules to establish either protection or its absence.
        drop_default = len(policies) == 1 and policies[0] == ["-P", "INPUT", "DROP"]
        findings.append(Finding(
            "CIS-LITE-006", "Firewall iptables",
            "PASS" if code == 0 and drop_default else "WARN", "high",
            f"código={code}; " + ("; ".join(" ".join(policy) for policy in policies) if code == 0 and policies else (stderr or stdout or "No se pudieron leer políticas")),
            "Revise reglas persistentes y use una política INPUT restrictiva sin bloquear su acceso actual.",
            expected="Consulta iptables correcta y una única política INPUT DROP; no evalúa todas las reglas.",
        ))
        return findings

    return [Finding("CIS-LITE-006", "Firewall", "WARN", "high", "No se encontró UFW ni iptables.", "Instale y configure un firewall compatible con su distribución.")]


def audit() -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(audit_file_permissions())
    findings.extend(audit_ssh())
    findings.extend(audit_services())
    findings.extend(audit_firewall())
    return findings


def replace_or_append_directive(content: str, directive: str, value: str) -> str:
    """Set the global value before Include, preserving all Match sections."""
    lines = [f"{directive} {value}\n"]
    in_match = False
    for line in content.splitlines(keepends=True):
        stripped = line.strip()
        keyword = stripped.lower().split(None, 1)[0] if stripped else ""
        if keyword == "match":
            in_match = True
        if not in_match and keyword == directive.lower():
            continue
        lines.append(line)
    return "".join(lines)


def require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("La remediación exige ejecutar como root (sudo).")


def remediate_permissions() -> str:
    require_root()
    changed: list[str] = []
    # Preflight both files before changing anything. Descriptors pin the inode;
    # O_NOFOLLOW refuses symlinks and O_NONBLOCK avoids hanging on a FIFO.
    with ExitStack() as stack:
        planned = []
        for path, _, _ in ACCOUNT_FILES:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            stack.callback(os.close, fd)
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError(f"{path} no es un archivo regular; no se aplicaron cambios.")
            mode = stat.S_IMODE(metadata.st_mode)
            planned.append((path, fd, metadata, mode & allowed_account_mode(path, metadata)))
        for path, fd, metadata, target in planned:
            if metadata.st_uid == 0 and stat.S_IMODE(metadata.st_mode) == target:
                continue
            try:
                if metadata.st_uid != 0:
                    os.fchown(fd, 0, -1)
                    changed.append(f"{path}: propietario root")
                if stat.S_IMODE(os.fstat(fd).st_mode) != target:
                    os.fchmod(fd, target)
                    changed.append(f"{path}: modo {target:04o}")
                actual = os.fstat(fd)
                if actual.st_uid != 0 or actual.st_gid != metadata.st_gid or stat.S_IMODE(actual.st_mode) != target:
                    raise RuntimeError("La verificación de propietario/grupo/modo no coincide con lo previsto.")
            except (OSError, RuntimeError) as exc:
                raise RuntimeError(f"Falló la remediación de {path}: {exc}. Cambios ya realizados: {changed}. Revise el estado; no hay rollback automático.") from exc
    return "; ".join(changed) if changed else "Sin cambios necesarios en los permisos de cuentas."


def remediate_ssh_root_login() -> str:
    require_root()
    config = Path("/etc/ssh/sshd_config")
    sshd = shutil.which("sshd")
    if not config.exists() or not sshd:
        raise RuntimeError("No se encontró sshd o su archivo de configuración.")
    original = config.read_text(encoding="utf-8")
    # Conditional exceptions require an operator to evaluate connection contexts.
    # Includes may also contain Match; a global -T check cannot rule those out.
    if any(line.strip().lower().split(None, 1)[0] in {"match", "include"}
           for line in original.splitlines() if line.strip() and not line.lstrip().startswith("#")):
        raise RuntimeError("La remediación automática no admite Match/Include; revise SSH manualmente.")
    updated = replace_or_append_directive(original, "PermitRootLogin", "no")
    backup = config.with_name(f"{config.name}.security-auditor-{datetime.now().strftime('%Y%m%d%H%M%S%f')}.bak")
    with backup.open("x", encoding="utf-8") as stream:
        os.chmod(backup, 0o600)
        stream.write(original)
    try:
        config.write_text(updated, encoding="utf-8")
        code, stdout, stderr = command([sshd, "-t", "-f", str(config)])
        if code != 0:
            raise RuntimeError(f"Configuración SSH inválida: {stderr or stdout}")
        settings, error = ssh_effective_settings()
        if error or settings.get("permitrootlogin") != "no":
            raise RuntimeError(f"No se pudo verificar PermitRootLogin no: {error or settings}")
    except (OSError, RuntimeError):
        config.write_text(original, encoding="utf-8")
        raise
    return f"PermitRootLogin no guardado y validado. Recargue SSH manualmente y pruebe el acceso. Respaldo: {backup}"


def report_data(findings: list[Finding]) -> dict:
    counts = {status: sum(item.status == status for item in findings) for status in ("PASS", "FAIL", "WARN", "INFO")}
    return {
        "tool": "security_auditor",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host": os.uname().nodename,
        "platform": " ".join(os.uname()),
        "summary": counts,
        "scope": {
            "checks": len(findings),
            "control_families": len({"CIS-LITE-005" if item.id.startswith("CIS-LITE-005-") else item.id for item in findings}),
        },
        "findings": [asdict(item) for item in findings],
    }


def markdown_report(data: dict) -> str:
    summary = data["summary"]
    rows = [
        "# Reporte de seguridad (CIS ligero)",
        "",
        f"- Host: `{data['host']}`",
        f"- Fecha UTC: `{data['generated_at']}`",
        f"- Resultado: {summary['PASS']} PASS, {summary['FAIL']} FAIL, {summary['WARN']} WARN, {summary['INFO']} INFO",
        f"- Alcance: {data.get('scope', {}).get('checks', len(data['findings']))} comprobaciones; no representa un porcentaje de cumplimiento CIS.",
        "- Severidad: impacto potencial si el criterio se incumple; un PASS no requiere corrección.",
        "",
        "| ID | Estado | Severidad | Control | Evidencia | Criterio esperado | Riesgo del incumplimiento | Acción propuesta |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for item in data["findings"]:
        clean = lambda value: str(value).replace("|", "\\|").replace("\n", " ")
        values = dict(item)
        values.setdefault("expected", "No registrado en este reporte anterior.")
        values.setdefault("risk", "No registrado en este reporte anterior.")
        rows.append("| {id} | {status} | {severity} | {title} | {evidence} | {expected} | {risk} | {recommendation} |".format(**{key: clean(value) for key, value in values.items()}))
    return "\n".join(rows) + "\n"


def write_report(data: dict, output: Path, report_format: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if report_format == "json":
        output.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    else:
        output.write_text(markdown_report(data), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("json", "markdown"), default="json", help="Formato del reporte")
    parser.add_argument("--output", type=Path, help="Ruta de salida (por defecto: stdout)")
    parser.add_argument("--remediate", choices=("permissions", "ssh-root-login"), help="Control seguro que desea remediar")
    parser.add_argument("--yes", action="store_true", help="Confirma el cambio solicitado; obligatorio con --remediate")
    args = parser.parse_args()

    if args.remediate:
        if not args.yes:
            parser.error("--remediate requiere --yes para evitar cambios accidentales.")
        actions: dict[str, Callable[[], str]] = {
            "permissions": remediate_permissions,
            "ssh-root-login": remediate_ssh_root_login,
        }
        try:
            print(f"REMEDITADO: {actions[args.remediate]()}", file=sys.stderr)
        except (PermissionError, RuntimeError, OSError) as exc:
            print(f"ERROR DE REMEDIACIÓN: {exc}", file=sys.stderr)
            return 2

    data = report_data(audit())
    if args.output:
        write_report(data, args.output, args.format)
        print(f"Reporte escrito en {args.output}", file=sys.stderr)
    elif args.format == "json":
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(markdown_report(data))
    return 1 if data["summary"]["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
