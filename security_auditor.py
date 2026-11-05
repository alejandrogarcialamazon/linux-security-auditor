#!/usr/bin/env python3
"""Auditor de endurecimiento ligero para hosts Linux.

No sustituye una evaluación CIS certificada. Ejecutar como root mejora la
visibilidad, pero el modo de auditoría no modifica el sistema.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass
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


def command(args: list[str]) -> tuple[int, str, str]:
    """Run a command without a shell and return decoded output."""
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=12, check=False)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)


def file_mode(path: Path) -> int | None:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None


def audit_file_permissions() -> list[Finding]:
    checks = [
        (Path("/etc/passwd"), 0o644, "CIS-LITE-001", "Permisos de /etc/passwd"),
        (Path("/etc/shadow"), 0o640, "CIS-LITE-002", "Permisos de /etc/shadow"),
    ]
    findings: list[Finding] = []
    for path, expected, check_id, title in checks:
        mode = file_mode(path)
        if mode is None:
            findings.append(Finding(check_id, title, "WARN", "medium", f"{path} no existe o no es accesible.", "Verifique que el archivo exista y sea legible.", True))
            continue
        owner = path.stat().st_uid
        # passwd permits read by everyone but never write by group/others; shadow
        # must not be accessible by others. Group permissions vary across distros.
        insecure = bool(mode & 0o022) if path.name == "passwd" else bool(mode & 0o007)
        owner_ok = owner == 0
        status = "PASS" if not insecure and owner_ok else "FAIL"
        evidence = f"modo={mode:04o}, uid={owner}; referencia habitual={expected:04o}"
        findings.append(Finding(
            check_id, title, status, "high", evidence,
            f"Ejecute chmod {expected:03o} {path} y asegure propietario root.",
            remediable=status == "FAIL",
        ))
    return findings


def ssh_effective_settings() -> tuple[dict[str, str], str]:
    sshd = shutil.which("sshd")
    config = Path("/etc/ssh/sshd_config")
    if not sshd or not config.exists():
        return {}, "sshd o /etc/ssh/sshd_config no está disponible"
    code, stdout, stderr = command([sshd, "-T", "-f", str(config)])
    if code != 0:
        return {}, f"sshd -T falló: {stderr or stdout}"
    settings: dict[str, str] = {}
    for line in stdout.splitlines():
        key, _, value = line.partition(" ")
        if key in {"permitrootlogin", "passwordauthentication"}:
            settings[key] = value.strip().lower()
    return settings, ""


def audit_ssh() -> list[Finding]:
    settings, error = ssh_effective_settings()
    if error:
        return [Finding("CIS-LITE-003", "Configuración efectiva de SSH", "WARN", "medium", error, "Instale/active OpenSSH Server y valide su configuración.")]

    findings: list[Finding] = []
    root_login = settings.get("permitrootlogin", "unknown")
    findings.append(Finding(
        "CIS-LITE-003", "SSH: acceso directo de root",
        "PASS" if root_login == "no" else "FAIL", "high",
        f"permitrootlogin={root_login}", "Defina PermitRootLogin no.",
        remediable=root_login != "no",
    ))
    password_auth = settings.get("passwordauthentication", "unknown")
    # Password auth can be required by an organization's access model, therefore
    # this remains advisory and is intentionally not auto-remediated.
    findings.append(Finding(
        "CIS-LITE-004", "SSH: autenticación por contraseña",
        "PASS" if password_auth == "no" else "WARN", "medium",
        f"passwordauthentication={password_auth}",
        "Tras verificar acceso por llave para una cuenta administrativa, defina PasswordAuthentication no.",
    ))
    return findings


def service_is_active(name: str) -> tuple[bool | None, str]:
    if not shutil.which("systemctl"):
        return None, "systemctl no está disponible"
    code, stdout, stderr = command(["systemctl", "is-active", name])
    if code == 0:
        return True, stdout
    if code in {3, 4}:
        return False, stdout or "inactive/not-found"
    return None, stderr or stdout


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
        active, evidence = service_is_active(unit)
        if active is None:
            findings.append(Finding("CIS-LITE-005", f"Servicio {unit}", "INFO", "low", evidence, "No evaluable sin systemd."))
        elif active:
            findings.append(Finding("CIS-LITE-005", f"Servicio {unit}", "FAIL", "medium", reason, f"Deshabilite el servicio si no existe una necesidad documentada: systemctl disable --now {unit}"))
        else:
            findings.append(Finding("CIS-LITE-005", f"Servicio {unit}", "PASS", "low", evidence, "Sin acción requerida."))
    return findings


def audit_firewall() -> list[Finding]:
    findings: list[Finding] = []
    ufw = shutil.which("ufw")
    if ufw:
        code, stdout, stderr = command([ufw, "status"])
        active = code == 0 and "Status: active" in stdout
        findings.append(Finding(
            "CIS-LITE-006", "Firewall UFW",
            "WARN" if code != 0 else ("PASS" if active else "FAIL"), "high", stdout or stderr or "Sin salida",
            "Defina reglas explícitas de acceso administrativo y active UFW.",
        ))
        return findings

    iptables = shutil.which("iptables")
    if iptables:
        code, stdout, stderr = command([iptables, "-S"])
        policies = [line for line in stdout.splitlines() if line.startswith("-P ")]
        drop_default = any(line in {"-P INPUT DROP", "-P INPUT REJECT"} for line in policies)
        findings.append(Finding(
            "CIS-LITE-006", "Firewall iptables",
            "PASS" if code == 0 and drop_default else "WARN", "high",
            "; ".join(policies) if policies else (stderr or "No se pudieron leer políticas"),
            "Revise reglas persistentes y use una política INPUT restrictiva sin bloquear su acceso actual.",
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
    # Preserve the distribution-specific group (e.g. `shadow`) while ensuring
    # the account database is owned by root.
    os.chown("/etc/passwd", 0, -1)
    os.chown("/etc/shadow", 0, -1)
    os.chmod("/etc/passwd", 0o644)
    os.chmod("/etc/shadow", 0o640)
    return "Propietario y permisos de /etc/passwd y /etc/shadow ajustados."


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
        "",
        "| ID | Estado | Severidad | Control | Evidencia | Recomendación |",
        "|---|---|---|---|---|---|",
    ]
    for item in data["findings"]:
        clean = lambda value: str(value).replace("|", "\\|").replace("\n", " ")
        rows.append("| {id} | {status} | {severity} | {title} | {evidence} | {recommendation} |".format(**{key: clean(value) for key, value in item.items()}))
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
