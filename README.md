# Auditor y Auto-Remediador de Seguridad para Linux

Herramienta Python sin dependencias externas para revisar controles básicos de endurecimiento inspirados en CIS Benchmark. Está pensada para laboratorios, Vagrant y home labs: aporta una señal rápida, no una certificación CIS ni un sustituto de una revisión de seguridad.

## Controles incluidos

| Área | ID | Comprobación |
|---|---|---|
| Cuentas | CIS-LITE-001 | `/etc/passwd`: propietario root y permisos como máximo `0644` |
| Cuentas | CIS-LITE-002 | `/etc/shadow`: propietario root, máximo `0640` y lectura de grupo restringida |
| SSH | CIS-LITE-003 | `PermitRootLogin no` en la configuración efectiva |
| SSH | CIS-LITE-004 | `PasswordAuthentication no` como recomendación |
| Servicios | CIS-LITE-005 | Telnet, rsh, rexec, tftp y xinetd activos |
| Firewall | CIS-LITE-006 | Estado de UFW o política de entrada de iptables |

> La herramienta usa `sshd -T` para consultar la configuración efectiva de SSH, por lo que considera `Include` y valores por defecto. Si ese comando no está disponible, informa `WARN`, no asume que el servidor sea seguro.

## Requisitos

- Linux con Python 3.10 o superior.
- Para detectar servicios: systemd.
- Para inspeccionar SSH: OpenSSH Server (`sshd`).
- Para las correcciones: ejecutar con `sudo`.

No requiere instalar paquetes con `pip`.

## Uso

```bash
# Auditoría en consola (JSON)
python3 security_auditor.py

# Reporte Markdown y JSON
python3 security_auditor.py --format markdown --output reports/auditoria.md
python3 security_auditor.py --format json --output reports/auditoria.json
```

El código de salida es `0` si no hay hallazgos `FAIL`, `1` si los hay y `2` ante un error de remediación. Un `0` con `WARN` no significa auditoría completa: revise el resumen.

### Remediación explícita

La auditoría es siempre de solo lectura salvo que se indiquen ambas opciones `--remediate` y `--yes`.

```bash
# Corrige propietario y quita permisos excedentes sin ampliar los existentes
sudo python3 security_auditor.py --remediate permissions --yes

# Deshabilita el login SSH directo de root
# Se valida con sshd -t y sshd -T y se conserva un .bak privado.
# Ante Match/Include se exige revisión manual. No se recarga el servicio.
sudo python3 security_auditor.py --remediate ssh-root-login --yes
```

`PasswordAuthentication` **no se modifica automáticamente**: desactivarlo puede perder el acceso remoto si antes no se verificó una llave SSH funcional. Defínalo manualmente solo después de validar una cuenta administrativa con llave pública.

## Flujo sugerido

1. Ejecute la auditoría y guarde los reportes.
2. Revise cada `FAIL` y `WARN` con el responsable del host.
3. Asegure una consola local o una segunda sesión SSH antes de cualquier cambio de red/SSH.
4. Aplique únicamente una remediación, vuelva a auditar y pruebe el acceso.
5. Conserve el JSON/Markdown como evidencia.

## Limitaciones y seguridad

- `/etc/shadow` admite lectura de grupo únicamente para GID 0 o el grupo local `shadow`. Con otro grupo se exige como máximo `0600`; se conserva el GID. No se auditan ACL ni pertenencias transitivas de grupos.
- La revisión de iptables solo mira la política por defecto de `INPUT`; no puede determinar si todas las reglas son adecuadas ni si son persistentes.
- Los servicios se marcan por su estado activo, no se deshabilitan automáticamente.
- No gestiona nftables, firewalld, IPv6, SELinux/AppArmor, kernel, actualizaciones ni controles CIS completos.

Consulte el manual ampliado en [docs/MANUAL.md](docs/MANUAL.md). El mismo contenido se entrega como [docs/MANUAL.pdf](docs/MANUAL.pdf).

## Estructura

```text
security_auditor.py  # Auditoría, reporte y remediación controlada
README.md            # Inicio rápido
docs/MANUAL.md       # Diseño, controles, operación y riesgos
docs/MANUAL.pdf      # Versión imprimible del manual
```

## Licencia

Publicado sin licencia de software por decisión del titular. La visibilidad pública no concede por sí sola una licencia de reutilización. Valide los cambios en un entorno no productivo antes de aplicarlos en servidores reales.

## Desarrollo y revisión

```bash
python3 -m unittest discover -s tests -v
python3 tools/build_pdf.py docs/MANUAL.md docs/MANUAL.pdf
```

GitHub Actions verifica Python 3.10–3.14 en Linux. Las pruebas de remediación usan archivos temporales y mocks: no modifican las cuentas ni SSH del equipo.

Consulte [la evaluación del proyecto](docs/REVISION.md)

Corrección de permisos: [mejora 1](docs/MEJORA-01-PERMISOS.md).

Clasificación de comprobaciones inconclusas: [mejora 2](docs/MEJORA-02-INCONCLUSOS.md).

Reportes con criterios, riesgos e identificadores únicos: [mejora 3](docs/MEJORA-03-REPORTES.md).
