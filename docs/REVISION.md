# Evaluación para publicación

## Conveniencia

Conviene un repositorio público como herramienta educativa y punto de partida
para contribuciones. Tiene pocas dependencias, alcance explícito y reportes
estructurados. No debe presentarse como una implementación completa de CIS ni
como un remediador apto para aplicar indiscriminadamente en producción.

## Funcionamiento

1. Lee metadatos de passwd/shadow y consulta SSH, systemd y UFW/iptables.
2. Emite estados PASS, FAIL, WARN e INFO en JSON o Markdown.
3. Devuelve 1 si hay FAIL y 0 en caso contrario; WARN/INFO no hacen fallar el proceso.
4. Solo modifica el sistema con `--remediate CONTROL --yes` y privilegios root.
5. No reinicia SSH, no deshabilita servicios y no cambia reglas de firewall.

## Cambios de esta revisión

- Compatibilidad real con Python 3.10 usando `timezone.utc`.
- Error al consultar UFW tratado como incertidumbre, no como firewall inactivo.
- Directiva global SSH colocada antes de otras directivas y operación idempotente.
- Remediación SSH conservadora: rechazo de Match/Include, respaldo 0600,
  validación sintáctica y efectiva, restauración ante error y aviso de recarga manual.
- Pruebas aisladas y CI para Python 3.10–3.14.
- Exclusión de credenciales, backups y reportes locales de Git.

## Límites pendientes

- Probar en VMs descartables Debian/Ubuntu y Red Hat antes de recomendar uso operativo.
- El PASS global de SSH no evalúa todos los contextos Match de cada conexión.
- Firewall: cobertura parcial de iptables/UFW, sin nftables/firewalld ni IPv6.
- Los permisos no incluyen ACL, SELinux o todas las particularidades de cada distribución.
- La remediación de permisos no es una transacción: un fallo puede dejar cambios parciales.
- La auditoría sin privilegios puede tener visibilidad incompleta; `0` no significa
  cumplimiento integral ni ausencia de WARN/INFO.
- Una prueba en un sandbox verifica ejecución y formato, no la seguridad del host físico.

## Publicación

Publicar código, pruebas y documentación. Mantener privados los reportes reales,
inventarios de hosts, credenciales y respaldos. Elegir una licencia explícita si
se desea permitir reutilización por terceros.
