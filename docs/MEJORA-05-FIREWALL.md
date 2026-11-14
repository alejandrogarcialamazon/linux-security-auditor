# Mejora 5 — Auditoría de firewall por backend

Fecha: 2026-11-13.

## Funcionamiento y límites

Se consultan nftables, firewalld e IPv6 aunque UFW esté instalado. Si UFW tiene prioridad, también se consulta iptables IPv4 de manera separada. Cada hallazgo tiene ID propio en la familia CIS-LITE-006. UFW inactivo sigue siendo un incumplimiento del gestor UFW, no una prueba de ausencia total de filtrado.

nftables se consulta con JSON y sólo aprueba el criterio acotado de políticas input drop para ambas familias (inet o ip/ip6). firewalld consulta estado, zonas activas y sus targets: sólo DROP/REJECT de todas las zonas identificadas aprueba ese criterio. ip6tables consulta una política INPUT DROP única. Errores, formatos desconocidos, familias parciales y herramientas no disponibles producen WARN. Un PASS no acredita las reglas completas, forwarding, prioridades, Docker, alcance externo o persistencia.

No se aplican reglas, no se activa ningún gestor y no se recarga ningún servicio. Los backends pueden compartir reglas; los hallazgos no se suman como capas independientes de protección.

Referencias: https://netfilter.org/projects/nftables/manpage.html y https://firewalld.org/documentation/man-pages/firewall-cmd.html

## Verificación

87 pruebas locales en Python 3.14, 85 aprobadas y dos integraciones omitidas por falta de sshd. Casos nuevos: backends coexistentes, JSON nftables vacío/desconocido, doble pila, targets firewalld, errores de consultas, IPv6, procesos fuera de systemd, variantes activas, habilitación y puertos convencionales.

```bash
python3 -m unittest discover -s tests -v
```

Validación remota: 87 pruebas aprobadas con Python 3.10.12, sin omisiones; PDF y auditoría correctos sin sudo. Metadatos de passwd, shadow y sshd_config sin cambios. Las consultas restringidas producen WARN; esto no certifica el firewall completo. Los reportes reales permanecen excluidos de Git.
