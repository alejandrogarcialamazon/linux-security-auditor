# Mejora 6 — Servicios, procesos y puertos

Fecha: 2026-11-13.

## Funcionamiento y límites

Se conservan los cinco IDs de servicios. Se consultan variantes .socket/.service, incluidos telnetd, tftpd y rlogin. systemctl show distingue LoadState, ActiveState y UnitFileState. ss -H -lntu consulta escuchas IPv4/IPv6 TCP/UDP y ps -eo comm= nombres de procesos, sin leer argumentos ni contenidos de configuraciones.

Unidad activa o daemon conocido presente: FAIL. Unidad habilitada pero inactiva, puerto convencional sin identificación suficiente o visibilidad incompleta: WARN. PASS exige que las consultas disponibles terminen correctamente y no haya indicios bajo la cobertura descrita. Un puerto 23/69/etc. no identifica por sí solo un protocolo; no se afirma accesibilidad desde otra máquina. No se afirma que un paquete esté desinstalado ni se cubren todos los nombres posibles.

Se mantienen como límites hidepid, espacios de nombres, contenedores y servicios con nombres/puertos personalizados. Las recomendaciones exigen revisión antes de deshabilitar; la herramienta no modifica unidades ni procesos.

Referencia: https://man7.org/linux/man-pages/man8/ss.8.html

## Verificación

87 pruebas locales en Python 3.14, 85 aprobadas y dos integraciones omitidas por falta de sshd. Casos nuevos: backends coexistentes, JSON nftables vacío/desconocido, doble pila, targets firewalld, errores de consultas, IPv6, procesos fuera de systemd, variantes activas, habilitación y puertos convencionales.

```bash
python3 -m unittest discover -s tests -v
```

Validación remota: 87 pruebas aprobadas con Python 3.10.12, sin omisiones; PDF y auditoría correctos sin sudo. Metadatos de passwd, shadow y sshd_config sin cambios. Las consultas restringidas producen WARN; esto no certifica el firewall completo. Los reportes reales permanecen excluidos de Git.
