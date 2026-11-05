# Mejora 1 — Evaluación y corrección de permisos de cuentas

Fecha: 2026-11-05. Alcance: CIS-LITE-001 y CIS-LITE-002.

## Problema

La versión anterior aceptaba `/etc/shadow` con modo `0660`: sólo comprobaba
permisos de otros, omitiendo escritura/ejecución del grupo y bits especiales.
La corrección aplicaba modos fijos `0644` y `0640`, ampliando configuraciones
válidas más restrictivas, como `0400`. También consultaba dos veces los metadatos
y recomendaba modificar archivos que ya estaban aprobados.

## Comportamiento nuevo

| Archivo | Criterio |
|---|---|
| passwd | Archivo regular, UID 0, permisos contenidos en `0644` |
| shadow | Archivo regular, UID 0, permisos contenidos en `0640` con GID 0 o grupo local `shadow`; con otro grupo, contenidos en `0600` |

- Los modos son máximos, no una obligación de añadir lectura/escritura.
- Se rechazan escritura de grupo, ejecución, bits especiales y acceso de otros
  a shadow. La resolución del grupo usa NSS, no un GID fijo por distribución.
- Grupo inexistente/no autorizado con lectura de shadow: FAIL y propuesta
  de eliminar la lectura de grupo, conservando el GID. Error operativo de NSS:
  WARN, sin anunciar que el control está aprobado ni ofrecer corrección.
- Cada archivo se inspecciona una vez con `lstat`; enlaces, tipos no regulares,
  archivos ausentes o metadatos inaccesibles producen WARN no remediable.
- Un PASS recomienda conservar el estado, no ejecutar chmod.

## Remediación

Se mantiene la exigencia de root y `--remediate permissions --yes`. Se abren y
validan ambos archivos antes del primer cambio, sin leer su contenido. Los
descriptores usan `O_NOFOLLOW`, `O_NONBLOCK` y `O_CLOEXEC` para rechazar enlaces,
evitar bloqueo en FIFO y no heredar descriptores accidentalmente.

Se corrige sólo el UID incorrecto y se calcula `modo_actual & máximo_permitido`.
Se conserva el grupo, se verifican propietario/grupo/modo después de la operación
y una segunda ejecución sin diferencias no cambia nada. Los errores identifican
las acciones anteriores; aún no hay rollback transaccional entre archivos.

## Verificación

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q security_auditor.py tests
python3 tools/build_pdf.py docs/MANUAL.md docs/MANUAL.pdf
```

Resultado local: 32 pruebas aprobadas con Python 3.14, incluidas las 12 previas.
Una prueba recorre las 4096 combinaciones de modo para cada archivo: 8192
evaluaciones. Casos adicionales: propietario incorrecto; grupos root, shadow,
ajeno y desconocido; fallo NSS; enlaces/FIFO/directorios; metadatos ausentes;
idempotencia; modos restrictivos; prevalidación de ambos archivos; fallo de chmod;
verificación posterior; cierre de descriptores y conservación del contenido.

Las pruebas de cambios usan fixtures temporales y propiedad simulada; no cambian
los archivos de cuentas reales. Se comprobó además la generación local de JSON.
Validación adicional en una VM Linux del laboratorio con Python 3.10.12:
32 pruebas aprobadas, compilación y PDF correctos y auditoría JSON ejecutada sin
sudo. Se usaron copias temporales, eliminadas al terminar. Los metadatos de
passwd, shadow y sshd_config permanecieron iguales. La auditoría sin privilegios
produjo 7 PASS y 2 WARN; esto refleja visibilidad parcial, no correcciones del host.
No se probaron remediaciones sobre archivos de cuentas reales ni se certifica
compatibilidad con todas las distribuciones.

## Límites

No se evalúan ACL, SELinux/AppArmor, membresías del grupo shadow ni configuraciones
especiales de NSS. Las distribuciones con grupos de lectura distintos de root o
shadow requieren revisión de su política antes de aplicar correcciones. No se
añaden permisos faltantes ni se intenta reparar la disponibilidad de las cuentas.

Referencia: [shadow(5), shadow-utils](https://man7.org/linux/man-pages/man5/shadow.5.html).
