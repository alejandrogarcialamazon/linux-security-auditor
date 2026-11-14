# Mejora 7 — Plan de remediación sin aplicar cambios

Fecha: 2026-11-13. Alcance: permisos de cuentas y acceso SSH directo de root.

## Uso

```bash
python3 security_auditor.py --remediate permissions --dry-run --format json
python3 security_auditor.py --remediate ssh-root-login --dry-run --format markdown
python3 security_auditor.py --remediate permissions --dry-run --output reports/plan.json
```

La selección del control es obligatoria. No se incorpora una opción «arreglar todo»
ni se automatizan firewall, servicios o autenticación por contraseña. El plan no
requiere root ni --yes; --yes junto a --dry-run nunca aplica cambios. Sin --dry-run
se conservan las exigencias de root y --yes. Las opciones de contexto/configuración
SSH alternativa continúan siendo incompatibles con remediaciones.

## Salida y significado

El esquema del plan es distinto del reporte de auditoría. Incluye control, dry_run,
applied=false, status, operations con before/after, blockers, requirements y recovery.
planned significa que se identifican operaciones, no que ya se validó toda su
seguridad. no_changes identifica ausencia de operaciones. blocked impide proponer
la aplicación automática. planned/no_changes devuelven 0; blocked devuelve 2.

Permisos: se leen metadatos sin abrir contenidos; se proponen sólo UID y bits
excedentes, preservando GID y permisos restrictivos. Se registra identidad del
archivo y metadatos previos para revisión/recuperación manual. Un archivo ausente,
no regular, enlace o error bloquea el lote; no se anuncia como remediable otro
archivo del lote cuando la aplicación conjunta no podría completarse.

SSH: se comparte la comprobación de disponibilidad y elegibilidad entre auditoría,
plan y aplicación. Match/Include, enlace, archivo ilegible, codificación inválida o
sshd ausente bloquean la corrección. Se muestran únicamente valores reconocidos
de PermitRootLogin y el cambio a no; no se serializa el archivo ni comentarios
que pudieran contener información privada. Se explica el respaldo 0600 y la
validación de sintaxis/valor efectivo durante la aplicación. No se promete MFA,
no se recarga SSH y no se comprueba acceso alternativo de forma destructiva.

El plan puede describir la colocación de la directiva al principio del archivo.
Un no-op SSH real todavía se valida antes de declararse correcto. El plan no
se importa como una orden ejecutable: la aplicación inspecciona nuevamente el
estado y puede rechazar condiciones que hayan cambiado.

## Requisitos y recuperación

Se deben revisar los valores previstos y conservar un acceso alternativo antes de
aplicar. El control de permisos sigue sin transacción/rollback automático: informa
cambios parciales, y la recuperación exige revisar identidad y metadatos registrados.
La aplicación SSH conserva su respaldo y restaura contenido ante error de validación;
una recarga posterior y una nueva conexión corresponden al operador.

--dry-run no modifica archivos del sistema ni servicios. --output es una escritura
explícita del informe solicitado; se distingue de una modificación de configuración.

## Pruebas

105 pruebas locales en Python 3.14: 103 aprobadas y dos integraciones omitidas por
no disponer de sshd. Casos nuevos: diferencias mínimas, propietario, modo restrictivo,
lote bloqueado, redacción de SSH, Match/Include, enlaces, ausencia de comandos,
capacidad de remediación, root/yes innecesarios en dry-run, salida JSON/Markdown,
informe explícito y validación de no-op. Se incluyen las pruebas anteriores de
restauración SSH y rechazo de remediaciones sin confirmación.

```bash
python3 -m unittest discover -s tests -v
```

Validación remota en Python 3.10.12: 105 pruebas aprobadas sin omisiones, PDF y auditoría correctos. Se ejecutaron ambos dry-run reales sin sudo: permisos devolvió no_changes y SSH blocked por su elegibilidad; ninguno aplicó cambios. Los metadatos reales permanecieron iguales. Los reportes operativos quedan excluidos de Git.

## Ajuste de coherencia del firewall

Se completa la interpretación de la mejora 5: el estado inactivo de UFW se presenta
como WARN en el reporte agregado, sin afirmar que no haya otro backend filtrando.
Los resultados de nftables, firewalld e iptables siguen siendo independientes y
acotados a sus criterios; no se fusionan en una certificación de protección total.
