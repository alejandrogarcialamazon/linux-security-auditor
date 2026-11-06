# Mejora 3 — Reportes explicables e identificadores únicos

Fecha: 2026-11-06. Alcance: formato JSON/Markdown y presentación de hallazgos.

## Problema y solución

Los PASS de SSH y firewall todavía podían sugerir cambios, cinco servicios compartían
ID y el informe mezclaba observación, objetivo y acción. Ahora cada hallazgo incluye
`expected` y `risk`; todos los PASS recomiendan «Sin cambios necesarios». La severidad
se explica como impacto potencial del incumplimiento, no como una acción pendiente.

Los servicios tienen IDs estables por unidad: CIS-LITE-005-TELNET, -RSH, -REXEC,
-TFTP y -XINETD. El JSON añade `scope.checks` y `scope.control_families`. Cinco servicios
cuentan como cinco comprobaciones de una misma familia. No se calcula conformidad CIS.
Markdown separa evidencia, criterio esperado, riesgo y acción propuesta, escapando
barras y saltos de línea en todos los campos. Acepta JSON anteriores sin campos nuevos.

## Compatibilidad

Se mantienen summary, findings, recommendation y los códigos de salida 0/1/2.
Los consumidores deben aceptar los campos adicionales y actualizar filtros por los
antiguos IDs de servicios repetidos. No cambian los criterios de auditoría ni se
añaden remediaciones. Se conservan las ediciones remotas del titular en el README
y la eliminación de docs/GITHUB.md.

## Pruebas

```bash
python3 -m unittest discover -s tests -v
python3 tools/build_pdf.py docs/MANUAL.md docs/MANUAL.pdf
```

56 pruebas locales aprobadas con Python 3.14, incluidas 5 nuevas de reportes:
PASS sin acciones, IDs únicos/estables en todos los estados, JSON con criterios y
riesgos, alcance por familias, escape de Markdown y renderizado de JSON anterior.
Validación remota en una copia temporal del host de laboratorio con Python 3.10.12:
56 pruebas aprobadas, compilación, PDF y auditoría JSON correctas sin sudo. Los
metadatos comprobados de passwd/shadow/sshd_config permanecieron sin cambios.
La auditoría devolvió 7 PASS y 3 WARN por visibilidad parcial. No se aplicaron
remediaciones ni se publicaron reportes privados.

## Límites

Estos campos hacen explícita la interpretación de cada control; no amplían su
cobertura ni convierten una auditoría sin privilegios en una evaluación completa.
Los reportes reales del laboratorio permanecen fuera del repositorio público.
