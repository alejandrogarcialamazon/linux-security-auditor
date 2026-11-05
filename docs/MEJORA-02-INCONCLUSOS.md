# Mejora 2 — Separar incumplimientos de comprobaciones inconclusas

Fecha: 2026-11-05. Depende de la mejora 1 de permisos.

## Problema

Una salida UFW inesperada con código 0 se convertía en FAIL. Un parámetro SSH
ausente también podía producir FAIL y aparecer como remediable. systemctl podía
producir PASS con código 3/4 sin una salida reconocida, o INFO ante un error de
consulta. El idioma del sistema podía alterar la interpretación de los comandos.

## Política de resultados

- PASS: evidencia reconocida y consulta correcta que satisface el criterio.
- FAIL: evidencia reconocida y consulta correcta que incumple el criterio.
- WARN: recomendación pendiente o imposibilidad de concluir por falta de datos,
  permisos, herramientas, tiempo de espera o formatos reconocidos.
- INFO: reservado para contexto o inaplicabilidad explícita; no oculta errores.

No se cambia el contrato de salida CLI: 1 si existe FAIL, 0 en caso contrario
y 2 ante un error de remediación. Una ejecución con sólo WARN sigue devolviendo
0 por compatibilidad: el consumidor debe revisar el resumen. Los códigos 124/127
citados a continuación pertenecen al comando consultado, no al proceso auditor.

## Cambios

| Consulta | Evidencia concluyente | Tratamiento de incertidumbre |
|---|---|---|
| Comandos | Se conserva returncode/stdout/stderr | Timeout: 124; error al iniciar: 127; evidencia explícita |
| SSH root | `no`: PASS; modalidades reconocidas de acceso: FAIL según criterio existente | Valor ausente/desconocido: WARN no remediable |
| SSH contraseña | `no`: PASS; `yes`: WARN consultivo | Valor ausente/desconocido: WARN con diagnóstico diferente |
| systemctl | 0 + `active`: activo; 3 + `inactive`/`failed`: no activo | Código/salida incompatibles, estados transitorios o falta de systemctl: WARN |
| UFW | 0 + un único encabezado `Status: active`/`inactive`: PASS/FAIL | Error, encabezado vacío, desconocido o duplicado: WARN |
| iptables | 0 + una única política INPUT DROP: PASS para ese criterio | Error, salida ausente, duplicada, desconocida o ACCEPT: WARN |

El entorno de cada comando fija LC_ALL, LANG y LANGUAGE en C, sin modificar el
del padre. Se decodifica UTF-8 con sustitución de bytes inválidos, evitando una
excepción de decodificación que impida entregar evidencia.

Si `sshd -T` falla, ambos controles SSH se conservan como WARN. Se rechazan
parámetros duplicados y respuestas sin parámetros reconocidos. Una respuesta
parcial permite evaluar sólo los parámetros presentes y válidos.

En iptables se retira REJECT como supuesto valor válido de política por defecto.
La protección completa del firewall, nftables/firewalld y las reglas de IPv6
siguen fuera de alcance. UFW inactivo sigue siendo un incumplimiento de ese
control; no se concluye a partir de ello que no exista ningún otro filtro.

## Pruebas y reproducción

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q security_auditor.py tests
python3 tools/build_pdf.py docs/MANUAL.md docs/MANUAL.pdf
```

Resultado local: 51 pruebas aprobadas con Python 3.14 (32 de la entrega previa
y 19 nuevas). Se prueban timeout, permisos, comandos ausentes, idioma, salidas
vacías/desconocidas/duplicadas/contradictorias, estados transitorios y datos
parciales. Un escenario completamente inconcluso genera 10 WARN, sin PASS ni FAIL.

Una reproducción simulada del reporte facilitado por el usuario mantiene
7 PASS, 2 FAIL y 1 WARN: las mejoras no ocultan los incumplimientos comprobados.
También se verifican los códigos CLI 0/1/2 y la producción local de JSON.

No se modificaron SSH, firewall, servicios ni cuentas reales durante las pruebas.
Validación adicional en una VM Linux del laboratorio con Python 3.10.12:
51 pruebas aprobadas, compilación y PDF correctos y auditoría JSON ejecutada sin
sudo. Se usaron copias temporales que se eliminaron al terminar; los metadatos
comprobados de passwd, shadow y sshd_config permanecieron iguales. La auditoría
produjo 7 PASS y 3 WARN, sin FAIL; los WARN incluyen controles sin visibilidad
suficiente. Esto no significa que se hayan corregido los hallazgos del reporte
previo obtenido con sudo. No se ejecutaron remediaciones sobre el sistema real.
La CI multiversión se ejecutará al producirse el push programado; no se ha
adelantado la publicación.

Referencias:
- [systemctl, manual Ubuntu](https://manpages.ubuntu.com/manpages/noble/man1/systemctl.1.html).
- [ufw, manual Ubuntu](https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html).
- [iptables, proyecto netfilter](https://man7.org/linux/man-pages/man8/iptables.8.html).
