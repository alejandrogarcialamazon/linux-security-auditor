# Mejora 8 — Remediaciones recuperables e idempotentes

Fecha: 2026-11-13. Alcance: permisos de cuentas y configuración SSH simple.

## Permisos

La aplicación abre todos los archivos sin seguir enlaces, exige tipos regulares,
toma locks cooperativos y registra UID/GID/modo e identidad antes de modificar.
Comprueba identidad y metadatos antes y después. Sólo quita bits excedentes y corrige
el propietario: no amplía permisos restrictivos ni cambia grupos.

Si una operación posterior falla, intenta restaurar, en orden inverso, los metadatos
de los descriptores ya tocados. Se verifica cada restauración y se distinguen
rolled_back de rollback_failed. Si otro proceso reemplazó un path, el archivo
ajeno no se modifica; se comunica la incidencia. Una segunda ejecución sobre el
estado corregido no vuelve a cambiar los archivos.

## SSH

Para configuración simple, elegible y sin Match/Include, se toma un lock estable
privado. El candidato se escribe en el mismo directorio, preserva UID/GID/modo y
copia metadatos mediante copystat. Se sincroniza y valida con sshd -t y -T antes
de reemplazar el destino. Se conserva un respaldo exclusivo 0600 y se publica
mediante os.replace. Se verifica otra vez el resultado instalado.

Un fallo posterior intenta restaurar contenido y metadatos originales mediante
otra sustitución atómica. Las líneas originales, incluidos finales CRLF, se
conservan en el respaldo y restauración. Si hubo una sustitución/edición externa
se rechaza sobrescribirla automáticamente y se declara recuperación incompleta.
El respaldo sigue disponible para revisión. Los no-op se validan sin generar
otro respaldo ni reemplazar la configuración. No se recarga el servicio.

## Registro opcional

```bash
sudo python3 security_auditor.py --remediate permissions --yes --remediation-log /var/log/security-auditor/cambio-unico.json
```

El destino del registro debe ser nuevo: un archivo, enlace o journal preexistente
no se sobrescribe. El journal se reserva 0600 y sus actualizaciones son atómicas,
con fsync de archivo y directorio. Registra versión de esquema, tiempos UTC,
antes/después, identidad, estado y errores. SSH registra hashes y ruta del respaldo,
no el contenido de la configuración. Un cambio externo del journal se detecta.
Sin esta opción, el resultado/error devuelve el registro en la salida de la
operación; no se promete persistencia tras un corte de energía.

## Límites de recuperación

No existe atomicidad conjunta entre dos archivos ni garantía de rollback ante
SIGKILL, fallo de disco o corte eléctrico. Los locks sólo coordinan participantes
que los respetan. No reemplazan las herramientas de gestión de cuentas ni un
snapshot. ACL y etiquetas SELinux necesitan validación específica: se conservan
los atributos POSIX indicados y se intenta copiar otros metadatos, sin certificar
su política. Un rollback_failed o journal_error exige revisión manual. applied
nulo significa incertidumbre; changed describe si se intentaron cambios, no que
éstos hayan quedado confirmados.

## Pruebas

121 pruebas locales: 118 aprobadas y 3 omitidas por falta de sshd/namespaces.
Casos nuevos: metadatos reales de fixtures, idempotencia, fallo en segundo archivo,
rollback completo e incompleto, conflicto de lock, journal ajeno, error del journal,
candidato SSH inválido, error posterior, edición concurrente y preservación CRLF.
No se aplican remediaciones sobre los archivos reales del host de desarrollo.
Validación remota en VM: 121 pruebas aprobadas sin omisiones en Python 3.10.12, con namespace real y SSH real sobre fixtures. Ver alcance de VM y doble distribución de CI en la mejora 9.
