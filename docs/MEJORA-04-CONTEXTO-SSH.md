# Mejora 4 — Contextos SSH e interpretación de autenticación

Fecha: 2026-11-06. Depende del reporte estructurado de la mejora 3.

## Problema

La evaluación global no describía excepciones Match y presentaba modalidades de
acceso root con una explicación genérica. PasswordAuthentication no no demuestra
por sí solo ausencia de autenticación interactiva ni una política de MFA.

## Funcionamiento

Se conserva una consulta global y se agregan hasta 16 contextos explícitos mediante
sshd -T -C. El daemon interpreta Include y Match; la herramienta no intenta
reimplementar su parser. Cada contexto requiere user y addr; host, laddr y lport
se aportan cuando correspondan. addr es el origen del cliente; laddr/lport son la
dirección/puerto locales del servidor. No se abren conexiones de prueba al daemon.

```bash
python3 security_auditor.py --ssh-context 'user=root,addr=127.0.0.1,host=localhost' --format json
python3 security_auditor.py --ssh-context 'user=root,addr=127.0.0.1' --ssh-context 'user=root,addr=127.0.0.2' --format markdown
python3 security_auditor.py --ssh-config /ruta/sshd_config --format json
```

Los ejemplos representan conexiones simuladas de loopback. El archivo indicado
se consulta en disco; no se verifica que coincida con opciones de arranque o con
una instancia concreta en memoria. Un PASS global no se extrapola a los contextos.
Faltas de permisos, atributos de conexión requeridos o datos válidos producen WARN.

Se validan claves, IPs y puerto; se rechazan duplicados, vacíos y separadores en
valores. La consulta usa una lista de argumentos sin shell. Se normalizan IPs,
puerto y orden de campos; contextos equivalentes no generan filas duplicadas.
Cada combinación conserva IDs estables con sufijo CTX y sus campos JSON context
(normalizado) y source (archivo). Los controles se agrupan por familia en scope.

## Root y métodos

without-password se explica como alias de prohibit-password, con contraseña e
interacción deshabilitadas para root. Sigue incumpliendo la política estricta
PermitRootLogin no. yes y forced-commands-only tienen explicaciones propias.

El control consultivo CIS-LITE-007 añade KbdInteractiveAuthentication,
PubkeyAuthentication, UsePAM y AuthenticationMethods. Reconoce secuencias y
alternativas de métodos. INFO puede describir secuencias obligatorias con llave;
no acredita factores independientes. WARN señala vías interactivas, valores no
reconocidos o requisitos deshabilitados. PASS tiene alcance limitado al criterio
consultado; no confirma que un usuario pueda conectarse ni que exista MFA real.
No se examina la implementación de PAM ni el almacenamiento de llaves.

## Seguridad y compatibilidad

No se añaden remediaciones. Las opciones nuevas no pueden combinarse con
--remediate; las filas contextuales o de archivos alternativos son no remediables.
No se recargan servicios ni se cambia la configuración efectiva del host.

Se añade un control SSH por contexto: la ejecución global pasa de 10 a 11
comprobaciones y cada contexto explícito agrega tres más. Los lectores deben
aceptar CIS-LITE-007 y sufijos CTX. Se conservan los códigos de salida 0/1/2.

## Pruebas

```bash
python3 -m unittest discover -s tests -v
python3 tools/build_pdf.py docs/MANUAL.md docs/MANUAL.pdf
```

Python 3.14 local: 75 pruebas, 73 aprobadas y dos integraciones omitidas porque no
está instalado sshd. Python 3.10.12 en el host del laboratorio: 75 aprobadas, sin
omisiones, compilación/PDF y auditoría JSON correctos. La CLI contextual real
produjo 14 IDs únicos. Se ejecutó sin sudo: los WARN de la auditoría real indican
visibilidad parcial y no corrigen los hallazgos del reporte anterior con sudo.

Las integraciones crean configuración y clave efímeras, consultan OpenSSH real con
Include/Match y comparan global/orígenes diferentes. Se comprueba que el fixture
no cambia y que configuración inválida produce WARN. Otras pruebas cubren alias,
campos parciales, secuencias de métodos, IDs estables, deduplicación, límites,
JSON y rechazo de remediación con opciones de consulta. No se inicia un daemon.
Los metadatos de cuentas y configuración SSH reales permanecieron sin cambios;
los reportes de host no se incluyen en el repositorio público.

Referencias: [sshd -T y -C](https://man.openbsd.org/sshd),
[opciones de SSH y AuthenticationMethods](https://man.openbsd.org/sshd_config).
