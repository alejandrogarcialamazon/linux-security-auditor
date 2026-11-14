# Mejora 9 — Integración reproducible en entornos descartables

Fecha: 2026-11-13. Alcance: recorridos con fixtures reales sin remediar el host.

## Ejecutar

```bash
python3 -m unittest discover -s tests -v
python3 integration/vm_checks.py --fixtures-only
```

El arnés sólo genera archivos sintéticos en directorios temporales. Para permisos,
si el usuario no es root, crea un namespace con unshare -Ur: UID 0 queda mapeado
al usuario ordinario, sin sudo ni acceso administrativo al host. Si no está
permitido, devuelve 77 y la integración se informa como omitida; no como aprobada.
En una VM/container de pruebas como root, usa directamente los mismos fixtures.

Se prueba audit → plan → apply → audit, una repetición sin cambios y un fallo
provocado en el segundo archivo con restauración del primero. ACCOUNT_FILES se
redirige exclusivamente al directorio temporal, nunca a /etc. Los cambios de
propietario a IDs fuera del mapping se cubren por pruebas unitarias de syscalls;
no se afirma haber probado todos los UID del host en el namespace.

SSH usa una clave efímera y una configuración temporal; valida con OpenSSH real
(-t/-T), reemplaza atómicamente el fixture, comprueba el no-op y provoca un fallo
posterior para verificar restauración. No inicia un daemon ni abre puertos.
Los archivos, clave, respaldos y journals de fixture se eliminan al terminar.

## VM y CI

integration/Vagrantfile prepara dos VMs de 1 CPU/1 GiB. El operador debe elegir
boxes Ubuntu y Debian compatibles mediante AUDITOR_UBUNTU_BOX y AUDITOR_DEBIAN_BOX;
no se descarga ni crea ninguna VM automáticamente desde esta tarea. Antes de
ensayos operativos ajenos a fixtures, crear un snapshot explícito y verificar
restauración con el hipervisor. Este arnés no toma snapshots del host existente.

GitHub Actions añade integración en containers Ubuntu 24.04 y Debian 12, además
de Python 3.10–3.14. Se instala OpenSSH sólo en esos entornos descartables; una
policy-rc.d evita iniciar servicios y se prepara el directorio de validación.
Los containers no se presentan como VMs: prueban distribución y herramientas;
la ejecución adicional en el host VM real verifica ese entorno concreto.

## Evidencia y límites

En el host del laboratorio Python 3.10.12 se ejecuta la suite y el arnés con
namespace de usuario sin sudo. Se comprueban metadatos de passwd/shadow/sshd_config
antes y después para acreditar ausencia de modificaciones de configuración real.
La evidencia operativa se conserva en reports/, fuera del repositorio público.
La CI se dispara al publicar; no se presupone su resultado antes de ejecutarla.

121 pruebas locales, con 3 omisiones de integración por condiciones del entorno.
Validación remota final: 121 pruebas aprobadas sin omisiones en Python 3.10.12, incluido el flujo completo de permisos con UID aislado y el de SSH con OpenSSH real. PDF, auditoría y ambos dry-run correctos; metadatos reales sin cambios. No se probaron
reglas inseguras en la red del laboratorio ni se deshabilitaron accesos reales.

Regresión de entorno: el probe de unshare fija LC_ALL/LANG/LANGUAGE=C para reconocer una denegación de permisos en cualquier idioma del servicio. Un fallo real del fixture sigue siendo error, no omisión.
