# Mejora 12 — Auditoría remota y plantilla Jenkins

Fecha: 2026-11-16.

python3 tools/audit_remote.py 192.168.89.89 --user alejandro --identity /home/alejandro/.ssh/id_ed25519 --extended > reports/remoto.json

Transfiere únicamente siete módulos explícitos, los ejecuta con Python 3 en un directorio temporal y lo elimina al terminar normalmente. BatchMode, IdentitiesOnly y StrictHostKeyChecking permanecen activos; no acepta remediaciones ni comandos arbitrarios. No solicita contraseñas ni modifica known_hosts. Requiere Python 3.10+ y clave/huella previamente configuradas. El resultado refleja los permisos del usuario remoto; no eleva privilegios. Un corte abrupto puede dejar el directorio temporal para limpieza manual.

examples/Jenkinsfile es una plantilla sin desplegar: pruebas y auditoría manual de un host autorizado. Código 1 marca ejecución inestable por hallazgos; otros errores fallan el job. Configurar credenciales SSH en el agente sin incluirlas en el repositorio. Los reportes contienen información interna y no se publican automáticamente.

## Validación

Suite unittest y pruebas específicas en tests/test_policy_reporting.py. La integración del laboratorio se ejecuta por SSH con archivos temporales; no se remedia /etc ni se recargan servicios. Evidencia privada en reports/, excluida de Git.
