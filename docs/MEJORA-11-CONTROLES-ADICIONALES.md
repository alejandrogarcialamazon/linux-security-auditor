# Mejora 11 — Cuentas, sudoers y sincronización

Fecha: 2026-11-16.

python3 security_auditor.py --extended añade CIS-LITE-008 (cuentas UID 0 distintas de root en /etc/passwd), 009 (metadatos del sudoers principal) y 010 (timedatectl NTPSynchronized). No lee hashes ni contenidos de sudoers. Archivos inaccesibles, formato inesperado o comandos inconclusos producen WARN. UID 0 adicional, permisos excesivos o reloj explícitamente no sincronizado producen FAIL.

Es un alcance limitado: no cubre NSS/LDAP, contenido de políticas sudo, includes, ni calidad/autenticidad de fuentes NTP. No cambia cuentas, servicios ni permisos. Pruebas con archivos temporales y respuestas simuladas cubren fallos, desconocidos y respuestas exactas.

## Validación

Suite unittest y pruebas específicas en tests/test_policy_reporting.py. La integración del laboratorio se ejecuta por SSH con archivos temporales; no se remedia /etc ni se recargan servicios. Evidencia privada en reports/, excluida de Git.
