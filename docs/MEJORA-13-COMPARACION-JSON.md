# Mejora 13 — JSON versionado y comparación

Fecha: 2026-11-16.

Los reportes nuevos incluyen schema_version=1. python3 security_auditor.py --compare reports/antes.json --output reports/despues.json compara por ID en el mismo host y perfil. También admite reportes anteriores sin versión como formato inicial compatible. Rechaza versiones desconocidas, IDs duplicados, estados inválidos y otro host/perfil, con salida 2.

El bloque comparison distingue added, removed, unchanged, resolved (únicamente FAIL a PASS) y changed. Retirar un control, exceptuarlo o volverlo inconcluso nunca se presenta como resuelto. No compara evidencia textual ni demuestra remediación causal; --extended y contextos pueden cambiar el alcance, visible como controles añadidos/retirados. Reporte previo máximo 16 MiB. El código de salida principal sigue basado en hallazgos actuales.

## Validación

Suite unittest y pruebas específicas en tests/test_policy_reporting.py. La integración del laboratorio se ejecuta por SSH con archivos temporales; no se remedia /etc ni se recargan servicios. Evidencia privada en reports/, excluida de Git.
