# Mejora 14 — Resumen de alcance y ejecución

Fecha: 2026-11-16.

El bloque coverage contiene total, pass, fail, review (WARN + INFO), excepted y failed_by_severity. execution registra duración de la auditoría y su modo. Markdown muestra revisión pendiente, excepciones y duración. No presenta porcentajes CIS ni asegura cobertura total del host.

WARN e INFO incluyen advertencias consultivas y comprobaciones desconocidas: review exige inspección del detalle y no significa que todos sean errores operativos. EXCEPTED se mantiene separado de PASS. La duración excluye escritura de reportes y comparación posterior; no mide cada comando ni latencia SSH. Las opciones de análisis están bloqueadas durante remediaciones para evitar etiquetarlas como auditoría de solo lectura.

## Validación

Suite unittest y pruebas específicas en tests/test_policy_reporting.py. La integración del laboratorio se ejecuta por SSH con archivos temporales; no se remedia /etc ni se recargan servicios. Evidencia privada en reports/, excluida de Git.
