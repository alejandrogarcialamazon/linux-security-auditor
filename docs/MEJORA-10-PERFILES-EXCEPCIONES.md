# Mejora 10 — Perfiles y excepciones temporales

Fecha: 2026-11-16.

--profile servidor|laboratorio|expuesto selecciona explícitamente criterios. El perfil laboratorio advierte root por llave; root yes sigue siendo FAIL. El perfil expuesto considera PasswordAuthentication yes un FAIL. Evidencia desconocida nunca se convierte en PASS.

--exceptions archivo.json requiere {"version":1,"exceptions":[{"id":"CIS-LITE-003","host":"host-ejemplo","reason":"Necesidad temporal","responsible":"Operador","expires_at":"2026-12-01T00:00:00-03:00"}]}. Host e ID coinciden exactamente; no admite comodines ni duplicados. Excepciones vencidas no alteran el hallazgo. Las vigentes se muestran EXCEPTED, conservan estado base y criterio, nunca cuentan como PASS. --fail-on-exceptions devuelve 1 también con excepciones vigentes. Archivos inválidos devuelven 2. No pueden usarse para modificar una remediación. Guardar excepciones reales fuera del repositorio.

## Validación

Suite unittest y pruebas específicas en tests/test_policy_reporting.py. La integración del laboratorio se ejecuta por SSH con archivos temporales; no se remedia /etc ni se recargan servicios. Evidencia privada en reports/, excluida de Git.
