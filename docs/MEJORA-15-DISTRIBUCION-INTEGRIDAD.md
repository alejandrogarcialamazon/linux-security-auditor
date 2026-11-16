# Mejora 15 — Distribución autocontenida y verificación de integridad

Fecha: 2026-11-16. Versión de aplicación: 0.15.0. Python 3.10+ en Linux.

## Construir y verificar

```bash
python3 tools/build_distribution.py --output reports/distribution
python3 tools/build_distribution.py --verify reports/distribution
python3 reports/distribution/linux-security-auditor.pyz --version
python3 reports/distribution/linux-security-auditor.pyz --extended --format markdown
```

El constructor usa únicamente la biblioteca estándar. Incluye ocho módulos explícitos
más __main__.py, sin credenciales, reportes, historial Git, pruebas ni archivos del
laboratorio. Orden y fechas ZIP fijos permiten reproducir exactamente el artefacto
con las mismas fuentes y entorno de compresión. Python/zlib diferentes pueden
producir bytes distintos. Los archivos generados permanecen en reports/, ignorado.

SHA256SUMS verifica el archivo completo. La verificación rechaza nombres inesperados,
rutas relativas ajenas al artefacto, manifiestos malformados, enlaces simbólicos y
contenido alterado. No ejecuta el artefacto para verificarlo. Un hash no es firma
digital ni prueba de autoría: obtener el manifiesto por un canal de confianza.

## Instalar y ejecutar

Tras verificar, el operador puede instalar en su propia cuenta:

```bash
mkdir -p "$HOME/.local/bin"
install -m 0755 reports/distribution/linux-security-auditor.pyz "$HOME/.local/bin/linux-security-auditor"
"$HOME/.local/bin/linux-security-auditor" --version
```

No se ejecuta esta instalación automáticamente. También puede copiarse el .pyz y
SHA256SUMS a un directorio privado del host y ejecutar `sha256sum -c SHA256SUMS`
antes de usar Python 3.10+. No necesita pip ni dependencias de ejecución. El archivo
conserva las mismas opciones y controles explícitos de remediación que las fuentes;
la auditoría predeterminada es de solo lectura. Verifique los accesos del usuario:
la distribución no otorga privilegios ni elimina advertencias por falta de permisos.

--version identifica la versión; JSON incluye tool_version y schema_version.
La identidad de un build concreto se verifica mediante SHA-256. Para actualizar,
verificar el nuevo archivo y reemplazar la copia instalada; para volver atrás,
conservar el artefacto anterior y su manifiesto confiable. No instala servicios,
no cambia PATH ni modifica SSH/firewall. No se creó una GitHub Release.

## Validación

Pruebas específicas en tests/test_distribution.py: contenido permitido,
reproducibilidad, CLI desde directorio ajeno a las fuentes, detección de alteración,
rechazo de rutas manipuladas y enlaces simbólicos. Suite completa: 138 pruebas; local con tres omisiones de integración,
y 138 aprobadas sin omisiones en el host 192.168.89.89 con Python 3.10.12. Auditoría del artefacto en directorio temporal,
sin instalarlo globalmente ni aplicar remediaciones. Evidencia privada en reports/.

También se endurece la validación de reportes contra versiones booleanas y se
trata un archivo de cuentas vacío como evidencia inconclusa, cubierto por pruebas.
