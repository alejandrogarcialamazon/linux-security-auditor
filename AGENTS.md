# Desarrollo con Codex y OpenCode

Herramienta educativa para Linux, Python 3.10+, sin dependencias de ejecución.

- Mantener la auditoría de solo lectura como comportamiento predeterminado.
- Las remediaciones exigen control explícito y `--yes`; nunca ejecutarlas sobre
  el host de desarrollo para probar. Usar archivos temporales y mocks.
- No recargar SSH ni modificar firewall, cuentas o servicios automáticamente.
- Ejecutar `python3 -m unittest discover -s tests -v` antes de publicar cambios.
- Regenerar el manual con `python3 tools/build_pdf.py docs/MANUAL.md docs/MANUAL.pdf`.
- GitHub: usar `gh auth status` y `gh api user --jq .login` para verificar cuenta.
  Usar las credenciales del usuario; nunca copiar tokens a archivos del proyecto,
  argumentos, reportes o mensajes. No ejecutar `gh auth token` para mostrarlos.
- Revisar el diff y los archivos a publicar; excluir reportes de hosts y secretos.
- No afirmar conformidad CIS ni seguridad completa a partir de un PASS.
