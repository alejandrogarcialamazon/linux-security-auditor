# GitHub desde Codex y OpenCode

## Acceso local compartido

GitHub CLI (`gh`) mantiene la autenticación del usuario fuera del repositorio.
Codex y OpenCode pueden utilizarla cuando se ejecutan con ese mismo usuario,
acceso a red y permiso para ejecutar comandos. No hace falta copiar tokens
entre proyectos ni añadir credenciales a configuraciones MCP.

Configuración inicial, desde una terminal de confianza:

```bash
gh auth login --hostname github.com --git-protocol https --web
gh auth setup-git --hostname github.com
gh auth status
gh api user --jq .login
```

GitHub CLI intenta usar el almacén de credenciales del sistema; si no está
disponible puede guardar la credencial en su archivo de configuración local.
Ese archivo debe permanecer privado. Nunca mostrar `gh auth token`, copiar
credenciales a prompts ni guardar un token en el remoto de Git.

## Codex

La instalación local usa las instrucciones de `~/.codex/AGENTS.md`. El proyecto
incluye su propio `AGENTS.md` con pruebas y reglas de remediación. Los permisos
de cada sesión siguen aplicándose. Las sesiones remotas, de otro usuario o de
otro equipo necesitan autenticación propia; la credencial local no las habilita.

La conexión de GitHub en la aplicación es independiente de la autenticación
local de `gh`. Conectarla permite usar las herramientas que ofrezca esa integración.

## OpenCode

El perfil global `github` permite trabajar con Git y GitHub CLI usando las mismas
credenciales locales. Iniciar con `opencode --agent github` o seleccionarlo en la
interfaz. El perfil solicita aprobación para comandos; los perfiles existentes
de infraestructura conservan sus permisos.

## Publicar y comprobar

Verificar primero la cuenta y revisar `git diff --cached`. El nombre propuesto
es `linux-security-auditor`. La creación debe solicitar visibilidad pública:

```bash
gh repo create linux-security-auditor --public --source . --remote origin --push
gh repo view --json nameWithOwner,url,visibility
gh run list --limit 5
```

La CI ejecuta pruebas aisladas, nunca remediaciones reales ni auditorías de
infraestructura privada. Los reportes `reports/` quedan excluidos de Git.

Referencias: [autenticación de gh](https://cli.github.com/manual/gh_auth_login),
[Git con gh](https://cli.github.com/manual/gh_auth_setup-git),
[configuración de Codex](https://developers.openai.com/codex/config-basic/),
[reglas de OpenCode](https://opencode.ai/docs/rules/),
[perfiles de OpenCode](https://opencode.ai/docs/agents/).
