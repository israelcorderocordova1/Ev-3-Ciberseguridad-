# Registro de trazabilidad - Sistema Alumnos

Cada fila la agrega Jenkins al terminar un build (`scripts/trazabilidad.py`).

| Build | Fecha (UTC) | Versión | Commit | Mensaje del commit | Pruebas | Bandit H/M/L | pip-audit | ZAP H/M/L | Resultado | Producción |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 2026-11-27 19:39 | 1.0.1+7c1131d41a76 | Sin Git; fuente SHA256 7c1131d41a76 | Ejecución local; no existe commit remoto | 16/16 OK | 0/0/0 | 1 vuln. | n/a | FAILURE | no desplegado |
| 2 | 2026-11-27 19:44 | 1.0.2+2e2168a3e1a5 | Sin Git; fuente SHA256 2e2168a3e1a5 | Ejecución local; no existe commit remoto | 17/17 OK | 0/0/0 | 0 vuln. | 0/0/0 | SUCCESS | 1.0.2+2e2168a3e1a5 |
| 2 | 2026-11-27 20:19 | 1.0.2+d7dfa09 | `d7dfa09` | Pipeline: etapas SAST (Bandit), SCA (pip-audit), Deploy Staging, DAST  | 9/9 OK | 2/2/1 | 19 vuln. | 3/3/1 | UNSTABLE | no desplegado |
| 3 | 2026-11-27 20:21 | 1.0.3+e7bfb57 | `e7bfb57` | VULN-08: cabeceras de seguridad CSP, X-Frame-Options, nosniff y otras  | 9/9 OK | 0/0/0 | 19 vuln. | 0/0/0 | SUCCESS | 1.0.3+e7bfb57 |
| 4 | 2026-11-27 20:22 | 1.0.4+43b576b | `43b576b` | VULN-09: actualización de dependencias con CVE (Flask 3.1.3, Werkzeug  | 9/9 OK | 0/0/0 | 0 vuln. | 0/0/0 | SUCCESS | 1.0.4+43b576b |
| 5 | 2026-11-27 20:23 | 1.0.5+30ecea3 | `30ecea3` | PIPE-01: el gate de pip-audit no detenía el build (código de salida pe | 9/9 OK | 0/0/0 | 19 vuln. | 0/0/0 | UNSTABLE | no desplegado |
| 6 | 2026-11-27 20:24 | 1.0.6+e0a1f2c | `e0a1f2c` | PIPE-01: el gate de pip-audit no detenía el build (código de salida pe | 9/9 OK | 0/0/0 | 0 vuln. | 0/0/0 | SUCCESS | 1.0.6+e0a1f2c |
| 7 | 2026-11-27 21:24 | 1.0.7+56d576b | `56d576b` | DEPS: merge PR de Dependabot gunicorn-27.0.1 | 9/9 OK | 0/0/0 | 0 vuln. | 0/0/0 | SUCCESS | 1.0.7+56d576b |
