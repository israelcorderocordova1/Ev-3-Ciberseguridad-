# Registro de seguridad · Sistema Alumnos

Estudiante: ____________________   Repositorio: https://github.com/israelcorderocordova1/Ev-3-Ciberseguridad-   Fecha: 2026-11-27

Cada fila se puede seguir hasta un **build de Jenkins** (job `SistemaAlumnos-DevSecOps`) y un **commit** (`VULN-xx`).

## 1. Revisiones de seguridad realizadas

| # | Etapa del SDLC | Herramienta / técnica | Build | Resultado (resumen) |
|---|---|---|---|---|
| R0 | Desarrollo (antes del push, shift-left) | `scripts/revisar_local.sh` en el contenedor taller (pytest + Bandit + pip-audit) | local | Inicial: 9/9 pruebas OK, Bandit 2 High / 2 Medium / 1 Low, 19 CVE. Final: todo OK |
| R1 | Código (SAST) | Bandit en la etapa *Security Review (SAST)* | #2 | 2 High / 2 Medium / 1 Low → #6: 0 / 0 / 0 |
| R2 | Dependencias (SCA) | pip-audit en la etapa *Dependency Management* | #2 | 19 vulnerabilidades en 4 paquetes (Flask, Werkzeug, Jinja2, gunicorn) → #6: 0 |
| R3 | Pruebas dinámicas (DAST) | OWASP ZAP 2.16.1 (spider + pasivo + activo) sobre staging | #2 | 3 High / 3 Medium / 1 Low → #6: 0 / 0 / 0 (solo informativas) |
| R4 | Revisión manual | Lectura de `app.py` | — | CSRF, fuerza bruta, clave MD5 "admin", fuga de errores SQL, log injection |
| R5 | Producción | Prometheus + Grafana (dashboard y 2 reglas de alerta) | #6 | Incidente simulado detectado y contenido (ver sección 4) |
| R6 | Revisión del propio pipeline | Análisis del resultado del build #3 | #3 → #5 | El gate de pip-audit no bloqueaba (PIPE-01) → corregido |

## 2. Vulnerabilidades identificadas y corregidas

| ID | Vulnerabilidad (CWE) | Detectada por | Ubicación (original) | Riesgo | Corrección aplicada | Commit | Build que lo verifica |
|---|---|---|---|---|---|---|---|
| VULN-01 | Inyección SQL (CWE-89) + exposición de errores (CWE-209) | Bandit B608, ZAP "SQL Injection", manual | `app.py:205` `/alumnos/buscar` | Alto | Consulta parametrizada `LIKE ?`; error genérico sin la consulta | 69a22f0 | #3 |
| VULN-02 | XSS reflejado (CWE-79) | ZAP "XSS Reflected / DOM" | `app.py:154` `/hello` | Alto | `markupsafe.escape()` + largo máximo | d8e935d | #3 |
| VULN-03 | Clave secreta en el código (CWE-798/259) | Bandit B105 | `app.py:20` | Medio | `SECRET_KEY` desde variable de entorno o aleatoria; cookies HttpOnly + SameSite | 45e2af0 | #3 |
| VULN-04 | Hash débil MD5 y clave "admin" (CWE-327, CWE-521) | Bandit B324, manual | `app.py:22, 221` | Alto | Hash PBKDF2/scrypt (`check_password_hash`) desde el entorno, comparación en tiempo constante | ade71a2 | #3 |
| VULN-05 | Debug activo y bind 0.0.0.0 (CWE-489, CWE-605) | Bandit B201, B104 | `app.py:241` | Alto | `debug=False`, `127.0.0.1` (en entornos corre gunicorn) | e984de6 | #3 |
| VULN-06 | Falta de token anti-CSRF (CWE-352) | ZAP "Absence of Anti-CSRF Tokens" | formulario `/login` | Medio | Token aleatorio en sesión + validación `hmac.compare_digest` | 443a5a4 | #3 |
| VULN-07 | Sin límite de intentos de login (CWE-307) + log injection (CWE-117) | Manual, `simular_ataque.py` | `/login` | Medio | 5 fallos / 5 min por IP → HTTP 429, métrica `login_bloqueados_total`, logs con `%r` | bbc504e | #3 |
| VULN-08 | Cabeceras de seguridad ausentes (CWE-693, CWE-1021) | ZAP CSP / Anti-clickjacking / X-Content-Type-Options | todas las respuestas | Medio | CSP, X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP, no-store | e7bfb57 | #3 |
| VULN-09 | Componentes con vulnerabilidades conocidas (CWE-1395) | pip-audit (19 CVE/PYSEC) | `requirements.txt` | Alto | Actualización a versiones sin CVE (ver sección 5) | 43b576b / e0a1f2c | #4, #6 |
| PIPE-01 | Gate del pipeline inefectivo | Revisión del build #3 (SUCCESS con 19 CVE) | `Jenkinsfile` etapa *Dependency Management* | Medio | Se elimina `| tee` (perdía el código de salida); demostrado en #5 (UNSTABLE, no despliega) | 30ecea3 | #5, #6 |

## 3. Resultados de OWASP ZAP

| Alerta de ZAP | Riesgo | URL de ejemplo | VULN relacionada | Cómo se mitiga | ¿Mitigada? Build |
|---|---|---|---|---|---|
| Cross Site Scripting (Reflected) | High | `/hello?name=</h1><script>alert(1);</script>` | VULN-02 | Escape de salida HTML | Sí, #3 |
| Cross Site Scripting (DOM Based) | High | `/hello?name=<script>alert(5397)</script>` | VULN-02 | Escape + CSP `script-src 'self'` | Sí, #3 |
| SQL Injection | High | `/alumnos/buscar?nombre='` | VULN-01 | Consulta parametrizada | Sí, #3 |
| Absence of Anti-CSRF Tokens | Medium | `/` (formulario login) | VULN-06 | Token anti-CSRF por sesión | Sí, #3 |
| Content Security Policy Header Not Set | Medium | `/` | VULN-08 | Cabecera CSP restrictiva | Sí, #3 |
| Missing Anti-clickjacking Header | Medium | `/` | VULN-08 | `X-Frame-Options: DENY` + `frame-ancestors 'none'` | Sí, #3 |
| X-Content-Type-Options Header Missing | Low | `/` | VULN-08 | `X-Content-Type-Options: nosniff` | Sí, #3 |
| Session Management Response Identified | Informational | `/` | — | Esperado (cookie de sesión del token CSRF, HttpOnly/SameSite) | N/A |

## 4. Monitoreo e incidentes

Ver Desarrollo EV3.docx, evidencias 8 y 9 (tabla con la hora, panel, clasificación, respuesta y verificación).

## 5. Gestión de dependencias

| Paquete | Versión inicial | Vulnerabilidades (IDs) | Versión final | Origen del cambio | ¿Pruebas, pip-audit y ZAP siguen OK? Build |
|---|---|---|---|---|---|
| Flask | 2.2.2 | PYSEC-2023-62, PYSEC-2026-2151 | 3.1.3 | Manual (VULN-09) / Dependabot | Sí: 9/9, 0 vuln, ZAP 0/0/0 – #6 |
| Werkzeug | 2.2.2 | PYSEC-2023-57, -58, -221, PYSEC-2026-2043/2044/2045/2046/2320/3417/4312 | 3.1.9 | Manual (VULN-09) / Dependabot | Sí – #6 |
| Jinja2 | 3.1.2 | PYSEC-2026-1471/1472/1473/1474/1475 | 3.1.6 | Manual (VULN-09) / Dependabot | Sí – #6 |
| gunicorn | 21.2.0 | PYSEC-2026-1433, PYSEC-2026-1434 | 27.0.1 | Manual (VULN-09) / Dependabot | Sí – #6 |
| prometheus-client | 0.17.1 | — (actualización preventiva) | 0.26.0 | Manual (VULN-09) / Dependabot | Sí – #6 |
| pytest (dev) | 8.3.4 | — | 9.2.0 | Manual | Sí – #6 |

## 6. Trazabilidad

| Actividad | Hallazgo | Build que lo detectó | Commit / PR que lo resolvió | Build que lo verificó | Versión en producción |
|---|---|---|---|---|---|
| Revisión de seguridad (Bandit) | B608 SQLi, B105, B324, B201, B104 | #2 | VULN-01, 03, 04, 05 | #3 | 1.0.3+e7bfb57 |
| Prueba automatizada (OWASP ZAP) | 3 High / 3 Medium / 1 Low | #2 | VULN-01, 02, 06, 08 | #3 | 1.0.3+e7bfb57 |
| Gestión de dependencias (pip-audit / Dependabot) | 19 CVE en 4 paquetes | #2, #5 | VULN-09 (rama `deps/vuln-09-actualizacion`, PR) | #4, #6 | 1.0.6+e0a1f2c |
| Revisión del pipeline | PIPE-01 gate inefectivo | #3 | 30ecea3 | #5 (bloquea), #6 (verde) | 1.0.6+e0a1f2c |
