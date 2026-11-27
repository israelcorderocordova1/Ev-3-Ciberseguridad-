# Sistema Alumnos

API y portal web hecho en Flask para consultar alumnos, con login de administrador y métricas para Prometheus.
El proyecto partió de un código con vulnerabilidades y lo fui corrigiendo mientras armaba un pipeline de CI/CD
en Jenkins con revisiones de seguridad en cada etapa.

Proyecto de la asignatura Ciberseguridad en Desarrollo (OCY1102).

## Qué hace

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/` | Portada con enlaces, buscador y formulario de login |
| GET | `/hello?name=Ana` | Saludo |
| GET | `/alumnos` | Lista de alumnos |
| GET | `/alumnos/<id>` | Detalle de un alumno |
| GET | `/alumnos/buscar?nombre=Ana` | Búsqueda por nombre |
| POST | `/login` | Login del administrador |
| GET | `/health` · `/version` | Estado y versión desplegada |
| GET | `/metrics` | Métricas para Prometheus |

## Cómo correrlo

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
.venv/bin/python -m pytest        # 9 pruebas
.venv/bin/python app.py           # http://127.0.0.1:5000
```

Variables de entorno que usa la app:

- `SECRET_KEY`: clave de sesión. Si no se define, se genera una aleatoria al partir.
- `ADMIN_CLAVE_HASH`: hash de la clave del admin (`werkzeug.security.generate_password_hash`). Sin esta variable el login de admin queda deshabilitado.
- `DB_PATH`: ruta de la base SQLite (por defecto `alumnos.db`).
- `LOGIN_INTENTOS_MAX` / `LOGIN_VENTANA_S`: límite de intentos fallidos por IP (por defecto 5 en 300 s).

## Pipeline

El `Jenkinsfile` tiene estas etapas:

1. **Build**: entorno virtual limpio, instala dependencias y compila.
2. **Test**: pytest con reporte JUnit.
3. **Security Review (SAST)**: Bandit sobre `app.py`.
4. **Dependency Management**: pip-audit sobre `requirements.txt`.
5. **Deploy Staging**: despliega en el puerto 5001.
6. **DAST - OWASP ZAP**: spider, escaneo pasivo y activo contra staging.
7. **Deploy Producción**: solo se ejecuta si todo lo anterior salió bien.

Si Bandit, pip-audit o ZAP encuentran algo, el build queda UNSTABLE y no se despliega a producción.
Al final de cada build se agrega una fila a `TRAZABILIDAD.md` con la versión, el commit y los resultados.

Las dependencias las vigila Dependabot (`.github/dependabot.yml`) y la producción se monitorea con Prometheus y Grafana.

## Estructura

```
app.py                 aplicación
tests/                 pruebas (pytest)
requirements*.txt      dependencias de ejecución y de pruebas
Jenkinsfile            pipeline
scripts/deploy.sh      despliegue + prueba de humo
scripts/zap_scan.py    escaneo con OWASP ZAP
scripts/trazabilidad.py registro de cada build
scripts/revisar_local.sh pruebas + Bandit + pip-audit antes de hacer push
docs/                  registro de seguridad y trazabilidad
```

## Commits

Cada corrección de seguridad va en su propio commit con el ID del hallazgo, por ejemplo
`VULN-01: consulta parametrizada en /alumnos/buscar`. El detalle de cada uno está en
[docs/REGISTRO_SEGURIDAD.md](docs/REGISTRO_SEGURIDAD.md).
