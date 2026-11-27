// Jenkinsfile - Pipeline de "Sistema Alumnos" (SecureDev · Evaluación Parcial 3 · OCY1102)
//
// Esta es la versión BASE: construye, prueba y despliega en producción.
// Los marcadores  >>> [ETIQUETA]  indican dónde agregar las etapas de seguridad.
pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 40, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    // Revisa GitHub cada ~3 minutos: cada push (tuyo o un PR de Dependabot fusionado) dispara un build.
    triggers {
        pollSCM('H/3 * * * *')
    }

    environment {
        PIP_DISABLE_PIP_VERSION_CHECK = '1'
    }

    stages {
        stage('Build') {
            steps {
                script {
                    // Versión = 1.0.<nº de build>+<commit corto>: une cada despliegue con su commit (trazabilidad)
                    def sha = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
                    env.APP_VERSION = "1.0.${env.BUILD_NUMBER}+${sha}"
                }
                echo "Versión de este build: ${env.APP_VERSION}"
                sh 'git log -1 --format="Commit %h de %an: %s"'
                // Cada build parte limpio: sin reportes viejos y con un entorno virtual nuevo
                sh 'rm -rf .venv reports && mkdir -p reports'
                sh 'python3 -m venv .venv'
                sh '.venv/bin/pip install --quiet -r requirements.txt -r requirements-dev.txt'
                sh '.venv/bin/python -m compileall -q app.py'
            }
        }

        stage('Test') {
            steps {
                sh '.venv/bin/python -m pytest --junitxml=reports/junit.xml'
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'reports/junit.xml'
                }
            }
        }

        // ---------------------------------------------------------------- SEGURIDAD (shift-left)
        stage('Security Review (SAST)') {
            steps {
                // Bandit: análisis estático del código. Reporte JSON (trazabilidad) + texto legible.
                sh 'bandit -f json -o reports/bandit.json app.py || true'
                sh 'bandit -f txt -o reports/bandit.txt app.py || true'
                sh 'cat reports/bandit.txt'
                script {
                    // Hallazgos de severidad Medium o High => build UNSTABLE (no se despliega a producción)
                    def rc = sh(returnStatus: true, script: 'bandit -q -ll app.py > /dev/null')
                    if (rc != 0) {
                        unstable('Bandit encontró hallazgos de severidad Medium/High')
                    }
                }
            }
        }

        stage('Dependency Management') {
            steps {
                // pip-audit: dependencias con CVE conocidos (SCA). Complementa a Dependabot en GitHub.
                sh 'pip-audit -r requirements.txt -f json -o reports/pip-audit.json || true'
                script {
                    // Sin tuberías: con "| tee" el código de salida de pip-audit se perdía y el gate no bloqueaba (build #3)
                    def rc = sh(returnStatus: true, script: 'pip-audit -r requirements.txt > reports/pip-audit.txt 2>&1')
                    sh 'cat reports/pip-audit.txt'
                    if (rc != 0) {
                        unstable('pip-audit encontró dependencias con vulnerabilidades conocidas')
                    }
                }
            }
        }

        // ---------------------------------------------------------------- DAST
        stage('Deploy Staging') {
            steps {
                sh 'bash scripts/deploy.sh staging 5001'
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                script {
                    // zap_scan.py termina con código 2 si hay alertas High/Medium
                    def rc = sh(returnStatus: true, script: 'python3 scripts/zap_scan.py http://jenkins:5001')
                    if (rc == 2) {
                        unstable('OWASP ZAP encontró alertas High/Medium en staging')
                    } else if (rc != 0) {
                        error('El escaneo de OWASP ZAP falló')
                    }
                }
            }
        }

        stage('Deploy Producción') {
            // GATE: solo se despliega a producción si TODAS las revisiones de seguridad pasaron
            when {
                expression { currentBuild.currentResult == 'SUCCESS' }
            }
            steps {
                sh 'bash scripts/deploy.sh produccion 5000'
                script { env.PRODUCCION = env.APP_VERSION }
            }
        }
    }

    post {
        always {
            // Registro de trazabilidad: build <-> versión <-> commit <-> pruebas <-> hallazgos <-> despliegue
            withEnv(["RESULTADO=${currentBuild.currentResult}"]) {
                sh 'python3 scripts/trazabilidad.py'
            }
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
    }
}
