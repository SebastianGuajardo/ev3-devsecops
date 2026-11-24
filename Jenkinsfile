pipeline {
    agent any

    stages {
        stage('Construccion') {
            steps {
                sh '''
                    echo "=== ETAPA 1: CONSTRUCCIÓN ==="
                    python3 -m venv venv
                    venv/bin/pip install --upgrade pip
                    venv/bin/pip install -r requirements.txt
                    venv/bin/python init_db.py
                '''
            }
        }

        stage('Pruebas') {
            steps {
                sh '''
                    echo "=== ETAPA 2: PRUEBAS ==="
                    venv/bin/pytest
                '''
            }
        }

        stage('Pruebas de Seguridad (OWASP ZAP)') {
            steps {
                sh '''
                    echo "=== ETAPA 3: PRUEBAS DE SEGURIDAD CON OWASP ZAP ==="
                    mkdir -p /var/jenkins_home/zap-reports
                    chmod 777 /var/jenkins_home/zap-reports

                    nohup venv/bin/python -c "from app import app; app.run(host='0.0.0.0', port=5000)" > flask_zap.log 2>&1 &
                    FLASK_PID=$!
                    sleep 4

                    JENKINS_IP=$(hostname -i | awk '{print $1}')
                    echo "Escaneando aplicacion en http://${JENKINS_IP}:5000"

                    docker run --rm \
                      -v jenkins_home:/zap/wrk:rw \
                      ghcr.io/zaproxy/zaproxy:stable \
                      zap-baseline.py -t http://${JENKINS_IP}:5000 -r zap-reports/reporte_zap.html -I

                    kill $FLASK_PID || true
                '''
            }
        }

        stage('Despliegue') {
            steps {
                sh '''
                    echo "=== ETAPA 4: DESPLIEGUE ==="
                    mkdir -p /var/jenkins_home/deploy
                    rm -rf /var/jenkins_home/deploy/*
                    cp -r app.py init_db.py vulnerable.db requirements.txt /var/jenkins_home/deploy/
                    ls -la /var/jenkins_home/deploy/
                '''
            }
        }
    }
}
