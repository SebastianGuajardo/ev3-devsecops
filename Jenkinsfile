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

        stage('Despliegue') {
            steps {
                sh '''
                    echo "=== ETAPA 3: DESPLIEGUE ==="
                    mkdir -p /var/jenkins_home/deploy
                    rm -rf /var/jenkins_home/deploy/*
                    cp -r app.py init_db.py vulnerable.db requirements.txt /var/jenkins_home/deploy/
                    ls -la /var/jenkins_home/deploy/
                '''
            }
        }
    }
}
