pipeline {
    agent any
    tools {
        maven 'maven'
        
    }

    environment {
        REPORTS_DIR = 'security-reports'
    }

    stages {
        stage('Preparation') {
            steps {
                echo ' Starting DevSecOps Security Analysis Pipeline (SAST, SCA, DAST)'
                sh '''
                    rm -rf ${REPORTS_DIR}
                    mkdir -p ${REPORTS_DIR}
                '''
                checkout scm
            }
        }

        stage('Build Application') {
            steps {
                echo ' Building application...'
                dir('FetchingData'){
                script {
                    try {
                        sh 'mvn clean package -DskipTests'
                    } catch (Exception e) {
                        echo "Build skipped: ${e.message}"
                    }
                }
                }
            }
        }
        
        stage('SCA - Dependency Scan') {
            steps {
                script {
                    echo "Running SCA for Maven project..."
                    withCredentials([string(credentialsId: 'SNYK_TOKEN', variable: 'SNYK_TOKEN')]) {
                        sh '''
                            # Install snyk locally (idempotent / safe)
                            npm install snyk

                            # Auth (ignore non-zero, we mask anyway)
                            npx snyk auth $SNYK_TOKEN || true

                            # Run scan to raw JSON (don't fail pipeline if exit code != 0)
                            npx snyk test --file=pom.xml --package-manager=maven --json \
                                > ${REPORTS_DIR}/sca-raw.json || true

                            # If .vulnerabilities doesn't exist or is null, create empty array
                            jq '
                                .vulnerabilities // [] |
                                map({
                                    title,
                                    severity,
                                    packageName,
                                    current_version: .version,
                                    recommended_version: (
                                        (.fixedIn[0]) //
                                        (.upgradePath[-1] | select(. != false)) //
                                        "N/A"
                                    )
                                })
                            ' ${REPORTS_DIR}/sca-raw.json > ${REPORTS_DIR}/sca-report.json || echo "[]">{REPORTS_DIR}/sca-report.json
                        '''
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: "${REPORTS_DIR}/sca-report.json", fingerprint: true
                }
            }
        }



        stage('SAST Analysis') {
            steps {
                echo ' Running SonarQube SAST Scan...'

                script {
                    withSonarQubeEnv('SonarQube') {
                        sh """
                            sonar-scanner \
                                -Dsonar.projectKey=my-project \
                                -Dsonar.sources=FetchingData/src \
                                -Dsonar.java.binaries=FetchingData/target/classes
                        """
                    }
                }

                echo ' Exporting SonarQube results to JSON...'
                script {
                    withSonarQubeEnv('SonarQube') {
                        sh """
                            curl -u \${SONAR_AUTH_TOKEN}: \
                                "\${SONAR_HOST_URL}/api/issues/search?componentKeys=my-project&ps=500" \
                                -o ${REPORTS_DIR}/sast-report.json
                        """
                    }
                }

                echo ' SAST scan completed'
            }
        }

        stage('Parse SAST Report') {
            steps {
                echo ' Parsing SAST report for LLM...'
                sh '''
                    python3 scripts/parser_sast_llm.py \
                        ${REPORTS_DIR}/sast-report.json \
                        ${REPORTS_DIR}/sast-findings.txt
                '''

                echo 'Report parsed and ready for LLM'
            }
        }

        stage('Start Application for DAST') {
            steps {
                echo ' Starting application for DAST scanning...'
                dir('FetchingData') {
                    script {
                        sh '''
                            echo "Starting Spring Boot application..."
                            nohup java -jar target/*.jar > app.log 2>&1 &
                            echo $! > app.pid
                            echo "Application PID: $(cat app.pid)"
                        '''
                        
                        // Wait for application to be ready
                        sh '''
                            echo "Waiting for application to start..."
                            for i in {1..60}; do
                                if curl -f http://localhost:8082/actuator/health 2>/dev/null; then
                                    echo "✓ Application is ready and responding!"
                                    break
                                fi
                                if [ $i -eq 60 ]; then
                                    echo "✗ Application failed to start within 120 seconds"
                                    exit 1
                                fi
                                echo "  Waiting... (${i}/60)"
                                sleep 2
                            done
                        '''
                    }
                }
            }
        }

        stage('DAST Analysis - ZAP Scan') {
            steps {
                echo ' Running DAST scan with OWASP ZAP...'
                script {
                    sh '''
                        echo "Starting OWASP ZAP scan against http://localhost:8082"
                        docker run --rm --network host \\
                            -v $(pwd)/${REPORTS_DIR}:/zap/wrk/:rw \\
                            owasp/zap2docker-stable zap-baseline.py \\
                            -t http://localhost:8082 \\
                            -J \\
                            -j \\
                            -r ${REPORTS_DIR}/dast-report.json || true
                    '''
                }
                echo ' DAST scan completed'
            }
            post {
                always {
                    archiveArtifacts artifacts: "${REPORTS_DIR}/dast-report.json", allowEmptyArchive: true
                }
            }
        }

        stage('Stop Application') {
            steps {
                echo ' Stopping application...'
                dir('FetchingData') {
                    script {
                        sh '''
                            if [ -f app.pid ]; then
                                PID=$(cat app.pid)
                                echo "Stopping application (PID: $PID)..."
                                kill $PID 2>/dev/null || true
                                rm -f app.pid
                                echo "Application stopped"
                            else
                                echo "No PID file found, trying to kill by process name..."
                                pkill -f "java.*jar.*target" || true
                            fi
                        '''
                    }
                }
            }
        }

        stage('Parse DAST Report') {
            steps {
                echo ' Parsing DAST report for LLM...'
                sh '''
                    cd parsers
                    python3 pardast.py \
                        ../${REPORTS_DIR}/dast-report.json \
                        ../${REPORTS_DIR}/dast-findings.txt || echo "DAST parsing skipped (report may be empty)"
                '''

                echo 'DAST report parsed and ready for LLM'
            }
        }

        stage('Generate Policies with AI') {
            steps {
                echo 'Generating security policies with LLM...'
                sh '''
                    python3 scripts/generate_policies.py \
                        --input ${REPORTS_DIR}/sast-findings.txt \
                        --output ${REPORTS_DIR}/security-policies.json \
                        --model llama3.3 \
                        --framework nist-csf
                '''

                echo ' Policies generated'
            }
        }

        stage('Display Summary') {
            steps {
                echo ' Generating summary...'
                sh '''
                    echo "======================================"
                    echo "PIPELINE RESULTS SUMMARY"
                    echo "======================================"

                    if [ -f "${REPORTS_DIR}/sast-findings.txt" ]; then
                        FINDING_COUNT=$(grep -c "^--- Finding" ${REPORTS_DIR}/sast-findings.txt || echo "0")
                        echo "Total SAST Findings: $FINDING_COUNT"
                    fi

                    if [ -f "${REPORTS_DIR}/dast-findings.txt" ]; then
                        DAST_COUNT=$(grep -c "^--- DAST Finding" ${REPORTS_DIR}/dast-findings.txt || echo "0")
                        echo "Total DAST Findings: $DAST_COUNT"
                    fi

                    if [ -f "${REPORTS_DIR}/security-policies.json" ]; then
                        echo "Security policies generated: "
                        python3 -c "import json; print('Total policies:', len(json.load(open('${REPORTS_DIR}/security-policies.json')).get('policies', [])))"
                    fi

                    echo "======================================"
                '''
            }
        }

        stage('Archive Results') {
            steps {
                echo ' Archiving artifacts...'
                archiveArtifacts artifacts: "${REPORTS_DIR}/*", allowEmptyArchive: false
            }
        }
    }

    post {
        success {
            echo ' Pipeline completed successfully!'
        }
        failure {
            echo 'Pipeline failed!'
        }
    }
}
