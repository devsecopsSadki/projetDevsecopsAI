pipeline {
    agent any
    tools {
        maven 'maven'
        
    }

    environment {
        REPORTS_DIR = 'security-reports'
        DOCKER_NET  = 'secnet'
        APP_PORT    = '8082'
        ZAP_PATH    = '/swagger-ui/index.html'
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

                        // Go into the real app directory that has pom.xml
                        dir('FetchingData') {

                            sh '''
                                echo "Installing Snyk locally (no sudo needed)..."
                                npm install snyk

                                echo "Authenticating with Snyk..."
                                npx snyk auth $SNYK_TOKEN || true

                                echo "Running Snyk test on FetchingData/pom.xml..."
                                # Save full raw Snyk JSON to the reports directory
                                # Using absolute path from workspace root
                                npx snyk test --file=pom.xml --package-manager=maven --json \
                                    > ../security-reports/sca-raw.json 2>&1 || true
                                
                                echo "Verifying report was created..."
                                ls -lh ../security-reports/sca-raw.json || echo "WARNING: Report file not created"
                            '''
                        }
                    }
                }
            }

            post {
                always {
                    archiveArtifacts artifacts: "${REPORTS_DIR}/sca-raw.json", fingerprint: true, allowEmptyArchive: true
                }
            }
        }

        stage('Parse SCA Report') {
            steps {
                echo ' Parsing SCA report for LLM...'
                sh '''
                    # Verify report exists before parsing
                    if [ -f "${REPORTS_DIR}/sca-raw.json" ]; then
                        echo "Report file found, parsing..."
                        cd parsers
                        python3 parsca.py \
                            ../${REPORTS_DIR}/sca-raw.json \
                            ../${REPORTS_DIR}/sca-findings.txt
                    else
                        echo "ERROR: sca-raw.json not found, skipping parsing"
                        exit 1
                    fi
                '''

                echo 'SCA report parsed and ready for LLM'
            }
            
            post {
                always {
                    archiveArtifacts artifacts: "${REPORTS_DIR}/sca-findings.txt", fingerprint: true, allowEmptyArchive: true
                }
            }
        }





        stage('SAST Analysis') {
            steps {
                echo ' Running SonarQube SAST Scan...'

                script {
                    withSonarQubeEnv('SonarQube') {
                         sh '''
                                # Make sure the CLI is on PATH for this step
                                export PATH="$PATH:/opt/sonar-scanner/bin"

                                # Run analysis (include host + token)
                                sonar-scanner \
                                  -Dsonar.projectKey=my-project \
                                  -Dsonar.sources=FetchingData/src \
                                  -Dsonar.java.binaries=FetchingData/target/classes \
                                  -Dsonar.host.url=$SONAR_HOST_URL \
                                  -Dsonar.login=$SONAR_AUTH_TOKEN
                              '''
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
            post {
    always {
        archiveArtifacts artifacts: "${REPORTS_DIR}/sast-report.json", 
                         fingerprint: true, 
                         allowEmptyArchive: true
    }
}
        }

       stage('Parse SAST Report') {
            steps {
                echo 'Parsing SAST report for LLM...'
                
                script {
                    sh """
                        python3 parsers/sast/parsast.py \
                            ${REPORTS_DIR}/sast-report.json \
                            ${REPORTS_DIR}/sast-findings.txt
                    """
                }

                echo ' Report parsed and ready for LLM'
            }
            post {
                always {
                    archiveArtifacts artifacts: "${REPORTS_DIR}/sast-findings.txt", 
                                     allowEmptyArchive: true, 
                                     fingerprint: true
                }
            }
        }

       stage('Start Application') {
         steps {
           echo "Starting application on :${APP_PORT}..."
           dir('FetchingData') {
             sh '''
               # Kill leftovers & clean pid
               pkill -f "java.*jar.*target" || true
               rm -f app.pid

               ARTIFACT=$(ls target/*.jar 2>/dev/null | head -n1 || true)
               if [ -z "$ARTIFACT" ]; then
                 echo "No jar found in target/. Skipping run."
                 exit 1
               fi

               # Run in background; bind to all interfaces so ZAP can reach it
               nohup java -jar "$ARTIFACT" \
                 --server.port=${APP_PORT} \
                 --server.address=0.0.0.0 \
                 > app.log 2>&1 &
               echo $! > app.pid
               echo "Started PID $(cat app.pid)"

               # Wait (max 45s) for readiness using curl/wget/nc
               READY=0
               for i in $(seq 1 45); do
                 if command -v curl >/dev/null 2>&1; then
                   curl -fsS "http://127.0.0.1:${APP_PORT}/actuator/health" >/dev/null 2>&1 && { READY=1; break; }
                   curl -fsS "http://127.0.0.1:${APP_PORT}/"               >/dev/null 2>&1 && { READY=1; break; }
                 elif command -v wget >/dev/null 2>&1; then
                   wget -qO- "http://127.0.0.1:${APP_PORT}/actuator/health" >/dev/null 2>&1 && { READY=1; break; }
                   wget -qO- "http://127.0.0.1:${APP_PORT}/"               >/dev/null 2>&1 && { READY=1; break; }
                 elif command -v nc >/dev/null 2>&1; then
                   nc -z 127.0.0.1 ${APP_PORT} && { READY=1; break; }
                 fi
                 sleep 1
               done

               if [ "$READY" -ne 1 ]; then
                 echo "WARNING: app did not become ready on port ${APP_PORT} in time."
                 echo "Last 100 lines of app.log for debugging:"
                 tail -n 100 app.log || true
                 exit 1
               else
                 echo "App is up on port ${APP_PORT}."
               fi
             '''
           }
         }
       }


        stage('DAST Analysis - ZAP Scan') {
          steps {
            echo '🕷️ Running DAST scan with OWASP ZAP...'
            sh '''
              echo "Starting OWASP ZAP scan against http://elegant_lichterman:${APP_PORT}${ZAP_PATH}"

              # Ensure network exists
              docker network inspect "${DOCKER_NET}" >/dev/null 2>&1 || docker network create "${DOCKER_NET}"

              # Ensure reports dir is writable and files exist
              mkdir -p "${WORKSPACE}/${REPORTS_DIR}"
              chmod -R 0777 "${WORKSPACE}/${REPORTS_DIR}" || true
              touch "${WORKSPACE}/${REPORTS_DIR}/dast-report.json" "${WORKSPACE}/${REPORTS_DIR}/dast-report.html" || true

              # Verify target returns 200/302 before scanning (avoid Groovy $ parsing by keeping this whole block single-quoted)
              set -e
              curl -s -o /dev/null -w "%{http_code}\n" "http://elegant_lichterman:${APP_PORT}${ZAP_PATH}" | grep -E '^(200|302)$' || {
                echo "Target URL is not 200/302. Update ZAP_PATH to a page that returns 200."
                exit 1
              }
              set +e

              # Run ZAP (as root to avoid write issues) and write into the mounted folder
              docker run --rm \
                --network "${DOCKER_NET}" \
                --user 0 \
                -v "${WORKSPACE}/${REPORTS_DIR}:/zap/wrk/:rw" \
                -w /zap/wrk \
                zaproxy/zap-stable zap-baseline.py \
                  -t "http://elegant_lichterman:${APP_PORT}${ZAP_PATH}" \
                  -J dast-report.json \
                  -r dast-report.html || true

              echo "Verifying DAST report was created..."
              ls -lh "${WORKSPACE}/${REPORTS_DIR}/dast-report.json" || echo "WARNING: DAST report not created"
            '''
            echo 'DAST scan completed'
          }
          post {
            always {
              archiveArtifacts artifacts: "${REPORTS_DIR}/dast-report.json,${REPORTS_DIR}/dast-report.html",
                               fingerprint: true,
                               allowEmptyArchive: true
            }
          }
        }





        stage('Stop Application') {
            steps {
                echo '🛑 Stopping application...'
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
                script {
                    sh '''
                        if [ -f "${REPORTS_DIR}/dast-report.json" ]; then
                            echo "DAST report file found, parsing..."
                            cd parsers/dast
                            python3 pardast.py \
                                ../../${REPORTS_DIR}/dast-report.json \
                                ../../${REPORTS_DIR}/dast-findings.txt
                        else
                            echo "WARNING: dast-report.json not found, skipping parsing"
                            echo "No DAST findings to report." > ${REPORTS_DIR}/dast-findings.txt
                        fi
                    '''
                }

                echo 'DAST report parsed and ready for LLM'
            }
            post {
                always {
                    archiveArtifacts artifacts: "${REPORTS_DIR}/dast-findings.txt",
                                     fingerprint: true,
                                     allowEmptyArchive: true
                }
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
