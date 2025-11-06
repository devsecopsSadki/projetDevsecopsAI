pipeline {
    agent any
    tools {
        maven 'maven'
        
    }

    environment {
      REPORTS_DIR       = 'security-reports'
      DOCKER_NET        = 'secnet'
      APP_INTERNAL_PORT = '8080'   // port INSIDE the app container
      APP_HOST_PORT     = '8082'   // port on your Windows host
      ZAP_PATH          = '/actuator/health'      // or '/actuator/health' if it exists and returns 200
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

       

        stage('Build Docker Image') {
            steps {
                echo "🐳 Building Docker image for application..."
                dir('FetchingData') {
                    sh '''
                       docker build --no-cache -t my-app:latest .

                        echo "✅ Docker is is  image built successfully"
                    '''
                }
            }
        }

        stage('Start Application in Docker') {
          steps {
            echo "🚀 Starting application in Docker container on network ${DOCKER_NET}..."
            sh '''
              docker network inspect "${DOCKER_NET}" >/dev/null 2>&1 || docker network create "${DOCKER_NET}"

              docker rm -f app-container 2>/dev/null || true

              docker run -d \
                --name app-container \
                --network "${DOCKER_NET}" \
                -p ${APP_HOST_PORT}:${APP_INTERNAL_PORT} \
                -e SERVER_PORT=${APP_INTERNAL_PORT} \
                my-app:latest

              echo "Container started, waiting for app to be ready..."

              READY=0
              for i in $(seq 1 60); do
                # Check from the SAME docker network (don’t rely on host localhost)
                CODE=$(docker run --rm --network "${DOCKER_NET}" curlimages/curl:8.10.1 \
                  -s -o /dev/null -w "%{http_code}" \
                  "http://app-container:${APP_INTERNAL_PORT}${ZAP_PATH}" || echo "000")

                # consider 200/204/301/302/401/403/405 as "up"
                if echo "$CODE" | grep -Eq '^(200|204|301|302|401|403|405)$'; then
                  echo "✓ App is up inside ${DOCKER_NET} (HTTP ${CODE})"
                  READY=1
                  break
                fi
                sleep 2
              done

              if [ "$READY" -ne 1 ]; then
                echo "❌ App did not become ready in time"
                docker logs app-container || true
                exit 1
              fi

              echo "✅ App is running in container on network ${DOCKER_NET}"
            '''
          }
        }



        stage('Debug - Verify Network Connectivity') {
          steps {
            echo '🔍 Testing network connectivity...'
            sh '''
              echo "1) From Jenkins to app via host port:"
              curl -s -o /dev/null -w "HTTP %{http_code}\\n" "http://localhost:${APP_HOST_PORT}${ZAP_PATH}" || echo "Failed"

              echo ""
              echo "2) From a temp container on ${DOCKER_NET} to app-container (internal port):"
              docker run --rm --network "${DOCKER_NET}" curlimages/curl:8.10.1 \
                -s -o /dev/null -w "HTTP %{http_code}\\n" "http://app-container:${APP_INTERNAL_PORT}${ZAP_PATH}" || echo "Failed"

              echo ""
              echo "3) Containers on network:"
              docker network inspect "${DOCKER_NET}" | grep -A 5 '"Containers"' || true
            '''
          }
        }


        stage('DAST Analysis - ZAP Scan') {
          steps {
            echo '🕷️ Running DAST scan with OWASP ZAP...'

              sh '''
                set -eu
                TARGET_URL="http://app-container:${APP_INTERNAL_PORT}/"
                echo "Starting OWASP ZAP scan against ${TARGET_URL}"

                mkdir -p "${WORKSPACE}/${REPORTS_DIR}"

                # Preflight: ensure target is up from SAME Docker network
                docker run --rm --network "${DOCKER_NET}" curlimages/curl:8.10.1 \
                  -s -o /dev/null -w "%{http_code}" "http://app-container:${APP_INTERNAL_PORT}/actuator/health" | grep -Eq "^(200|302)$"

                # Run ZAP in a named container, write reports into container FS
                ZAP_CONT="zap-run-$$"
                docker run --name "${ZAP_CONT}" \
                  --network "${DOCKER_NET}" --user 0 \
                  zaproxy/zap-stable zap-baseline.py \
                    -t "${TARGET_URL}" \
                    -g /zap/wrk/gen.conf \
                    -J /zap/wrk/dast-report.json \
                    -r /zap/wrk/dast-report.html \
                    -x /zap/wrk/dast-report.xml \
                    -m 10 -I -d

                # Copy reports out of the container to the workspace
                docker cp "${ZAP_CONT}:/zap/wrk/dast-report.json" "${WORKSPACE}/${REPORTS_DIR}/" || true
                docker cp "${ZAP_CONT}:/zap/wrk/dast-report.html" "${WORKSPACE}/${REPORTS_DIR}/" || true
                docker cp "${ZAP_CONT}:/zap/wrk/dast-report.xml"  "${WORKSPACE}/${REPORTS_DIR}/" || true

                # Always remove the container
                docker rm -f "${ZAP_CONT}" >/dev/null 2>&1 || true

                echo "Verifying DAST reports..."
                ls -lh "${WORKSPACE}/${REPORTS_DIR}/dast-report.json" || echo "WARNING: JSON report not created"
                ls -lh "${WORKSPACE}/${REPORTS_DIR}/dast-report.html" || echo "WARNING: HTML report not created"
                ls -lh "${WORKSPACE}/${REPORTS_DIR}/dast-report.xml"  || echo "WARNING: XML report not created"
              '''




            echo '✅ DAST scan completed'
          }
          post {
            always {
              archiveArtifacts artifacts: "${REPORTS_DIR}/dast-report.json,${REPORTS_DIR}/dast-report.html",
                               fingerprint: true, allowEmptyArchive: true
            }
          }
        }


        stage('Stop Application') {
            steps {
                echo '🛑 Stopping application container...'
                sh '''
                    docker stop app-container 2>/dev/null || true
                    docker rm app-container 2>/dev/null || true
                    echo "✅ Application container stopped and removed"
                '''
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
