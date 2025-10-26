pipeline {
    agent any

    environment {
        REPORTS_DIR = 'security-reports'
    }

    stages {
        stage('Preparation') {
            steps {
                echo ' Starting SAST Analysis Pipeline'
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
                        sh 'mvn clean compile -DskipTests'
                    } catch (Exception e) {
                        echo "Build skipped: ${e.message}"
                    }
                }
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