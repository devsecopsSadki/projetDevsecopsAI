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
    ZAP_PATH          = '/actuator/health' // or '/' if that’s what returns 200
  }

  stages {
    stage('Preparation') {
      steps {
        echo 'Starting DevSecOps Security Analysis Pipeline (SAST, SCA, DAST)'
        sh '''
          rm -rf "${REPORTS_DIR}"
          mkdir -p "${REPORTS_DIR}"
        '''
        checkout scm
      }
    }

    stage('Build Application') {
      steps {
        echo 'Building application...'
        dir('FetchingData') {
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
            dir('FetchingData') {
              sh '''
                echo "Installing Snyk locally (no sudo needed)..."
                npm install snyk

                echo "Authenticating with Snyk..."
                npx snyk auth "$SNYK_TOKEN" || true

                echo "Running Snyk test on FetchingData/pom.xml..."
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
        echo 'Parsing SCA report for LLM...'
        sh '''
          if [ -f "${REPORTS_DIR}/sca-raw.json" ]; then
            echo "Report file found, parsing..."
            cd parsers
            python3 parsca.py "../${REPORTS_DIR}/sca-raw.json" "../${REPORTS_DIR}/sca-findings.txt"
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
        echo 'Running SonarQube SAST Scan...'
        script {
          withSonarQubeEnv('SonarQube') {
            sh '''
              export PATH="$PATH:/opt/sonar-scanner/bin"
              sonar-scanner \
                -Dsonar.projectKey=my-project \
                -Dsonar.sources=FetchingData/src \
                -Dsonar.java.binaries=FetchingData/target/classes \
                -Dsonar.host.url="$SONAR_HOST_URL" \
                -Dsonar.login="$SONAR_AUTH_TOKEN"
            '''
          }
        }

        echo 'Exporting SonarQube results to JSON...'
        script {
          withSonarQubeEnv('SonarQube') {
            sh """
              curl -u \${SONAR_AUTH_TOKEN}: \
                "\${SONAR_HOST_URL}/api/issues/search?componentKeys=my-project&ps=500" \
                -o ${REPORTS_DIR}/sast-report.json
            """
          }
        }
        echo 'SAST scan completed'
      }
      post {
        always {
          archiveArtifacts artifacts: "${REPORTS_DIR}/sast-report.json", fingerprint: true, allowEmptyArchive: true
        }
      }
    }

    stage('Parse SAST Report') {
      steps {
        echo 'Parsing SAST report for LLM...'
        sh """
          python3 parsers/sast/parsast.py \
            ${REPORTS_DIR}/sast-report.json \
            ${REPORTS_DIR}/sast-findings.txt
        """
        echo 'Report parsed and ready for LLM'
      }
      post {
        always {
          archiveArtifacts artifacts: "${REPORTS_DIR}/sast-findings.txt", allowEmptyArchive: true, fingerprint: true
        }
      }
    }

    stage('Build Docker Image') {
      steps {
        echo "🐳 Building Docker image for application..."
        dir('FetchingData') {
          sh '''
            docker build --no-cache -t my-app:latest .
            echo "✅ Docker image built successfully"
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
            CODE=$(docker run --rm --network "${DOCKER_NET}" curlimages/curl:8.10.1 \
              -s -o /dev/null -w "%{http_code}" \
              "http://app-container:${APP_INTERNAL_PORT}${ZAP_PATH}" || echo "000")
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
        sh '''#!/usr/bin/env bash
set -eu

# ------------ Config ------------
DOCKER_NET="${DOCKER_NET:-secnet}"
WORKSPACE="${WORKSPACE:-$PWD}"
REPORTS_DIR="${REPORTS_DIR:-security-reports}"
ENDPOINTS_FILE="${ENDPOINTS_FILE:-${WORKSPACE}/endpoints.txt}"
TARGET_BASE="${TARGET_BASE:-http://app-container:8080}"
ZAP_CONTAINER="${ZAP_CONTAINER:-zap-scan}"
ZAP_API_PORT="${ZAP_API_PORT:-8090}"
SPIDER_MINUTES="${SPIDER_MINUTES:-5}"
ASCAN_MAX_SECONDS="${ASCAN_MAX_SECONDS:-600}"
# --------------------------------

mkdir -p "${WORKSPACE}/${REPORTS_DIR}"
docker rm -f "${ZAP_CONTAINER}" >/dev/null 2>&1 || true

echo "Starting ZAP daemon on port ${ZAP_API_PORT}..."
docker run -d --name "${ZAP_CONTAINER}" \
  --network "${DOCKER_NET}" \
  -p "${ZAP_API_PORT}:8090" \
  zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8090 \
         -config api.disablekey=true \
         -config api.addrs.addr.name=.* \
         -config api.addrs.addr.regex=true

echo "Waiting for ZAP API to become ready..."
RETRY=0
while [ "$RETRY" -lt 30 ]; do
  if docker run --rm --network "${DOCKER_NET}" curlimages/curl:8.10.1 \
       -s "http://${ZAP_CONTAINER}:8090/JSON/core/view/version/" >/dev/null 2>&1; then
    echo "✓ ZAP API is ready"
    break
  fi
  RETRY=$((RETRY + 1))
  sleep 2
  if [ "$RETRY" -eq 30 ]; then
    echo "ERROR: ZAP did not start in time"
    docker logs "${ZAP_CONTAINER}" || true
    exit 1
  fi
done

if [ -f "${ENDPOINTS_FILE}" ]; then
  echo "Pre-warming endpoints via ZAP proxy (${ZAP_CONTAINER}:${ZAP_API_PORT})..."
  while IFS= read -r path || [ -n "$path" ]; do
    [ -z "$path" ] && continue
    echo "$path" | grep -q "^[[:space:]]*#" && continue
    case "$path" in
      http://*|https://*) full_url="$path" ;;
      /*)                 full_url="${TARGET_BASE%/}${path}" ;;
      *)                  full_url="${TARGET_BASE%/}/$path" ;;
    esac
    docker run --rm --network "${DOCKER_NET}" curlimages/curl:8.10.1 \
      -s -o /dev/null -x "http://${ZAP_CONTAINER}:8090" "$full_url" || true
    sleep 0.02
  done < "${ENDPOINTS_FILE}"
fi

echo "Starting spider scan for ${SPIDER_MINUTES} minute(s)..."
SCAN_RESPONSE="$(docker run --rm --network "${DOCKER_NET}" curlimages/curl:8.10.1 \
  -s "http://${ZAP_CONTAINER}:8090/JSON/spider/action/scan/?url=${TARGET_BASE%/}/")"

SCAN_ID="$(printf '%s' "$SCAN_RESPONSE" | sed -n 's/.*"scan":"\\([0-9]\\+\\)".*/\\1/p')"
if [ -z "${SCAN_ID:-}" ]; then
  echo "ERROR: Failed to start spider scan"
  echo "Response: $SCAN_RESPONSE"
  exit 1
fi
echo "Spider scan started with ID: ${SCAN_ID}"

ELAPSED=0
MAX_TIME=$((SPIDER_MINUTES * 60))
while [ "$ELAPSED" -lt "$MAX_TIME" ]; do
  STATUS="$(docker run --rm --network "${DOCKER_NET}" curlimages/curl:8.10.1 \
    -s "http://${ZAP_CONTAINER}:8090/JSON/spider/view/status/?scanId=${SCAN_ID}" \
      | sed -n 's/.*"status":"\\([0-9]\\+\\)".*/\\1/p')"
  [ -z "$STATUS" ] && STATUS="0"
  echo "Spider progress: ${STATUS}%"
  [ "$STATUS" = "100" ] && { echo "✓ Spider scan completed"; break; }
  sleep 10
  ELAPSED=$((ELAPSED + 10))
done

echo "Starting active scan..."
ASCAN_RESPONSE="$(docker run --rm --network "${DOCKER_NET}" curlimages/curl:8.10.1 \
  -s "http://${ZAP_CONTAINER}:8090/JSON/ascan/action/scan/?url=${TARGET_BASE%/}/")"

ASCAN_ID="$(printf '%s' "$ASCAN_RESPONSE" | sed -n 's/.*"scan":"\\([0-9]\\+\\)".*/\\1/p')"
if [ -z "${ASCAN_ID:-}" ]; then
  echo "ERROR: Failed to start active scan"
  echo "Response: $ASCAN_RESPONSE"
  exit 1
fi
echo "Active scan started with ID: ${ASCAN_ID}"

ELAPSED=0
while [ "$ELAPSED" -lt "$ASCAN_MAX_SECONDS" ]; do
  ASTATUS="$(docker run --rm --network "${DOCKER_NET}" curlimages/curl:8.10.1 \
    -s "http://${ZAP_CONTAINER}:8090/JSON/ascan/view/status/?scanId=${ASCAN_ID}" \
      | sed -n 's/.*"status":"\\([0-9]\\+\\)".*/\\1/p')"
  [ -z "$ASTATUS" ] && ASTATUS="0"
  echo "Active scan progress: ${ASTATUS}%"
  [ "$ASTATUS" = "100" ] && { echo "✓ Active scan completed"; break; }
  sleep 15
  ELAPSED=$((ELAPSED + 15))
done

echo "Generating reports inside ZAP container..."
docker exec "${ZAP_CONTAINER}" sh -c "wget -qO /tmp/dast-report.html http://localhost:8090/OTHER/core/other/htmlreport/"
docker exec "${ZAP_CONTAINER}" sh -c "wget -qO /tmp/dast-report.json http://localhost:8090/OTHER/core/other/jsonreport/"
docker exec "${ZAP_CONTAINER}" sh -c "wget -qO /tmp/dast-report.xml  http://localhost:8090/OTHER/core/other/xmlreport/"

echo "Copying reports to ${WORKSPACE}/${REPORTS_DIR}..."
docker cp "${ZAP_CONTAINER}:/tmp/dast-report.html" "${WORKSPACE}/${REPORTS_DIR}/" || true
docker cp "${ZAP_CONTAINER}:/tmp/dast-report.json" "${WORKSPACE}/${REPORTS_DIR}/" || true
docker cp "${ZAP_CONTAINER}:/tmp/dast-report.xml"  "${WORKSPACE}/${REPORTS_DIR}/" || true

echo "Cleaning up ZAP container..."
docker stop "${ZAP_CONTAINER}" >/dev/null 2>&1 || true
docker rm   "${ZAP_CONTAINER}" >/dev/null 2>&1 || true

echo "Reports generated:"
ls -lh "${WORKSPACE}/${REPORTS_DIR}" || true
'''
        echo '✅ DAST scan completed'
      }
      post {
        always {
          archiveArtifacts artifacts: "${REPORTS_DIR}/dast-report.json, ${REPORTS_DIR}/dast-report.html, ${REPORTS_DIR}/dast-report.xml",
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
        echo 'Parsing DAST report for LLM...'
        sh '''
          if [ -f "${REPORTS_DIR}/dast-report.json" ]; then
            echo "DAST report file found, parsing..."
            cd parsers/dast
            python3 pardast.py \
              "../../${REPORTS_DIR}/dast-report.json" \
              "../../${REPORTS_DIR}/dast-findings.txt"
          else
            echo "WARNING: dast-report.json not found, skipping parsing"
            echo "No DAST findings to report." > "${REPORTS_DIR}/dast-findings.txt"
          fi
        '''
        echo 'DAST report parsed and ready for LLM'
      }
      post {
        always {
          archiveArtifacts artifacts: "${REPORTS_DIR}/dast-findings.txt", fingerprint: true, allowEmptyArchive: true
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
        echo 'Policies generated'
      }
    }

    stage('Display Summary') {
      steps {
        echo 'Generating summary...'
        sh '''
          echo "======================================"
          echo "PIPELINE RESULTS SUMMARY"
          echo "======================================"

          if [ -f "${REPORTS_DIR}/sast-findings.txt" ]; then
            FINDING_COUNT=$(grep -c "^--- Finding" "${REPORTS_DIR}/sast-findings.txt" || echo "0")
            echo "Total SAST Findings: $FINDING_COUNT"
          fi

          if [ -f "${REPORTS_DIR}/dast-findings.txt" ]; then
            DAST_COUNT=$(grep -c "^--- DAST Finding" "${REPORTS_DIR}/dast-findings.txt" || echo "0")
            echo "Total DAST Findings: $DAST_COUNT"
          fi

          if [ -f "${REPORTS_DIR}/security-policies.json" ]; then
            echo "Security policies generated: "
            python3 - <<'PY'
import json, sys
data=json.load(open(sys.argv[1]))
print('Total policies:', len(data.get('policies', [])))
PY
            "${REPORTS_DIR}/security-policies.json"
          fi

          echo "======================================"
        '''
      }
    }

    stage('Archive Results') {
      steps {
        echo 'Archiving artifacts...'
        archiveArtifacts artifacts: "${REPORTS_DIR}/*", allowEmptyArchive: false
      }
    }
  }

  post {
    success {
      echo 'Pipeline completed successfully!'
    }
    failure {
      echo 'Pipeline failed!'
    }
  }
}
