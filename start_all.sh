#!/bin/bash
set -e

echo "=============================================="
echo " UEBA Insider Threat System – Startup Script"
echo "=============================================="

PROJECT_DIR="$HOME/Desktop/insider_project"
DOCKER_DIR="$PROJECT_DIR/docker"
GEN_DIR="$PROJECT_DIR/log_generator"
VENV_ACTIVATE="$PROJECT_DIR/venv/bin/activate"
GEN_LOG="$PROJECT_DIR/generator.log"

ES_URL="http://localhost:9200"
KIBANA_URL="http://localhost:5601"

# --------------------------------------------------
# 1. Ensure Docker is running
# --------------------------------------------------
echo "[1/7] Ensuring Docker service is running..."
sudo systemctl start docker

# --------------------------------------------------
# 2. Stop system services to avoid port conflicts
# --------------------------------------------------
echo "[2/7] Disabling system Elasticsearch/Logstash (safe)..."
sudo systemctl stop elasticsearch logstash 2>/dev/null || true
sudo systemctl disable elasticsearch logstash 2>/dev/null || true

# --------------------------------------------------
# 3. Start ELK stack (Docker)
# --------------------------------------------------
echo "[3/7] Starting ELK stack (Docker)..."
cd "$DOCKER_DIR"
docker-compose up -d

# --------------------------------------------------
# 4. Wait for Elasticsearch
# --------------------------------------------------
echo "[4/7] Waiting for Elasticsearch..."
for i in {1..60}; do
  if curl -s -u elastic:C7cmrEkygq9=JTU7HTAu "$ES_URL" >/dev/null 2>&1; then
    echo "✅ Elasticsearch is ready."
    break
  fi
  sleep 2
done

# --------------------------------------------------
# 5. Wait for Kibana
# --------------------------------------------------
echo "[5/7] Waiting for Kibana..."
for i in {1..90}; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$KIBANA_URL" || true)
  if [[ "$CODE" == "200" || "$CODE" == "302" ]]; then
    echo "✅ Kibana is ready."
    break
  fi
  sleep 2
done

# --------------------------------------------------
# 6. Start UEBA email alert service
# --------------------------------------------------
echo "[6/7] Starting UEBA email alert service..."
sudo systemctl restart ueba-alert.service

# --------------------------------------------------
# 7. Start log generator (background)
# --------------------------------------------------
echo "[7/7] Starting log generator..."
pkill -f "python.*generator.py" >/dev/null 2>&1 || true

bash -c "
source '$VENV_ACTIVATE' &&
cd '$GEN_DIR' &&
nohup python generator.py > '$GEN_LOG' 2>&1 &
"

# --------------------------------------------------
# FINAL STATUS
# --------------------------------------------------
echo ""
echo "=============================================="
echo " ✅ UEBA System Started Successfully"
echo "=============================================="
echo " Elasticsearch: $ES_URL"
echo " Kibana:        $KIBANA_URL"
echo ""
echo " UEBA Service Logs:"
echo "   sudo journalctl -u ueba-alert.service -n 20"
echo ""
echo " Generator Logs:"
echo "   tail -n 20 $GEN_LOG"
echo ""
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"


