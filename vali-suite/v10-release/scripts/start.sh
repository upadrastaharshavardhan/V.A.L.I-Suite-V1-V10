#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "→ Creating .env from .env.example"
  cp .env.example .env
fi

mkdir -p data/logs data/sessions data/ssh data/canaries data/blocklist

echo "→ Building and starting VALI v10..."
docker compose up --build -d

echo ""
echo "VALI v10 is starting."
echo ""
echo "  Web Decoy:     http://localhost:8080"
echo "  SSH Honeypot:  ssh anyuser@localhost -p 2222"
echo "  Dashboard:     http://localhost:8501"
echo "  Logger API:    http://localhost:8001/health"
echo "  STIX-lite:     http://localhost:8001/export/stix-lite"
echo "  Metrics:       http://localhost:8001/metrics"
echo ""
echo "Demo the loop:  ./scripts/demo.sh"
echo "Status:         ./scripts/status.sh"
echo "Rotate/purge:   ./scripts/rotate.sh"
echo ""
echo "Optional: ENABLE_LLM=true + OPENAI_API_KEY in .env"
echo "Optional: WEBHOOK_URL= for alerts"
echo ""
