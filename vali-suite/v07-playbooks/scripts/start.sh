#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "→ Creating .env from .env.example"
  cp .env.example .env
fi

mkdir -p data/logs data/sessions data/ssh data/canaries data/blocklist

echo "→ Building and starting VALI v7..."
docker compose up --build -d

echo ""
echo "VALI v7 Advanced is starting."
echo ""
echo "  Web Decoy:     http://localhost:8080"
echo "  SSH Honeypot:  ssh anyuser@localhost -p 2222"
echo "  Dashboard:     http://localhost:8501"
echo "  Logger API:    http://localhost:8001/health"
echo "  Metrics:       http://localhost:8001/metrics"
echo "  Blocklist:     http://localhost:8001/blocklist  (API key required)"
echo ""
echo "Optional: ENABLE_LLM=true + OPENAI_API_KEY"
echo "Optional: WEBHOOK_URL= for canary alerts"
echo ""
