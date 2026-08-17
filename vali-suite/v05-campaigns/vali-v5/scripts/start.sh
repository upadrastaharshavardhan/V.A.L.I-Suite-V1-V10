#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "→ Creating .env from .env.example"
  cp .env.example .env
fi

mkdir -p data/logs data/sessions data/ssh data/canaries

echo "→ Building and starting VALI v5..."
docker compose up --build -d

echo ""
echo "VALI v5 Advanced is starting."
echo ""
echo "  Web Decoy:     http://localhost:8080"
echo "  SSH Honeypot:  ssh anyuser@localhost -p 2222"
echo "  Dashboard:     http://localhost:8501"
echo "  Logger API:    http://localhost:8001/health"
echo "  Metrics:       http://localhost:8001/metrics"
echo ""
echo "Optional LLM: ENABLE_LLM=true + OPENAI_API_KEY in .env"
echo "Logs: docker compose logs -f"
echo "Stop: docker compose down"
echo ""
