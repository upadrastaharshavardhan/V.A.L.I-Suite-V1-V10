#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "→ Creating .env from .env.example"
  cp .env.example .env
fi

mkdir -p data/logs data/sessions data/ssh

echo "→ Building and starting VALI v2..."
docker compose up --build -d

echo ""
echo "VALI v2 is starting up."
echo ""
echo "  Web Decoy:     http://localhost:8080"
echo "  SSH Honeypot:  ssh localhost -p 2222   (any user/pass)"
echo "  Dashboard:     http://localhost:8501"
echo "  Logger:        http://localhost:8001/health"
echo ""
echo "Follow logs:  docker compose logs -f"
echo "Stop:         docker compose down"
echo ""
