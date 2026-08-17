#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
    echo "Creating .env from .env.example..."
    cp .env.example .env
fi

echo "Building and starting VALI..."
docker compose up --build -d

echo ""
echo "VALI is starting."
echo "  Web Decoy:   http://localhost:8080"
echo "  Dashboard:   http://localhost:8501"
echo "  Logger API:  http://localhost:8001/health"
echo ""
echo "Run 'docker compose logs -f' to follow logs."
echo "Run 'docker compose down' to stop."
