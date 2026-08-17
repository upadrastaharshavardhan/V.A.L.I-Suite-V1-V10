#!/usr/bin/env bash
# VALI v10 — quick demo of the deception loop
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== VALI v10 Demo ==="
echo "This script hits the web decoy to generate progressive engagement + telemetry."
echo ""

# Wait for web decoy
echo "→ Waiting for web decoy on :8080 ..."
for i in $(seq 1 30); do
  if curl -sf -o /dev/null http://localhost:8080/; then
    break
  fi
  sleep 1
done

if ! curl -sf -o /dev/null http://localhost:8080/; then
  echo "Web decoy not up. Run ./scripts/start.sh first."
  exit 1
fi

echo "→ Simulating attacker browsing (progressive unlock path)..."
# Cookie jar to keep session
JAR=$(mktemp)
trap 'rm -f "$JAR"' EXIT

curl -s -c "$JAR" -b "$JAR" http://localhost:8080/ >/dev/null
curl -s -c "$JAR" -b "$JAR" http://localhost:8080/login >/dev/null
curl -s -c "$JAR" -b "$JAR" -X POST -d "username=admin&password=wrong" http://localhost:8080/login >/dev/null
curl -s -c "$JAR" -b "$JAR" http://localhost:8080/dashboard >/dev/null
curl -s -c "$JAR" -b "$JAR" http://localhost:8080/users >/dev/null
curl -s -c "$JAR" -b "$JAR" http://localhost:8080/dashboard >/dev/null
curl -s -c "$JAR" -b "$JAR" http://localhost:8080/api/docs >/dev/null || true
curl -s -c "$JAR" -b "$JAR" http://localhost:8080/staging >/dev/null || true
curl -s -c "$JAR" -b "$JAR" http://localhost:8080/config >/dev/null || true
curl -s -c "$JAR" -b "$JAR" http://localhost:8080/backups >/dev/null || true
curl -s -c "$JAR" -b "$JAR" http://localhost:8080/vault >/dev/null || true
curl -s -c "$JAR" -b "$JAR" http://localhost:8080/api/v1/secrets >/dev/null || true

echo "→ Done. Open the dashboard to see the session:"
echo "   http://localhost:8501"
echo ""
echo "Logger health:"
curl -s http://localhost:8001/health || true
echo ""
echo "Tip: try SSH too → ssh anyuser@localhost -p 2222"
echo "=== Demo complete ==="
