#!/usr/bin/env bash
cd "$(dirname "$0")/.."
echo "=== VALI v9 Status ==="
docker compose ps 2>/dev/null || true
echo ""
echo "Data:"
echo "  Sessions  : $(ls data/sessions 2>/dev/null | wc -l)"
echo "  Canaries  : $(ls data/canaries 2>/dev/null | wc -l)"
echo "  Log files : $(ls data/logs 2>/dev/null | wc -l)"
echo "  Blocklist : $(wc -l < data/blocklist/high_risk_ips.txt 2>/dev/null || echo 0)"
