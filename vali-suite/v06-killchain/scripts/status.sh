#!/usr/bin/env bash
cd "$(dirname "$0")/.."
echo "=== VALI v6 Status ==="
docker compose ps 2>/dev/null || true
echo ""
echo "Data:"
echo "  Sessions : $(ls data/sessions 2>/dev/null | wc -l)"
echo "  Canaries : $(ls data/canaries 2>/dev/null | wc -l)"
echo "  Log files: $(ls data/logs 2>/dev/null | wc -l)"
