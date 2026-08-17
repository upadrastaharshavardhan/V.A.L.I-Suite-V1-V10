#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo "VALI v8 rotation"
echo "  1) Purge sessions + canaries"
echo "  2) Full data purge (incl. blocklist)"
echo "  3) Force recreate containers"
read -p "Choice [1/2/3]: " c
case "$c" in
  1) rm -f data/sessions/* data/canaries/*; echo "Purged" ;;
  2) rm -f data/sessions/* data/canaries/* data/logs/* data/blocklist/*; echo "Full purge" ;;
  3) docker compose down; docker compose up -d --force-recreate; echo "Recreated" ;;
  *) echo "Invalid"; exit 1 ;;
esac
