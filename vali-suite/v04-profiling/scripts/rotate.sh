#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "VALI v4 rotation"
echo "  1) Purge sessions + canaries"
echo "  2) Full data purge"
echo "  3) Force recreate containers"
read -p "Choice [1/2/3]: " c

case "$c" in
  1) rm -f data/sessions/* data/canaries/*; echo "Purged sessions & canaries" ;;
  2) rm -f data/sessions/* data/canaries/* data/logs/*; echo "Full purge done" ;;
  3) docker compose down; docker compose up -d --force-recreate; echo "Containers recreated" ;;
  *) echo "Invalid"; exit 1 ;;
esac
