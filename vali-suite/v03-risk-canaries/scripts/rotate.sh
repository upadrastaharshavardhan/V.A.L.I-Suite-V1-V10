#!/usr/bin/env bash
# VALI hygiene / rotation helper
set -euo pipefail
cd "$(dirname "$0")/.."

echo "VALI rotation options:"
echo "  1) Purge sessions & canaries (keep logs)"
echo "  2) Full data purge"
echo "  3) Recreate containers (force new instances)"
read -p "Choice [1/2/3]: " choice

case "$choice" in
  1)
    rm -f data/sessions/* data/canaries/*
    echo "Sessions and canaries purged."
    ;;
  2)
    rm -f data/sessions/* data/canaries/* data/logs/*
    echo "All local VALI data purged."
    ;;
  3)
    docker compose down
    docker compose up -d --force-recreate
    echo "Containers recreated."
    ;;
  *)
    echo "Invalid choice"
    exit 1
    ;;
esac
