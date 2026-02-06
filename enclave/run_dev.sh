#!/usr/bin/env bash
# =============================================================================
# run_dev.sh — Start a single Nova KMS node in simulation mode
# =============================================================================
#
# Usage:
#   ./run_dev.sh              # Start node 0 on port 8000
#   SIM_NODE_INDEX=1 ./run_dev.sh   # Start node 1 on port 8001
#
# Environment variables (all optional):
#   SIMULATION_MODE   — Override (default: "1")
#   SIM_NODE_INDEX    — Which peer index to act as (default: 0)
#   SIM_PORT          — Override port (default: derived from node index)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

export SIMULATION_MODE="${SIMULATION_MODE:-1}"
export SIM_NODE_INDEX="${SIM_NODE_INDEX:-0}"

echo "╔══════════════════════════════════════════╗"
echo "║  Nova KMS — Simulation Mode              ║"
echo "║  Node index: $SIM_NODE_INDEX                            ║"
echo "╚══════════════════════════════════════════╝"

python app.py
