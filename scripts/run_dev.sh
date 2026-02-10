#!/usr/bin/env bash
# =============================================================================
# run_dev.sh — Start a single Nova KMS node in simulation mode
# =============================================================================
#
# Usage:
#   ./run_dev.sh                   # Start node 0 on port 4000
#   SIM_NODE_INDEX=1 ./run_dev.sh  # Start node 1 on port 4001
#
# Environment variables (all optional):
#   SIMULATION_MODE   — Override (default: "1")
#   SIM_NODE_INDEX    — Which peer index to act as (default: 0)
#   SIM_PORT          — Override port (default: derived from node index)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/../enclave"

export SIMULATION_MODE="${SIMULATION_MODE:-1}"
export SIM_NODE_INDEX="${SIM_NODE_INDEX:-0}"
export SIM_PORT="${SIM_PORT:-$((4000 + SIM_NODE_INDEX))}"
export IN_ENCLAVE="${IN_ENCLAVE:-false}"

echo "╔══════════════════════════════════════════╗"
echo "║  Nova KMS — Simulation Mode              ║"
echo "║  Node index: $SIM_NODE_INDEX                            ║"
echo "║  Port: $SIM_PORT                                 ║"
echo "╚══════════════════════════════════════════╝"

python app.py
