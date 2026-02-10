#!/usr/bin/env bash
# =============================================================================
# run_multi_node.sh — Start 3 Nova KMS simulation nodes on ports 4000-4002
# =============================================================================
#
# Usage:
#   ./run_multi_node.sh         # Start all 3 nodes in background
#   ./run_multi_node.sh stop    # Kill all running simulation nodes
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/../enclave"

NUM_NODES=3
PIDS=()

stop_all() {
    echo ""
    echo "Stopping all simulation nodes..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            echo "  Stopped PID $pid"
        fi
    done
    wait 2>/dev/null || true
    echo "All nodes stopped."
    exit 0
}

if [[ "${1:-}" == "stop" ]]; then
    # Kill any python processes running app.py with SIMULATION_MODE
    pkill -f "python app.py" 2>/dev/null && echo "Stopped running nodes." || echo "No nodes running."
    exit 0
fi

trap stop_all SIGINT SIGTERM

export SIMULATION_MODE=1
export IN_ENCLAVE="${IN_ENCLAVE:-false}"

echo "╔══════════════════════════════════════════╗"
echo "║  Nova KMS — Multi-Node Simulation        ║"
echo "║  Starting $NUM_NODES nodes on ports 4000-$((4000 + NUM_NODES - 1))      ║"
echo "╚══════════════════════════════════════════╝"
echo ""

BASE_PORT=${BASE_PORT:-4000}
export BASE_PORT
VENV_PYTHON="${SCRIPT_DIR}/../.venv/bin/python3"
PYTHON_CMD="python3"

if [[ -f "$VENV_PYTHON" ]]; then
    PYTHON_CMD="$VENV_PYTHON"
fi

# Build SIM_PEERS_CSV using deterministic simulation wallets so the peer list
# matches the ports we actually launch (and PoP mutual auth stays consistent).
SIM_PEERS_CSV="$($PYTHON_CMD - <<'PY'
import os
from simulation import DEFAULT_SIM_PEERS
base = int(os.environ.get('BASE_PORT', '4000'))
print(",".join(
    f"{p.tee_wallet}|http://localhost:{base + i}"
    for i, p in enumerate(DEFAULT_SIM_PEERS[:3])
))
PY
)"
export SIM_PEERS_CSV

for i in $(seq 0 $((NUM_NODES - 1))); do
    port=$((BASE_PORT + i))
    echo "Starting node $i on port $port ..."
    SIM_PORT=$port SIM_NODE_INDEX=$i $PYTHON_CMD app.py &
    PIDS+=($!)
    sleep 1
done

echo ""
echo "All $NUM_NODES nodes started.  Press Ctrl+C to stop."
for i in $(seq 0 $((NUM_NODES - 1))); do
    echo "  Node $i: http://localhost:$((BASE_PORT + i))"
done
echo ""

# Wait for all background processes
wait
