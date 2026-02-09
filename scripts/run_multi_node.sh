#!/usr/bin/env bash
# =============================================================================
# run_multi_node.sh — Start 3 Nova KMS simulation nodes on ports 8000-8002
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

echo "╔══════════════════════════════════════════╗"
echo "║  Nova KMS — Multi-Node Simulation        ║"
echo "║  Starting $NUM_NODES nodes on ports 8000-$((8000 + NUM_NODES - 1))      ║"
echo "╚══════════════════════════════════════════╝"
echo ""

BASE_PORT=${BASE_PORT:-8010}
VENV_PYTHON="${SCRIPT_DIR}/../.venv/bin/python3"
PYTHON_CMD="python3"

if [[ -f "$VENV_PYTHON" ]]; then
    PYTHON_CMD="$VENV_PYTHON"
fi

# Construct SIM_PEERS_CSV for dynamic topology
SIM_PEERS_CSV="0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|http://localhost:$((BASE_PORT + 0)),"
SIM_PEERS_CSV+="0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB|http://localhost:$((BASE_PORT + 1)),"
SIM_PEERS_CSV+="0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC|http://localhost:$((BASE_PORT + 2))"

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
