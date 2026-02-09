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

for i in $(seq 0 $((NUM_NODES - 1))); do
    port=$((8000 + i))
    echo "Starting node $i on port $port ..."
    SIM_NODE_INDEX=$i python app.py &
    PIDS+=($!)
    sleep 1
done

echo ""
echo "All $NUM_NODES nodes started.  Press Ctrl+C to stop."
echo "  Node 0: http://localhost:8000"
echo "  Node 1: http://localhost:8001"
echo "  Node 2: http://localhost:8002"
echo ""

# Wait for all background processes
wait
