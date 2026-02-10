#!/bin/bash
set -e

# Ensure we're running from the project root
if [ ! -f "enclave/app.py" ]; then
    echo "Error: Must run from project root"
    exit 1
fi

# Detect Python interpreter (venv or system)
PYTHON_CMD="python3"
if [ -d ".venv" ]; then
    echo "Using .venv/bin/python3"
    PYTHON_CMD=".venv/bin/python3"
elif [ -d "venv" ]; then
    echo "Using venv/bin/python3"
    PYTHON_CMD="venv/bin/python3"
fi

echo "Starting KMS Simulation Cluster..."

# Cleanup function to kill background processes on exit
cleanup() {
    echo "Stopping simulation nodes..."
    pkill -P $$ || true
}
trap cleanup EXIT

# Create logs directory
mkdir -p logs

# Start Node 0
echo "Starting Node 0 on port 4000..."
IN_ENCLAVE=false SIMULATION_MODE=1 SIM_PORT=4000 SIM_NODE_INDEX=0 $PYTHON_CMD enclave/app.py > logs/node0.log 2>&1 &

# Start Node 1
echo "Starting Node 1 on port 4001..."
IN_ENCLAVE=false SIMULATION_MODE=1 SIM_PORT=4001 SIM_NODE_INDEX=1 $PYTHON_CMD enclave/app.py > logs/node1.log 2>&1 &

# Start Node 2
echo "Starting Node 2 on port 4002..."
IN_ENCLAVE=false SIMULATION_MODE=1 SIM_PORT=4002 SIM_NODE_INDEX=2 $PYTHON_CMD enclave/app.py > logs/node2.log 2>&1 &

echo "Sim nodes running. Monitoring logs..."
echo "Press Ctrl+C to stop."

# Tail logs (this keeps the script running until Ctrl+C)
tail -f logs/node0.log logs/node1.log logs/node2.log
