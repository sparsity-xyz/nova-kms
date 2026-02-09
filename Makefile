# =============================================================================
# Nova KMS - Makefile
# =============================================================================

.PHONY: help build-docker simulation simulation-multi stop-simulation

help:
	@echo "Nova KMS Build & Development"
	@echo ""
	@echo "Targets:"
	@echo "  build-docker      Build the production Docker image"
	@echo "  simulation        Run a single KMS node in simulation mode"
	@echo "  simulation-multi  Run 3 simulation nodes in the background"
	@echo "  stop-simulation   Stop all running simulation nodes"
	@echo ""

build-docker:
	docker build -t nova-kms:latest .

simulation:
	./scripts/run_dev.sh

simulation-multi:
	./scripts/run_multi_node.sh

stop-simulation:
	./scripts/run_multi_node.sh stop
