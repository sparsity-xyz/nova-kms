# =============================================================================
# Nova KMS - Makefile
# =============================================================================

.PHONY: help build-docker

help:
	@echo "Nova KMS Build & Development"
	@echo ""
	@echo "Targets:"
	@echo "  build-docker      Build the production Docker image"
	@echo ""

build-docker:
	docker build -t nova-kms:latest .
