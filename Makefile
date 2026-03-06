# =============================================================================
# Nova KMS - Makefile
# =============================================================================

.PHONY: help build-docker test lint fmt

help:
	@echo "Nova KMS Build & Development"
	@echo ""
	@echo "Targets:"
	@echo "  build-docker      Build the production Docker image"
	@echo "  test              Run all Cargo tests"
	@echo "  lint              Run Cargo clippy"
	@echo "  fmt               Run Cargo fmt"
	@echo ""

build-docker:
	docker build -t nova-kms:latest .

test:
	cargo test

lint:
	cargo clippy

fmt:
	cargo fmt

