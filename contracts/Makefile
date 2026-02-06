-include .env

.PHONY: install build clean test deploy verify-blockscout verify-basescan

# Install dependencies
install:
	@echo "Installing dependencies..."
	@mkdir -p lib
	@[ -d lib/forge-std ] || forge install foundry-rs/forge-std --no-git

# Build all contracts
build:
	@echo "Building contracts..."
	forge build

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	forge clean

# Run tests
test:
	@echo "Running tests..."
	forge test -vvv

# Format code
fmt:
	@echo "Formatting contracts..."
	forge fmt

# Deploy KMSRegistry
deploy:
	@echo "======================================"
	@echo "Deploying KMSRegistry"
	@echo "======================================"
	@echo "Required env vars: NOVA_APP_REGISTRY_PROXY, KMS_APP_ID, PRIVATE_KEY"
	forge script script/DeployKMSRegistry.s.sol --tc DeployKMSRegistry \
		--rpc-url $(RPC_URL) \
		--private-key $(PRIVATE_KEY) \
		--broadcast

# Verify KMSRegistry on Blockscout (no API key required)
verify-blockscout:
	@if [ -z "$(CONTRACT_ADDRESS)" ]; then echo "Error: CONTRACT_ADDRESS not set"; exit 1; fi; \
	echo "Verifying KMSRegistry at $(CONTRACT_ADDRESS) on Blockscout..."; \
	forge verify-contract \
		--rpc-url $(RPC_URL) \
		$(CONTRACT_ADDRESS) \
		src/KMSRegistry.sol:KMSRegistry \
		--constructor-args $$(cast abi-encode "constructor(address,uint256)" $(NOVA_APP_REGISTRY_PROXY) $(KMS_APP_ID)) \
		--verifier blockscout \
		--verifier-url https://base-sepolia.blockscout.com/api/ \
		--watch

# Verify KMSRegistry on Basescan (requires BASESCAN_API_KEY)
verify-basescan:
	@if [ -z "$(CONTRACT_ADDRESS)" ]; then echo "Error: CONTRACT_ADDRESS not set"; exit 1; fi; \
	echo "Verifying KMSRegistry at $(CONTRACT_ADDRESS) on Basescan..."; \
	forge verify-contract \
		--rpc-url $(RPC_URL) \
		$(CONTRACT_ADDRESS) \
		src/KMSRegistry.sol:KMSRegistry \
		--constructor-args $$(cast abi-encode "constructor(address,uint256)" $(NOVA_APP_REGISTRY_PROXY) $(KMS_APP_ID)) \
		--etherscan-api-key $(BASESCAN_API_KEY) \
		--watch
