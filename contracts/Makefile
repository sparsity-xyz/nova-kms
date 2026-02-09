-include .env

.PHONY: install build clean test fmt deploy set-app-id verify-blockscout verify-basescan

# Install dependencies
install:
	@echo "Installing dependencies..."
	@mkdir -p lib
	@[ -d lib/forge-std ] || forge install foundry-rs/forge-std --no-git
	@[ -d lib/openzeppelin-contracts-upgradeable ] || forge install OpenZeppelin/openzeppelin-contracts-upgradeable --no-git

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
	@echo "Required env vars: NOVA_APP_REGISTRY_PROXY, PRIVATE_KEY"
	forge script script/DeployKMSRegistry.s.sol --tc DeployKMSRegistry \
		--rpc-url $(RPC_URL) \
		--private-key $(PRIVATE_KEY) \
		--broadcast

# Verify KMSRegistry implementation on Blockscout
verify-blockscout:
	@if [ -z "$(CONTRACT_ADDRESS)" ]; then echo "Error: CONTRACT_ADDRESS not set"; exit 1; fi; \
	echo "Verifying KMSRegistry Implementation at $(CONTRACT_ADDRESS) on Blockscout..."; \
	forge verify-contract \
		--rpc-url $(RPC_URL) \
		$(CONTRACT_ADDRESS) \
		src/KMSRegistry.sol:KMSRegistry \
		--verifier blockscout \
		--verifier-url https://base-sepolia.blockscout.com/api/ \
		--watch

# Verify KMSRegistry implementation on Basescan
verify-basescan:
	@if [ -z "$(CONTRACT_ADDRESS)" ]; then echo "Error: CONTRACT_ADDRESS not set"; exit 1; fi; \
	echo "Verifying KMSRegistry Implementation at $(CONTRACT_ADDRESS) on Basescan..."; \
	forge verify-contract \
		--rpc-url $(RPC_URL) \
		$(CONTRACT_ADDRESS) \
		src/KMSRegistry.sol:KMSRegistry \
		--etherscan-api-key $(BASESCAN_API_KEY) \
		--watch

# Set KMS App ID on the proxy
set-app-id:
	@if [ -z "$(CONTRACT_ADDRESS)" ]; then echo "Error: CONTRACT_ADDRESS (proxy) not set"; exit 1; fi; \
	if [ -z "$(KMS_APP_ID)" ]; then echo "Error: KMS_APP_ID not set"; exit 1; fi; \
	echo "Setting KMS App ID to $(KMS_APP_ID) on $(CONTRACT_ADDRESS)..."; \
	cast send $(CONTRACT_ADDRESS) "setKmsAppId(uint256)" $(KMS_APP_ID) \
		--rpc-url $(RPC_URL) \
		--private-key $(PRIVATE_KEY)
