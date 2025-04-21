# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGENERATE=$(GOCMD) generate
GOMOD=$(GOCMD) mod
PROTOC=protoc

# Proto parameters (adjust paths if necessary)
PROTO_DIR=api/v2
PROTO_FILES=$(PROTO_DIR)/api.proto
GO_OUT_DIR=. # Output Go files relative to project root

# Target definitions
# Declare targets that don't correspond to files as .PHONY
.PHONY: all clean generate generate-ent generate-proto test tidy build help

all: build ## Build the application (default if help wasn't default)

clean: ## Clean Go build cache and module download cache
	@echo "Cleaning Go build cache..."
	$(GOCLEAN) -cache
	@echo "Cleaning Go module download cache (requires re-download)..."
	$(GOCLEAN) -modcache
	@echo "Clean finished."

generate: generate-ent generate-proto ## Run all code generation (Ent and Protobuf)
	@echo "All code generation finished."

generate-ent: ## Generate Ent database code (runs from within storage/ent)
	@echo "Generating Ent code..."
	cd storage/ent && $(GOGENERATE) ./...
	@echo "Ent generation finished."

generate-proto: ## Generate Go code from Protobuf definitions
	@echo "Generating Protobuf Go code (outputting to $(GO_OUT_DIR))..."
	# Ensure protoc, protoc-gen-go, and protoc-gen-go-grpc are installed and in PATH
	$(PROTOC) --go_out=$(GO_OUT_DIR) --go_opt=paths=source_relative \
	    --go-grpc_out=$(GO_OUT_DIR) --go-grpc_opt=paths=source_relative \
	    $(PROTO_FILES)
	@echo "Protobuf generation finished."

test: ## Run all tests verbosely
	@echo "Running tests..."
	# Runs tests recursively from the project root
	$(GOTEST) -v ./...
	@echo "Tests finished."

tidy: ## Tidy Go module dependencies
	@echo "Tidying modules..."
	$(GOMOD) tidy
	@echo "Tidy finished."

build: ## Build all packages
	@echo "Building..."
	$(GOBUILD) ./...
	@echo "Build finished."

help: ## Display help message for common targets
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Default goal - run 'make' without args will show help
.DEFAULT_GOAL := help