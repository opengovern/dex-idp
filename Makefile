# -----------------------------------------------------------------------------
#  Go toolchain & project settings
# -----------------------------------------------------------------------------
GOCMD            := go
GOBUILD          := $(GOCMD) build
GOCLEAN          := $(GOCMD) clean
GOTEST           := $(GOCMD) test
GOGENERATE       := $(GOCMD) generate
GOMOD            := $(GOCMD) mod
PROTOC           := protoc

VERSION         ?= $(shell ./scripts/git-version)
BINARY_NAME      := dex
CMD_PATH         := ./cmd/dex
DOCKER_ENTRY     := ./cmd/docker-entrypoint
OUTPUT_DIR       := ./bin

# -----------------------------------------------------------------------------
#  Detect OS: only on Linux do we ask for a fully static link
# -----------------------------------------------------------------------------
OS               := $(shell uname | tr A-Z a-z)
ifeq ($(OS),linux)
  EXT_STATIC     := -extldflags "-static"
else
  EXT_STATIC     :=
endif

# -----------------------------------------------------------------------------
#  Phony targets
# -----------------------------------------------------------------------------
.PHONY: all clean generate generate-ent generate-proto test tidy build release-binary help

all: build release-binary

# -----------------------------------------------------------------------------
clean: ## wipe out go caches + bin/
	@echo "Cleaning build + module cache…"
	$(GOCLEAN) -cache
	$(GOCLEAN) -modcache
	rm -rf $(OUTPUT_DIR)
	@echo "Clean done."

# -----------------------------------------------------------------------------
generate: generate-ent generate-proto ## run all codegen
	@echo "✨  Codegen complete."

generate-ent: ## ent ORM
	@echo "Generating ent…"
	cd storage/ent && $(GOGENERATE) ./...
	@echo "Done."

generate-proto: ## protobuf → Go
	@echo "Generating protobuf…"
	$(PROTOC) -I./api/v2 -I. \
	  --go_out=. --go_opt=paths=source_relative \
	  --go-grpc_out=. --go-grpc_opt=paths=source_relative \
	  api/v2/api.proto
	@echo "Done."

# -----------------------------------------------------------------------------
test: ## run go tests
	@echo "Running tests…"
	$(GOTEST) -v ./...
	@echo "Tests passed."

tidy: ## go mod tidy
	@echo "Tidying modules…"
	$(GOMOD) tidy
	@echo "Tidy done."

# -----------------------------------------------------------------------------
build: ## dev build of dex (dynamic)
	@echo "Building dev binary…"
	mkdir -p $(OUTPUT_DIR)
	$(GOBUILD) -o $(OUTPUT_DIR)/$(BINARY_NAME) $(CMD_PATH)
	@echo "→ $(OUTPUT_DIR)/$(BINARY_NAME)"

# -----------------------------------------------------------------------------
release-binary: ## static (on Linux) release builds
	@echo "Recreating $(OUTPUT_DIR) for release builds…"
	rm -rf $(OUTPUT_DIR)
	mkdir -p $(OUTPUT_DIR)
	@echo "→ dex"
	$(GOBUILD) \
	  -ldflags "-w -X main.version=$(VERSION) $(EXT_STATIC)" \
	  -o $(OUTPUT_DIR)/dex $(CMD_PATH)
	@echo "→ docker-entrypoint"
	$(GOBUILD) \
	  -ldflags "-w -X main.version=$(VERSION) $(EXT_STATIC)" \
	  -o $(OUTPUT_DIR)/docker-entrypoint $(DOCKER_ENTRY)
	@echo "Done. Release binaries:"
	@printf "  - %s/dex\n  - %s/docker-entrypoint\n" $(OUTPUT_DIR) $(OUTPUT_DIR)

# -----------------------------------------------------------------------------
help: ## show this help
	@echo "Usage: make [target]"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | sort \
	  | awk 'BEGIN {FS = ":.*?## "}; \
	         {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
