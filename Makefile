# OpenNGFW build entrypoints. CI runs exactly these targets; keep them
# the single source of truth for how the project is built and checked.

MODULE      := github.com/detailtech/oss-ngfw
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -X $(MODULE)/internal/version.Version=$(VERSION) \
               -X $(MODULE)/internal/version.Commit=$(COMMIT) \
               -X $(MODULE)/internal/version.BuildDate=$(BUILD_DATE)

BIN_DIR     := bin
TOOLS_DIR   := $(BIN_DIR)/tools

# Pinned codegen tool versions. Bump deliberately; regenerated output is
# committed, so CI verifies `make proto` produces no diff.
BUF_VERSION                 := v1.50.1
PROTOC_GEN_GO_VERSION       := v1.36.11
PROTOC_GEN_GO_GRPC_VERSION  := v1.5.1
PROTOC_GEN_GW_VERSION       := v2.27.7

.PHONY: all build test lint proto proto-verify tools clean integration-test

all: build test lint

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/ ./cmd/...

test:
	go test -race ./...

# Real-engine tests: nftables + network namespaces + live traffic.
# Requires root, nft, ip, nc (skips itself otherwise).
integration-test:
	go test -tags integration -count=1 -v ./test/integration/

lint:
	golangci-lint run ./...
	go vet ./...

tools:
	GOBIN=$(abspath $(TOOLS_DIR)) go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	GOBIN=$(abspath $(TOOLS_DIR)) go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)
	GOBIN=$(abspath $(TOOLS_DIR)) go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@$(PROTOC_GEN_GW_VERSION)
	GOBIN=$(abspath $(TOOLS_DIR)) go install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)

proto: tools
	PATH=$(abspath $(TOOLS_DIR)):$$PATH $(TOOLS_DIR)/buf lint
	PATH=$(abspath $(TOOLS_DIR)):$$PATH $(TOOLS_DIR)/buf generate

# Fails if committed generated code is stale relative to the .proto sources.
proto-verify: proto
	git diff --exit-code -- api/gen

clean:
	rm -rf $(BIN_DIR)
