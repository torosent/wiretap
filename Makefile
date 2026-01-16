# Wiretap - Network Packet Analyzer
# Makefile for building, testing, and releasing

BINARY_NAME=wiretap
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS=-ldflags "-X github.com/wiretap/wiretap/internal/cli.Version=$(VERSION) \
                  -X github.com/wiretap/wiretap/internal/cli.Commit=$(COMMIT) \
                  -X github.com/wiretap/wiretap/internal/cli.BuildTime=$(BUILD_TIME)"

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt

# Directories
CMD_DIR=./cmd/wiretap
BUILD_DIR=./build
COVERAGE_DIR=./coverage

.PHONY: all build build-linux build-darwin build-windows clean test test-coverage \
        test-verbose lint fmt deps tidy install uninstall release help

## Default target
all: deps test build

## Build the binary for current platform
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)"

## Build for Linux (amd64)
build-linux:
	@echo "Building for Linux (amd64)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)

## Build for Linux (arm64)
build-linux-arm64:
	@echo "Building for Linux (arm64)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)

## Build for macOS (amd64)
build-darwin:
	@echo "Building for macOS (amd64)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)

## Build for macOS (arm64)
build-darwin-arm64:
	@echo "Building for macOS (arm64)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)

## Build for Windows (amd64)
build-windows:
	@echo "Building for Windows (amd64)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)

## Build all platforms
build-all: build-linux build-linux-arm64 build-darwin build-darwin-arm64 build-windows
	@echo "All platforms built successfully"

## Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -race ./...

## Run tests with verbose output
test-verbose:
	@echo "Running tests (verbose)..."
	$(GOTEST) -race -v ./...

## Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@echo "Coverage report: $(COVERAGE_DIR)/coverage.html"

## Run benchmarks
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

## Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) -s -w .

## Check code formatting
fmt-check:
	@echo "Checking code formatting..."
	@test -z "$$($(GOFMT) -s -l . | tee /dev/stderr)" || (echo "Code is not formatted" && exit 1)

## Run linter
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

## Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download

## Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	$(GOMOD) tidy

## Install binary to GOPATH/bin
install: build
	@echo "Installing $(BINARY_NAME)..."
	cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/$(BINARY_NAME)
	@echo "Installed to $(GOPATH)/bin/$(BINARY_NAME)"

## Uninstall binary from GOPATH/bin
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	rm -f $(GOPATH)/bin/$(BINARY_NAME)

## Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -rf $(COVERAGE_DIR)
	$(GOCMD) clean

## Create release with goreleaser (requires goreleaser installed)
release:
	@echo "Creating release..."
	goreleaser release --clean

## Create snapshot release (no publishing)
release-snapshot:
	@echo "Creating snapshot release..."
	goreleaser release --snapshot --clean

## Show version info
version:
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"

## Set capabilities on Linux (requires sudo)
set-caps:
	@echo "Setting capabilities for packet capture..."
	sudo setcap cap_net_raw,cap_net_admin+ep $(BUILD_DIR)/$(BINARY_NAME)

## Help
help:
	@echo "Wiretap - Network Packet Analyzer"
	@echo ""
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' Makefile | sed 's/## /  /'
	@echo ""
	@echo "Examples:"
	@echo "  make build          # Build for current platform"
	@echo "  make test           # Run all tests"
	@echo "  make test-coverage  # Run tests with coverage report"
	@echo "  make build-all      # Build for all platforms"
