.PHONY: help build build-debug self-check test integration integration-venice integration-neardirect integration-nearcloud integration-nanogpt integration-phalacloud integration-chutes integration-neardirect-fixture integration-venice-fixture capture-neardirect capture-venice vet teeplint lint check clean reports report-venice report-neardirect report-nearcloud report-nanogpt report-phalacloud report-chutes e2e-venice

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
LDFLAGS  = -X main.Version=$(VERSION) -X main.Commit=$(COMMIT)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-22s %s\n", $$1, $$2}'

build: ## Build the teep binary
	go build -ldflags "$(LDFLAGS)" -trimpath -o teep ./cmd/teep

build-debug: ## Build with debug tag (enables --force flag for serve)
	go build -tags debug -ldflags "$(LDFLAGS)" -trimpath -o teep ./cmd/teep

self-check: build ## Build and run self-check
	./teep self-check

test: ## Run unit tests with race detector (-short skips integration)
	go test -short -race ./cmd/... ./internal/...

integration: integration-venice integration-neardirect integration-nearcloud integration-nanogpt integration-phalacloud integration-chutes integration-neardirect-fixture integration-venice-fixture ## Run all integration tests

integration-venice: ## Run Venice integration tests (requires VENICE_API_KEY)
	go test -v -race -timeout 120s -run TestIntegration_Venice ./internal/proxy/

integration-neardirect: ## Run NEAR Direct integration tests (requires NEARAI_API_KEY)
	go test -v -race -timeout 120s -run TestIntegration_NearDirect ./internal/proxy/

integration-nearcloud: ## Run NearCloud gateway integration tests (requires NEARAI_API_KEY)
	go test -v -race -timeout 180s -run TestIntegration_NearCloud ./internal/proxy/

integration-nanogpt: ## Run NanoGPT integration tests (requires NANOGPT_API_KEY)
	go test -v -race -timeout 120s -run TestIntegration_NanoGPT ./internal/proxy/

integration-phalacloud: ## Run Phala Cloud integration tests (requires PHALA_API_KEY)
	go test -v -race -timeout 120s -run TestIntegration_PhalaCloud ./internal/proxy/

integration-chutes: ## Run Chutes integration tests (requires CHUTES_API_KEY)
	go test -v -race -timeout 120s -run TestIntegration_Chutes ./internal/proxy/

integration-neardirect-fixture: ## Run NEAR Direct fixture integration test (no API key needed)
	go test -v -race -timeout 60s -run TestIntegration_NearDirect_Fixture ./internal/integration/

integration-venice-fixture: ## Run Venice fixture integration test (no API key needed)
	go test -v -race -timeout 60s -run TestIntegration_Venice_Fixture ./internal/integration/

capture-neardirect: ## Capture NEAR Direct fixtures (requires NEARAI_API_KEY)
	go run ./cmd/capture_neardirect

capture-venice: ## Capture Venice fixtures (requires VENICE_API_KEY)
	go run ./cmd/capture_venice

vet: ## Run go vet
	go vet ./cmd/... ./internal/...

teeplint: ## Run architectural linter
	go run ./cmd/teeplint

lint: vet teeplint ## Run gofmt + go vet + golangci-lint + teeplint
	@echo "gofmt check..."
	@test -z "$$(gofmt -l cmd/ internal/)" || { gofmt -l cmd/ internal/; exit 1; }
	golangci-lint run ./cmd/... ./internal/...

check: lint test ## Run lint + test

reports: report-venice report-neardirect report-nearcloud report-nanogpt report-phalacloud report-chutes ## Run all attestation reports

report-venice: build ## Verify Venice attestation (requires VENICE_API_KEY)
	./teep verify venice --model e2ee-qwen3-5-122b-a10b --log-level debug --save-dir /tmp/teep-attestation-venice

report-neardirect: build ## Verify NEAR Direct attestation (requires NEARAI_API_KEY)
	./teep verify neardirect --model Qwen/Qwen3.5-122B-A10B --log-level debug --save-dir /tmp/teep-attestation-neardirect

report-nearcloud: build ## Verify NearCloud gateway attestation (requires NEARAI_API_KEY)
	./teep verify nearcloud --model Qwen/Qwen3.5-122B-A10B --log-level debug --save-dir /tmp/teep-attestation-nearcloud

report-nanogpt: build ## Verify NanoGPT attestation (requires NANOGPT_API_KEY)
	./teep verify nanogpt --model TEE/gemma-3-27b-it --log-level debug --save-dir /tmp/teep-attestation-nanogpt

report-phalacloud: build ## Verify Phala Cloud attestation (requires PHALA_API_KEY)
	./teep verify phalacloud --model phala/deepseek-v3.2 --log-level debug --save-dir /tmp/teep-attestation-phalacloud

report-chutes: build ## Verify Chutes attestation (requires CHUTES_API_KEY)
	./teep verify chutes --model 0df3133d-c477-56d2-b4db-f2093bb150a1 --log-level debug --save-dir /tmp/teep-attestation-chutes

e2e-venice: ## Run Venice E2E test (requires VENICE_API_KEY)
	./test/e2e-venice.sh

clean: ## Remove built binary
	rm -f teep
