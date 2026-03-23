.PHONY: help build test integration integration-venice integration-near integration-nearcloud integration-nearai-fixture integration-venice-fixture capture-nearai capture-venice vet fmt lint check clean reports report-venice report-near report-nearcloud e2e-venice

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-22s %s\n", $$1, $$2}'

build: ## Build the teep binary
	go build -o teep ./cmd/teep

test: ## Run unit tests with race detector (-short skips integration)
	go test -short -race ./cmd/... ./internal/...

integration: integration-venice integration-near integration-nearcloud integration-nearai-fixture integration-venice-fixture ## Run all integration tests

integration-venice: ## Run Venice integration tests (requires VENICE_API_KEY)
	go test -v -race -timeout 120s -run TestIntegration_Venice ./internal/proxy/

integration-near: ## Run NEAR AI integration tests (requires NEARAI_API_KEY)
	go test -v -race -timeout 120s -run TestIntegration_NearAI ./internal/proxy/

integration-nearcloud: ## Run NearCloud gateway integration tests (requires NEARAI_API_KEY)
	go test -v -race -timeout 180s -run TestIntegration_NearCloud ./internal/proxy/

integration-nearai-fixture: ## Run NEAR AI fixture integration test (no API key needed)
	go test -v -race -timeout 60s -run TestIntegration_NearAI_Fixture ./internal/integration/

integration-venice-fixture: ## Run Venice fixture integration test (no API key needed)
	go test -v -race -timeout 60s -run TestIntegration_Venice_Fixture ./internal/integration/

capture-nearai: ## Capture NEAR AI fixtures (requires NEARAI_API_KEY)
	go run ./cmd/capture_nearai

capture-venice: ## Capture Venice fixtures (requires VENICE_API_KEY)
	go run ./cmd/capture_venice

vet: ## Run go vet
	go vet ./cmd/... ./internal/...

fmt: ## Check gofmt formatting
	@test -z "$$(gofmt -l cmd/ internal/)" || { gofmt -l cmd/ internal/; exit 1; }

lint: ## Run golangci-lint (strict config)
	golangci-lint run ./cmd/... ./internal/...

check: fmt vet lint test ## Run fmt + vet + lint + test

reports: report-venice report-near report-nearcloud ## Run all attestation reports

report-venice: build ## Verify Venice attestation (requires VENICE_API_KEY)
	./teep verify venice --model e2ee-qwen3-5-122b-a10b --log-level debug --save-dir /tmp/teep-attestation-venice

report-near: build ## Verify NEAR AI attestation (requires NEARAI_API_KEY)
	./teep verify nearai --model Qwen/Qwen3.5-122B-A10B --log-level debug --save-dir /tmp/teep-attestation-nearai

report-nearcloud: build ## Verify NearCloud gateway attestation (requires NEARAI_API_KEY)
	./teep verify nearcloud --model Qwen/Qwen3.5-122B-A10B --log-level debug --save-dir /tmp/teep-attestation-nearcloud

e2e-venice: ## Run Venice E2E test (requires VENICE_API_KEY)
	./test/e2e-venice.sh

clean: ## Remove built binary
	rm -f teep
