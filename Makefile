.PHONY: help build test integration integration-venice integration-near vet fmt lint check clean reports report-venice report-near

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-22s %s\n", $$1, $$2}'

build: ## Build the teep binary
	go build -o teep ./cmd/teep

test: ## Run unit tests with race detector (-short skips integration)
	go test -short -race ./cmd/... ./internal/...

integration: integration-venice integration-near ## Run all integration tests

integration-venice: ## Run Venice integration tests (requires VENICE_API_KEY)
	go test -v -race -timeout 120s -run TestIntegration_Venice ./internal/proxy/

integration-near: ## Run NEAR AI integration tests (requires NEARAI_API_KEY)
	go test -v -race -timeout 120s -run TestIntegration_NearAI ./internal/proxy/

vet: ## Run go vet
	go vet ./cmd/... ./internal/...

fmt: ## Check gofmt formatting
	@test -z "$$(gofmt -l cmd/ internal/)" || { gofmt -l cmd/ internal/; exit 1; }

lint: ## Run golangci-lint (strict config)
	golangci-lint run ./cmd/... ./internal/...

check: fmt vet lint test ## Run fmt + vet + lint + test

reports: report-venice report-near ## Run all attestation reports

report-venice: build ## Verify Venice attestation (requires VENICE_API_KEY)
	./teep verify --provider venice --model e2ee-qwen3-5-122b-a10b --log-level debug --save-dir /tmp/teep-attestation-venice

report-near: build ## Verify NEAR AI attestation (requires NEARAI_API_KEY)
	./teep verify --provider nearai --model Qwen/Qwen3.5-122B-A10B --log-level debug --save-dir /tmp/teep-attestation-nearai

clean: ## Remove built binary
	rm -f teep
