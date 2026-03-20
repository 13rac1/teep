.PHONY: build test integration vet fmt lint check clean reports report-venice report-near

build:
	go build -o teep ./cmd/teep

test:
	go test -short -race ./cmd/... ./internal/...

integration:
	go test -v -race -timeout 120s -run TestIntegration ./internal/proxy/

vet:
	go vet ./cmd/... ./internal/...

fmt:
	@test -z "$$(gofmt -l cmd/ internal/)" || { gofmt -l cmd/ internal/; exit 1; }

lint:
	golangci-lint run ./cmd/... ./internal/...

check: fmt vet lint test

reports: report-venice report-near

report-venice: build
	./teep verify --provider venice --model e2ee-qwen3-5-122b-a10b --log-level debug --save-dir /tmp/teep-attestation-venice

report-near: build
	./teep verify --provider nearai --model qwen2.5-72b-instruct --log-level debug --save-dir /tmp/teep-attestation-nearai

clean:
	rm -f teep
