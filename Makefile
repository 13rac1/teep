.PHONY: build test integration vet fmt lint check clean

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

clean:
	rm -f teep
