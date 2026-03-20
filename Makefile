.PHONY: build test vet fmt check clean

build:
	go build -o teep ./cmd/teep

test:
	go test -race ./cmd/... ./internal/...

vet:
	go vet ./cmd/... ./internal/...

fmt:
	@test -z "$$(gofmt -l cmd/ internal/)" || { gofmt -l cmd/ internal/; exit 1; }

check: fmt vet test

clean:
	rm -f teep
