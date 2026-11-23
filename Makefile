BINARY := bin/kube-hygiene
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test lint fmt clean

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) ./cmd/kube-hygiene

test:
	go test -race ./...

lint:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "run make fmt" && exit 1)

fmt:
	gofmt -w .

clean:
	rm -rf bin dist
