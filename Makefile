# Binary name the API serves and the installer installs (kept for existing
# installs). VERSION comes from git unless given: make build VERSION=1.2.3
BINARY=infrapilot-agent
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build build-all run test clean lint

build:
	go build -ldflags="-X main.version=$(VERSION)" -o bin/$(BINARY) .

# Cross-compile for all Linux targets (-s -w strips symbols for a smaller binary)
build-all:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/$(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/$(BINARY)-linux-arm64 .

run:
	go run . --dev --api-url http://localhost:3001

test:
	go test ./... -v -race

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/

tidy:
	go mod tidy
