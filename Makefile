# Binary name the API serves and the installer installs (kept for existing
# installs). VERSION comes from git unless given: make build VERSION=1.2.3
BINARY=infrapilot-agent
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Release build: the flags and the digest-pinned Go toolchain of the official
# agent build. `make release-docker` reproduces the binaries listed in
# https://api.getopservo.com/download/manifest.json byte for byte, from a
# checkout of the commit that production was built from.
#   - version string = hash of the agent source (*.go + go.mod + go.sum)
#   - -trimpath, -buildvcs=false, CGO off, stripped (-s -w)
#   - GO_IMAGE moves together with the official build's Go image
GO_IMAGE=golang@sha256:9ce231b28998b32e116927c61aa5c406183061d4f3f2d61b292c88e7f6bdf7ca
SRC_VERSION=$(shell find . -type f \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' \) | sort | xargs cat | sha256sum | cut -c1-12)
RELEASE_FLAGS=-trimpath -buildvcs=false -ldflags="-s -w -X main.version=src-$(SRC_VERSION)"

.PHONY: build build-all release release-docker run test clean lint

build:
	go build -ldflags="-X main.version=$(VERSION)" -o bin/$(BINARY) .

# Cross-compile for all Linux targets (-s -w strips symbols for a smaller binary)
build-all:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/$(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/$(BINARY)-linux-arm64 .

# Reproducible release build with the local toolchain. Matches production
# only when `go version` equals GO_IMAGE's Go version.
release:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(RELEASE_FLAGS) -o bin/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(RELEASE_FLAGS) -o bin/$(BINARY)-linux-arm64 .
	@echo "version: src-$(SRC_VERSION)"
	@cd bin && sha256sum $(BINARY)-linux-amd64 $(BINARY)-linux-arm64

# Same, inside the pinned production toolchain image (use this to verify).
release-docker:
	docker run --rm --user "$(shell id -u):$(shell id -g)" -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath \
	  -v "$(CURDIR)":/src -w /src -e CGO_ENABLED=0 $(GO_IMAGE) \
	  sh -c 'GOOS=linux GOARCH=amd64 go build $(RELEASE_FLAGS) -o bin/$(BINARY)-linux-amd64 . && \
	         GOOS=linux GOARCH=arm64 go build $(RELEASE_FLAGS) -o bin/$(BINARY)-linux-arm64 . && \
	         go version && cd bin && sha256sum $(BINARY)-linux-amd64 $(BINARY)-linux-arm64'
	@echo "version: src-$(SRC_VERSION)"

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
