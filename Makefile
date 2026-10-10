BINARY=infrapilot-agent
VERSION=0.1.0

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
