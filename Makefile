.PHONY: all proto build build-agent build-server test clean lint run-server run-agent

GO ?= go
PROTOC ?= protoc
PROTO_DIR = api/proto
GEN_DIR = api/gen

all: proto build

proto:
	@mkdir -p $(GEN_DIR)
	$(PROTOC) --go_out=$(GEN_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(GEN_DIR) --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/vulnscan/v1/agent.proto

build-agent:
	$(GO) build -o bin/agent ./cmd/agent

build-server:
	$(GO) build -o bin/server ./cmd/server

build: build-agent build-server

build-all-platforms:
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags="-s -w" -o agents/linux-amd64 ./cmd/agent
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags="-s -w" -o agents/linux-arm64 ./cmd/agent
	GOOS=windows GOARCH=amd64 $(GO) build -ldflags="-s -w" -o agents/windows-amd64.exe ./cmd/agent
	GOOS=windows GOARCH=arm64 $(GO) build -ldflags="-s -w" -o agents/windows-arm64.exe ./cmd/agent
	$(GO) build -ldflags="-s -w" -o bin/server ./cmd/server

test:
	$(GO) test -v -race ./...

test-cover:
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/ agents/* coverage.out coverage.html

run-server:
	$(GO) run ./cmd/server

run-agent:
	$(GO) run ./cmd/agent run

migrate-up:
	$(GO) run ./cmd/server migrate up

migrate-down:
	$(GO) run ./cmd/server migrate down

fmt:
	$(GO) fmt ./...

mod:
	$(GO) mod tidy
	$(GO) mod verify
