.PHONY: build run test clean dev deps

build:
	go build -o bin/atlas-server cmd/server/main.go

run: build
	./bin/atlas-server

dev:
	air

test:
	go test -v ./...

clean:
	rm -rf bin/

deps:
	go mod download
	go mod tidy

fmt:
	go fmt ./...

lint:
	golangci-lint run

mocks:
	mockery --all --output=internal/mocks

db-up:
	@echo "Database migrations will be added in Issue #2"

db-down:
	@echo "Database migrations will be added in Issue #2"
