.PHONY: generate ui ui-test test build lint check

ui:
	cd frontend && npm ci && npm run build

test:
	./scripts/go-live.test.sh
	go test ./...

ui-test:
	cd frontend && npm ci && npm test

build:
	go build -trimpath -ldflags="-s -w" -o fyke ./cmd/fyke

lint:
	go vet ./...

check: lint test
	cd frontend && npm ci && npm test && npm run build

generate:
	go generate ./...
