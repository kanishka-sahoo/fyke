.PHONY: generate ui test build lint

ui:
	cd frontend && npm ci && npm run build

test:
	go test ./...

build:
	go build -trimpath -ldflags="-s -w" -o fyke ./cmd/fyke

lint:
	go vet ./...

generate:
	go generate ./...
