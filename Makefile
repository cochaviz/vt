VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG     := github.com/cochaviz/vt/internal/cli
LDFLAGS := -s -w -X $(PKG).version=$(VERSION) -X $(PKG).commit=$(COMMIT) -X $(PKG).date=$(DATE)

.PHONY: build install test vet

build:
	go build -ldflags "$(LDFLAGS)" -o bin/vt ./cmd/vt

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/vt

test:
	go test ./...

vet:
	go vet ./...
