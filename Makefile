# semiplane — build, generate, test.
#
# Every generated artefact (internal/web/*_templ.go, web/static/app.css) is
# committed, so a plain `go build` needs nothing but the Go toolchain and the
# module cache. `make check` reproduces exactly what CI runs.

SHELL := /bin/bash
.DEFAULT_GOAL := help

GO      ?= go
DIST    ?= dist
TOOLS   := .tools
BIN     := $(DIST)/semiplane
PKG     := github.com/PopinjayJohn/vtt-semiplane
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(PKG)/internal/app.Version=$(VERSION) \
	-X $(PKG)/internal/app.Commit=$(COMMIT) \
	-X $(PKG)/internal/app.Date=$(DATE)

# shellcheck disable=SC1091
include tools/versions.env
TOOL_TAILWIND := $(TOOLS)/tailwindcss

# Targets in .PHONY are the contract; every one must be runnable on a clean
# checkout with only `make setup` behind it.
.PHONY: help
help: ## show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: ## download modules, install pinned tools, generate templ code
	$(GO) mod download
	@$(MAKE) --no-print-directory tools
	@$(MAKE) --no-print-directory generate

.PHONY: tools
tools: $(TOOL_TAILWIND) ## install pinned external tools into .tools/

$(TOOL_TAILWIND):
	@mkdir -p $(TOOLS)
	@echo "==> tailwindcss $(TAILWIND_VERSION)"
	@curl -fsSL -o $(TOOLS)/tailwindcss \
		"https://github.com/tailwindlabs/tailwindcss/releases/download/v$(TAILWIND_VERSION)/tailwindcss-linux-x64" \
		|| curl -fsSL -o $(TOOLS)/tailwindcss \
		"https://github.com/tailwindlabs/tailwindcss/releases/download/v$(TAILWIND_VERSION)/tailwindcss-linux-arm64"
	@chmod +x $(TOOLS)/tailwindcss

.PHONY: generate
generate: ## regenerate templ components (writes *_templ.go)
	$(GO) tool templ generate ./...

.PHONY: css
css: $(TOOL_TAILWIND) ## rebuild the committed stylesheet
	$(TOOL_TAILWIND) -i web/src/input.css -o web/static/app.css --minify

.PHONY: assets
assets: ## refresh the vendored datastar bundle (pinned in tools/versions.env)
	@echo "==> datastar $(DATASTAR_VERSION) is vendored at web/static/vendor/datastar.js"
	@echo "    Refreshing requires network access; verify the file matches upstream $(DATASTAR_VERSION)."

.PHONY: build
build: generate css ## build the standalone binary
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/semiplane

.PHONY: build-fast
build-fast: ## build without regenerating assets (inner loop)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/semiplane

.PHONY: run
run: build-fast ## run the server against ./vault
	$(BIN) --vault ./vault

.PHONY: dev
dev: build-fast ## run in development mode
	$(BIN) --vault ./vault --dev

# All test targets go through scripts/test.sh. A bare `go test ./...` links and
# runs one test binary per package, up to NumCPU at a time, and every package
# that pulls in modernc.org/sqlite links a very large pure-Go libc. That
# exhausted RAM and swap on a 23 GiB machine. The runner pins -p 1, bounds
# subtest parallelism, sets a heap ceiling and puts a timeout on every test so a
# spin panics with a stack trace instead of hanging until something else dies.
.PHONY: test
test: ## run the unit tests, memory-bounded
	./scripts/test.sh

.PHONY: test-race
test-race: ## run the tests under the race detector, memory-bounded
	./scripts/test.sh -race

.PHONY: test-integration
test-integration: ## run the integration-tagged tests
	./scripts/test.sh -tags=integration

.PHONY: test-one
test-one: ## run one package or test through the bounded runner: make test-one PKG=./internal/md/ [-run NAME]
	./scripts/test.sh $(PKG) $(ARGS)

.PHONY: cover
cover: ## run the tests and report coverage
	./scripts/test.sh -coverprofile=coverage.out
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: fuzz
fuzz: ## run the markdown and search fuzz targets for 30s each
	./scripts/test.sh ./internal/md/ -fuzz=FuzzNeverCorrupt -fuzztime=30s
	./scripts/test.sh ./internal/search/ -fuzz=FuzzBuildMatchQuery -fuzztime=30s

.PHONY: lint
lint: ## run golangci-lint
	golangci-lint run

.PHONY: fmt
fmt: ## format the tree
	gofmt -w .
	$(GO) tool templ fmt .

.PHONY: check
check: fmt-check generate-check css-check lint test ## the CI gate, locally
	@echo "==> check: green"

.PHONY: fmt-check
fmt-check: ## fail if anything is unformatted
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi
	@# templ v0.3.1020 spells this -fail, not -check. The old spelling made every
	@# invocation print a usage error to stderr, which the shell test below then
	# saw as output and reported as ten unformatted files — so the gate was not
	# merely misnamed, it was red on a clean tree and nobody could tell why.
	@$(GO) tool templ fmt -fail .

.PHONY: generate-check
generate-check: generate ## fail if generated code is stale
	@git diff --exit-code -- 'internal/**/*_templ.go' || \
		(echo "generated templ code is stale: run 'make generate' and commit"; exit 1)

.PHONY: css-check
css-check: css ## fail if the committed stylesheet is stale
	@git diff --exit-code -- web/static/app.css || \
		(echo "web/static/app.css is stale: run 'make css' and commit"; exit 1)

.PHONY: cross
cross: ## build release binaries for every supported platform
	@mkdir -p $(DIST)
	@for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
		os=$${target%/*}; arch=$${target#*/}; ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "==> $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath \
			-ldflags '$(LDFLAGS)' -o $(DIST)/semiplane_$${os}_$${arch}$$ext ./cmd/semiplane || exit 1; \
	done

.PHONY: snapshot
snapshot: build-fast ## full reindex into .semiplane-test/ for manual QA
	$(BIN) reindex --full --vault .semiplane-test

.PHONY: clean
clean: ## remove build output and test artefacts
	rm -rf $(DIST) coverage.out .semiplane-test
