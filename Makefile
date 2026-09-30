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

# The release artifact set. .goreleaser.yaml states the same six targets as a
# goos x goarch matrix rather than as a list, so the two files cannot literally
# share one variable — but `make targets-check` derives the matrix out of the
# YAML and compares it against this line, which is the only reason a count may
# be written down twice. It ran as a CI job on the day this was reconciled: the
# Makefile listed five and the matrix produced six, and neither file noticed.
# The plan's accept list says "5 artifacts"; that predates the matrix and
# undercounts it. Six is deliberate — windows/arm64 is the sixth, and dropping
# it to match a number would ship less for the sake of arithmetic.
TARGETS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

# The ratchet baseline. See the header of the file itself; this line only
# names it. Not named coverage-baseline.txt on purpose: `.gitignore` already
# owns the `coverage.*` family, and a gate input that a future ignore rule
# could silently swallow is a gate that can stop running without failing.
COVERAGE_PROFILE ?= coverage.out
COVERAGE_BASELINE := .coverage-baseline

# How far a package may fall before coverage-check calls it a drop, in
# percentage points.
#
# It exists because the gate's own number is quantised to one decimal place and
# a package's measured value is not reproducible to that decimal: the same tree
# measured 87.6 and 87.5 for internal/md on consecutive runs, because a test
# that is conditionally skipped or bailed changes which statements are reached.
# Comparing two 0.1-quantised numbers exactly makes a gate that fails on
# rounding, and a flaky gate is worse than no gate — a red build that means
# nothing is a build the team learns to retry rather than read.
#
# Half a point is chosen because it is larger than the noise and smaller than
# the smallest drop anyone would want to be told about: losing a function's
# tests is a whole point or several, not half of one. Raise it to silence a
# flaky gate and you have removed the gate instead of the flake.
COVERAGE_TOLERANCE ?= 0.5

# The Go toolchain the coverage numbers are recorded against, and the reason
# this variable exists at all.
#
# A coverage percentage is not a property of the tests alone: it is a property
# of the tests, the source, AND the compiler that instrumented the source, and
# the last of those is invisible in the profile. Measured on one tree, with one
# command and no source change:
#
#   package          go1.26.0   go1.27.1
#   /internal/config    94.2       94.9
#   /internal/plugin    91.7       92.4
#   /internal/vault     81.4       82.5
#   /internal/md        87.1       87.6
#   /internal/obs       77.6       77.6
#
# A baseline recorded on a 1.27 laptop and compared against a 1.26 runner
# therefore reports a two-point DROP in most packages and a four-point RAISED in
# one, and every one of those numbers is an artefact of the toolchain. That is
# what the coverage job was reporting on 10 packages before this variable
# existed, and it is a ratchet whose unit was never pinned — a gate measuring a
# proxy for the thing.
#
# So the toolchain is part of the baseline: it is recorded in the file's header,
# `coverage-check` refuses to compare across toolchains, and `cover` and
# `coverage-baseline` both run the toolchain named here. Regenerating on a
# different Go is therefore a deliberate act that changes this line, not
# something that happens by accident on whoever's machine ran it last.
COVERAGE_TOOLCHAIN ?= go1.26.6

# atomic, not the `go test` default of set. The two count the same statements
# from the same run, but `set` loses increments where a counter is shared between
# goroutines, so the two can disagree in the last decimal — and a baseline
# recorded under one and checked under the other is the same untrustworthy
# comparison as a baseline recorded under a different toolchain. Pinned here so
# that `make cover`, `make coverage-baseline` and `make coverage-check` cannot
# disagree about it, and so the numbers in .coverage-baseline say which mode
# they were taken with.
#
# atomic is also what `make test-race` already uses, so this is one convention
# in the repository rather than two.
COVERAGE_MODE ?= atomic

# Each entry is a marker that must be present in the built binary for the
# release notes' claim that the binary is self-contained to be true. These are
# the //go:embed payloads named in .goreleaser.yaml's header, all three of them.
# The campaign marker names one name that appears in the shipped campaign and
# nowhere else in the tree, so a hit cannot come from a Go string constant: the
# header once said the sample campaign was not embedded while
# internal/sample/campaign.go carried a //go:embed, and this list could not
# notice because the campaign was not in it.
# Each marker is a string that appears in exactly one of those payloads, so a
# hit proves that payload and not some other, and none of them may contain a
# character the shell reads — the list is expanded unquoted into a `for`.
EMBED_MARKERS := \
	internal/store/migrations/0001_init.sql:0001_init \
	web/static/app.css:tailwindcss\ v4.1.16 \
	web/static/icons.svg:The\ icon\ sprite.\ Drawn\ by\ hand \
	web/static/vendor/datastar.js:Datastar\ v1.0.4 \
	internal/sample/campaign:Dame\ Alis\ Rennard

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
	GOTOOLCHAIN=$(COVERAGE_TOOLCHAIN) ./scripts/test.sh -coverprofile=$(COVERAGE_PROFILE) -covermode=$(COVERAGE_MODE)
	$(GO) tool cover -func=$(COVERAGE_PROFILE) | tail -1

# The gate. It fails on a DROP and on a MISSING, names the package and both
# numbers, and stays quiet on a rise so adding tests is never blocked by a
# green build. It reads the profile, it does not produce one: CI runs the tests
# first so that "the tests failed" and "coverage fell" stay two different
# messages instead of one.
#
# It also refuses to compare a profile measured on one Go toolchain against a
# baseline recorded on another, and says which two. The reason is measured
# rather than asserted — see COVERAGE_TOOLCHAIN above for the table — and the
# alternative is a gate that reports a two-point coverage loss on a tree where
# no test was deleted, which is a number nobody can act on and therefore a
# number nobody reads.
.PHONY: coverage-check
coverage-check: ## fail if any package in the baseline lost coverage
	@test -f $(COVERAGE_PROFILE) || { echo "no $(COVERAGE_PROFILE): run 'make cover' first"; exit 1; }
	@test -f $(COVERAGE_BASELINE) || { echo "no $(COVERAGE_BASELINE)"; exit 1; }
	@recorded=`sed -n 's/^# toolchain: //p' $(COVERAGE_BASELINE)`; \
	running=`GOTOOLCHAIN=$(COVERAGE_TOOLCHAIN) $(GO) env GOVERSION`; \
	if [ -z "$$recorded" ]; then \
		echo "==> $(COVERAGE_BASELINE) records no '# toolchain:' line."; \
		echo "    Regenerate it: make cover && make coverage-baseline"; exit 1; \
	fi; \
	if [ "$$recorded" != "$$running" ]; then \
		echo "TOOLCHAIN $(COVERAGE_BASELINE) was recorded with $$recorded; this run measured $$running."; \
		echo "    A coverage percentage is a property of the compiler as well as"; \
		echo "    of the tests, so the two sets of numbers are not comparable and"; \
		echo "    a DROP here would be the toolchain rather than a lost test."; \
		echo "    Measure both with the same toolchain: make cover COVERAGE_TOOLCHAIN=$$recorded"; \
		exit 1; \
	fi
	@awk -v BASELINE=$(COVERAGE_BASELINE) -v TOL=$(COVERAGE_TOLERANCE) '\
	  FNR==NR { \
	    if (NF >= 2 && $$1 !~ /^#/) { \
	      if ($$1 in base) dup = dup " " $$1; \
	      base[$$1] = $$2 + 0; order[++nb] = $$1 \
	    } \
	    next \
	  } \
	  $$1 == "mode:" { next } \
	  NF >= 3 { \
	    f = $$1; \
	    sub(/:[0-9]+\.[0-9]+,[0-9]+\.[0-9]+$$/, "", f); \
	    sub(/\/[^/]*$$/, "", f); \
	    sub(/^github\.com\/PopinjayJohn\/vtt-semiplane/, "", f); \
	    if (f == "") f = "."; \
	    s = $$(NF-1); c = $$NF; \
	    tot[f] += s; if (c > 0) cov[f] += s; seen[f] = 1 \
	  } \
	  END { \
	    fails = 0; \
	    if (dup != "") { \
	      printf "MALFORMED %s lists%s more than once. A regenerated baseline must replace the value rows, not append to them.\n", BASELINE, dup; \
	      fails++ \
	    } \
	    for (i = 1; i <= nb; i++) { \
	      p = order[i]; \
	      if (!(p in seen)) { \
	        printf "MISSING   %s: recorded, not measured. The package was deleted or its tests stopped running; drop the row if that was deliberate.\n", p; \
	        fails++; continue \
	      } \
	    cur = sprintf("%.1f", 100 * cov[p] / tot[p]) + 0; \
	    if (cur + TOL < base[p]) { \
	      printf "DROP      %s: %.1f%% now, %.1f%% recorded in %s (tolerance %.1f)\n", p, cur, base[p], BASELINE, TOL; \
	      fails++; continue \
	    } \
	    if (cur > base[p] + TOL) printf "RAISED    %s: %.1f%% now, %.1f%% recorded - run \"make coverage-baseline\" and commit it\n", p, cur, base[p] \
	    } \
	    for (p in seen) if (!(p in base)) printf "UNTRACKED %s: %.1f%% and not in %s\n", p, 100 * cov[p] / tot[p], BASELINE; \
	    if (fails) { printf "\n%d problem(s) against %s\n", fails, BASELINE; exit fails } \
	  }' $(COVERAGE_BASELINE) $(COVERAGE_PROFILE)
	@echo "==> coverage: no tracked package lost coverage"

# Rewrites the value rows and keeps the leading comment block. The earlier
# version kept the whole old file as the "header", so regenerating twice
# appended the value rows a second time — and because a duplicated key reads
# as the last one written, the gate then compared against a stale number and
# passed. coverage-check now rejects a duplicated key for exactly that reason.
.PHONY: coverage-baseline
coverage-baseline: ## rewrite the coverage ratchet from the current profile
	@test -f $(COVERAGE_PROFILE) || { echo "no $(COVERAGE_PROFILE): run 'make cover' first"; exit 1; }
	@awk '\
	  $$1 == "mode:" { next } \
	  NF >= 3 { \
	    f = $$1; \
	    sub(/:[0-9]+\.[0-9]+,[0-9]+\.[0-9]+$$/, "", f); \
	    sub(/\/[^/]*$$/, "", f); \
	    sub(/^github\.com\/PopinjayJohn\/vtt-semiplane/, "", f); \
	    if (f == "") f = "."; \
	    s = $$(NF-1); c = $$NF; \
	    tot[f] += s; if (c > 0) cov[f] += s \
	  } \
	  END { for (f in tot) if (tot[f] > 0) printf "%s %.1f\n", f, 100 * cov[f] / tot[f] }' \
	  $(COVERAGE_PROFILE) | sort > $(COVERAGE_BASELINE).new
	@# The old `# toolchain:` line is dropped rather than kept: a header that
	@# carried a stale one would let a baseline recorded on one Go be read as
	@# if it had been measured on another, which is the exact failure this line
	@# exists to make visible. Everything else in the comment block is prose and
	@# is preserved.
	@if [ -f $(COVERAGE_BASELINE) ]; then \
	  sed -n '/^#/!q;p' $(COVERAGE_BASELINE) | grep -v '^# toolchain: ' > $(COVERAGE_BASELINE).hdr; \
	else : > $(COVERAGE_BASELINE).hdr; fi
	@cat $(COVERAGE_BASELINE).hdr $(COVERAGE_BASELINE).new > $(COVERAGE_BASELINE)
	@rm -f $(COVERAGE_BASELINE).hdr $(COVERAGE_BASELINE).new
	@awk 'NR>1 && $$1 !~ /^#/ && NF>=2 { if (seen[$$1]++) dup = dup " " $$1 } END { if (dup != "") { print "still duplicated:" dup; exit 1 } }' $(COVERAGE_BASELINE)
	@printf '# toolchain: %s\n' "`GOTOOLCHAIN=$(COVERAGE_TOOLCHAIN) $(GO) env GOVERSION`" >> $(COVERAGE_BASELINE)
	@echo "==> rewrote $(COVERAGE_BASELINE) against `GOTOOLCHAIN=$(COVERAGE_TOOLCHAIN) $(GO) env GOVERSION`: git diff it and commit the numbers"

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
check: fmt-check generate-check css-check lint targets-check test ## the CI gate, locally
	@echo "==> check: green"

.PHONY: fmt-check
fmt-check: ## fail if anything is unformatted
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi
	@# templ v0.3.1020 spells this -fail, not -check. Verified against
	@# `go tool templ fmt --help`, which lists -fail and no -check; -check
	@# exits 2 with "flag provided but not defined" before it formats
	@# anything, so the gate was red on a clean tree rather than merely
	@# misnamed. ci.yml ran the -check spelling and is now aligned to this one.
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
	@for target in $(TARGETS); do \
		os=$${target%/*}; arch=$${target#*/}; ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "==> $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath \
			-ldflags '$(LDFLAGS)' -o $(DIST)/semiplane_$${os}_$${arch}$$ext ./cmd/semiplane || exit 1; \
	done

# The Makefile and .goreleaser.yaml both state the artifact set, in two
# different shapes, so the gate derives one from the other rather than asking a
# reader to diff them. A goos x goarch matrix with goarm: [] and no surviving
# ignore entry is a plain product; this reduces the YAML to that product with
# sed, deliberately not a YAML parser, because a build dependency on a Python
# YAML module would be a worse trade than a substitution that has to keep
# matching the shape of a six-line block.
.PHONY: targets-check
targets-check: ## fail if the Makefile's TARGETS and .goreleaser.yaml disagree
	@os=$$(sed -n '/^    goos:/,/^    goarch:/p' .goreleaser.yaml | grep -E '^\s+- ' | sed 's/^[[:space:]]*- //'); \
	arch=$$(sed -n '/^    goarch:/,/^    goarm:/p' .goreleaser.yaml | grep -E '^\s+- ' | sed 's/^[[:space:]]*- //'); \
	product=$$(for a in $$arch; do for o in $$os; do echo "$$o/$$a"; done; done | sort | tr '\n' ' '); \
	listed=$$(for t in $(TARGETS); do echo "$$t"; done | sort | tr '\n' ' '); \
	if [ "$$product" = "$$listed" ]; then \
		echo "==> targets: $(words $(TARGETS)) in both ($(TARGETS))"; \
	else \
		echo "targets disagree."; \
		echo "  Makefile TARGETS:      $$listed"; \
		echo "  .goreleaser.yaml:      $$product"; \
		echo "  If an ignore: entry reappears, this reduction stops being the product"; \
		echo "  and it will say so rather than quietly agreeing with one side."; \
		exit 1; \
	fi

# The number, on its own, for a caller that has to count something. Exposed
# because release.yml checks the published archive count against it: a release
# that quietly dropped a target is otherwise indistinguishable from one that
# never built it.
.PHONY: target-count
target-count:
	@echo $(words $(TARGETS))

# The list itself, for the same reason and one step further: build.yml asserts
# each built artifact against the platform it claims by reading the target out
# of this variable rather than out of a list written beside it. A check that
# enumerated the six binaries by hand would be a fourth copy of a set that has
# already been written down twice and disagreed once — and the copy is what
# goes stale, not the set.
.PHONY: targets
targets:
	@echo $(TARGETS)

# Enforces the claim in .goreleaser.yaml's header that the binary carries its
# own stylesheet, icon sprite, DataStar bundle, migration SQL and sample
# campaign. The claim was a sentence in a config file that nothing read, and it
# once said the campaign was not embedded when it was. This reads it.
.PHONY: embed-check
embed-check: build-fast ## fail if the built binary is missing an embedded asset
	@fail=0; \
	for entry in $(EMBED_MARKERS); do \
		src=$${entry%%:*}; marker=$${entry#*:}; \
		if ! grep -a -q -F -- "$$marker" "$(BIN)"; then \
			echo "MISSING   $(PKG)/$$src  is not in $(BIN) (looked for: $$marker)"; fail=1; \
		else \
			echo "embedded  $(PKG)/$$src"; \
		fi; \
	done; \
	test $$fail -eq 0 || { echo "a //go:embed payload is not in the binary; the release header is wrong"; exit 1; }

.PHONY: snapshot
snapshot: build-fast ## full reindex into .semiplane-test/ for manual QA
	$(BIN) reindex --full --vault .semiplane-test

.PHONY: clean
clean: ## remove build output and test artefacts
	rm -rf $(DIST) coverage.out .semiplane-test
