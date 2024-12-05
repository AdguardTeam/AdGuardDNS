# Keep the Makefile POSIX-compliant.  We currently allow hyphens in
# target names, but that may change in the future.
#
# See https://pubs.opengroup.org/onlinepubs/9699919799/utilities/make.html.
.POSIX:

# This comment is used to simplify checking local copies of the
# Makefile.  Bump this number every time a significant change is made to
# this Makefile.
#
# AdGuard-Project-Version: 9

# Don't name these macros "GO" etc., because GNU Make apparently makes
# them exported environment variables with the literal value of
# "${GO:-go}" and so on, which is not what we need.  Use a dot in the
# name to make sure that users don't have an environment variable with
# the same name.
#
# See https://unix.stackexchange.com/q/646255/105635.
GO.MACRO = $${GO:-go}
VERBOSE.MACRO = $${VERBOSE:-0}

BRANCH = $${BRANCH:-$$(git rev-parse --abbrev-ref HEAD)}
GOAMD64 = v1
GOPROXY = https://proxy.golang.org|direct
GOTELEMETRY = off
GOTOOLCHAIN = go1.23.4
RACE = 0
REVISION = $${REVISION:-$$(git rev-parse --short HEAD)}
VERSION = 0

ENV = env \
	BRANCH="$(BRANCH)" \
	GO="$(GO.MACRO)" \
	GOAMD64='$(GOAMD64)' \
	GOPROXY='$(GOPROXY)' \
	GOTELEMETRY='$(GOTELEMETRY)' \
	GOTOOLCHAIN='$(GOTOOLCHAIN)' \
	PATH="$${PWD}/bin:$$("$(GO.MACRO)" env GOPATH)/bin:$${PATH}" \
	RACE='$(RACE)' \
	REVISION="$(REVISION)" \
	VERBOSE="$(VERBOSE.MACRO)" \
	VERSION="$(VERSION)" \

# Keep the line above blank.

ENV_MISC = env \
	PATH="$${PWD}/bin:$$("$(GO.MACRO)" env GOPATH)/bin:$${PATH}" \
	VERBOSE="$(VERBOSE.MACRO)" \

# Keep the line above blank.

# Keep this target first, so that a naked make invocation triggers a
# full build.
build: go-deps go-build

init: ; git config core.hooksPath ./scripts/hooks

test: go-test

go-bench:     ; $(ENV)          "$(SHELL)" ./scripts/make/go-bench.sh
go-build:     ; $(ENV)          "$(SHELL)" ./scripts/make/go-build.sh
go-deps:      ; $(ENV)          "$(SHELL)" ./scripts/make/go-deps.sh
go-env:       ; $(ENV)          "$(GO.MACRO)" env
go-fuzz:      ; $(ENV)          "$(SHELL)" ./scripts/make/go-fuzz.sh
go-gen:       ; $(ENV)          "$(SHELL)" ./scripts/make/go-gen.sh
go-lint:      ; $(ENV)          "$(SHELL)" ./scripts/make/go-lint.sh
go-test:      ; $(ENV) RACE='1' "$(SHELL)" ./scripts/make/go-test.sh
go-tools:     ; $(ENV)          "$(SHELL)" ./scripts/make/go-tools.sh
go-upd-tools: ; $(ENV)          "$(SHELL)" ./scripts/make/go-upd-tools.sh

go-check: go-tools go-lint go-test

# A quick check to make sure that all operating systems relevant to the
# development of the project can be typechecked and built successfully.
go-os-check:
	$(ENV) GOOS='darwin' "$(GO.MACRO)" vet ./internal/... ./internal/dnsserver/...
	$(ENV) GOOS='linux'  "$(GO.MACRO)" vet ./internal/... ./internal/dnsserver/...
# Additionally, check the AdGuard Home OSs in the dnsserver module.
	$(ENV) GOOS='freebsd' "$(GO.MACRO)" vet ./internal/dnsserver/...
	$(ENV) GOOS='openbsd' "$(GO.MACRO)" vet ./internal/dnsserver/...
	$(ENV) GOOS='windows' "$(GO.MACRO)" vet ./internal/dnsserver/...

txt-lint: ; $(ENV) "$(SHELL)" ./scripts/make/txt-lint.sh

md-lint:  ; $(ENV_MISC) "$(SHELL)" ./scripts/make/md-lint.sh
sh-lint:  ; $(ENV_MISC) "$(SHELL)" ./scripts/make/sh-lint.sh

# Targets related to AdGuard DNS start here.

sync-github: ; $(ENV) "$(SHELL)" ./scripts/make/github-sync.sh
