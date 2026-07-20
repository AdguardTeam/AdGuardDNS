# syntax=docker/dockerfile:1

# This comment is used to simplify checking local copies of the Dockerfile.
# Bump this number every time a significant change is made to this Dockerfile.
#
# AdGuard-Project-Version: 11

# Dockerfile guidelines:
#
# 1. Make sure that Docker correctly caches layers, on a second build attempt it
#    must not run lint / test second time when it's not required.
#
# 2. Use BuildKit to improve the build performance (--mount=type=cache, etc).
#
# 3. Prefer using ARG instead of ENV when appropriate, as ARG does not create a
#    layer in the final image.  However, be careful with what you use ARG for.
#    Also, prefer to give ARGs sensible default values.
#
# 4. Use --output and the export stage if you need to get any output on the host
#    machine.
#
#    NOTE:  Only use --output with FROM scratch.
#
# 5. Use .dockerignore to prevent unnecessary files from being sent to the
#    Docker daemon, which can invalidate the cache.
#
# 6. Add a CACHE_BUSTER argument to stages to be able to rerun the stages if
#    needed.  Keep it in sync with the files in .github/workflows/.

ARG BASE_IMAGE=adguard/go-builder:1.26.4--1

# The dependencies stage is needed to install packages and tool dependencies.
# This is also where binaries like osslsigncode, which may be required for tests
# in some projects, must be installed.
#
# Use fake BRANCH and REVISION values to both prevent git calls and also not
# ruin the caching with ARGs.
#
# NOTE:  Only ADD the files required to install the dependencies.
FROM "$BASE_IMAGE" AS dependencies
ADD Makefile go.mod go.sum /app/
ADD internal/dnsserver/go.mod internal/dnsserver/go.sum /app/internal/dnsserver/
ADD scripts /app/scripts
WORKDIR /app
RUN \
	--mount=type=cache,id=gocache,target=/root/.cache/go-build \
	--mount=type=cache,id=gopath,target=/go \
<<-'EOF'
set -e -f -o 'pipefail' -u -x
make \
	BRANCH='master' \
	REVISION='0000000000000000000000000000000000000000' \
	VERBOSE=1 \
	go-env \
	go-deps \
	;
EOF

# The linter stage is separated from the tester stage to make catching test
# failures easier.
#
# Use fake BRANCH and REVISION values to both prevent git calls and also not
# ruin the caching with ARGs.  IGNORE_NON_REPRODUCIBLE is set to 1 to make this
# stage reproducible even when linters that query external sources fail.
FROM dependencies AS linter
ADD . /app
WORKDIR /app
RUN \
	--mount=type=cache,id=gocache,target=/root/.cache/go-build \
	--mount=type=cache,id=gopath,target=/go \
<<-'EOF'
set -e -f -o 'pipefail' -u -x
export GOMAXPROCS=2
make \
	BRANCH='master' \
	IGNORE_NON_REPRODUCIBLE='1' \
	REVISION='0000000000000000000000000000000000000000' \
	VERBOSE=1 \
	go-lint \
	md-lint \
	sh-lint \
	txt-lint \
	2>&1 \
	| tee /lint-output.txt \
	;
EOF

# linter-exporter exports the test result to the host machine so that it could
# parse and analyze it.  This stage should only be used in a CI.
FROM scratch AS linter-exporter
ARG CACHE_BUSTER=0
COPY --from=linter /lint-output.txt /lint-output.txt

# The test stage.  TEST_REPORTS_DIR is set to create JUnit reports for the
# tester-exporter stage; run with --build-arg TEST_REPORTS_DIR='' if you don't
# need them on your machine.
#
# Use fake BRANCH and REVISION values to both prevent git calls and also not
# ruin the caching with ARGs.
#
# To run the tests:
#
#   docker build --target tester -t 'app' .
#
# Projects that have go-bench and/or go-fuzz targets should add them here as
# well.
FROM linter AS tester
ARG CACHE_BUSTER=0
ARG TEST_INTEGRATION=1
ARG TEST_REPORTS_DIR=/test-reports
RUN \
	--mount=type=cache,id=gocache,target=/root/.cache/go-build \
	--mount=type=cache,id=gopath,target=/go \
<<-'EOF'
set -e -f -o 'pipefail' -u -x
export GOMAXPROCS=2

export TEST_REDIS_PORT=6379
readonly TEST_REDIS_PORT

readonly redis_server_pidfile='redis-server.pid'

redis-server \
	--daemonize yes \
	--pidfile "$redis_server_pidfile" \
	--port "$TEST_REDIS_PORT" \
	;

make \
	BRANCH='master' \
	REVISION='0000000000000000000000000000000000000000' \
	TEST_REPORTS_DIR="$TEST_REPORTS_DIR" \
	VERBOSE=1 \
	go-test \
	;

exit_code="$(cat "${TEST_REPORTS_DIR}/test-exit-code.txt")"
readonly exit_code

redis_server_pid="$(head -n 1 "$redis_server_pidfile")"
readonly redis_server_pid

kill "$redis_server_pid"

make \
	BRANCH='master' \
	REVISION='0000000000000000000000000000000000000000' \
	VERBOSE=1 \
	go-fuzz \
	go-bench \
	;

exit "$exit_code"
EOF

# tester-exporter exports the test result to the host machine so that it could
# parse and analyze it.  This stage should only used in a CI.
#
# It the file test-report.xml, which contains test results in the JUnit format.
#
# Run the following command to export the test result:
#
#   docker build \
#	   --output . \
#	   --progress plain \
#	   --target tester-exporter \
#	   .
FROM scratch AS tester-exporter
ARG CACHE_BUSTER=0
ARG TEST_REPORTS_DIR=/test-reports
COPY --from=tester "$TEST_REPORTS_DIR" "$TEST_REPORTS_DIR"

# The builder stage is used to build release artifacts.  Real BRANCH and
# REVISION must be used here.
FROM dependencies AS builder
ARG APP_VERSION=""
ARG BRANCH=master
ARG CACHE_BUSTER=0
ARG OUTPUT="agdns"
ARG RACE=0
ARG REVISION=0000000000000000000000000000000000000000
ARG SOURCE_DATE_EPOCH=0
ADD . /app
WORKDIR /app
RUN \
	--mount=type=cache,id=gocache,target=/root/.cache/go-build \
	--mount=type=cache,id=gopath,target=/go \
<<-'EOF'
set -e -f -o 'pipefail' -u -x
make \
	APP_VERSION="$APP_VERSION" \
	BRANCH="$BRANCH" \
	GOAMD64='v4' \
	OUT="dist/${OUTPUT}" \
	RACE="$RACE" \
	REVISION="$REVISION" \
	SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
	VERBOSE=1 \
	go-build \
	;
EOF

# The deb-builder stage packs the binary into a .deb package.
FROM alanfranz/fpm-within-docker:ubuntu-bionic AS deb-builder
WORKDIR /app
ARG COMMIT_SHA
ARG NAME=agdns
COPY --from=builder "/app/dist/${NAME}" "/app/${NAME}"
RUN <<-'EOF'
# TODO(a.garipov):  Use set -o 'pipefail' when the image supports it.
set -e -f -u -x
fpm \
	--category 'non-free/web' \
	--deb-user 'web' \
	--license 'proprietary' \
	--prefix '/usr/local/bin' \
	--url 'https://adguard.com/' \
	-a 'noarch' \
	-m 'Adguard Go Team' \
	-n "adguard-${NAME}-service" \
	-s 'dir' \
	-t 'deb' \
	-v "1.${COMMIT_SHA}" \
	"${NAME}" \
	;
EOF

# The runtime stage.
#
# NOTE:  For .deb services this includes only the package.
FROM scratch AS runtime
COPY --from=deb-builder /app/*.deb /
