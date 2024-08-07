#!/bin/sh

# This comment is used to simplify checking local copies of the script.  Bump
# this number every time a significant change is made to this script.
#
# AdGuard-Project-Version: 6

verbose="${VERBOSE:-0}"
readonly verbose

if [ "$verbose" -gt '0' ]
then
	set -x
fi

# Set $EXIT_ON_ERROR to zero to see all errors.
if [ "${EXIT_ON_ERROR:-1}" -eq '0' ]
then
	set +e
else
	set -e
fi

set -f -u



# Source the common helpers, including not_found and run_linter.
. ./scripts/make/helper.sh



# Simple analyzers

# blocklist_imports is a simple check against unwanted packages.  The following
# packages are banned:
#
#   *  Packages errors and log are replaced by our own packages in the
#      github.com/AdguardTeam/golibs module.
#
#   *  Package io/ioutil is soft-deprecated.
#
#   *  Package reflect is often an overkill, and for deep comparisons there are
#      much better functions in module github.com/google/go-cmp.  Which is
#      already our indirect dependency and which may or may not enter the stdlib
#      at some point.
#
#      See https://github.com/golang/go/issues/45200.
#
#   *  Package sort is replaced by package slices.
#
#   *  Package unsafe is… unsafe.
#
#   *  Package golang.org/x/exp/slices has been moved into stdlib.
#
#   *  Package golang.org/x/net/context has been moved into stdlib.
#
# Currently, the only standard exception are files generated from protobuf
# schemas, which use package reflect.  If your project needs more exceptions,
# add and document them.
#
# NOTE: For AdGuard DNS, there are the following exceptions:
#
#   *  internal/profiledb/internal/filecachepb/unsafe.go: a “safe” unsafe helper
#      to prevent excessive allocations.
#
# TODO(a.garipov): Add deprecated package golang.org/x/exp/maps and once all
# projects switch to Go 1.23 or later.
blocklist_imports() {
	git grep\
		-e '[[:space:]]"errors"$'\
		-e '[[:space:]]"golang.org/x/exp/slices"$'\
		-e '[[:space:]]"golang.org/x/net/context"$'\
		-e '[[:space:]]"io/ioutil"$'\
		-e '[[:space:]]"log"$'\
		-e '[[:space:]]"reflect"$'\
		-e '[[:space:]]"sort"$'\
		-e '[[:space:]]"unsafe"$'\
		-n\
		-- '*.go'\
		':!*.pb.go'\
		':!internal/profiledb/internal/filecachepb/unsafe.go'\
		| sed -e 's/^\([^[:space:]]\+\)\(.*\)$/\1 blocked import:\2/'\
		|| exit 0
}

# method_const is a simple check against the usage of some raw strings and
# numbers where one should use named constants.
method_const() {
	git grep -F\
		-e '"DELETE"'\
		-e '"GET"'\
		-e '"PATCH"'\
		-e '"POST"'\
		-e '"PUT"'\
		-n\
		-- '*.go'\
		| sed -e 's/^\([^[:space:]]\+\)\(.*\)$/\1 http method literal:\2/'\
		|| exit 0
}

# underscores is a simple check against Go filenames with underscores.  Add new
# build tags and OS as you go.  The main goal of this check is to discourage the
# use of filenames like client_manager.go.
underscores() {
	underscore_files="$(
		git ls-files '*_*.go'\
			| grep -F\
			-e '_generate.go'\
			-e '_grpc.pb.go'\
			-e '_linux.go'\
			-e '_noreuseport.go'\
			-e '_others.go'\
			-e '_reuseport.go'\
			-e '_test.go'\
			-e '_unix.go'\
			-e '_windows.go'\
			-v\
			| sed -e 's/./\t\0/'
	)"
	readonly underscore_files

	if [ "$underscore_files" != '' ]
	then
		echo 'found file names with underscores:'
		echo "$underscore_files"
	fi
}

# TODO(a.garipov): Add an analyzer to look for `fallthrough`, `goto`, and `new`?



# Checks

# TODO(a.garipov): Remove the dnsserver stuff once it is separated.
dnssrvmod='github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/...'
readonly dnssrvmod

run_linter -e blocklist_imports

run_linter -e method_const

run_linter -e underscores

run_linter -e gofumpt --extra -e -l .

# TODO(a.garipov): golint is deprecated, find a suitable replacement.

run_linter "$GO" vet ./... "$dnssrvmod"

run_linter govulncheck ./... "$dnssrvmod"

# NOTE: For AdGuard DNS, ignore the generated protobuf files.
run_linter gocyclo --ignore '\.pb\.go$' --over 10 .

# NOTE: For AdGuard DNS, ignore the generated protobuf files.
run_linter gocognit --ignore '\.pb\.go$' --over='10' .

run_linter ineffassign ./... "$dnssrvmod"

run_linter unparam ./... "$dnssrvmod"

git ls-files -- 'Makefile' '*.conf' '*.go' '*.mod' '*.sh' '*.yaml' '*.yml'\
	| xargs misspell --error\
	| sed -e 's/^/misspell: /'

run_linter nilness ./... "$dnssrvmod"

# TODO(a.garipov):  Remove the grep crutch once golang/go#60509 is fixed.
#
# TODO(a.garipov):  Add a filtering function to run_linter.
fieldalignment_output="$( fieldalignment ./... "$dnssrvmod" 2>&1 | grep -e '\.pb\.go' -v || : )"
readonly fieldalignment_output

if [ "$fieldalignment_output" != '' ]
then
	printf '%s\n' "$fieldalignment_output"

	exit 1
fi

# TODO(a.garipov): Remove the grep crutch once golang/go#61574 is fixed.
shadow_output="$( shadow --strict ./... "$dnssrvmod" 2>&1 | grep -e '\.pb\.go' -v || : )"
readonly shadow_output

if [ "$shadow_output" != '' ]
then
	printf '%s\n' "$shadow_output"

	exit 1
fi

run_linter gosec --quiet ./... "$dnssrvmod"

run_linter errcheck ./... "$dnssrvmod"

staticcheck_matrix='
darwin: GOOS=darwin
linux:  GOOS=linux
'
readonly staticcheck_matrix

echo "$staticcheck_matrix" | run_linter staticcheck --matrix ./... "$dnssrvmod"
