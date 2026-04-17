#!/bin/sh

# This comment is used to simplify checking local copies of the script.  Bump
# this number every time a significant change is made to this script.
#
# AdGuard-Project-Version: 18

verbose="${VERBOSE:-0}"
readonly verbose

if [ "$verbose" -gt '0' ]; then
	set -x
fi

# Set $EXIT_ON_ERROR to zero to see all errors.
if [ "${EXIT_ON_ERROR:-1}" -eq '0' ]; then
	set +e
else
	set -e
fi

set -f -u

# Source the common helpers, including not_found and run_linter.
. ./scripts/make/helper.sh

# Simple analyzers

# blocklist_imports is a simple best-effort check against unwanted packages.
# The following packages are banned:
#
#   *  Package errors is replaced by our own package in the
#      github.com/AdguardTeam/golibs module.
#
#   *  Packages log and github.com/AdguardTeam/golibs/log are replaced by
#      stdlib's new package log/slog and AdGuard's new utilities package
#      github.com/AdguardTeam/golibs/logutil/slogutil.
#
#   *  Package github.com/prometheus/client_golang/prometheus/promauto is not
#      recommended, as it encourages reliance on global state.
#
#   *  Packages golang.org/x/exp/maps, golang.org/x/exp/slices, and
#      golang.org/x/net/context have been moved into stdlib.
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
# Currently, the only standard exception are files generated from protobuf
# schemas, which use package reflect.  If your project needs more exceptions,
# add and document them.
#
# NOTE:  Flag -H for grep is non-POSIX but all of Busybox, GNU, macOS, and
# OpenBSD support it.
#
# NOTE: For AdGuard DNS, there are the following exceptions:
#
#   *  internal/agdtest/profile.go: a test helper requiring the use of
#      reflect.Type.
#   *  internal/agdprotobuf/unsafe.go: a “safe” unsafe helper
#      to prevent excessive allocations.
blocklist_imports() {
	import_or_tab="$(printf '^\\(import \\|\t\\)')"
	readonly import_or_tab

	find_with_ignore \
		-type 'f' \
		'(' \
		-name '*.go' \
		'!' -name '*.pb.go' \
		'!' -path './internal/agdtest/profile.go' \
		'!' -path './internal/agdprotobuf/unsafe.go' \
		')' \
		-exec \
		'grep' \
		'-H' \
		'-e' "$import_or_tab"'"errors"$' \
		'-e' "$import_or_tab"'"github.com/AdguardTeam/golibs/log"$' \
		'-e' "$import_or_tab"'"github.com/prometheus/client_golang/prometheus/promauto"$' \
		'-e' "$import_or_tab"'"golang.org/x/exp/maps"$' \
		'-e' "$import_or_tab"'"golang.org/x/exp/slices"$' \
		'-e' "$import_or_tab"'"golang.org/x/net/context"$' \
		'-e' "$import_or_tab"'"io/ioutil"$' \
		'-e' "$import_or_tab"'"log"$' \
		'-e' "$import_or_tab"'"reflect"$' \
		'-e' "$import_or_tab"'"sort"$' \
		'-e' "$import_or_tab"'"unsafe"$' \
		'-n' \
		'{}' \
		';'
}

# method_const is a simple check against the usage of some raw strings and
# numbers where one should use named constants.
#
# NOTE:  Flag -H for grep is non-POSIX but all of Busybox, GNU, macOS, and
# OpenBSD support it.
method_const() {
	find_with_ignore \
		-type 'f' \
		-name '*.go' \
		-exec \
		'grep' \
		'-H' \
		'-e' '"DELETE"' \
		'-e' '"GET"' \
		'-e' '"PATCH"' \
		'-e' '"POST"' \
		'-e' '"PUT"' \
		'-n' \
		'{}' \
		';'
}

# underscores is a simple check against Go filenames with underscores.  Add new
# build tags and OS as you go.  The main goal of this check is to discourage the
# use of filenames like client_manager.go.
underscores() {
	underscore_files="$(
		find_with_ignore \
			-type 'f' \
			-name '*_*.go' \
			'!' '(' \
			-name '*_darwin.go' \
			-o -name '*_generate.go' \
			-o -name '*_grpc.pb.go' \
			-o -name '*_linux.go' \
			-o -name '*_others.go' \
			-o -name '*_test.go' \
			-o -name '*_unix.go' \
			-o -name '*_windows.go' \
			')' \
			-exec 'printf' '\t%s\n' '{}' ';'
	)"
	readonly underscore_files

	if [ "$underscore_files" != '' ]; then
		printf \
			'found file names with underscores:\n%s\n' \
			"$underscore_files"
	fi
}

go="${GO:-go}"
readonly go

# TODO(a.garipov): Add an analyzer to look for `fallthrough`, `goto`, and `new`?

# Checks

run_linter -e blocklist_imports

run_linter -e method_const

run_linter -e underscores

run_linter -e "$go" tool gofumpt --extra -e -l .

run_linter "$go" vet work

# govulncheck is not stricly reproducible, because it queries the VulnDB, which
# is updated constantly.  If a stricly reproducible lint is desired, for example
# for Docker lint stages, set IGNORE_NON_REPRODUCIBLE to 1 to ignore the exit
# code from govulncheck.
if [ "${IGNORE_NON_REPRODUCIBLE:-0}" -gt '0' ]; then
	# run_linter calls set +e, so don't mind the cancelling effect of ||.
	# shellcheck disable=SC2310
	run_linter "$go" tool govulncheck work || :
else
	run_linter "$go" tool govulncheck work
fi

# NOTE: For AdGuard DNS, ignore the generated protobuf files.
run_linter "$go" tool gocyclo --ignore '\.pb\.go$' --over 10 .

# NOTE: For AdGuard DNS, ignore the generated protobuf files.
run_linter "$go" tool gocognit --ignore '\.pb\.go$' --over 10 .

run_linter "$go" tool ineffassign work

run_linter "$go" tool unparam work

find_with_ignore \
	-type 'f' \
	'(' \
	-name 'Makefile' \
	-o -name '*.conf' \
	-o -name '*.go' \
	-o -name '*.mod' \
	-o -name '*.sh' \
	-o -name '*.yaml' \
	-o -name '*.yml' \
	')' \
	-exec "$go" 'tool' 'misspell' '--error' '{}' '+'

run_linter "$go" tool nilness work

# TODO(a.garipov):  Remove the grep crutch once golang/go#60509 is fixed.
#
# TODO(a.garipov):  Add a filtering function to run_linter.
fieldalignment_output="$(
	"$go" tool fieldalignment work 2>&1 \
		| grep -e '\.pb\.go' -v \
		|| :
)"
readonly fieldalignment_output

if [ "$fieldalignment_output" != '' ]; then
	printf '%s\n' "$fieldalignment_output"

	exit 1
fi

# TODO(a.garipov): Remove the grep crutch once golang/go#61574 is fixed.
shadow_output="$(
	"$go" tool shadow --strict work 2>&1 \
		| grep -e '\.pb\.go' -v \
		|| :
)"
readonly shadow_output

if [ "$shadow_output" != '' ]; then
	printf '%s\n' "$shadow_output"

	exit 1
fi

run_linter "$go" tool gosec --exclude-generated --fmt=golint --quiet work

run_linter "$go" tool errcheck work

run_linter "$go" tool staticcheck --matrix work <<-'EOF'
	darwin: GOOS=darwin
	linux:  GOOS=linux
EOF
