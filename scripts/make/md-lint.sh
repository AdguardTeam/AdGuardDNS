#!/bin/sh

# This comment is used to simplify checking local copies of the script.  Bump
# this number every time a significant change is made to this script.
#
# AdGuard-Project-Version: 3

verbose="${VERBOSE:-0}"
readonly verbose

# Don't use -f, because we use globs in this script.
set -e -u

if [ "$verbose" -gt '0' ]; then
	set -x
fi

markdownlint \
	./*.md \
	./doc/*.md \
	;
