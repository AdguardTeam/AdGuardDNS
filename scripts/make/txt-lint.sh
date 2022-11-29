#!/bin/sh

# _SCRIPT_VERSION is used to simplify checking local copies of the script.  Bump
# this number every time a significant change is made to this script.
_SCRIPT_VERSION='2'
readonly _SCRIPT_VERSION

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

# We don't need glob expansions and we want to see errors about unset variables.
set -f -u

# Source the common helpers, including not_found.
. ./scripts/make/helper.sh

git ls-files -- '*.md' '*.yaml' '*.yml'\
	| xargs misspell --error\
	| sed -e 's/^/misspell: /'
