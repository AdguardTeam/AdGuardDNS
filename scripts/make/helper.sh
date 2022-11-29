#!/bin/sh

# Common script helpers
#
# This file contains common script helpers.  It should be sourced in scripts
# right after the initial environment processing.

# _HELPER_VERSION is used to simplify checking local copies of the script.  Bump
# this number every time a significant change is made to this script.
_HELPER_VERSION='1'
readonly _HELPER_VERSION



# Deferred helpers

not_found_msg='
looks like a binary not found error.
make sure you have installed the linter binaries using:

	$ make go-tools
'
readonly not_found_msg

not_found() {
	if [ "$?" -eq '127' ]
	then
		# Code 127 is the exit status a shell uses when a command or a file is
		# not found, according to the Bash Hackers wiki.
		#
		# See https://wiki.bash-hackers.org/dict/terms/exit_status.
		echo "$not_found_msg" 1>&2
	fi
}
trap not_found EXIT



# Helpers

# with_progname adds the program's name to its combined output.
with_progname() {
	with_progname_cmd="${1:?provide a command}"
	shift

	"$with_progname_cmd" "$@" 2>&1 | sed -e "s/^/${with_progname_cmd}: /"
}

# exit_on_output exits with a nonzero exit code if there is anything in the
# command's combined output.
exit_on_output() (
	set +e

	if [ "$VERBOSE" -lt '2' ]
	then
		set +x
	fi

	cmd="$1"
	shift

	output="$( with_progname "$cmd" "$@" 2>&1 )"
	exitcode="$?"
	if [ "$exitcode" -ne '0' ]
	then
		echo "'$cmd' failed with code $exitcode"
	fi

	if [ "$output" != '' ]
	then
		echo "$output"

		if [ "$exitcode" -eq '0' ]
		then
			exitcode='1'
		fi
	fi

	return "$exitcode"
)
