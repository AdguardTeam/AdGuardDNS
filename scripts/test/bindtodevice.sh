#!/bin/sh

set -e -f -o 'pipefail' -u -x

use_sudo="${USE_SUDO:-0}"
readonly use_sudo

maybe_sudo() {
	if [ "$use_sudo" -eq '0' ]; then
		"$@"
	else
		sudo "$@"
	fi
}

maybe_sudo docker build \
	--progress='plain' \
	-f scripts/test/bindtodevice.Dockerfile \
	-t 'agdns_bindtodevice_test' \
	scripts/test \
	;

gomodcache="$(go env GOMODCACHE)"
readonly gomodcache

# The entrypoint manipulates network interfaces, which requires
# --cap-add='NET_ADMIN' at container runtime.  See ./bindtodevice-entrypoint.sh.
maybe_sudo docker run \
	--cap-add='NET_ADMIN' \
	--name='agdns_bindtodevice_test' \
	--rm \
	-i \
	-t \
	-v "$PWD":'/test' \
	-v "$gomodcache":'/go/pkg/mod' \
	'agdns_bindtodevice_test' \
	;
