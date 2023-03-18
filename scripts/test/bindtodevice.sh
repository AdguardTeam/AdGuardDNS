#!/bin/sh

set -e -f -u -x

use_sudo="${USE_SUDO:-0}"
readonly use_sudo

maybe_sudo() {
	if [ "$use_sudo" -eq 0 ]
	then
		"$@"
	else
		sudo "$@"
	fi
}

maybe_sudo docker build\
	-t agdns_bindtodevice_test\
	-\
	< ./scripts/test/bindtodevice.docker

maybe_sudo docker run\
	--cap-add='NET_ADMIN'\
	--name='agdns_bindtodevice_test'\
	--rm\
	-i\
	-t\
	-v "$PWD":'/test'\
	-v "$( go env GOMODCACHE )":'/go/pkg/mod'\
	agdns_bindtodevice_test
